package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/server/webapi/middleware"
	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// requireSession wraps next with the session-resolving auth middleware for tests.
func requireSession(sm middleware.WebAPISessionResolver, next func(http.ResponseWriter, *http.Request, *state.WebAPISession)) http.Handler {
	return middleware.NewAuthMiddleware(nil, slog.Default()).RequireSession(sm, next)
}

// MockICBMService is a mock implementation of ICBMService
type MockICBMService struct {
	mock.Mock
}

func (m *MockICBMService) ChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	if msg := args.Get(0); msg != nil {
		return msg.(*wire.SNACMessage), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockICBMService) ClientEvent(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x14_ICBMClientEvent) error {
	args := m.Called(ctx, instance, inFrame, inBody)
	return args.Error(0)
}

// createTestSessionManager creates a WebAPISessionManager with a pre-populated session.
func createTestSessionManager(screenName string) (*state.WebAPISessionManager, string) {
	return createTestSessionManagerWithOSCAR(screenName, nil)
}

// createTestSessionManagerWithOSCAR creates a WebAPISessionManager with an OSCAR session instance set.
func createTestSessionManagerWithOSCAR(screenName string, oscarSession *state.SessionInstance) (*state.WebAPISessionManager, string) {
	mgr := state.NewWebAPISessionManager()
	session, _ := mgr.CreateSession(
		context.Background(),
		state.DisplayScreenName(screenName),
		"test-dev",
		[]string{"im", "presence", "buddylist", "sentIM", "typing"},
		oscarSession,
		slog.Default(),
	)
	return mgr, session.AimSID
}

// stubLocateService answers UserInfoQuery with a reply carrying screenName, or
// with an error when screenName is empty (i.e. the target is offline or blocked).
func stubLocateService(screenName string) *MockLocateService {
	ls := &MockLocateService{}
	call := ls.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	if screenName == "" {
		call.Return(wire.SNACMessage{}, io.EOF)
	} else {
		call.Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: screenName},
		}}, nil)
	}
	return ls
}

// stubFeedbagService answers Query with a single buddy item for buddy, carrying
// alias when one is given.
func stubFeedbagService(buddy, alias string) *MockFeedbagService {
	item := wire.FeedbagItem{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: buddy}
	if alias != "" {
		item.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, alias)}}
	}
	fs := &MockFeedbagService{}
	fs.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{item}}}, nil,
	)
	return fs
}

// sendIMForDest drives SendIM addressed to t, with the recipient's display name
// resolving to locateName and the sender's alias for them set to alias, and returns
// the events queued for the sender.
func sendIMForDest(t *testing.T, dest, locateName, alias string) []types.Event {
	t.Helper()

	oscarInstance := state.NewSession().AddInstance()
	icbmService := &MockICBMService{}
	icbmService.On("ChannelMsgToHost", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil)

	mgr := state.NewWebAPISessionManager()
	session, err := mgr.CreateSession(context.Background(), state.DisplayScreenName("Ann Dupree"),
		"test-dev", []string{"im", "sentIM", "conversation"}, oscarInstance, slog.Default())
	require.NoError(t, err)

	handler := &MessagingHandler{
		SessionManager: mgr,
		ICBMService:    icbmService,
		LocateService:  stubLocateService(locateName),
		FeedbagService: stubFeedbagService(dest, alias),
		Logger:         slog.Default(),
	}

	// startSession wires this in production; SendIM reads aliases off the session.
	session.BuddyAliasLoader = func(ctx context.Context) (map[string]string, error) {
		return LookupBuddyAliases(ctx, handler.FeedbagService, session.OSCARSession)
	}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid="+session.AimSID+"&t="+url.QueryEscape(dest)+"&message=hi", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(mgr, handler.SendIM).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	return session.EventQueue.GetAllEvents()
}

// The client sends t as the normalized aimId, so the recipient's display name has
// to come from the locate reply. Echoing t back as a displayId would overwrite the
// properly formatted name the client already holds for that aimId.
func TestMessagingHandler_SendIM_DestDisplayIDFromLocateReply(t *testing.T) {
	var sentIM types.SentIMEvent
	var conv map[string]interface{}
	for _, event := range sendIMForDest(t, "mikelee", "Mike Lee", "") {
		switch event.Type {
		case types.EventTypeSentIM:
			sentIM, _ = event.Data.(types.SentIMEvent)
		case types.EventTypeConversation:
			data, _ := event.Data.(map[string]interface{})
			convs, _ := data["conversations"].([]map[string]interface{})
			require.Len(t, convs, 1)
			conv = convs[0]
		}
	}

	assert.Equal(t, "anndupree", sentIM.Sender.AimID)
	assert.Equal(t, "Ann Dupree", sentIM.Sender.DisplayID)
	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Equal(t, "Mike Lee", sentIM.Dest.DisplayID)

	require.NotNil(t, conv)
	assert.Equal(t, "mikelee", conv["aimId"])
	assert.Equal(t, "Mike Lee", conv["displayId"])
}

// An alias is private to the sender and lives only in their feedbag, and the client
// deletes the alias it holds every time it merges a user map. So the sentIM echo has
// to repeat it, or messaging an aliased buddy renames him back to his screen name.
func TestMessagingHandler_SendIM_DestCarriesAlias(t *testing.T) {
	var sentIM types.SentIMEvent
	for _, event := range sendIMForDest(t, "mikelee", "Mike Lee", "MICHAELLEE") {
		if event.Type == types.EventTypeSentIM {
			sentIM, _ = event.Data.(types.SentIMEvent)
		}
	}

	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Equal(t, "Mike Lee", sentIM.Dest.DisplayID)
	assert.Equal(t, "MICHAELLEE", sentIM.Dest.Friendly)
}

// When the recipient's display name cannot be resolved, displayId is omitted
// rather than filled in with the aimId, leaving the client's existing name intact.
func TestMessagingHandler_SendIM_OmitsDestDisplayIDWhenUnresolved(t *testing.T) {
	var sentIM types.SentIMEvent
	var conv map[string]interface{}
	for _, event := range sendIMForDest(t, "mikelee", "", "") {
		switch event.Type {
		case types.EventTypeSentIM:
			sentIM, _ = event.Data.(types.SentIMEvent)
		case types.EventTypeConversation:
			data, _ := event.Data.(map[string]interface{})
			convs, _ := data["conversations"].([]map[string]interface{})
			require.Len(t, convs, 1)
			conv = convs[0]
		}
	}

	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Empty(t, sentIM.Dest.DisplayID)
	encoded, err := json.Marshal(sentIM)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "displayId\":\"mikelee\"")

	require.NotNil(t, conv)
	assert.Equal(t, "mikelee", conv["aimId"])
	assert.NotContains(t, conv, "displayId")
}

func TestMessagingHandler_SendIM(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()

	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockICBMService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success",
			queryParams: "t=recipient&message=hello+world",
			setupMocks: func(is *MockICBMService) {
				is.On("ChannelMsgToHost", mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNACFrame"), mock.AnythingOfType("wire.SNAC_0x04_0x06_ICBMChannelMsgToHost")).
					Return(nil, nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"msgId"`)
				assert.Contains(t, body, `"state":"delivered"`)
			},
		},
		{
			name:               "Error_MissingRecipient",
			queryParams:        "message=hello",
			setupMocks:         func(is *MockICBMService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
		{
			name:               "Error_MissingMessage",
			queryParams:        "t=recipient",
			setupMocks:         func(is *MockICBMService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: message")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icbmService := &MockICBMService{}

			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &MessagingHandler{
				SessionManager: sessionMgr,
				ICBMService:    icbmService,
				LocateService:  stubLocateService(""),
				FeedbagService: stubFeedbagService("someone", ""),
				Logger:         slog.Default(),
			}

			tt.setupMocks(icbmService)

			reqURL := "/im/sendIM?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(handler.SessionManager, handler.SendIM).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			responseBody := strings.TrimSpace(rr.Body.String())
			if tt.checkResponse != nil {
				tt.checkResponse(t, responseBody)
			}

			icbmService.AssertExpectations(t)
		})
	}
}

func TestMessagingHandler_SendIM_POST(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()
	icbmService := &MockICBMService{}

	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	icbmService.On("ChannelMsgToHost", mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNACFrame"), mock.AnythingOfType("wire.SNAC_0x04_0x06_ICBMChannelMsgToHost")).
		Return(nil, nil)

	handler := &MessagingHandler{
		SessionManager: sessionMgr,
		ICBMService:    icbmService,
		LocateService:  stubLocateService(""),
		FeedbagService: stubFeedbagService("someone", ""),
		Logger:         slog.Default(),
	}

	body := strings.NewReader("message=" + url.QueryEscape("hello from post"))
	req, err := http.NewRequest(http.MethodPost, "/im/sendIM?aimsid="+aimsid+"&f=json&t=recipient&r=1", body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"msgId"`)
	icbmService.AssertExpectations(t)
}

func TestMessagingHandler_SendIM_MissingAimsid(t *testing.T) {
	handler := &MessagingHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestMessagingHandler_SendIM_InvalidSession(t *testing.T) {
	handler := &MessagingHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid=nonexistent&t=someone&message=hi", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid or expired session")
}

func TestMessagingHandler_SetTyping(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()

	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockICBMService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_TypingStarted",
			queryParams: "t=recipient&typingStatus=typing",
			setupMocks: func(is *MockICBMService) {
				is.On("ClientEvent", mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x04_0x14_ICBMClientEvent{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient",
					Event:      0x0002,
				}).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:        "Success_TypingPaused",
			queryParams: "t=recipient&typingStatus=typed",
			setupMocks: func(is *MockICBMService) {
				is.On("ClientEvent", mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x04_0x14_ICBMClientEvent{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient",
					Event:      0x0001,
				}).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:        "Success_TypingStopped",
			queryParams: "t=recipient&typingStatus=none",
			setupMocks: func(is *MockICBMService) {
				is.On("ClientEvent", mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x04_0x14_ICBMClientEvent{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient",
					Event:      0x0000,
				}).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "Error_MissingRecipient",
			queryParams:        "typingStatus=typing",
			setupMocks:         func(is *MockICBMService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icbmService := &MockICBMService{}

			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &MessagingHandler{
				SessionManager: sessionMgr,
				ICBMService:    icbmService,
				LocateService:  stubLocateService(""),
				FeedbagService: stubFeedbagService("someone", ""),
				Logger:         slog.Default(),
			}

			tt.setupMocks(icbmService)

			reqURL := "/im/setTyping?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(handler.SessionManager, handler.SetTyping).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}

			icbmService.AssertExpectations(t)
		})
	}
}

func TestMessagingHandler_SetTyping_MissingAimsid(t *testing.T) {
	handler := &MessagingHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/setTyping", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetTyping).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}
