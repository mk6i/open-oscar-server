package webapi

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

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// requireSession wraps next with the session-resolving auth middleware for tests.
func requireSession(sm SessionResolver, next func(http.ResponseWriter, *http.Request, *Session)) http.Handler {
	return NewAuthMiddleware(nil, slog.Default()).RequireSession(sm, next)
}

// createTestSessionManager creates a SessionManager with a pre-populated session.
// createTestSessionManagerWithOSCAR creates a SessionManager with an OSCAR session instance set.
func createTestSessionManagerWithOSCAR(screenName string, oscarSession *state.SessionInstance) (*SessionManager, string) {
	mgr := NewSessionManager()
	session, _ := mgr.CreateSession(state.DisplayScreenName(screenName), "test-dev", []string{"im", "presence", "buddylist", "sentIM", "typing"}, oscarSession, "", slog.Default())
	return mgr, session.AimSID
}

// stubLocateService answers UserInfoQuery with a reply carrying screenName, or
// with an error when screenName is empty (i.e. the target is offline or blocked).
func stubLocateService(t *testing.T, screenName string) *mockLocateService {
	ls := newMockLocateService(t)
	call := ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	if screenName == "" {
		call.Return(wire.SNACMessage{}, io.EOF).Maybe()
	} else {
		call.Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: screenName},
		}}, nil).Maybe()
	}
	return ls
}

// stubFeedbagService answers Query with a single buddy item for buddy, carrying
// alias when one is given.
func stubFeedbagService(t *testing.T, buddy, alias string) *mockFeedbagService {
	item := wire.FeedbagItem{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: buddy}
	if alias != "" {
		item.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, alias)}}
	}
	fs := newMockFeedbagService(t)
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{item}}}, nil,
	).Maybe()
	return fs
}

// sendIMForDest drives SendIM addressed to t, with the recipient's display name
// resolving to locateName and the sender's alias for them set to alias, and returns
// the events queued for the sender.
func sendIMForDest(t *testing.T, dest, locateName, alias string) []Event {
	t.Helper()

	oscarInstance := state.NewSession().AddInstance()
	icbmService := newMockICBMService(t)
	icbmService.EXPECT().ChannelMsgToHost(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil)

	mgr := NewSessionManager()
	session, err := mgr.CreateSession(state.DisplayScreenName("Ann Dupree"), "test-dev", []string{"im", "sentIM", "conversation"}, oscarInstance, "", slog.Default())
	require.NoError(t, err)

	handler := &MessagingHandler{
		ICBMService:    icbmService,
		LocateService:  stubLocateService(t, locateName),
		FeedbagService: stubFeedbagService(t, dest, alias),
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
	var sentIM SentIMEvent
	var conv ConversationEntryData
	for _, event := range sendIMForDest(t, "mikelee", "Mike Lee", "") {
		switch event.Type {
		case EventTypeSentIM:
			sentIM, _ = event.Data.(SentIMEvent)
		case EventTypeConversation:
			data, _ := event.Data.(*ConversationData)
			require.NotNil(t, data)
			require.Len(t, data.Conversations, 1)
			conv = data.Conversations[0]
		}
	}

	assert.Equal(t, "anndupree", sentIM.Sender.AimID)
	assert.Equal(t, "Ann Dupree", sentIM.Sender.DisplayID)
	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Equal(t, "Mike Lee", sentIM.Dest.DisplayID)

	assert.Equal(t, "mikelee", conv.AimID)
	assert.Equal(t, "Mike Lee", conv.DisplayID)
}

// An alias is private to the sender and lives only in their feedbag, and the client
// deletes the alias it holds every time it merges a user map. So the sentIM echo has
// to repeat it, or messaging an aliased buddy renames him back to his screen name.
func TestMessagingHandler_SendIM_DestCarriesAlias(t *testing.T) {
	var sentIM SentIMEvent
	for _, event := range sendIMForDest(t, "mikelee", "Mike Lee", "MICHAELLEE") {
		if event.Type == EventTypeSentIM {
			sentIM, _ = event.Data.(SentIMEvent)
		}
	}

	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Equal(t, "Mike Lee", sentIM.Dest.DisplayID)
	assert.Equal(t, "MICHAELLEE", sentIM.Dest.Friendly)
}

// When the recipient's display name cannot be resolved, displayId is omitted
// rather than filled in with the aimId, leaving the client's existing name intact.
func TestMessagingHandler_SendIM_OmitsDestDisplayIDWhenUnresolved(t *testing.T) {
	var sentIM SentIMEvent
	var conv ConversationEntryData
	for _, event := range sendIMForDest(t, "mikelee", "", "") {
		switch event.Type {
		case EventTypeSentIM:
			sentIM, _ = event.Data.(SentIMEvent)
		case EventTypeConversation:
			data, _ := event.Data.(*ConversationData)
			require.NotNil(t, data)
			require.Len(t, data.Conversations, 1)
			conv = data.Conversations[0]
		}
	}

	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Empty(t, sentIM.Dest.DisplayID)
	encoded, err := json.Marshal(sentIM)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "displayId\":\"mikelee\"")

	assert.Equal(t, "mikelee", conv.AimID)
	assert.Empty(t, conv.DisplayID)
	// omitempty is what keeps it out of the payload.
	encodedConv, err := json.Marshal(conv)
	require.NoError(t, err)
	assert.NotContains(t, string(encodedConv), "displayId")
}

func TestMessagingHandler_SendIM(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()

	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*mockICBMService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success",
			queryParams: "t=recipient&message=hello+world",
			setupMocks: func(is *mockICBMService) {
				is.EXPECT().ChannelMsgToHost(mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNACFrame"), mock.AnythingOfType("wire.SNAC_0x04_0x06_ICBMChannelMsgToHost")).
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
			setupMocks:         func(is *mockICBMService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
		{
			name:               "Error_MissingMessage",
			queryParams:        "t=recipient",
			setupMocks:         func(is *mockICBMService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: message")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icbmService := newMockICBMService(t)

			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &MessagingHandler{
				ICBMService:    icbmService,
				LocateService:  stubLocateService(t, ""),
				FeedbagService: stubFeedbagService(t, "someone", ""),
				Logger:         slog.Default(),
			}

			tt.setupMocks(icbmService)

			reqURL := "/im/sendIM?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			responseBody := strings.TrimSpace(rr.Body.String())
			if tt.checkResponse != nil {
				tt.checkResponse(t, responseBody)
			}
		})
	}
}

// The ICBM service refuses to store a message for an offline recipient unless the
// store directive is present, so the client's offlineIM flag has to become one.
func TestMessagingHandler_SendIM_OfflineIMSetsStoreTLV(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()
	icbmService := newMockICBMService(t)

	var sent wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	icbmService.EXPECT().ChannelMsgToHost(mock.Anything, oscarInstance, mock.Anything, mock.Anything).
		Run(func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) {
			sent = inBody
		}).
		Return(nil, nil)

	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	handler := &MessagingHandler{
		ICBMService:    icbmService,
		LocateService:  stubLocateService(t, ""),
		FeedbagService: stubFeedbagService(t, "recipient", ""),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid="+aimsid+"&t=recipient&message=hi&offlineIM=true", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	_, hasStore := sent.Bytes(wire.ICBMTLVStore)
	assert.True(t, hasStore)
}

// An undeliverable IM must still produce an envelope: the web client reads
// response.statusCode, and an empty body leaves it with no status at all.
func TestMessagingHandler_SendIM_UndeliverableReportsStatus(t *testing.T) {
	tests := []struct {
		name string
		errs wire.SNACError
	}{
		{
			name: "RecipientOffline",
			errs: wire.SNACError{Code: wire.ErrorCodeNotLoggedOn},
		},
		{
			name: "OfflineInboxFull",
			errs: wire.SNACError{
				Code: wire.ErrorCodeNotLoggedOn,
				TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ErrorTLVErrorSubcode, wire.ICBMSubErrOfflineIMExceedMax),
				}},
			},
		},
		{
			name: "SenderBlockedRecipient",
			errs: wire.SNACError{Code: wire.ErrorCodeInLocalPermitDeny},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oscarInstance := state.NewSession().AddInstance()
			icbmService := newMockICBMService(t)
			icbmService.EXPECT().ChannelMsgToHost(mock.Anything, oscarInstance, mock.Anything, mock.Anything).
				Return(&wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMErr},
					Body:  tt.errs,
				}, nil)

			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
			handler := &MessagingHandler{
				ICBMService:    icbmService,
				LocateService:  stubLocateService(t, ""),
				FeedbagService: stubFeedbagService(t, "recipient", ""),
				Logger:         slog.Default(),
			}

			req, err := http.NewRequest("GET", "/im/sendIM?aimsid="+aimsid+"&f=json&t=recipient&message=hi", nil)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Contains(t, rr.Body.String(), `"statusCode":602`)
			assert.NotContains(t, rr.Body.String(), `"msgId"`)
		})
	}
}

func TestMessagingHandler_SendIM_POST(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()
	icbmService := newMockICBMService(t)

	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	icbmService.EXPECT().ChannelMsgToHost(mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNACFrame"), mock.AnythingOfType("wire.SNAC_0x04_0x06_ICBMChannelMsgToHost")).
		Return(nil, nil)

	handler := &MessagingHandler{
		ICBMService:    icbmService,
		LocateService:  stubLocateService(t, ""),
		FeedbagService: stubFeedbagService(t, "someone", ""),
		Logger:         slog.Default(),
	}

	body := strings.NewReader("message=" + url.QueryEscape("hello from post"))
	req, err := http.NewRequest(http.MethodPost, "/im/sendIM?aimsid="+aimsid+"&f=json&t=recipient&r=1", body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"msgId"`)
}

func TestMessagingHandler_SendIM_MissingAimsid(t *testing.T) {
	sessionMgr := NewSessionManager()
	handler := &MessagingHandler{
		Logger: slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestMessagingHandler_SendIM_InvalidSession(t *testing.T) {
	sessionMgr := NewSessionManager()
	handler := &MessagingHandler{
		Logger: slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid=nonexistent&t=someone&message=hi", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid or expired session")
}

func TestMessagingHandler_SetTyping(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()

	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*mockICBMService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_TypingStarted",
			queryParams: "t=recipient&typingStatus=typing",
			setupMocks: func(is *mockICBMService) {
				is.EXPECT().ClientEvent(mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x04_0x14_ICBMClientEvent{
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
			setupMocks: func(is *mockICBMService) {
				is.EXPECT().ClientEvent(mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x04_0x14_ICBMClientEvent{
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
			setupMocks: func(is *mockICBMService) {
				is.EXPECT().ClientEvent(mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x04_0x14_ICBMClientEvent{
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
			setupMocks:         func(is *mockICBMService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icbmService := newMockICBMService(t)

			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &MessagingHandler{
				ICBMService:    icbmService,
				LocateService:  stubLocateService(t, ""),
				FeedbagService: stubFeedbagService(t, "someone", ""),
				Logger:         slog.Default(),
			}

			tt.setupMocks(icbmService)

			reqURL := "/im/setTyping?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(sessionMgr, handler.SetTyping).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}
		})
	}
}

func TestMessagingHandler_SetTyping_MissingAimsid(t *testing.T) {
	sessionMgr := NewSessionManager()
	handler := &MessagingHandler{
		Logger: slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/setTyping", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SetTyping).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

// ChannelMsgToHost delivers before it returns, so an ICBMClientErr can reach the pump
// while SendIM is still inside that call. Recording the cookie->msgId mapping after
// the send loses that race and emits a clientError naming no message. The interleaving
// is driven deterministically by handling the error SNAC from inside the mock.
func TestMessagingHandler_SendIM_ClientErrorDuringSendNamesTheMessage(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()
	icbmService := newMockICBMService(t)

	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	sess, err := sessionMgr.GetSession(context.Background(), aimsid)
	require.NoError(t, err)

	icbmService.EXPECT().
		ChannelMsgToHost(mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNACFrame"), mock.AnythingOfType("wire.SNAC_0x04_0x06_ICBMChannelMsgToHost")).
		Run(func(_ context.Context, _ *state.SessionInstance, _ wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) {
			sess.handleSNACMessage(wire.SNACMessage{
				Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientErr},
				Body: wire.SNAC_0x04_0x0B_ICBMClientErr{
					Cookie:     inBody.Cookie,
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "Recipient",
				},
			})
		}).
		Return(nil, nil)

	handler := &MessagingHandler{
		ICBMService:    icbmService,
		LocateService:  stubLocateService(t, ""),
		FeedbagService: stubFeedbagService(t, "someone", ""),
		Logger:         slog.Default(),
	}

	req, reqErr := http.NewRequest("GET", "/im/sendIM?aimsid="+aimsid+"&t=recipient&message=hello", nil)
	require.NoError(t, reqErr)
	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var sentMsgID string
	var clientErr ClientErrorEvent
	for _, event := range sess.EventQueue.GetAllEvents() {
		switch event.Type {
		case EventTypeSentIM:
			if e, ok := event.Data.(SentIMEvent); ok {
				sentMsgID = e.MsgID
			}
		case EventTypeClientError:
			clientErr, _ = event.Data.(ClientErrorEvent)
		}
	}

	// The cookie the client is told about must be the msgId it was handed for the
	// very message that failed.
	require.NotEmpty(t, sentMsgID)
	assert.Equal(t, sentMsgID, clientErr.Cookie)
	assert.Equal(t, "recipient", clientErr.Source.AimID)
}
