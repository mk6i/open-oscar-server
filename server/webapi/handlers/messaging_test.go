package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

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
				Logger:         slog.Default(),
			}

			tt.setupMocks(icbmService)

			reqURL := "/im/sendIM?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			handler.SendIM(rr, req)

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
		Logger:         slog.Default(),
	}

	body := strings.NewReader("message=" + url.QueryEscape("hello from post"))
	req, err := http.NewRequest(http.MethodPost, "/im/sendIM?aimsid="+aimsid+"&f=json&t=recipient&r=1", body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler.SendIM(rr, req)

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
	handler.SendIM(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing required parameter: aimsid")
}

func TestMessagingHandler_SendIM_InvalidSession(t *testing.T) {
	handler := &MessagingHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid=nonexistent&t=someone&message=hi", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.SendIM(rr, req)

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
				Logger:         slog.Default(),
			}

			tt.setupMocks(icbmService)

			reqURL := "/im/setTyping?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			handler.SetTyping(rr, req)

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
	handler.SetTyping(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing required parameter: aimsid")
}
