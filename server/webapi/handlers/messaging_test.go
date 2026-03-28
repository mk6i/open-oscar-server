package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// MockMessageRelayer is a mock implementation of MessageRelayer
type MockMessageRelayer struct {
	mock.Mock
}

func (m *MockMessageRelayer) RelayToScreenName(ctx context.Context, recipient state.IdentScreenName, msg wire.SNACMessage) {
	m.Called(ctx, recipient, msg)
}

// MockOfflineMessageManager is a mock implementation of OfflineMessageManager
type MockOfflineMessageManager struct {
	mock.Mock
}

func (m *MockOfflineMessageManager) SaveMessage(ctx context.Context, msg state.OfflineMessage) (int, error) {
	args := m.Called(ctx, msg)
	return args.Int(0), args.Error(1)
}

// MockSessionRetriever is a mock implementation of SessionRetriever
type MockSessionRetriever struct {
	mock.Mock
}

func (m *MockSessionRetriever) AllSessions() []*state.Session {
	args := m.Called()
	if sessions := args.Get(0); sessions != nil {
		return sessions.([]*state.Session)
	}
	return nil
}

func (m *MockSessionRetriever) RetrieveSession(screenName state.IdentScreenName) *state.Session {
	args := m.Called(screenName)
	if session := args.Get(0); session != nil {
		return session.(*state.Session)
	}
	return nil
}

// MockRelationshipFetcher is a mock implementation of RelationshipFetcher
type MockRelationshipFetcher struct {
	mock.Mock
}

func (m *MockRelationshipFetcher) Relationship(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) (state.Relationship, error) {
	args := m.Called(ctx, me, them)
	return args.Get(0).(state.Relationship), args.Error(1)
}

// createTestSessionManager creates a WebAPISessionManager with a pre-populated session.
func createTestSessionManager(screenName string) (*state.WebAPISessionManager, string) {
	mgr := state.NewWebAPISessionManager()
	session, _ := mgr.CreateSession(
		context.Background(),
		state.DisplayScreenName(screenName),
		"test-dev",
		[]string{"im", "presence", "buddylist", "sentIM"},
		nil,
		slog.Default(),
	)
	return mgr, session.AimSID
}

func TestMessagingHandler_SendIM(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockMessageRelayer, *MockOfflineMessageManager, *MockSessionRetriever, *MockRelationshipFetcher)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_OnlineRecipient",
			queryParams: "t=recipient&message=hello+world",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("recipient")).
					Return(state.Relationship{}, nil)
				sr.On("RetrieveSession", state.NewIdentScreenName("recipient")).
					Return(&state.Session{})
				mr.On("RelayToScreenName", mock.Anything, state.NewIdentScreenName("recipient"), mock.AnythingOfType("wire.SNACMessage")).
					Return()
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"msgId"`)
				assert.Contains(t, body, `"state":"delivered"`)
			},
		},
		{
			name:        "Success_OfflineRecipient_OfflineIM",
			queryParams: "t=offlineuser&message=hello&offlineIM=1",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("offlineuser")).
					Return(state.Relationship{}, nil)
				sr.On("RetrieveSession", state.NewIdentScreenName("offlineuser")).
					Return(nil)
				om.On("SaveMessage", mock.Anything, mock.AnythingOfType("state.OfflineMessage")).
					Return(1, nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"msgId"`)
			},
		},
		{
			name:        "Error_MissingRecipient",
			queryParams: "message=hello",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
			},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
		{
			name:        "Error_MissingMessage",
			queryParams: "t=recipient",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
			},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: message")
			},
		},
		{
			name:        "Error_BlockedBySender",
			queryParams: "t=blockeduser&message=hello",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("blockeduser")).
					Return(state.Relationship{YouBlock: true}, nil)
			},
			expectedStatusCode: http.StatusForbidden,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "cannot send message to blocked user")
			},
		},
		{
			name:        "Error_BlockedByRecipient",
			queryParams: "t=blocker&message=hello",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("blocker")).
					Return(state.Relationship{BlocksYou: true}, nil)
			},
			expectedStatusCode: http.StatusNotFound,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "recipient is not online")
			},
		},
		{
			name:        "Error_OfflineInboxFull",
			queryParams: "t=offlineuser&message=hello&offlineIM=1",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("offlineuser")).
					Return(state.Relationship{}, nil)
				sr.On("RetrieveSession", state.NewIdentScreenName("offlineuser")).
					Return(nil)
				om.On("SaveMessage", mock.Anything, mock.AnythingOfType("state.OfflineMessage")).
					Return(0, state.ErrOfflineInboxFull)
			},
			expectedStatusCode: http.StatusConflict,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "recipient inbox full")
			},
		},
		{
			name:        "Error_OfflineRecipient_NoOfflineIM",
			queryParams: "t=offlineuser&message=hello&offlineIM=0",
			setupMocks: func(mr *MockMessageRelayer, om *MockOfflineMessageManager, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("offlineuser")).
					Return(state.Relationship{}, nil)
				sr.On("RetrieveSession", state.NewIdentScreenName("offlineuser")).
					Return(nil)
			},
			expectedStatusCode: http.StatusNotFound,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "recipient is not online")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageRelayer := &MockMessageRelayer{}
			offlineMsgMgr := &MockOfflineMessageManager{}
			sessionRetriever := &MockSessionRetriever{}
			relFetcher := &MockRelationshipFetcher{}

			sessionMgr, aimsid := createTestSessionManager("testuser")

			handler := &MessagingHandler{
				SessionManager:        sessionMgr,
				MessageRelayer:        messageRelayer,
				OfflineMessageManager: offlineMsgMgr,
				SessionRetriever:      sessionRetriever,
				RelationshipFetcher:   relFetcher,
				Logger:                slog.Default(),
			}

			tt.setupMocks(messageRelayer, offlineMsgMgr, sessionRetriever, relFetcher)

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

			messageRelayer.AssertExpectations(t)
			offlineMsgMgr.AssertExpectations(t)
			sessionRetriever.AssertExpectations(t)
			relFetcher.AssertExpectations(t)
		})
	}
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
	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockMessageRelayer, *MockSessionRetriever, *MockRelationshipFetcher)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_TypingStarted",
			queryParams: "t=recipient&typing=true",
			setupMocks: func(mr *MockMessageRelayer, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("recipient")).
					Return(state.Relationship{}, nil)
				sr.On("RetrieveSession", state.NewIdentScreenName("recipient")).
					Return(&state.Session{})
				mr.On("RelayToScreenName", mock.Anything, state.NewIdentScreenName("recipient"), mock.AnythingOfType("wire.SNACMessage")).
					Return()
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:        "Success_TypingStopped",
			queryParams: "t=recipient&typing=false",
			setupMocks: func(mr *MockMessageRelayer, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("recipient")).
					Return(state.Relationship{}, nil)
				sr.On("RetrieveSession", state.NewIdentScreenName("recipient")).
					Return(&state.Session{})
				mr.On("RelayToScreenName", mock.Anything, state.NewIdentScreenName("recipient"), mock.AnythingOfType("wire.SNACMessage")).
					Return()
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:        "Success_BlockedSilent",
			queryParams: "t=blockeduser&typing=true",
			setupMocks: func(mr *MockMessageRelayer, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("blockeduser")).
					Return(state.Relationship{YouBlock: true}, nil)
				// No relay should happen
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:        "Success_OfflineRecipient",
			queryParams: "t=offlineuser&typing=true",
			setupMocks: func(mr *MockMessageRelayer, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {
				rf.On("Relationship", mock.Anything, mock.Anything, state.NewIdentScreenName("offlineuser")).
					Return(state.Relationship{}, nil)
				sr.On("RetrieveSession", state.NewIdentScreenName("offlineuser")).
					Return(nil)
				// No relay should happen for offline users
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:               "Error_MissingRecipient",
			queryParams:        "typing=true",
			setupMocks:         func(mr *MockMessageRelayer, sr *MockSessionRetriever, rf *MockRelationshipFetcher) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageRelayer := &MockMessageRelayer{}
			sessionRetriever := &MockSessionRetriever{}
			relFetcher := &MockRelationshipFetcher{}

			sessionMgr, aimsid := createTestSessionManager("testuser")

			handler := &MessagingHandler{
				SessionManager:      sessionMgr,
				MessageRelayer:      messageRelayer,
				SessionRetriever:    sessionRetriever,
				RelationshipFetcher: relFetcher,
				Logger:              slog.Default(),
			}

			tt.setupMocks(messageRelayer, sessionRetriever, relFetcher)

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

			messageRelayer.AssertExpectations(t)
			sessionRetriever.AssertExpectations(t)
			relFetcher.AssertExpectations(t)
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
