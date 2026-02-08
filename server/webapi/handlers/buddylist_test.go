package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// MockWebAPISessionManager is a mock implementation of the WebAPISessionManager
type MockWebAPISessionManager struct {
	mock.Mock
}

func (m *MockWebAPISessionManager) GetSession(ctx context.Context, aimsid string) (*state.WebAPISession, error) {
	args := m.Called(ctx, aimsid)
	if session := args.Get(0); session != nil {
		return session.(*state.WebAPISession), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockWebAPISessionManager) TouchSession(ctx context.Context, aimsid string) error {
	args := m.Called(ctx, aimsid)
	return args.Error(0)
}

// MockFeedbagManager is a mock implementation of FeedbagManager
type MockFeedbagManager struct {
	mock.Mock
}

func (m *MockFeedbagManager) RetrieveFeedbag(ctx context.Context, screenName state.IdentScreenName) (wire.FeedbagItems, error) {
	args := m.Called(ctx, screenName)
	if items := args.Get(0); items != nil {
		return items.(wire.FeedbagItems), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockFeedbagManager) InsertItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error {
	args := m.Called(ctx, screenName, item)
	return args.Error(0)
}

func (m *MockFeedbagManager) UpdateItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error {
	args := m.Called(ctx, screenName, item)
	return args.Error(0)
}

func (m *MockFeedbagManager) DeleteItem(ctx context.Context, screenName state.IdentScreenName, item wire.FeedbagItem) error {
	args := m.Called(ctx, screenName, item)
	return args.Error(0)
}

func TestBuddyListHandler_AddTempBuddy(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        map[string][]string
		setupMocks         func(*MockWebAPISessionManager, *MockFeedbagManager, string)
		expectedStatusCode int
		expectedResponse   string
		checkSession       func(*testing.T, *state.WebAPISession)
	}{
		{
			name: "Success_SingleBuddy",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"buddy1"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					TempBuddies:  nil,
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"buddyNames":["buddy1"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *state.WebAPISession) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.Equal(t, 1, len(session.TempBuddies))
			},
		},
		{
			name: "Success_MultipleBuddies",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"buddy1", "buddy2", "buddy3"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					TempBuddies:  nil,
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"buddyNames":["buddy1","buddy2","buddy3"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *state.WebAPISession) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.True(t, session.TempBuddies["buddy2"])
				assert.True(t, session.TempBuddies["buddy3"])
				assert.Equal(t, 3, len(session.TempBuddies))
			},
		},
		{
			name: "Success_AddToExistingTempBuddies",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"buddy2"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:     aimsid,
					ScreenName: state.DisplayScreenName("testuser"),
					EventQueue: types.NewEventQueue(100),
					TempBuddies: map[string]bool{
						"buddy1": true,
					},
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"buddyNames":["buddy2"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *state.WebAPISession) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.True(t, session.TempBuddies["buddy2"])
				assert.Equal(t, 2, len(session.TempBuddies))
			},
		},
		{
			name: "Error_MissingAimSID",
			queryParams: map[string][]string{
				"t": {"buddy1"},
			},
			setupMocks:         func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing aimsid parameter"}}`,
		},
		{
			name: "Error_MissingBuddyNames",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy names (t parameter)"}}`,
		},
		{
			name: "Error_SessionNotFound",
			queryParams: map[string][]string{
				"aimsid": {"invalid-session"},
				"t":      {"buddy1"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				sm.On("GetSession", mock.Anything, aimsid).Return(nil, state.ErrNoWebAPISession)
			},
			expectedStatusCode: http.StatusNotFound,
			expectedResponse:   `{"response":{"statusCode":404,"statusText":"session not found"}}`,
		},
		{
			name: "Error_SessionExpired",
			queryParams: map[string][]string{
				"aimsid": {"expired-session"},
				"t":      {"buddy1"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				sm.On("GetSession", mock.Anything, aimsid).Return(nil, state.ErrWebAPISessionExpired)
			},
			expectedStatusCode: http.StatusGone,
			expectedResponse:   `{"response":{"statusCode":410,"statusText":"session expired"}}`,
		},
		{
			name: "Error_InternalServerError",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"buddy1"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				sm.On("GetSession", mock.Anything, aimsid).Return(nil, errors.New("database error"))
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse:   `{"response":{"statusCode":500,"statusText":"internal server error"}}`,
		},
		{
			name: "Success_WithWhitespace",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"  buddy1  ", "buddy2 ", " buddy3"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					TempBuddies:  nil,
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"buddyNames":["  buddy1  ","buddy2 "," buddy3"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *state.WebAPISession) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.True(t, session.TempBuddies["buddy2"])
				assert.True(t, session.TempBuddies["buddy3"])
				assert.Equal(t, 3, len(session.TempBuddies))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			sessionManager := &MockWebAPISessionManager{}
			feedbagManager := &MockFeedbagManager{}
			logger := slog.Default()

			handler := &BuddyListHandler{
				SessionManager: sessionManager,
				FeedbagManager: feedbagManager,
				Logger:         logger,
			}

			aimsid := ""
			if aimsids, ok := tt.queryParams["aimsid"]; ok && len(aimsids) > 0 {
				aimsid = aimsids[0]
			}
			tt.setupMocks(sessionManager, feedbagManager, aimsid)

			// Create request with query parameters
			reqURL := "/aim/addTempBuddy"
			if len(tt.queryParams) > 0 {
				values := url.Values{}
				for key, vals := range tt.queryParams {
					for _, val := range vals {
						values.Add(key, val)
					}
				}
				reqURL += "?" + values.Encode()
			}

			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute
			handler.AddTempBuddy(rr, req)

			// Verify status code
			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			// Verify response body
			responseBody := strings.TrimSpace(rr.Body.String())
			assert.Equal(t, tt.expectedResponse, responseBody)

			// Check session state if provided
			if tt.checkSession != nil && aimsid != "" {
				// Get the session from mock to verify state
				for _, call := range sessionManager.Calls {
					if call.Method == "GetSession" {
						if session, ok := call.ReturnArguments[0].(*state.WebAPISession); ok {
							tt.checkSession(t, session)
							break
						}
					}
				}
			}

			// Verify all mock expectations were met
			sessionManager.AssertExpectations(t)
			feedbagManager.AssertExpectations(t)
		})
	}
}

func TestBuddyListHandler_AddTempBuddy_EventQueueBehavior(t *testing.T) {
	// Test that events are properly added to the event queue
	sessionManager := &MockWebAPISessionManager{}
	feedbagManager := &MockFeedbagManager{}
	logger := slog.Default()

	handler := &BuddyListHandler{
		SessionManager: sessionManager,
		FeedbagManager: feedbagManager,
		Logger:         logger,
	}

	eventQueue := types.NewEventQueue(100)
	session := &state.WebAPISession{
		AimSID:       "test-session",
		ScreenName:   state.DisplayScreenName("testuser"),
		EventQueue:   eventQueue,
		TempBuddies:  nil,
		LastAccessed: time.Now(),
	}

	sessionManager.On("GetSession", mock.Anything, "test-session").Return(session, nil)
	sessionManager.On("TouchSession", mock.Anything, "test-session").Return(nil)

	req, err := http.NewRequest("GET", "/aim/addTempBuddy?aimsid=test-session&t=buddy1&t=buddy2", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.AddTempBuddy(rr, req)

	// Verify that events were added to the queue
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check that the event queue has the correct number of events
	events := eventQueue.GetAllEvents()
	assert.GreaterOrEqual(t, len(events), 2, "Should have at least 2 events for 2 buddies")

	// Verify event content
	for _, event := range events {
		assert.Equal(t, types.EventTypeBuddyList, event.Type)
		eventData, ok := event.Data.(types.BuddyListEvent)
		assert.True(t, ok, "Event data should be BuddyListEvent")
		assert.Equal(t, "addTemp", eventData.Action)
		assert.NotNil(t, eventData.Buddy)
		buddyInfo, ok := eventData.Buddy.(*BuddyPresenceInfo)
		assert.True(t, ok, "Buddy should be *BuddyPresenceInfo")
		if ok {
			assert.Contains(t, []string{"buddy1", "buddy2"}, buddyInfo.AimID)
			assert.Equal(t, "offline", buddyInfo.State)
			assert.Equal(t, "aim", buddyInfo.UserType)
		}
	}

	sessionManager.AssertExpectations(t)
}

func TestBuddyListHandler_AddBuddy(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        map[string][]string
		setupMocks         func(*MockWebAPISessionManager, *MockFeedbagManager, string)
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name: "Success_AddBuddyToExistingGroup",
			queryParams: map[string][]string{
				"aimsid": {"test-session"},
				"buddy":  {"newbuddy"},
				"group":  {"Friends"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)

				// Mock feedbag retrieval with existing group
				existingItems := wire.FeedbagItems{
					{
						ItemID:  1,
						ClassID: wire.FeedbagClassIdGroup,
						Name:    "Friends",
						GroupID: 0,
					},
				}
				fm.On("RetrieveFeedbag", mock.Anything, state.NewIdentScreenName("testuser")).
					Return(existingItems, nil)

				// Mock buddy insertion
				fm.On("InsertItem", mock.Anything, state.NewIdentScreenName("testuser"), mock.MatchedBy(func(item wire.FeedbagItem) bool {
					return item.ClassID == wire.FeedbagClassIdBuddy &&
						item.Name == "newbuddy" &&
						item.GroupID == 1
				})).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"buddyInfo":{"aimId":"newbuddy","state":"offline","userType":"aim"},"resultCode":"success"}}}`,
		},
		{
			name: "Success_AddBuddyCreateNewGroup",
			queryParams: map[string][]string{
				"aimsid": {"test-session"},
				"buddy":  {"newbuddy"},
				"group":  {"NewGroup"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)

				// Mock feedbag retrieval with no existing groups
				fm.On("RetrieveFeedbag", mock.Anything, state.NewIdentScreenName("testuser")).
					Return(wire.FeedbagItems{}, nil)

				// Mock group creation
				fm.On("InsertItem", mock.Anything, state.NewIdentScreenName("testuser"), mock.MatchedBy(func(item wire.FeedbagItem) bool {
					return item.ClassID == wire.FeedbagClassIdGroup &&
						item.Name == "NewGroup" &&
						item.ItemID == 1
				})).Return(nil)

				// Mock buddy insertion
				fm.On("InsertItem", mock.Anything, state.NewIdentScreenName("testuser"), mock.MatchedBy(func(item wire.FeedbagItem) bool {
					return item.ClassID == wire.FeedbagClassIdBuddy &&
						item.Name == "newbuddy" &&
						item.GroupID == 1
				})).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"buddyInfo":{"aimId":"newbuddy","state":"offline","userType":"aim"},"resultCode":"success"}}}`,
		},
		{
			name: "Error_BuddyAlreadyExists",
			queryParams: map[string][]string{
				"aimsid": {"test-session"},
				"buddy":  {"existingbuddy"},
				"group":  {"Friends"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)

				// Mock feedbag retrieval with existing buddy
				existingItems := wire.FeedbagItems{
					{
						ItemID:  1,
						ClassID: wire.FeedbagClassIdBuddy,
						Name:    "existingbuddy",
						GroupID: 1,
					},
				}
				fm.On("RetrieveFeedbag", mock.Anything, state.NewIdentScreenName("testuser")).
					Return(existingItems, nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"alreadyExists"}}}`,
		},
		{
			name: "Error_MissingBuddyParameter",
			queryParams: map[string][]string{
				"aimsid": {"test-session"},
				"group":  {"Friends"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fm *MockFeedbagManager, aimsid string) {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(session, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			sessionManager := &MockWebAPISessionManager{}
			feedbagManager := &MockFeedbagManager{}
			logger := slog.Default()

			handler := &BuddyListHandler{
				SessionManager: sessionManager,
				FeedbagManager: feedbagManager,
				Logger:         logger,
			}

			aimsid := ""
			if aimsids, ok := tt.queryParams["aimsid"]; ok && len(aimsids) > 0 {
				aimsid = aimsids[0]
			}
			tt.setupMocks(sessionManager, feedbagManager, aimsid)

			// Create request
			reqURL := "/buddylist/addBuddy"
			if len(tt.queryParams) > 0 {
				values := url.Values{}
				for key, vals := range tt.queryParams {
					for _, val := range vals {
						values.Add(key, val)
					}
				}
				reqURL += "?" + values.Encode()
			}

			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute
			handler.AddBuddy(rr, req)

			// Verify
			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			responseBody := strings.TrimSpace(rr.Body.String())
			assert.Equal(t, tt.expectedResponse, responseBody)

			sessionManager.AssertExpectations(t)
			feedbagManager.AssertExpectations(t)
		})
	}
}
