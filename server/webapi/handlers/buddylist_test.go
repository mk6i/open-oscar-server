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

func TestBuddyListHandler_AddTempBuddy(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        map[string][]string
		session            *state.WebAPISession
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
			session: &state.WebAPISession{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   types.NewEventQueue(100),
				TempBuddies:  nil,
				LastAccessed: time.Now(),
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
			session: &state.WebAPISession{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   types.NewEventQueue(100),
				TempBuddies:  nil,
				LastAccessed: time.Now(),
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
			session: &state.WebAPISession{
				AimSID:     "test-session-id",
				ScreenName: state.DisplayScreenName("testuser"),
				EventQueue: types.NewEventQueue(100),
				TempBuddies: map[string]bool{
					"buddy1": true,
				},
				LastAccessed: time.Now(),
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
			name: "Error_MissingBuddyNames",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
			},
			session: &state.WebAPISession{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   types.NewEventQueue(100),
				LastAccessed: time.Now(),
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy names (t parameter)"}}`,
		},
		{
			name: "Success_WithWhitespace",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"  buddy1  ", "buddy2 ", " buddy3"},
			},
			session: &state.WebAPISession{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   types.NewEventQueue(100),
				TempBuddies:  nil,
				LastAccessed: time.Now(),
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
			handler := &BuddyListHandler{
				Logger: slog.Default(),
			}

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

			rr := httptest.NewRecorder()
			handler.AddTempBuddy(rr, req, tt.session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.Equal(t, tt.expectedResponse, strings.TrimSpace(rr.Body.String()))

			if tt.checkSession != nil && tt.session != nil {
				tt.checkSession(t, tt.session)
			}
		})
	}
}

func TestBuddyListHandler_AddTempBuddy_DoesNotPushBuddyListEvent(t *testing.T) {
	handler := &BuddyListHandler{Logger: slog.Default()}

	eventQueue := types.NewEventQueue(100)
	session := &state.WebAPISession{
		AimSID:       "test-session",
		ScreenName:   state.DisplayScreenName("testuser"),
		EventQueue:   eventQueue,
		TempBuddies:  nil,
		LastAccessed: time.Now(),
	}

	req, err := http.NewRequest("GET", "/aim/addTempBuddy?aimsid=test-session&t=buddy1&t=buddy2", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.AddTempBuddy(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, eventQueue.GetAllEvents(), "addTempBuddy must not push buddylist events")
}

func TestBuddyListHandler_RemoveTempBuddy(t *testing.T) {
	handler := &BuddyListHandler{Logger: slog.Default()}

	session := &state.WebAPISession{
		AimSID:     "test-session",
		ScreenName: state.DisplayScreenName("testuser"),
		TempBuddies: map[string]bool{
			"buddy1": true,
			"buddy2": true,
		},
		LastAccessed: time.Now(),
	}

	req, err := http.NewRequest("GET", "/aim/removeTempBuddy?aimsid=test-session&t=buddy1", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.RemoveTempBuddy(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.False(t, session.TempBuddies["buddy1"])
	assert.True(t, session.TempBuddies["buddy2"])
}

func TestFeedbagGroupMatchesRequested(t *testing.T) {
	assert.True(t, feedbagGroupMatchesRequested("Buddies", "Buddies"))
	assert.True(t, feedbagGroupMatchesRequested("", "Buddies"))
	assert.True(t, feedbagGroupMatchesRequested("  ", "Buddies"))
	assert.True(t, feedbagGroupMatchesRequested("Friends", "friends"))
	assert.False(t, feedbagGroupMatchesRequested("", "Friends"))
}

func TestFindFeedbagGroupID(t *testing.T) {
	items := []wire.FeedbagItem{
		{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "", GroupID: 0},
		{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "jon", GroupID: 1},
	}
	id, ok := findFeedbagGroupID(items, "Buddies")
	assert.True(t, ok)
	assert.Equal(t, uint16(1), id)

	id, ok = findFeedbagGroupID(items, "Friends")
	assert.False(t, ok)
	assert.Equal(t, uint16(0), id)
}

func TestStoredGroupNameForRequest(t *testing.T) {
	items := []wire.FeedbagItem{
		{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "", GroupID: 1},
		{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "jon", GroupID: 1},
	}
	st, ok := storedGroupNameForRequest(items, "Buddies")
	assert.True(t, ok)
	assert.Equal(t, "", st)

	items2 := []wire.FeedbagItem{
		{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 2},
	}
	st2, ok2 := storedGroupNameForRequest(items2, "Friends")
	assert.True(t, ok2)
	assert.Equal(t, "Friends", st2)
}

func TestBuddyListHandler_AddBuddy(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        map[string][]string
		setupMocks         func(*MockWebAPISessionManager, *MockFeedbagService, *MockFeedbagService, string) *state.WebAPISession
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
			setupMocks: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}

				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				// addBuddyToFeedbag calls UpsertItem twice: once for group order update, once for buddy insert
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil)
				blmFs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				return session
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"buddyInfo":{"aimId":"newbuddy","state":"offline","userType":"aim"},"resultCode":"success"}}}`,
		},
		{
			name: "Success_EventPushSkippedOnBLMError",
			queryParams: map[string][]string{
				"aimsid": {"test-session"},
				"buddy":  {"newbuddy"},
				"group":  {"Friends"},
			},
			setupMocks: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}

				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				// addBuddyToFeedbag calls UpsertItem twice: once for group order update, once for buddy insert
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil)
				blmFs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{}, errors.New("feedbag unavailable")).Once()
				return session
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
			setupMocks: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				session := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}

				// Friends group with existingbuddy already present
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
					{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "existingbuddy"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
				return session
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
			setupMocks: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				return &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionManager := &MockWebAPISessionManager{}
			feedbagService := &MockFeedbagService{}
			blmFeedbagService := &MockFeedbagService{}
			blm := NewBuddyListManager(blmFeedbagService, &MockSessionRetriever{}, slog.Default())
			logger := slog.Default()

			handler := &BuddyListHandler{
				SessionManager:   sessionManager,
				FeedbagService:   feedbagService,
				BuddyListManager: blm,
				Logger:           logger,
			}

			aimsid := ""
			if aimsids, ok := tt.queryParams["aimsid"]; ok && len(aimsids) > 0 {
				aimsid = aimsids[0]
			}
			session := tt.setupMocks(sessionManager, feedbagService, blmFeedbagService, aimsid)

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

			rr := httptest.NewRecorder()
			handler.AddBuddy(rr, req, session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			responseBody := strings.TrimSpace(rr.Body.String())
			assert.Equal(t, tt.expectedResponse, responseBody)

			feedbagService.AssertExpectations(t)
			blmFeedbagService.AssertExpectations(t)
		})
	}
}

func TestBuddyListHandler_AddGroup(t *testing.T) {
	type setupFunc func(*MockWebAPISessionManager, *MockFeedbagService, *MockFeedbagService, string) *state.WebAPISession

	newSession := func(aimsid string) *state.WebAPISession {
		return &state.WebAPISession{
			AimSID:       aimsid,
			ScreenName:   state.DisplayScreenName("testuser"),
			EventQueue:   types.NewEventQueue(100),
			LastAccessed: time.Now(),
		}
	}

	tests := []struct {
		name               string
		queryParams        map[string][]string
		setup              setupFunc
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name:        "Error_MissingGroupParam",
			queryParams: map[string][]string{"aimsid": {"sess"}},
			setup: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				return newSession(aimsid)
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing group parameter"}}`,
		},
		{
			name:        "Success_GroupAdded",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NewGroup"}},
			setup: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := newSession(aimsid)
				// Empty feedbag — AddGroup will create root + NewGroup in pending
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				blmFs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"success"}}}`,
		},
		{
			name:        "Success_EventPushSkippedOnBLMError",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NewGroup"}},
			setup: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := newSession(aimsid)
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				blmFs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{}, errors.New("feedbag unavailable")).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"success"}}}`,
		},
		{
			name:        "Success_GroupAlreadyExists",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}},
			setup: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := newSession(aimsid)
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"alreadyExists"}}}`,
		},
		{
			name:        "Error_FeedbagQueryFails",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NewGroup"}},
			setup: func(sm *MockWebAPISessionManager, fs *MockFeedbagService, blmFs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := newSession(aimsid)
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{}, errors.New("feedbag error"))
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"error"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &MockWebAPISessionManager{}
			fs := &MockFeedbagService{}
			blmFs := &MockFeedbagService{}
			blm := NewBuddyListManager(blmFs, &MockSessionRetriever{}, slog.Default())

			aimsid := ""
			if v := tt.queryParams["aimsid"]; len(v) > 0 {
				aimsid = v[0]
			}
			session := tt.setup(sm, fs, blmFs, aimsid)

			handler := &BuddyListHandler{
				SessionManager:   sm,
				FeedbagService:   fs,
				BuddyListManager: blm,
				Logger:           slog.Default(),
			}

			values := url.Values{}
			for k, vs := range tt.queryParams {
				for _, v := range vs {
					values.Add(k, v)
				}
			}
			req, _ := http.NewRequest("GET", "/buddylist/addGroup?"+values.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.AddGroup(rr, req, session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.Equal(t, tt.expectedResponse, strings.TrimSpace(rr.Body.String()))
			fs.AssertExpectations(t)
			blmFs.AssertExpectations(t)
		})
	}
}

func TestBuddyListHandler_RemoveBuddy(t *testing.T) {
	type setupFunc func(*MockWebAPISessionManager, *BuddyListManager, *MockFeedbagService, string) *state.WebAPISession

	newBuddyListManager := func(fs *MockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, &MockSessionRetriever{}, slog.Default())
	}

	tests := []struct {
		name               string
		queryParams        map[string][]string
		setup              setupFunc
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name:        "Error_MissingBuddyParam",
			queryParams: map[string][]string{"aimsid": {"sess"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				return &state.WebAPISession{AimSID: aimsid, ScreenName: state.DisplayScreenName("testuser"), LastAccessed: time.Now()}
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter"}}`,
		},
		{
			name:        "Success_BuddyRemoved",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"someBuddy"}, "group": {"Friends"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
					{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "someBuddy"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.On("DeleteItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				// Second Query for GetBuddyListForUser event push
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"success"}}}`,
		},
		{
			name:        "Success_EventPushSkippedOnBLMError",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"someBuddy"}, "group": {"Friends"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
					{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "someBuddy"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.On("DeleteItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				// BLM query fails — response should still be success
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{}, errors.New("feedbag unavailable")).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"success"}}}`,
		},
		{
			name:        "Success_BuddyNotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"ghost"}, "group": {"Friends"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					LastAccessed: time.Now(),
				}
				// Group exists but "ghost" is not in it
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"notFound"}}}`,
		},
		{
			name:        "Success_GroupNotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"someBuddy"}, "group": {"NoSuchGroup"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					LastAccessed: time.Now(),
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &MockWebAPISessionManager{}
			fs := &MockFeedbagService{}
			blm := newBuddyListManager(fs)

			aimsid := ""
			if v := tt.queryParams["aimsid"]; len(v) > 0 {
				aimsid = v[0]
			}
			session := tt.setup(sm, blm, fs, aimsid)

			handler := &BuddyListHandler{
				SessionManager:   sm,
				BuddyListManager: blm,
				Logger:           slog.Default(),
			}

			values := url.Values{}
			for k, vs := range tt.queryParams {
				for _, v := range vs {
					values.Add(k, v)
				}
			}
			req, _ := http.NewRequest("GET", "/buddylist/removeBuddy?"+values.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.RemoveBuddy(rr, req, session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.Equal(t, tt.expectedResponse, strings.TrimSpace(rr.Body.String()))
			fs.AssertExpectations(t)
		})
	}
}

func TestBuddyListHandler_RemoveGroup(t *testing.T) {
	type setupFunc func(*MockWebAPISessionManager, *BuddyListManager, *MockFeedbagService, string) *state.WebAPISession

	newBuddyListManager := func(fs *MockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, &MockSessionRetriever{}, slog.Default())
	}

	tests := []struct {
		name               string
		queryParams        map[string][]string
		setup              setupFunc
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name:        "Error_MissingGroupParam",
			queryParams: map[string][]string{"aimsid": {"sess"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				return &state.WebAPISession{AimSID: aimsid, ScreenName: state.DisplayScreenName("testuser"), LastAccessed: time.Now()}
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing group parameter"}}`,
		},
		{
			name:        "Success_GroupRemoved",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				// Root order record + Friends group; DeleteGroup will delete Friends and update root.
				items := []wire.FeedbagItem{
					{
						GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "",
						TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1}),
						}},
					},
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.On("DeleteItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				// Second Query for GetBuddyListForUser event push
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"success"}}}`,
		},
		{
			name:        "Success_EventPushSkippedOnBLMError",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   types.NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				items := []wire.FeedbagItem{
					{
						GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "",
						TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1}),
						}},
					},
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.On("DeleteItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				// BLM query fails — response should still be success
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{}, errors.New("feedbag unavailable")).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"success"}}}`,
		},
		{
			name:        "Success_GroupNotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NoSuchGroup"}},
			setup: func(sm *MockWebAPISessionManager, blm *BuddyListManager, fs *MockFeedbagService, aimsid string) *state.WebAPISession {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					LastAccessed: time.Now(),
				}
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &MockWebAPISessionManager{}
			fs := &MockFeedbagService{}
			blm := newBuddyListManager(fs)

			aimsid := ""
			if v := tt.queryParams["aimsid"]; len(v) > 0 {
				aimsid = v[0]
			}
			session := tt.setup(sm, blm, fs, aimsid)

			handler := &BuddyListHandler{
				SessionManager:   sm,
				BuddyListManager: blm,
				Logger:           slog.Default(),
			}

			values := url.Values{}
			for k, vs := range tt.queryParams {
				for _, v := range vs {
					values.Add(k, v)
				}
			}
			req, _ := http.NewRequest("GET", "/buddylist/removeGroup?"+values.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.RemoveGroup(rr, req, session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.Equal(t, tt.expectedResponse, strings.TrimSpace(rr.Body.String()))
			fs.AssertExpectations(t)
		})
	}
}

func TestBuddyListHandler_sessionMiddleware(t *testing.T) {
	tests := []struct {
		name               string
		aimsid             string
		setupMocks         func(*MockWebAPISessionManager, string)
		expectedStatusCode int
		expectedResponse   string
		expectNextCalled   bool
	}{
		{
			name:               "Error_MissingAimsid",
			aimsid:             "",
			setupMocks:         func(sm *MockWebAPISessionManager, aimsid string) {},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing aimsid parameter"}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Error_SessionNotFound",
			aimsid: "unknown-session",
			setupMocks: func(sm *MockWebAPISessionManager, aimsid string) {
				sm.On("GetSession", mock.Anything, aimsid).Return(nil, state.ErrNoWebAPISession)
			},
			expectedStatusCode: http.StatusNotFound,
			expectedResponse:   `{"response":{"statusCode":404,"statusText":"session not found"}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Error_SessionExpired",
			aimsid: "expired-session",
			setupMocks: func(sm *MockWebAPISessionManager, aimsid string) {
				sm.On("GetSession", mock.Anything, aimsid).Return(nil, state.ErrWebAPISessionExpired)
			},
			expectedStatusCode: http.StatusGone,
			expectedResponse:   `{"response":{"statusCode":410,"statusText":"session expired"}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Error_InternalSessionError",
			aimsid: "some-session",
			setupMocks: func(sm *MockWebAPISessionManager, aimsid string) {
				sm.On("GetSession", mock.Anything, aimsid).Return(nil, errors.New("db error"))
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse:   `{"response":{"statusCode":500,"statusText":"internal server error"}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Success_PassesSessionToNext",
			aimsid: "valid-session",
			setupMocks: func(sm *MockWebAPISessionManager, aimsid string) {
				sess := &state.WebAPISession{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					LastAccessed: time.Now(),
				}
				sm.On("GetSession", mock.Anything, aimsid).Return(sess, nil)
				sm.On("TouchSession", mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"OK"}}`,
			expectNextCalled:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &MockWebAPISessionManager{}
			tt.setupMocks(sm, tt.aimsid)

			handler := &BuddyListHandler{
				SessionManager: sm,
				Logger:         slog.Default(),
			}

			nextCalled := false
			next := func(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
				nextCalled = true
				resp := BaseResponse{}
				resp.Response.StatusCode = 200
				resp.Response.StatusText = "OK"
				SendResponse(w, r, resp, handler.Logger)
			}

			wrapped := handler.SessionMiddleware(next)

			reqURL := "/buddylist/test"
			if tt.aimsid != "" {
				reqURL += "?aimsid=" + tt.aimsid
			}
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.Equal(t, tt.expectedResponse, strings.TrimSpace(rr.Body.String()))
			assert.Equal(t, tt.expectNextCalled, nextCalled)

			sm.AssertExpectations(t)
		})
	}
}
