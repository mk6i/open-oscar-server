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

// MockFeedbagService is a mock implementation of FeedbagService
type MockFeedbagService struct {
	mock.Mock
}

func (m *MockFeedbagService) DeleteItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem) (*wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	if msg := args.Get(0); msg != nil {
		return msg.(*wire.SNACMessage), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockFeedbagService) Query(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) (wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

func (m *MockFeedbagService) QueryIfModified(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x05_FeedbagQueryIfModified) (wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

func (m *MockFeedbagService) RespondAuthorizeToHost(ctx context.Context, instance state.IdentScreenName, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost) error {
	args := m.Called(ctx, instance, inFrame, inBody)
	return args.Error(0)
}

func (m *MockFeedbagService) RightsQuery(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
	args := m.Called(ctx, inFrame)
	return args.Get(0).(wire.SNACMessage)
}

func (m *MockFeedbagService) StartCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x11_FeedbagStartCluster) {
	m.Called(ctx, instance, inFrame, inBody)
}

func (m *MockFeedbagService) EndCluster(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) error {
	args := m.Called(ctx, instance, inFrame)
	return args.Error(0)
}

func (m *MockFeedbagService) UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, items []wire.FeedbagItem) (*wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, items)
	if msg := args.Get(0); msg != nil {
		return msg.(*wire.SNACMessage), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockFeedbagService) Use(ctx context.Context, instance *state.SessionInstance) error {
	args := m.Called(ctx, instance)
	return args.Error(0)
}

// MockBuddyBroadcaster is a mock implementation of BuddyBroadcaster
type MockBuddyBroadcaster struct {
	mock.Mock
}

func (m *MockBuddyBroadcaster) BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error {
	args := m.Called(ctx, screenName, userInfo)
	return args.Error(0)
}

func (m *MockBuddyBroadcaster) BroadcastBuddyDeparted(ctx context.Context, screenName state.IdentScreenName) error {
	args := m.Called(ctx, screenName)
	return args.Error(0)
}

// MockProfileManager is a mock implementation of ProfileManager
type MockProfileManager struct {
	mock.Mock
}

func (m *MockProfileManager) SetProfile(ctx context.Context, screenName state.IdentScreenName, profile state.UserProfile) error {
	args := m.Called(ctx, screenName, profile)
	return args.Error(0)
}

func (m *MockProfileManager) Profile(ctx context.Context, screenName state.IdentScreenName) (state.UserProfile, error) {
	args := m.Called(ctx, screenName)
	return args.Get(0).(state.UserProfile), args.Error(1)
}

// onlineUserInfoReply builds a locate UserInfoReply for an online user,
// optionally marking them idle by the given number of minutes (0 = not idle).
func onlineUserInfoReply(screenName string, idleMinutes uint16) wire.SNACMessage {
	info := wire.TLVUserInfo{ScreenName: screenName}
	if idleMinutes > 0 {
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, idleMinutes))
	}
	return wire.SNACMessage{
		Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{TLVUserInfo: info},
	}
}

// screenNameMatcher matches a UserInfoQuery request body by its target screen name.
func screenNameMatcher(screenName string) any {
	return mock.MatchedBy(func(b wire.SNAC_0x02_0x05_LocateUserInfoQuery) bool {
		return b.ScreenName == screenName
	})
}

func TestPresenceHandler_GetPresence(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockFeedbagService, *MockLocateService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_BuddyList",
			queryParams: "bl=1",
			setupMocks: func(fr *MockFeedbagService, ls *MockLocateService) {
				// Return feedbag with a group and buddy
				fr.On("Query", mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{
						Body: wire.SNAC_0x13_0x06_FeedbagReply{
							Items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 0},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "buddy1", GroupID: 1},
							},
						},
					}, nil)
				ls.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("buddy1")).
					Return(onlineUserInfoReply("buddy1", 0), nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"groups"`)
				assert.Contains(t, body, `"Friends"`)
				assert.Contains(t, body, `"buddy1"`)
				assert.Contains(t, body, `"online"`)
			},
		},
		{
			name:        "Success_TargetUsers",
			queryParams: "t=user1,user2",
			setupMocks: func(fr *MockFeedbagService, ls *MockLocateService) {
				ls.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("user1")).
					Return(onlineUserInfoReply("user1", 0), nil)
				// user2 is idle for 7 minutes.
				ls.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("user2")).
					Return(onlineUserInfoReply("user2", 7), nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"users"`)
				assert.Contains(t, body, `"user1"`)
				assert.Contains(t, body, `"user2"`)
				assert.Contains(t, body, `"idle"`)
			},
		},
		{
			name:        "Success_BlockedOrOfflineUser",
			queryParams: "t=blockeduser",
			setupMocks: func(fr *MockFeedbagService, ls *MockLocateService) {
				// A blocked or offline user comes back as a locate error.
				ls.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("blockeduser")).
					Return(wire.SNACMessage{Body: wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}}, nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"blockeduser"`)
				assert.Contains(t, body, `"offline"`)
			},
		},
		{
			name:               "Success_EmptyRequest",
			queryParams:        "",
			setupMocks:         func(fr *MockFeedbagService, ls *MockLocateService) {},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:        "Error_TooManyTargets",
			queryParams: "t=u1,u2,u3,u4,u5,u6,u7,u8,u9,u10,u11",
			// No UserInfoQuery should be issued; the request is rejected up front.
			setupMocks:         func(fr *MockFeedbagService, ls *MockLocateService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "too many screen names requested")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feedbagService := &MockFeedbagService{}
			locateService := &MockLocateService{}

			oscarInstance := state.NewSession().AddInstance()
			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				FeedbagService: feedbagService,
				LocateService:  locateService,
				Logger:         slog.Default(),
			}

			tt.setupMocks(feedbagService, locateService)

			reqURL := "/presence/get?aimsid=" + aimsid
			if tt.queryParams != "" {
				reqURL += "&" + tt.queryParams
			}
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			handler.GetPresence(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}

			feedbagService.AssertExpectations(t)
			locateService.AssertExpectations(t)
		})
	}
}

func TestPresenceHandler_GetPresence_MissingAimsid(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.GetPresence(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestPresenceHandler_GetPresence_SessionNotFound(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get?aimsid=nonexistent", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.GetPresence(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "session not found")
}

func TestPresenceHandler_SetState_MissingAimsid(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.SetState(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestPresenceHandler_SetState_InvalidState(t *testing.T) {
	sessionMgr, aimsid := createTestSessionManager("testuser")

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=bogus", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.SetState(rr, req)

	// Web-only sessions (no OSCAR session) return 200 before checking state param
	// because the handler returns early with success for web-only sessions
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestPresenceHandler_SetState_WebOnlySession(t *testing.T) {
	// Web-only sessions (no OSCAR session) should return success
	sessionMgr, aimsid := createTestSessionManager("testuser")

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=online", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.SetState(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"statusCode":200`)
}

func TestIsICQScreenName(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		expected   bool
	}{
		{"ICQ_Number", "123456789", true},
		{"AIM_Name", "cooluser", false},
		{"AIM_WithNumbers", "cool123", false},
		{"Empty", "", false},
		{"Single_Digit", "5", true},
		{"Mixed_Chars", "12abc34", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isICQScreenName(tt.screenName))
		})
	}
}

func TestPresenceHandler_Icon(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockSessionRetriever)
		expectedStatusCode int
		checkRedirect      func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:        "Redirect_OfflineUser",
			queryParams: "name=offlineuser",
			setupMocks: func(sr *MockSessionRetriever) {
				sr.On("RetrieveSession", state.NewIdentScreenName("offlineuser")).Return(nil)
			},
			expectedStatusCode: http.StatusFound,
			checkRedirect: func(t *testing.T, rr *httptest.ResponseRecorder) {
				location := rr.Header().Get("Location")
				assert.Contains(t, location, "offline")
			},
		},
		{
			name:               "Error_MissingName",
			queryParams:        "",
			setupMocks:         func(sr *MockSessionRetriever) {},
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionRetriever := &MockSessionRetriever{}

			handler := &PresenceHandler{
				SessionRetriever: sessionRetriever,
				Logger:           slog.Default(),
			}

			tt.setupMocks(sessionRetriever)

			reqURL := "/presence/icon"
			if tt.queryParams != "" {
				reqURL += "?" + tt.queryParams
			}
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			handler.Icon(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkRedirect != nil {
				tt.checkRedirect(t, rr)
			}

			sessionRetriever.AssertExpectations(t)
		})
	}
}

func TestPresenceHandler_SetProfile(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockProfileManager)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_SetProfile",
			queryParams: "profile=Hello+World",
			setupMocks: func(pm *MockProfileManager) {
				pm.On("SetProfile", mock.Anything, state.NewIdentScreenName("testuser"), mock.AnythingOfType("state.UserProfile")).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:               "Error_ProfileTooLarge",
			queryParams:        "profile=" + strings.Repeat("x", 4097),
			setupMocks:         func(pm *MockProfileManager) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "profile too large")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileManager := &MockProfileManager{}

			sessionMgr, aimsid := createTestSessionManager("testuser")

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				ProfileManager: profileManager,
				Logger:         slog.Default(),
			}

			tt.setupMocks(profileManager)

			reqURL := "/presence/setProfile?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			handler.SetProfile(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}

			profileManager.AssertExpectations(t)
		})
	}
}

func TestPresenceHandler_GetProfile(t *testing.T) {
	profileManager := &MockProfileManager{}

	sessionMgr, aimsid := createTestSessionManager("testuser")

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		ProfileManager: profileManager,
		Logger:         slog.Default(),
	}

	profileManager.On("Profile", mock.Anything, state.NewIdentScreenName("testuser")).
		Return(state.UserProfile{ProfileText: "My profile"}, nil)

	req, err := http.NewRequest("GET", "/presence/getProfile?aimsid="+aimsid, nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.GetProfile(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"statusCode":200`)
	assert.Contains(t, body, `"My profile"`)
	assert.Contains(t, body, `"testuser"`)

	profileManager.AssertExpectations(t)
}
