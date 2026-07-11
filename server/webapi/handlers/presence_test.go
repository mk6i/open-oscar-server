package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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
								{ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 1},
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

			// Presence payloads carry the viewer's alias, so GetPresence reads the
			// feedbag. Registered last so a case's own Query stub takes precedence.
			feedbagService.On("Query", mock.Anything, mock.Anything, mock.Anything).
				Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil).Maybe()

			reqURL := "/presence/get?aimsid=" + aimsid
			if tt.queryParams != "" {
				reqURL += "&" + tt.queryParams
			}
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

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

// TestPresenceHandler_GetPresence_BuddyListGrouping verifies that bl=1 places
// each buddy under its own group using realistic feedbag data, where group rows
// carry ItemID 0 and a distinct nonzero GroupID, and buddy rows reference those
// GroupIDs. This is the shape the OSCAR feedbag actually stores.
func TestPresenceHandler_GetPresence_BuddyListGrouping(t *testing.T) {
	feedbagService := &MockFeedbagService{}
	locateService := &MockLocateService{}

	items := []wire.FeedbagItem{
		// Root order group: ItemID 0, GroupID 0, empty name — not a real buddy group.
		{ItemID: 0, GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
		// Named groups: ItemID 0, distinct nonzero GroupIDs.
		{ItemID: 0, GroupID: 10, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
		{ItemID: 0, GroupID: 20, ClassID: wire.FeedbagClassIdGroup, Name: "Work"},
		// Buddies reference their group's GroupID.
		{ItemID: 101, GroupID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "alice"},
		{ItemID: 201, GroupID: 20, ClassID: wire.FeedbagClassIdBuddy, Name: "bob"},
	}
	feedbagService.On("Query", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
	locateService.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("alice")).
		Return(onlineUserInfoReply("alice", 0), nil)
	locateService.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("bob")).
		Return(onlineUserInfoReply("bob", 0), nil)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&bl=1", nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var parsed struct {
		Response struct {
			Data struct {
				Groups []struct {
					Name    string `json:"name"`
					Buddies []struct {
						AimID string `json:"aimId"`
					} `json:"buddies"`
				} `json:"groups"`
			} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &parsed))

	// Build name -> set of buddy aimIds.
	byGroup := map[string][]string{}
	for _, g := range parsed.Response.Data.Groups {
		for _, b := range g.Buddies {
			byGroup[g.Name] = append(byGroup[g.Name], b.AimID)
		}
	}

	// Exactly the two named groups appear; the root group is excluded.
	assert.Len(t, parsed.Response.Data.Groups, 2)
	assert.Equal(t, []string{"alice"}, byGroup["Friends"])
	assert.Equal(t, []string{"bob"}, byGroup["Work"])

	feedbagService.AssertExpectations(t)
	locateService.AssertExpectations(t)
}

func TestPresenceHandler_GetPresence_MissingAimsid(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

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
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid or expired session")
}

func TestPresenceHandler_SetState_MissingAimsid(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: state.NewWebAPISessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestPresenceHandler_SetState_InvalidState(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=bogus", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid state parameter")
}

func TestPresenceHandler_SetState_EmitsMyInfoEvent(t *testing.T) {
	// The AIM client re-renders its own status badge only from "myInfo" events,
	// so setState must queue one on the user's own session for the change to be
	// visible in their UI.
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	broadcaster := &MockBuddyBroadcaster{}
	broadcaster.On("BroadcastBuddyArrived", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := &PresenceHandler{
		SessionManager:   sessionMgr,
		BuddyBroadcaster: broadcaster,
		Logger:           slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=away&awayMsg=brb", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	session, err := sessionMgr.GetSession(context.Background(), aimsid)
	assert.NoError(t, err)

	var myInfo map[string]interface{}
	for _, event := range session.EventQueue.GetAllEvents() {
		if event.Type == "myInfo" {
			myInfo, _ = event.Data.(map[string]interface{})
		}
	}
	assert.NotNil(t, myInfo, "expected a myInfo event to be queued")
	assert.Equal(t, "away", myInfo["state"])
	assert.Equal(t, "brb", myInfo["awayMsg"])
	assert.Equal(t, "testuser", myInfo["aimId"])
}

func TestPresenceHandler_SetState_MyInfoNormalizesAimID(t *testing.T) {
	// The client shallow-merges myInfo onto the shared user object, so aimId must
	// be the normalized id while displayId and friendly keep the user's own
	// casing and spacing.
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("Mike Kelly", oscarInstance)

	broadcaster := &MockBuddyBroadcaster{}
	broadcaster.On("BroadcastBuddyArrived", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := &PresenceHandler{
		SessionManager:   sessionMgr,
		BuddyBroadcaster: broadcaster,
		Logger:           slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=away", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// The setState response body carries the same identity fields.
	var resp struct {
		Response struct {
			Data map[string]interface{} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "mikekelly", resp.Response.Data["aimId"])
	assert.Equal(t, "Mike Kelly", resp.Response.Data["displayId"])

	session, err := sessionMgr.GetSession(context.Background(), aimsid)
	assert.NoError(t, err)

	var myInfo map[string]interface{}
	for _, event := range session.EventQueue.GetAllEvents() {
		if event.Type == "myInfo" {
			myInfo, _ = event.Data.(map[string]interface{})
		}
	}
	require.NotNil(t, myInfo, "expected a myInfo event to be queued")
	assert.Equal(t, "mikekelly", myInfo["aimId"])
	assert.Equal(t, "Mike Kelly", myInfo["displayId"])
	assert.Equal(t, "Mike Kelly", myInfo["friendly"])
}

func TestPresenceHandler_SetState_NoOSCARSession_Rejected(t *testing.T) {
	// Anonymous (web-only, no OSCAR) sessions are rejected by the session
	// middleware before the handler runs.
	sessionMgr, aimsid := createTestSessionManager("testuser")

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=online", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid or expired session")
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
		expectedStatusCode int
		checkRedirect      func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "Redirect_OfflineUser",
			// No aimsid, so there is no OSCAR session to query on behalf of and
			// the target resolves to offline.
			queryParams:        "name=offlineuser",
			expectedStatusCode: http.StatusFound,
			checkRedirect: func(t *testing.T, rr *httptest.ResponseRecorder) {
				location := rr.Header().Get("Location")
				assert.Contains(t, location, "offline")
			},
		},
		{
			name:               "Error_MissingName",
			queryParams:        "",
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &PresenceHandler{
				SessionManager: state.NewWebAPISessionManager(),
				LocateService:  &MockLocateService{},
				Logger:         slog.Default(),
			}

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
		})
	}
}

func TestPresenceHandler_SetProfile(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()

	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*MockLocateService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_SetProfile",
			queryParams: "profile=Hello+World",
			setupMocks: func(ls *MockLocateService) {
				ls.On("SetInfo", mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNAC_0x02_0x04_LocateSetInfo")).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:               "Error_ProfileTooLarge",
			queryParams:        "profile=" + strings.Repeat("x", 4097),
			setupMocks:         func(ls *MockLocateService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "profile too large")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locateService := &MockLocateService{}

			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				LocateService:  locateService,
				Logger:         slog.Default(),
			}

			tt.setupMocks(locateService)

			reqURL := "/presence/setProfile?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(handler.SessionManager, handler.SetProfile).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}

			locateService.AssertExpectations(t)
		})
	}
}

func TestPresenceHandler_GetProfile(t *testing.T) {
	locateService := &MockLocateService{}

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	locateService.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("testuser")).
		Return(wire.SNACMessage{
			Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
				LocateInfo: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "My profile"),
					},
				},
			},
		}, nil)

	req, err := http.NewRequest("GET", "/presence/getProfile?aimsid="+aimsid, nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetProfile).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"statusCode":200`)
	assert.Contains(t, body, `"My profile"`)
	assert.Contains(t, body, `"testuser"`)

	locateService.AssertExpectations(t)
}
