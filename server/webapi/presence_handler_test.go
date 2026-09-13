package webapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
		setupMocks         func(*mockFeedbagService, *mockLocateService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_BuddyList",
			queryParams: "bl=1",
			setupMocks: func(fr *mockFeedbagService, ls *mockLocateService) {
				// Return feedbag with a group and buddy
				fr.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{
						Body: wire.SNAC_0x13_0x06_FeedbagReply{
							Items: []wire.FeedbagItem{
								{ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 1},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "buddy1", GroupID: 1},
							},
						},
					}, nil)
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("buddy1")).
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
			setupMocks: func(fr *mockFeedbagService, ls *mockLocateService) {
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("user1")).
					Return(onlineUserInfoReply("user1", 0), nil)
				// user2 is idle for 7 minutes.
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("user2")).
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
			setupMocks: func(fr *mockFeedbagService, ls *mockLocateService) {
				// A blocked or offline user comes back as a locate error.
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("blockeduser")).
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
			setupMocks:         func(fr *mockFeedbagService, ls *mockLocateService) {},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			// A full search page: memberDir/search returns 20 profiles and the
			// client asks about every one, plus the keyword when it is a UIN.
			// This is the largest list a real client sends, and it must be served
			// whole — anything but a 200 costs the user the entire page.
			name:        "Success_FullSearchPage",
			queryParams: "t=" + strings.Join(searchPageTargets(21), "&t="),
			setupMocks: func(fr *mockFeedbagService, ls *mockLocateService) {
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					RunAndReturn(func(_ context.Context, _ *state.SessionInstance, _ wire.SNACFrame, body wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error) {
						return onlineUserInfoReply(body.ScreenName, 0), nil
					}).Times(21)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"user0"`)
				assert.Contains(t, body, `"user20"`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feedbagService := newMockFeedbagService(t)
			locateService := newMockLocateService(t)

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
			feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
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
		})
	}
}

// TestPresenceHandler_GetPresence_PublishesIconForOnlineBuddiesOnly verifies that
// the icon is published only for an online, non-blocking user, and that an
// offline or blocking user is never even looked up — so neither their icon nor
// its hash leaks to a caller they are invisible to.
func TestPresenceHandler_GetPresence_PublishesIconForOnlineBuddiesOnly(t *testing.T) {
	ctx := context.Background()

	feedbagService := newMockFeedbagService(t)
	feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil).Maybe()

	locateService := newMockLocateService(t)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("onlineuser")).
		Return(onlineUserInfoReply("onlineuser", 0), nil)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("offlineuser")).
		Return(wire.SNACMessage{Body: wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}}, nil)

	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, state.NewIdentScreenName("onlineuser")).
		Return(bartID([]byte{0xab, 0xcd}), nil).Once()

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	sess, err := sessionMgr.GetSession(ctx, aimsid)
	require.NoError(t, err)
	sess.BaseURL = "http://api.example.com"

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		IconSource:     BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()},
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&t=onlineuser,offlineuser", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			Data struct {
				Users []struct {
					AimID     string `json:"aimId"`
					State     string `json:"state"`
					BuddyIcon string `json:"buddyIcon"`
				} `json:"users"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))

	icons := map[string]string{}
	states := map[string]string{}
	for _, u := range got.Response.Data.Users {
		icons[u.AimID] = u.BuddyIcon
		states[u.AimID] = u.State
	}

	assert.Equal(t, "online", states["onlineuser"])
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=onlineuser&type=buddyIcon&bartId=abcd",
		icons["onlineuser"])

	assert.Equal(t, "offline", states["offlineuser"])
	assert.Empty(t, icons["offlineuser"])
	iconRetriever.AssertNotCalled(t, "BuddyIconMetadata", mock.Anything, state.NewIdentScreenName("offlineuser"))
}

// TestPresenceHandler_GetPresence_BuddyListGrouping verifies that bl=1 places
// each buddy under its own group using realistic feedbag data, where group rows
// carry ItemID 0 and a distinct nonzero GroupID, and buddy rows reference those
// GroupIDs. This is the shape the OSCAR feedbag actually stores.
func TestPresenceHandler_GetPresence_BuddyListGrouping(t *testing.T) {
	feedbagService := newMockFeedbagService(t)
	locateService := newMockLocateService(t)

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
	feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("alice")).
		Return(onlineUserInfoReply("alice", 0), nil)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("bob")).
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
}

func TestPresenceHandler_GetPresence_MissingAimsid(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: NewSessionManager(),
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
		SessionManager: NewSessionManager(),
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
		SessionManager: NewSessionManager(),
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

func TestPresenceHandler_SetState_AppliesAwayState(t *testing.T) {
	// setState sets the away message and the status bits through the OSCAR
	// services; the identity badge re-renders from the myInfo the user info
	// update raises, so the handler queues no event of its own.
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	locateService := newMockLocateService(t)
	locateService.EXPECT().
		SetInfo(mock.Anything, oscarInstance, wire.SNAC_0x02_0x04_LocateSetInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "brb"),
				},
			},
		}).
		Return(nil)

	oserviceService := newMockOServiceService(t)
	oserviceService.EXPECT().
		SetUserInfoFields(mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceUserInfoStatus, wire.OServiceUserStatusAway),
				},
			},
		}).
		Return(nil)

	handler := &PresenceHandler{
		SessionManager:  sessionMgr,
		LocateService:   locateService,
		OServiceService: oserviceService,
		Logger:          slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=away&awayMsg=brb", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		Response struct {
			Data SetStateData `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "away", resp.Response.Data.State)
	assert.Equal(t, "brb", resp.Response.Data.AwayMsg)
	assert.Equal(t, "testuser", resp.Response.Data.AimID)

	session, err := sessionMgr.GetSession(context.Background(), aimsid)
	assert.NoError(t, err)
	assert.Empty(t, session.EventQueue.GetAllEvents())
}

func TestPresenceHandler_SetState_OnlineClearsAwayMessage(t *testing.T) {
	// Coming back online drops the away message, which LocateSetInfo owns, along
	// with the status bits.
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	locateService := newMockLocateService(t)
	locateService.EXPECT().
		SetInfo(mock.Anything, oscarInstance, wire.SNAC_0x02_0x04_LocateSetInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, ""),
				},
			},
		}).
		Return(nil)

	oserviceService := newMockOServiceService(t)
	oserviceService.EXPECT().
		SetUserInfoFields(mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0)),
				},
			},
		}).
		Return(nil)

	handler := &PresenceHandler{
		SessionManager:  sessionMgr,
		LocateService:   locateService,
		OServiceService: oserviceService,
		Logger:          slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=online&awayMsg=brb", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"awayMsg":""`)
}

func TestPresenceHandler_SetState_ServiceError(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	oserviceService := newMockOServiceService(t)
	oserviceService.EXPECT().
		SetUserInfoFields(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(assert.AnError)

	handler := &PresenceHandler{
		SessionManager:  sessionMgr,
		OServiceService: oserviceService,
		Logger:          slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=dnd", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestPresenceHandler_SetState_NormalizesAimID(t *testing.T) {
	// The client keys users by the normalized aimId, so the response must carry
	// that while displayId keeps the user's own casing and spacing.
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("Mike Kelly", oscarInstance)

	// An away state with no message leaves the stored away message alone, so the
	// handler sends the status change only.
	oserviceService := newMockOServiceService(t)
	oserviceService.EXPECT().
		SetUserInfoFields(mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceUserInfoStatus, wire.OServiceUserStatusAway),
				},
			},
		}).
		Return(nil)

	handler := &PresenceHandler{
		SessionManager:  sessionMgr,
		OServiceService: oserviceService,
		Logger:          slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=away", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// The setState response body carries the same identity fields.
	var resp struct {
		Response struct {
			Data map[string]any `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "mikekelly", resp.Response.Data["aimId"])
	assert.Equal(t, "Mike Kelly", resp.Response.Data["displayId"])
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
				SessionManager: NewSessionManager(),
				LocateService:  newMockLocateService(t),
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
		setupMocks         func(*mockLocateService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_SetProfile",
			queryParams: "profile=Hello+World",
			setupMocks: func(ls *mockLocateService) {
				ls.EXPECT().SetInfo(mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNAC_0x02_0x04_LocateSetInfo")).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:               "Error_ProfileTooLarge",
			queryParams:        "profile=" + strings.Repeat("x", 4097),
			setupMocks:         func(ls *mockLocateService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "profile too large")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locateService := newMockLocateService(t)

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
		})
	}
}

func TestPresenceHandler_GetProfile(t *testing.T) {
	locateService := newMockLocateService(t)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("testuser")).
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
}

func TestPresenceHandler_SetState_Occupied(t *testing.T) {
	// ICQ's Busy, which is a selectable connect state and must be accepted. An AIM
	// caller is told "away" instead, since AIM 8 draws "occupied" as offline.
	tests := []struct {
		name       string
		screenName string
		wantState  string
	}{
		{name: "icq account", screenName: "100003", wantState: "occupied"},
		{name: "aim account", screenName: "testuser", wantState: "away"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The account that decides the reported state is read off the OSCAR session.
			oscarSession := state.NewSession()
			oscarSession.SetIdentScreenName(state.NewIdentScreenName(tt.screenName))
			oscarInstance := oscarSession.AddInstance()
			sessionMgr, aimsid := createTestSessionManagerWithOSCAR(tt.screenName, oscarInstance)

			oserviceService := newMockOServiceService(t)
			oserviceService.EXPECT().
				SetUserInfoFields(mock.Anything, oscarInstance, wire.SNACFrame{}, wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceUserInfoStatus, wire.OServiceUserStatusBusy),
						},
					},
				}).
				// stand in for the service, which applies the status to the session
				Run(func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) {
					status, _ := inBody.Uint32BE(wire.OServiceUserInfoStatus)
					instance.SetUserStatusBitmask(status)
				}).
				Return(nil)

			handler := &PresenceHandler{
				SessionManager:  sessionMgr,
				OServiceService: oserviceService,
				Logger:          slog.Default(),
			}

			req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&view=occupied&away=", nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()
			requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)

			// The Busy bit reaches OSCAR either way; only the reported state differs.
			assert.Contains(t, rr.Body.String(), `"state":"`+tt.wantState+`"`)

			// The state must survive the round trip: the myInfo raised by the
			// user info update reads the Busy bit back off the wire.
			assert.Equal(t, tt.wantState, selfWebState(oscarSession.TLVUserInfo(), oscarSession.IdentScreenName().UIN() == 0))
		})
	}
}

func TestPresenceHandler_GetPresence_MdirAttachesProfile(t *testing.T) {
	// Search results are populated from this call, and a user carrying no nested
	// "profile" object is dropped by clients, so a found user would not render.
	ctx := context.Background()

	dirReply := wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}
	dirReply.Append(wire.NewTLVBE(wire.ODirTLVFirstName, "Bob"))
	dirReply.Append(wire.NewTLVBE(wire.ODirTLVLastName, "Smith"))
	dirReply.Append(wire.NewTLVBE(wire.ODirTLVCity, "Reno"))

	feedbagService := newMockFeedbagService(t)
	feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil).Maybe()

	locateService := newMockLocateService(t)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(onlineUserInfoReply("founduser", 0), nil)
	locateService.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: dirReply}, nil)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	_, err := sessionMgr.GetSession(ctx, aimsid)
	require.NoError(t, err)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&mdir=1&t=founduser", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			Data struct {
				Users []struct {
					AimID   string            `json:"aimId"`
					Profile *BuddyProfileInfo `json:"profile"`
				} `json:"users"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got.Response.Data.Users, 1)

	profile := got.Response.Data.Users[0].Profile
	require.NotNil(t, profile, "mdir=1 must carry a profile object")
	assert.Equal(t, "Bob", profile.FirstName)
	assert.Equal(t, "Smith", profile.LastName)
	require.Len(t, profile.HomeAddress, 1)
	assert.Equal(t, "Reno", profile.HomeAddress[0].City)
}

func TestPresenceHandler_GetPresence_MdirProfileIsEmptyNotAbsent(t *testing.T) {
	// A user with no directory record must still render, or a freshly created
	// account can never be found.
	ctx := context.Background()

	feedbagService := newMockFeedbagService(t)
	feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil).Maybe()

	locateService := newMockLocateService(t)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(onlineUserInfoReply("blankuser", 0), nil)
	locateService.EXPECT().DirInfo(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}}, nil)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	_, err := sessionMgr.GetSession(ctx, aimsid)
	require.NoError(t, err)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&mdir=1&t=blankuser", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	// The key must be present and non-null, which is what the client tests for.
	assert.Contains(t, rr.Body.String(), `"profile":{}`)
}

func TestPresenceHandler_GetPresence_NoMdirOmitsProfile(t *testing.T) {
	// Without mdir the directory is not consulted at all — the mock asserts that by
	// having no DirInfo expectation.
	ctx := context.Background()

	feedbagService := newMockFeedbagService(t)
	feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil).Maybe()

	locateService := newMockLocateService(t)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(onlineUserInfoReply("someuser", 0), nil)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	_, err := sessionMgr.GetSession(ctx, aimsid)
	require.NoError(t, err)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&t=someuser", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.NotContains(t, rr.Body.String(), `"profile"`)
}

func TestPresenceHandler_GetPresence_EmptyQueryRendersBothArrays(t *testing.T) {
	ctx := context.Background()

	// No expectations on either service: naming no list must cost no lookups.
	feedbagService := newMockFeedbagService(t)
	locateService := newMockLocateService(t)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	_, err := sessionMgr.GetSession(ctx, aimsid)
	require.NoError(t, err)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	req, _ := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&f=json&mdir=1", nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"users":[]`)
	assert.Contains(t, rr.Body.String(), `"groups":[]`)
}

func TestPresenceHandler_GetPresence_TruncatesOversizedTargetList(t *testing.T) {
	ctx := context.Background()

	feedbagService := newMockFeedbagService(t)

	var queried int
	locateService := newMockLocateService(t)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *state.SessionInstance, _ wire.SNACFrame, body wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error) {
			queried++
			return onlineUserInfoReply(body.ScreenName, 0), nil
		})

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	_, err := sessionMgr.GetSession(ctx, aimsid)
	require.NoError(t, err)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	query := "/presence/get?aimsid=" + aimsid + "&f=json"
	for i := range maxPresenceTargets + 8 {
		query += fmt.Sprintf("&t=user%d", i)
	}
	req, _ := http.NewRequest("GET", query, nil)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"statusCode":200`)
	assert.Equal(t, maxPresenceTargets, queried, "the list is cut to the cap, not refused")

	// A full search page has to fit: 20 profiles plus the searched-for UIN.
	assert.GreaterOrEqual(t, maxPresenceTargets, 21)
}

// searchPageTargets builds n distinct screen names, standing in for the hits of a
// member-directory search page.
func searchPageTargets(n int) []string {
	names := make([]string, 0, n)
	for i := range n {
		names = append(names, fmt.Sprintf("user%d", i))
	}
	return names
}

// setStatusCaps drives setStatus and returns the capability list that reached
// LocateService.SetInfo, or nil when SetInfo was never called.
func setStatusCaps(t *testing.T, instance *state.SessionInstance, query string) ([][16]byte, int) {
	t.Helper()

	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", instance)

	var gotCaps [][16]byte
	var called bool
	locate := newMockLocateService(t)
	locate.EXPECT().SetInfo(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *state.SessionInstance, inBody wire.SNAC_0x02_0x04_LocateSetInfo) {
			called = true
			b, ok := inBody.Bytes(wire.LocateTLVTagsInfoCapabilities)
			require.True(t, ok, "setStatus must always send a capabilities TLV")
			require.Zero(t, len(b)%16)
			gotCaps = userInfoCaps(wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, b)},
				},
			})
			// Apply it, as the real service would, so a follow-up call sees it.
			instance.SetCaps(gotCaps)
		}).Return(nil).Maybe()

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		LocateService:  locate,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setStatus?aimsid="+aimsid+query, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetStatus).ServeHTTP(rr, req)

	if !called {
		return nil, rr.Code
	}
	return gotCaps, rr.Code
}

func TestPresenceHandler_SetStatus_Mood(t *testing.T) {
	tests := []struct {
		name string
		// query is appended to the request, after aimsid.
		query string
		// wantCaps is the capability list that must reach SetInfo. A nil value
		// means SetInfo must not be called at all.
		wantCaps [][16]byte
		// wantCode defaults to 200.
		wantCode int
	}{
		{
			name:     "a known mood is advertised as its capability",
			query:    "&mood=0icqmood6",
			wantCaps: [][16]byte{wire.CapXStatusPlate},
		},
		{
			name:     "a mood with only a placeholder capability still resolves",
			query:    "&mood=0icqmood13",
			wantCaps: [][16]byte{wire.CapMoodHavingFun},
		},
		{
			// The client sends mood= alongside every plain state change, so this
			// is the path back to a moodless online/away/invisible.
			name:     "an empty mood clears the capability",
			query:    "&mood=",
			wantCaps: [][16]byte{},
		},
		{
			// A token the server cannot map is a client bug, not a reset: the
			// mood the user is actually showing is left alone.
			name:     "an unrecognized mood is rejected",
			query:    "&mood=0icqmood999",
			wantCode: http.StatusBadRequest,
		},
		{
			// A status-message-only update must leave the mood alone.
			name:  "an absent mood parameter leaves capabilities untouched",
			query: "&statusMsg=hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := state.NewSession().AddInstance()

			gotCaps, code := setStatusCaps(t, instance, tt.query)

			if tt.wantCode != 0 {
				assert.Equal(t, tt.wantCode, code)
				assert.Nil(t, gotCaps, "a rejected mood must not reach SetInfo")
				return
			}

			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, tt.wantCaps, gotCaps)
		})
	}
}

func TestPresenceHandler_SetStatus_MoodReplacesRatherThanAccumulates(t *testing.T) {
	instance := state.NewSession().AddInstance()

	_, code := setStatusCaps(t, instance, "&mood=0icqmood6")
	assert.Equal(t, http.StatusOK, code)

	gotCaps, code := setStatusCaps(t, instance, "&mood=0icqmood4")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, [][16]byte{wire.CapXStatusBeer}, gotCaps, "the previous mood must be dropped")
}

func TestPresenceHandler_SetStatus_PreservesNonMoodCaps(t *testing.T) {
	// The capability list is rewritten wholesale, so anything the instance
	// advertises that is not a mood has to be carried over.
	instance := state.NewSession().AddInstance()
	instance.SetCaps([][16]byte{wire.CapChat, wire.CapXStatusBeer})

	gotCaps, code := setStatusCaps(t, instance, "&mood=0icqmood6")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, [][16]byte{wire.CapChat, wire.CapXStatusPlate}, gotCaps)

	gotCaps, code = setStatusCaps(t, instance, "&mood=")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, [][16]byte{wire.CapChat}, gotCaps, "clearing a mood must keep the other caps")
}

func TestPresenceHandler_SetStatus_SetInfoError(t *testing.T) {
	instance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", instance)

	locate := newMockLocateService(t)
	locate.EXPECT().SetInfo(mock.Anything, mock.Anything, mock.Anything).Return(io.EOF)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		LocateService:  locate,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setStatus?aimsid="+aimsid+"&mood=0icqmood6", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetStatus).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
