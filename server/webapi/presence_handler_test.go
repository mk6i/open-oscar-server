package webapi

import (
	"bytes"
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

// onlineUserInfo builds a locate UserInfoReply for an online user, optionally
// marking them idle by the given number of minutes (0 = not idle).
func onlineUserInfo(screenName string, idleMinutes uint16) wire.SNAC_0x02_0x06_LocateUserInfoReply {
	info := wire.TLVUserInfo{ScreenName: screenName}
	if idleMinutes > 0 {
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, idleMinutes))
	}
	return wire.SNAC_0x02_0x06_LocateUserInfoReply{TLVUserInfo: info}
}

// onlineUsers returns the locate replies of online, non-idle users.
func onlineUsers(screenNames ...string) map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply {
	users := make(map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply, len(screenNames))
	for _, name := range screenNames {
		users[state.NewIdentScreenName(name).String()] = onlineUserInfo(name, 0)
	}
	return users
}

// sentLocateQueries returns the screen names of the locate user info queries
// sent to the OSCAR server.
func sentLocateQueries(conn *fakeConn) []string {
	var names []string
	for _, body := range conn.sentOf(wire.Locate, wire.LocateUserInfoQuery) {
		names = append(names, body.(wire.SNAC_0x02_0x05_LocateUserInfoQuery).ScreenName)
	}
	return names
}

// getPresence serves presence/get for session with the given query
// parameters, which start with '&'.
func getPresence(t *testing.T, h *PresenceHandler, session *Session, params string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/presence/get?aimsid="+session.AimSID+params, nil)
	rr := httptest.NewRecorder()
	requireSession(h.SessionManager, h.GetPresence).ServeHTTP(rr, req)
	return rr
}

func TestPresenceHandler_GetPresence(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		feedbag            []wire.FeedbagItem
		users              map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply
		seedPresence       func(*Session)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
		wantLocateQueries  []string
	}{
		{
			name:        "Success_BuddyList",
			queryParams: "bl=1",
			// The root group orders Friends before Coworkers; Family and Enemies
			// are missing from it. Friends orders buddy2 before buddy1; buddy3
			// and buddy4 are missing from it.
			feedbag: []wire.FeedbagItem{
				{
					ClassID: wire.FeedbagClassIdGroup,
					GroupID: 0,
					TLVLBlock: wire.TLVLBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 1}),
						},
					},
				},
				{ClassID: wire.FeedbagClassIdGroup, Name: "Coworkers", GroupID: 1},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "coworker1", GroupID: 1, ItemID: 1},
				{
					ClassID: wire.FeedbagClassIdGroup,
					Name:    "Friends",
					GroupID: 2,
					TLVLBlock: wire.TLVLBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{5, 2}),
						},
					},
				},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "buddy3", GroupID: 2, ItemID: 6},
				{
					ClassID: wire.FeedbagClassIdBuddy,
					Name:    "buddy1",
					GroupID: 2,
					ItemID:  2,
					TLVLBlock: wire.TLVLBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesAlias, "Buddy One"),
						},
					},
				},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "buddy4", GroupID: 2, ItemID: 7},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "buddy2", GroupID: 2, ItemID: 5},
				{ClassID: wire.FeedbagClassIdGroup, Name: "Family", GroupID: 3},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "family1", GroupID: 3, ItemID: 3},
				{ClassID: wire.FeedbagClassIdGroup, Name: "Enemies", GroupID: 4},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "enemy1", GroupID: 4, ItemID: 4},
			},
			// bl=1 is served from the presence view, so the state comes from the
			// buddy's arrival.
			seedPresence: func(sess *Session) {
				buddyArrives(sess, onlineBuddy("buddy1"))
				buddyArrives(sess, onlineBuddy("buddy2"))
				buddyArrives(sess, onlineBuddy("buddy3"))
				buddyArrives(sess, onlineBuddy("buddy4"))
				buddyArrives(sess, onlineBuddy("coworker1"))
				buddyArrives(sess, onlineBuddy("family1"))
				buddyArrives(sess, onlineBuddy("enemy1"))
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				want := `{"response":{"statusCode":200,"statusText":"Ok","data":{"groups":[{"name":"Friends","buddies":[{"aimId":"buddy2","displayId":"buddy2","state":"online","userType":"aim"},{"aimId":"buddy1","displayId":"buddy1","friendly":"Buddy One","state":"online","userType":"aim"},{"aimId":"buddy3","displayId":"buddy3","state":"online","userType":"aim"},{"aimId":"buddy4","displayId":"buddy4","state":"online","userType":"aim"}]},{"name":"Coworkers","buddies":[{"aimId":"coworker1","displayId":"coworker1","state":"online","userType":"aim"}]},{"name":"Family","buddies":[{"aimId":"family1","displayId":"family1","state":"online","userType":"aim"}]},{"name":"Enemies","buddies":[{"aimId":"enemy1","displayId":"enemy1","state":"online","userType":"aim"}]}]}}}`
				assert.Equal(t, want, body)
			},
		},
		{
			name:        "Success_BuddyList_NoGroupOrder",
			queryParams: "bl=1",
			// Neither the root group nor Family has an order attribute, so groups
			// and buddies keep their feedbag position.
			feedbag: []wire.FeedbagItem{
				{ClassID: wire.FeedbagClassIdGroup, GroupID: 0},
				{ClassID: wire.FeedbagClassIdGroup, Name: "Family", GroupID: 3},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "family2", GroupID: 3, ItemID: 9},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "family1", GroupID: 3, ItemID: 3},
				{ClassID: wire.FeedbagClassIdGroup, Name: "Coworkers", GroupID: 1},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "coworker1", GroupID: 1, ItemID: 1},
				{ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 2},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "buddy1", GroupID: 2, ItemID: 2},
			},
			seedPresence: func(sess *Session) {
				buddyArrives(sess, onlineBuddy("buddy1"))
				buddyArrives(sess, onlineBuddy("coworker1"))
				buddyArrives(sess, onlineBuddy("family1"))
				buddyArrives(sess, onlineBuddy("family2"))
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				want := `{"response":{"statusCode":200,"statusText":"Ok","data":{"groups":[{"name":"Family","buddies":[{"aimId":"family2","displayId":"family2","state":"online","userType":"aim"},{"aimId":"family1","displayId":"family1","state":"online","userType":"aim"}]},{"name":"Coworkers","buddies":[{"aimId":"coworker1","displayId":"coworker1","state":"online","userType":"aim"}]},{"name":"Friends","buddies":[{"aimId":"buddy1","displayId":"buddy1","state":"online","userType":"aim"}]}]}}}`
				assert.Equal(t, want, body)
			},
		},
		{
			name:        "Success_BuddyList_DropsOrphans",
			queryParams: "bl=1",
			// orphan1 references a group with no group row; orphan2 sits in the
			// root group.
			feedbag: []wire.FeedbagItem{
				{
					ClassID: wire.FeedbagClassIdGroup,
					GroupID: 0,
					TLVLBlock: wire.TLVLBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1}),
						},
					},
				},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "orphan1", GroupID: 7, ItemID: 1},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "orphan2", GroupID: 0, ItemID: 2},
				{ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 1},
				{ClassID: wire.FeedbagClassIdBuddy, Name: "buddy1", GroupID: 1, ItemID: 3},
			},
			seedPresence: func(sess *Session) {
				buddyArrives(sess, onlineBuddy("buddy1"))
				buddyArrives(sess, onlineBuddy("orphan1"))
				buddyArrives(sess, onlineBuddy("orphan2"))
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				want := `{"response":{"statusCode":200,"statusText":"Ok","data":{"groups":[{"name":"Friends","buddies":[{"aimId":"buddy1","displayId":"buddy1","state":"online","userType":"aim"}]}]}}}`
				assert.Equal(t, want, body)
			},
		},
		{
			name:        "Success_BuddyList_ProfileMsg_Alias",
			queryParams: "bl=1&profileMsg=1",
			// profileMsg=1 reads presence through a locate query; it fails here,
			// so the buddy renders offline but still carries its alias.
			feedbag: []wire.FeedbagItem{
				{ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 1},
				{
					ClassID: wire.FeedbagClassIdBuddy,
					Name:    "buddy1",
					GroupID: 1,
					ItemID:  1,
					TLVLBlock: wire.TLVLBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesAlias, "Buddy One"),
						},
					},
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				want := `{"response":{"statusCode":200,"statusText":"Ok","data":{"groups":[{"name":"Friends","buddies":[{"aimId":"buddy1","displayId":"buddy1","friendly":"Buddy One","state":"offline","userType":"aim"}]}]}}}`
				assert.Equal(t, want, body)
			},
			wantLocateQueries: []string{"buddy1"},
		},
		{
			name:        "Success_TargetUsers",
			queryParams: "t=user1,user2",
			users: map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply{
				"user1": onlineUserInfo("user1", 0),
				// user2 is idle for 7 minutes.
				"user2": onlineUserInfo("user2", 7),
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"users"`)
				assert.Contains(t, body, `"user1"`)
				assert.Contains(t, body, `"user2"`)
				assert.Contains(t, body, `"idle"`)
			},
			wantLocateQueries: []string{"user1", "user2"},
		},
		{
			// A blocked or offline user comes back as a locate error.
			name:               "Success_BlockedOrOfflineUser",
			queryParams:        "t=blockeduser",
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"blockeduser"`)
				assert.Contains(t, body, `"offline"`)
			},
			wantLocateQueries: []string{"blockeduser"},
		},
		{
			name:               "Success_EmptyRequest",
			queryParams:        "",
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
			name:               "Success_FullSearchPage",
			queryParams:        "t=" + strings.Join(searchPageTargets(21), "&t="),
			users:              onlineUsers(searchPageTargets(21)...),
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"user0"`)
				assert.Contains(t, body, `"user20"`)
			},
			wantLocateQueries: searchPageTargets(21),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn().answering(locateReplies(tt.users))
			sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

			// Seeded after the feedbag: an arrival resolves aliases off it.
			sess.feedbag.Reset(tt.feedbag)
			if tt.seedPresence != nil {
				tt.seedPresence(sess)
			}

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				Logger:         slog.Default(),
			}

			params := ""
			if tt.queryParams != "" {
				params = "&" + tt.queryParams
			}
			rr := getPresence(t, handler, sess, params)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, strings.TrimSpace(rr.Body.String()))
			}
			assert.Equal(t, tt.wantLocateQueries, sentLocateQueries(conn))
		})
	}
}

// TestPresenceHandler_GetPresence_PublishesIconForOnlineBuddiesOnly verifies that
// the icon is published only for an online, non-blocking user, and that an
// offline or blocking user is never even looked up — so neither their icon nor
// its hash leaks to a caller they are invisible to.
func TestPresenceHandler_GetPresence_PublishesIconForOnlineBuddiesOnly(t *testing.T) {
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, state.NewIdentScreenName("onlineuser")).
		Return(bartID([]byte{0xab, 0xcd}), nil).Once()

	conn := newFakeConn().answering(locateReplies(onlineUsers("onlineuser")))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.BaseURL = "http://api.example.com"

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		IconSource:     BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()},
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&t=onlineuser,offlineuser")
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

// A buddy's status message rides in the BART TLV, next to the icon reference.
func TestPresenceHandler_GetPresence_PublishesStatusMessage(t *testing.T) {
	withStatus := wire.TLVUserInfo{ScreenName: "hasstatus"}
	withStatus.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, []wire.BARTID{testStatusBART}))

	conn := newFakeConn().answering(locateReplies(map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply{
		"hasstatus": {TLVUserInfo: withStatus},
		"nostatus":  onlineUserInfo("nostatus", 0),
	}))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.BaseURL = "http://api.example.com"

	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).Return(nil, nil).Maybe()

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		IconSource:     BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()},
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&t=hasstatus,nostatus")
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			Data struct {
				Users []struct {
					AimID     string `json:"aimId"`
					StatusMsg string `json:"statusMsg"`
				} `json:"users"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got.Response.Data.Users, 2)

	byName := map[string]string{}
	for _, u := range got.Response.Data.Users {
		byName[u.AimID] = u.StatusMsg
	}
	assert.Equal(t, "brb", byName["hasstatus"])
	assert.Empty(t, byName["nostatus"])
}

// TestPresenceHandler_GetPresence_BuddyListGrouping verifies that bl=1 places
// each buddy under its own group using realistic feedbag data, where group rows
// carry ItemID 0 and a distinct nonzero GroupID, and buddy rows reference those
// GroupIDs. This is the shape the OSCAR feedbag actually stores.
func TestPresenceHandler_GetPresence_BuddyListGrouping(t *testing.T) {
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.feedbag.Reset([]wire.FeedbagItem{
		// Root order group: ItemID 0, GroupID 0, empty name — not a real buddy group.
		{ItemID: 0, GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
		// Named groups: ItemID 0, distinct nonzero GroupIDs.
		{ItemID: 0, GroupID: 10, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
		{ItemID: 0, GroupID: 20, ClassID: wire.FeedbagClassIdGroup, Name: "Work"},
		// Buddies reference their group's GroupID.
		{ItemID: 101, GroupID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "alice"},
		{ItemID: 201, GroupID: 20, ClassID: wire.FeedbagClassIdBuddy, Name: "bob"},
	})
	buddyArrives(sess, onlineBuddy("alice"))
	buddyArrives(sess, onlineBuddy("bob"))

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&bl=1")
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

// setState serves presence/setState for session with the given query
// parameters, which start with '&'.
func setState(t *testing.T, h *PresenceHandler, session *Session, params string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/presence/setState?aimsid="+session.AimSID+params, nil)
	rr := httptest.NewRecorder()
	requireSession(h.SessionManager, h.SetState).ServeHTTP(rr, req)
	return rr
}

// statusFields is the SetUserInfoFields body that sets the status bits.
func statusFields(status uint32) wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields {
	return wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.OServiceUserInfoStatus, status),
			},
		},
	}
}

// awayMessageInfo is the LocateSetInfo body that sets the away message.
func awayMessageInfo(msg string) wire.SNAC_0x02_0x04_LocateSetInfo {
	return wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, msg),
			},
		},
	}
}

func TestPresenceHandler_SetState_InvalidState(t *testing.T) {
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := setState(t, handler, sess, "&state=bogus")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid state parameter")
	assert.Empty(t, conn.sentSNACs())
}

func TestPresenceHandler_SetState_AppliesAwayState(t *testing.T) {
	// setState sets the away message and the status bits through OSCAR; the
	// identity badge re-renders from the myInfo the user info update raises, so
	// the handler queues no event of its own.
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := setState(t, handler, sess, "&state=away&awayMsg=brb")
	assert.Equal(t, http.StatusOK, rr.Code)

	// The away message goes first, so the user info update the status change
	// relays back carries it.
	assert.Equal(t, []wire.SNACMessage{
		{Frame: wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateSetInfo, RequestID: 1}, Body: awayMessageInfo("brb")},
		{Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceSetUserInfoFields, RequestID: 2}, Body: statusFields(wire.OServiceUserStatusAway)},
	}, conn.sentSNACs())

	var resp struct {
		Response struct {
			Data SetStateData `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "away", resp.Response.Data.State)
	assert.Equal(t, "brb", resp.Response.Data.AwayMsg)
	assert.Equal(t, "testuser", resp.Response.Data.AimID)

	assert.Equal(t, "brb", sess.self.awayMessage())
	assert.Empty(t, sess.EventQueue.GetAllEvents())
}

func TestPresenceHandler_SetState_OnlineClearsAwayMessage(t *testing.T) {
	// Coming back online drops the away message, which LocateSetInfo owns, along
	// with the status bits.
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.self.setAwayMessage("brb")

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := setState(t, handler, sess, "&state=online&awayMsg=brb")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"awayMsg":""`)

	assert.Equal(t, []any{awayMessageInfo("")}, conn.sentOf(wire.Locate, wire.LocateSetInfo))
	assert.Equal(t, []any{statusFields(0)}, conn.sentOf(wire.OService, wire.OServiceSetUserInfoFields))
	assert.Empty(t, sess.self.awayMessage())
}

func TestPresenceHandler_SetState_AvailableStateClearsTrackedAwayMessage(t *testing.T) {
	// The server drops the away message when the user leaves the unavailable
	// states, so the one myInfo reports goes with it. Invisible is not
	// unavailable.
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.self.setAwayMessage("brb")

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := setState(t, handler, sess, "&state=invisible")
	assert.Equal(t, http.StatusOK, rr.Code)

	assert.Empty(t, conn.sentOf(wire.Locate, wire.LocateSetInfo))
	assert.Equal(t, []any{statusFields(wire.OServiceUserStatusInvisible)}, conn.sentOf(wire.OService, wire.OServiceSetUserInfoFields))
	assert.Empty(t, sess.self.awayMessage())
}

func TestPresenceHandler_SetState_UnavailableStateKeepsTrackedAwayMessage(t *testing.T) {
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.self.setAwayMessage("brb")

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := setState(t, handler, sess, "&state=dnd")
	assert.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, "brb", sess.self.awayMessage())
}

func TestPresenceHandler_SetState_SendErrors(t *testing.T) {
	tests := []struct {
		name    string
		params  string
		sendErr error
		// limit gates the rate class of this SNAC.
		limit      *wire.SNACType
		wantStatus int
	}{
		{
			name:       "the status change cannot be sent",
			params:     "&state=dnd",
			sendErr:    assert.AnError,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "the away message cannot be sent",
			params:     "&state=away&awayMsg=brb",
			sendErr:    assert.AnError,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "the status change is rate limited",
			params:     "&state=dnd",
			limit:      &wire.SNACType{FoodGroup: wire.OService, SubGroup: wire.OServiceSetUserInfoFields},
			wantStatus: statusRateLimited,
		},
		{
			name:       "the away message is rate limited",
			params:     "&state=away&awayMsg=brb",
			limit:      &wire.SNACType{FoodGroup: wire.Locate, SubGroup: wire.LocateSetInfo},
			wantStatus: statusRateLimited,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn()
			conn.sendErr = tt.sendErr
			sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
			sess.self.setAwayMessage("old")
			if tt.limit != nil {
				limitRateClass(sess, tt.limit.FoodGroup, tt.limit.SubGroup)
			}

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				Logger:         slog.Default(),
			}

			rr := setState(t, handler, sess, tt.params)
			assert.Equal(t, tt.wantStatus, envelopeStatus(t, rr.Body.Bytes()))
			// A failed change leaves the tracked away message alone.
			assert.Equal(t, "old", sess.self.awayMessage())
			if tt.limit != nil {
				assert.Empty(t, conn.sentOf(tt.limit.FoodGroup, tt.limit.SubGroup))
			}
		})
	}
}

func TestPresenceHandler_SetState_NormalizesAimID(t *testing.T) {
	// The client keys users by the normalized aimId, so the response must carry
	// that while displayId keeps the user's own casing and spacing.
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "Mike Kelly", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := setState(t, handler, sess, "&state=away")
	assert.Equal(t, http.StatusOK, rr.Code)

	// An away state with no message leaves the stored away message alone, so the
	// handler sends the status change only.
	assert.Equal(t, []wire.SNACMessage{
		{Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceSetUserInfoFields, RequestID: 1}, Body: statusFields(wire.OServiceUserStatusAway)},
	}, conn.sentSNACs())

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

func TestPresenceHandler_Icon_LooksUpThroughSessionWithinLookupRate(t *testing.T) {
	conn := newFakeConn().answering(locateReplies(onlineUsers("buddy")))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		IconSource:     newTestIconSource(t),
		Logger:         slog.Default(),
	}

	icon := func() string {
		req := httptest.NewRequest("GET", "/presence/icon?name=buddy&aimsid="+sess.AimSID, nil)
		rr := httptest.NewRecorder()
		handler.Icon(rr, req)
		require.Equal(t, http.StatusFound, rr.Code)
		return rr.Header().Get("Location")
	}

	for range lookupBurst {
		assert.Equal(t, "/static/icons/online_aim_32.png", icon())
	}
	// Past the lookup rate, the badge is the one an anonymous caller gets.
	assert.Equal(t, "/static/icons/offline_aim_32.png", icon())
	assert.Len(t, sentLocateQueries(conn), lookupBurst)
}

func TestPresenceHandler_SetProfile(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		sendErr            error
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
		wantSent           []any
	}{
		{
			name:               "Success_SetProfile",
			queryParams:        "profile=Hello+World",
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
			wantSent: []any{wire.SNAC_0x02_0x04_LocateSetInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "Hello World"),
					},
				},
			}},
		},
		{
			name:               "Error_ProfileTooLarge",
			queryParams:        "profile=" + strings.Repeat("x", 4097),
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "profile too large")
			},
		},
		{
			name:               "Error_SendFails",
			queryParams:        "profile=Hello+World",
			sendErr:            io.EOF,
			expectedStatusCode: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "failed to save profile")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn()
			conn.sendErr = tt.sendErr
			sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				Logger:         slog.Default(),
			}

			reqURL := "/presence/setProfile?aimsid=" + sess.AimSID + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(handler.SessionManager, handler.SetProfile).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				tt.checkResponse(t, strings.TrimSpace(rr.Body.String()))
			}
			assert.Equal(t, tt.wantSent, conn.sentOf(wire.Locate, wire.LocateSetInfo))
		})
	}
}

func TestPresenceHandler_GetProfile(t *testing.T) {
	conn := newFakeConn().answering(locateReplies(map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply{
		"testuser": {
			LocateInfo: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "My profile"),
				},
			},
		},
	}))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/getProfile?aimsid="+sess.AimSID, nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetProfile).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"statusCode":200`)
	assert.Contains(t, body, `"My profile"`)
	assert.Contains(t, body, `"testuser"`)
	assert.Equal(t, []any{wire.SNAC_0x02_0x05_LocateUserInfoQuery{Type: uint16(wire.LocateTypeSig), ScreenName: "testuser"}},
		conn.sentOf(wire.Locate, wire.LocateUserInfoQuery))
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
			conn := newFakeConn()
			sessionMgr, sess := createTestSessionManager(t, tt.screenName, conn)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				Logger:         slog.Default(),
			}

			rr := setState(t, handler, sess, "&view=occupied&away=")
			assert.Equal(t, http.StatusOK, rr.Code)

			// The Busy bit reaches OSCAR either way; only the reported state differs.
			assert.Contains(t, rr.Body.String(), `"state":"`+tt.wantState+`"`)
			sent := conn.sentOf(wire.OService, wire.OServiceSetUserInfoFields)
			require.Equal(t, []any{statusFields(wire.OServiceUserStatusBusy)}, sent)

			// The state must survive the round trip: the myInfo raised by the
			// user info update reads the Busy bit back off the wire.
			fields := sent[0].(wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields)
			status, _ := fields.Uint32BE(wire.OServiceUserInfoStatus)
			relayed := wire.TLVUserInfo{ScreenName: tt.screenName}
			relayed.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, status))
			assert.Equal(t, tt.wantState, selfWebState(relayed, sess.isAIMViewer()))
		})
	}
}

// mdirServer answers locate queries with users and directory reads with
// record, for every name.
func mdirServer(users map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply, record wire.SNAC_0x02_0x0C_LocateGetDirReply) func(req wire.SNACMessage) []wire.SNACMessage {
	dir := dirServer{everyone: &record}
	locate := locateReplies(users)
	return func(req wire.SNACMessage) []wire.SNACMessage {
		if _, ok := req.Body.(wire.SNAC_0x02_0x0B_LocateGetDirInfo); ok {
			return dir.respond(req)
		}
		return locate(req)
	}
}

func TestPresenceHandler_GetPresence_MdirAttachesProfile(t *testing.T) {
	// Search results are populated from this call, and a user carrying no nested
	// "profile" object is dropped by clients, so a found user would not render.
	record := dirRecord("Bob", "Smith")
	record.Append(wire.NewTLVBE(wire.ODirTLVCity, "Reno"))

	conn := newFakeConn().answering(mdirServer(onlineUsers("founduser"), record))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&mdir=1&t=founduser")
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
	assert.Equal(t, []any{wire.SNAC_0x02_0x0B_LocateGetDirInfo{ScreenName: "founduser"}},
		conn.sentOf(wire.Locate, wire.LocateGetDirInfo))
}

func TestPresenceHandler_GetPresence_MdirProfileIsEmptyNotAbsent(t *testing.T) {
	// A user with no directory record must still render, or a freshly created
	// account can never be found.
	tests := []struct {
		name    string
		respond func(req wire.SNACMessage) []wire.SNACMessage
	}{
		{
			name:    "no directory record",
			respond: mdirServer(onlineUsers("blankuser"), wire.SNAC_0x02_0x0C_LocateGetDirReply{Status: wire.LocateGetDirReplyOK}),
		},
		{
			name: "the directory read fails",
			respond: func(req wire.SNACMessage) []wire.SNACMessage {
				if _, ok := req.Body.(wire.SNAC_0x02_0x0B_LocateGetDirInfo); ok {
					return []wire.SNACMessage{snacErr(wire.Locate, wire.ErrorCodeNotSupportedByHost)}
				}
				return locateReplies(onlineUsers("blankuser"))(req)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn().answering(tt.respond)
			sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				Logger:         slog.Default(),
			}

			rr := getPresence(t, handler, sess, "&mdir=1&t=blankuser")

			// The key must be present and non-null, which is what the client tests for.
			assert.Contains(t, rr.Body.String(), `"profile":{}`)
		})
	}
}

func TestPresenceHandler_GetPresence_NoMdirOmitsProfile(t *testing.T) {
	// Without mdir the directory is not consulted at all.
	conn := newFakeConn().answering(mdirServer(onlineUsers("someuser"), dirRecord("Some", "User")))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&t=someuser")

	assert.NotContains(t, rr.Body.String(), `"profile"`)
	assert.Empty(t, conn.sentOf(wire.Locate, wire.LocateGetDirInfo))
}

func TestPresenceHandler_GetPresence_EmptyQueryRendersBothArrays(t *testing.T) {
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&f=json&mdir=1")

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"users":[]`)
	assert.Contains(t, rr.Body.String(), `"groups":[]`)
	// Naming no list must cost no lookups.
	assert.Empty(t, conn.sentSNACs())
}

func TestPresenceHandler_GetPresence_TruncatesOversizedTargetList(t *testing.T) {
	targets := searchPageTargets(maxPresenceTargets + 8)
	conn := newFakeConn().answering(locateReplies(onlineUsers(targets...)))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&f=json&t="+strings.Join(targets, "&t="))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"statusCode":200`)
	assert.Equal(t, targets[:maxPresenceTargets], sentLocateQueries(conn), "the list is cut to the cap, not refused")

	// A full search page has to fit: 20 profiles plus the searched-for UIN.
	assert.GreaterOrEqual(t, maxPresenceTargets, 21)
}

func TestPresenceHandler_GetPresence_LookupsBypassRateGate(t *testing.T) {
	// The server never limits lookups, so a gated rate class must not hold
	// them back.
	conn := newFakeConn().answering(locateReplies(onlineUsers("user1")))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	limitRateClass(sess, wire.Locate, wire.LocateUserInfoQuery)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&t=user1")

	assert.Contains(t, rr.Body.String(), `"state":"online"`)
	assert.Equal(t, []string{"user1"}, sentLocateQueries(conn))
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

// newSetStatusDriver returns a function that drives setStatus and reports the
// capability list of the LocateSetInfo it sent, or nil when it sent none. The
// web session is built once, so consecutive calls see the capabilities the
// earlier ones left on it. It starts out with the sign-on capabilities, unless
// caps replaces them.
func newSetStatusDriver(t *testing.T, caps ...[16]byte) func(query string) ([][16]byte, int) {
	t.Helper()

	conn := newFakeConn()
	sessionMgr, session := createTestSessionManager(t, "testuser", conn)
	if len(caps) > 0 {
		session.capabilities = caps
	}

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	return func(query string) ([][16]byte, int) {
		before := len(conn.sentOf(wire.Locate, wire.LocateSetInfo))

		req, err := http.NewRequest("GET", "/presence/setStatus?aimsid="+session.AimSID+query, nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		requireSession(handler.SessionManager, handler.SetStatus).ServeHTTP(rr, req)

		sent := conn.sentOf(wire.Locate, wire.LocateSetInfo)
		if len(sent) == before {
			return nil, rr.Code
		}
		require.Len(t, sent, before+1)
		setInfo := sent[before].(wire.SNAC_0x02_0x04_LocateSetInfo)
		b, ok := setInfo.Bytes(wire.LocateTLVTagsInfoCapabilities)
		require.True(t, ok, "setStatus must always send a capabilities TLV")
		require.Zero(t, len(b)%16)
		return userInfoCaps(wire.TLVUserInfo{
			TLVBlock: wire.TLVBlock{
				TLVList: wire.TLVList{wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, b)},
			},
		}), rr.Code
	}
}

// A state change must not blank the status message: the client renders both from
// the same payload.
func TestPresenceHandler_SetState_PreservesStatusMessage(t *testing.T) {
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.self.setRelayed(bartBuddy("testuser", testStatusBART))

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	rr := setState(t, handler, sess, "&state=online")
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"statusMsg":"brb"`)
}

func TestPresenceHandler_SetStatus_StatusMessage(t *testing.T) {
	tests := []struct {
		name string
		// query is appended to the request, after aimsid.
		query string
		// wantStatusMsg is the text that must reach OSCAR, when wantSet is true.
		wantStatusMsg string
		wantSet       bool
	}{
		{
			name:          "a status message is sent as a BART status item",
			query:         "&statusMsg=out+to+lunch",
			wantStatusMsg: "out to lunch",
			wantSet:       true,
		},
		{
			// The client clears the status message by sending an empty one.
			name:    "an empty status message clears it",
			query:   "&statusMsg=",
			wantSet: true,
		},
		{
			name:  "an absent status message parameter leaves it alone",
			query: "&mood=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn()
			sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				Logger:         slog.Default(),
			}

			req, err := http.NewRequest("GET", "/presence/setStatus?aimsid="+sess.AimSID+tt.query, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			requireSession(handler.SessionManager, handler.SetStatus).ServeHTTP(rr, req)
			require.Equal(t, http.StatusOK, rr.Code)

			sent := conn.sentOf(wire.OService, wire.OServiceSetUserInfoFields)
			if !tt.wantSet {
				assert.Empty(t, sent)
				return
			}
			require.Len(t, sent, 1)

			fields := sent[0].(wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields)
			b, hasBART := fields.Bytes(wire.OServiceUserInfoBARTInfo)
			require.True(t, hasBART, "setStatus must send a BART TLV")

			var gotID wire.BARTID
			require.NoError(t, wire.UnmarshalBE(&gotID, bytes.NewReader(b)))
			assert.Equal(t, wire.BARTTypesStatusStr, gotID.Type)
			assert.Equal(t, wire.BARTFlagsData, gotID.Flags)

			gotStatusMsg, err := gotID.StatusText()
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatusMsg, gotStatusMsg)
		})
	}
}

func TestPresenceHandler_SetStatus_StatusMessageError(t *testing.T) {
	conn := newFakeConn()
	conn.sendErr = io.EOF
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setStatus?aimsid="+sess.AimSID+"&statusMsg=nope", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetStatus).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "failed to set status")
}

func TestPresenceHandler_SetStatus_StatusMessageTooLong(t *testing.T) {
	// An overlong message would wrap the one-byte length prefix and corrupt the
	// user info block.
	conn := newFakeConn()
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	tooLong := strings.Repeat("a", 252)
	req, err := http.NewRequest("GET", "/presence/setStatus?aimsid="+sess.AimSID+"&statusMsg="+tooLong, nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetStatus).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), wire.ErrStatusTextSizeExceeded.Error())
	// Nothing may reach OSCAR.
	assert.Empty(t, conn.sentSNACs())
}

func TestPresenceHandler_SetStatus_Mood(t *testing.T) {
	tests := []struct {
		name string
		// query is appended to the request, after aimsid.
		query string
		// wantCaps is the capability list that must reach SetInfo. A nil value
		// means SetInfo must not be sent at all.
		wantCaps [][16]byte
		// wantCode defaults to 200.
		wantCode int
	}{
		{
			name:     "a known mood is advertised as its capability",
			query:    "&mood=0icqmood6",
			wantCaps: [][16]byte{wire.CapICQCh2Extended, wire.CapUTF8Messages, wire.CapXStatusPlate},
		},
		{
			name:     "a mood with only a placeholder capability still resolves",
			query:    "&mood=0icqmood13",
			wantCaps: [][16]byte{wire.CapICQCh2Extended, wire.CapUTF8Messages, wire.CapMoodHavingFun},
		},
		{
			// The client sends mood= alongside every plain state change, so this
			// is the path back to a moodless online/away/invisible. Only the
			// mood is dropped.
			name:     "an empty mood clears the capability",
			query:    "&mood=",
			wantCaps: [][16]byte{wire.CapICQCh2Extended, wire.CapUTF8Messages},
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
			gotCaps, code := newSetStatusDriver(t)(tt.query)

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
	setStatus := newSetStatusDriver(t)

	_, code := setStatus("&mood=0icqmood6")
	assert.Equal(t, http.StatusOK, code)

	gotCaps, code := setStatus("&mood=0icqmood4")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, [][16]byte{wire.CapICQCh2Extended, wire.CapUTF8Messages, wire.CapXStatusBeer}, gotCaps,
		"the previous mood must be dropped")
}

func TestPresenceHandler_SetStatus_PreservesNonMoodCaps(t *testing.T) {
	// The capability list is rewritten wholesale, so anything the session
	// advertises that is not a mood has to be carried over.
	setStatus := newSetStatusDriver(t, wire.CapChat, wire.CapXStatusBeer)

	gotCaps, code := setStatus("&mood=0icqmood6")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, [][16]byte{wire.CapChat, wire.CapXStatusPlate}, gotCaps)

	gotCaps, code = setStatus("&mood=")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, [][16]byte{wire.CapChat}, gotCaps, "clearing a mood must keep the other caps")
}

func TestPresenceHandler_SetStatus_SetInfoError(t *testing.T) {
	conn := newFakeConn()
	conn.sendErr = io.EOF
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setStatus?aimsid="+sess.AimSID+"&mood=0icqmood6", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetStatus).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// presence/get?t= serves what the view knows and only pays for a locate query
// when the caller asks for something the view cannot carry.
func TestPresenceHandler_GetPresence_TargetsFallBackToLocate(t *testing.T) {
	type user struct {
		AimID     string `json:"aimId"`
		State     string `json:"state"`
		AwayMsg   string `json:"awayMsg"`
		StatusMsg string `json:"statusMsg"`
	}

	// getTargets drives presence/get for one target and returns the single user
	// the response carries, and the locate queries it sent.
	getTargets := func(t *testing.T, target, extraParams string, seed func(*Session), users map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply) (user, []string) {
		t.Helper()

		conn := newFakeConn().answering(locateReplies(users))
		sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
		seed(sess)

		handler := &PresenceHandler{
			SessionManager: sessionMgr,
			IconSource:     newTestIconSource(t),
			Logger:         slog.Default(),
		}

		rr := getPresence(t, handler, sess, "&t="+target+extraParams)
		require.Equal(t, http.StatusOK, rr.Code)

		var got struct {
			Response struct {
				Data struct {
					Users []user `json:"users"`
				} `json:"data"`
			} `json:"response"`
		}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
		require.Len(t, got.Response.Data.Users, 1)
		return got.Response.Data.Users[0], sentLocateQueries(conn)
	}

	t.Run("an online buddy is served from the view", func(t *testing.T) {
		got, queries := getTargets(t, "mikekelly", "", func(sess *Session) {
			buddyArrives(sess, bartBuddy("Mike Kelly", testStatusBART))
		}, nil)

		assert.Equal(t, "online", got.State)
		assert.Equal(t, "brb", got.StatusMsg)
		assert.Empty(t, queries)
	})

	// A target need not be a buddy, so nothing may be concluded from a miss.
	t.Run("a target the view has never seen is looked up", func(t *testing.T) {
		got, queries := getTargets(t, "stranger", "", func(*Session) {}, onlineUsers("stranger"))

		assert.Equal(t, "online", got.State)
		assert.Equal(t, []string{"stranger"}, queries)
	})

	// An away message is absent from presence broadcasts, so it costs a query.
	t.Run("an away buddy is looked up for their away message", func(t *testing.T) {
		awayReply := wire.TLVUserInfo{ScreenName: "awaybud"}
		awayReply.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))

		got, queries := getTargets(t, "awaybud", "", func(sess *Session) {
			buddyArrives(sess, awayReply)
		}, map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply{
			"awaybud": {
				TLVUserInfo: awayReply,
				LocateInfo: wire.TLVRestBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "out to lunch"),
				}},
			},
		})

		assert.Equal(t, "away", got.State)
		assert.Equal(t, "out to lunch", got.AwayMsg)
		assert.Equal(t, []string{"awaybud"}, queries)
	})

	// Profile text is likewise only reachable through a locate reply.
	t.Run("profileMsg forces a lookup even for a cached buddy", func(t *testing.T) {
		got, queries := getTargets(t, "mikekelly", "&profileMsg=1", func(sess *Session) {
			buddyArrives(sess, onlineBuddy("Mike Kelly"))
		}, onlineUsers("Mike Kelly"))

		assert.Equal(t, "online", got.State)
		assert.Equal(t, []string{"mikekelly"}, queries)
	})
}

// presence/get?bl=1 walks the whole roster, so only an unavailable buddy may cost
// a locate query.
func TestPresenceHandler_GetPresence_BuddyListQueriesOnlyAwayBuddies(t *testing.T) {
	conn := newFakeConn().answering(locateReplies(map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply{
		"awaybud": {
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "awaybud"},
			LocateInfo: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "out to lunch"),
			}},
		},
	}))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.feedbag.Reset([]wire.FeedbagItem{
		{ItemID: 0, GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
		{ItemID: 0, GroupID: 10, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
		{ItemID: 101, GroupID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "onlinebud"},
		{ItemID: 102, GroupID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "awaybud"},
		{ItemID: 103, GroupID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "neverseen"},
	})

	away := wire.TLVUserInfo{ScreenName: "awaybud"}
	away.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))
	buddyArrives(sess, onlineBuddy("onlinebud"))
	buddyArrives(sess, away)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		IconSource:     newTestIconSource(t),
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&bl=1")
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			Data struct {
				Groups []struct {
					Buddies []struct {
						AimID   string `json:"aimId"`
						State   string `json:"state"`
						AwayMsg string `json:"awayMsg"`
					} `json:"buddies"`
				} `json:"groups"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got.Response.Data.Groups, 1)

	states := map[string]string{}
	awayMsgs := map[string]string{}
	for _, b := range got.Response.Data.Groups[0].Buddies {
		states[b.AimID] = b.State
		awayMsgs[b.AimID] = b.AwayMsg
	}
	assert.Equal(t, "online", states["onlinebud"])
	assert.Equal(t, "away", states["awaybud"])
	// The away message is the one field a presence broadcast cannot carry.
	assert.Equal(t, "out to lunch", awayMsgs["awaybud"])
	// A buddy no arrival has been relayed for renders offline rather than
	// triggering a lookup.
	assert.Equal(t, "offline", states["neverseen"])
	assert.Equal(t, []string{"awaybud"}, sentLocateQueries(conn))
}

// presence/get?t= must not trust a cache hit it no longer holds. It branches on a
// lookup and then renders the record, so the record has to travel with the branch:
// looking it up a second time can miss after an eviction and report the user
// offline instead of falling back to the locate query.
func TestPresenceHandler_GetPresence_ForgottenTargetFallsBackToLocate(t *testing.T) {
	// The target is no longer watched, so only a live lookup knows their state,
	// and it finds them signed off.
	conn := newFakeConn().answering(locateReplies(nil))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	buddyArrives(sess, onlineBuddy("Mike Kelly"))
	sess.forgetBuddyPresence(state.NewIdentScreenName("mikekelly"))

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		IconSource:     newTestIconSource(t),
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&t=mikekelly")
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			Data struct {
				Users []struct {
					AimID string `json:"aimId"`
					State string `json:"state"`
				} `json:"users"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got.Response.Data.Users, 1)

	// The stale "online" snapshot must not survive the eviction.
	assert.Equal(t, "offline", got.Response.Data.Users[0].State)
	assert.Equal(t, []string{"mikekelly"}, sentLocateQueries(conn))
}

// An invisible user reads as offline, and an offline user publishes nothing.
func TestPresenceHandler_GetPresence_InvisibleUserPublishesNothing(t *testing.T) {
	invisible := wire.TLVUserInfo{ScreenName: "sneaky"}
	invisible.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, wire.OServiceUserStatusInvisible))
	invisible.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, []wire.BARTID{testStatusBART}))

	conn := newFakeConn().answering(locateReplies(map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply{
		"sneaky": {
			TLVUserInfo: invisible,
			LocateInfo: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "back later"),
			}},
		},
	}))
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
	sess.BaseURL = "http://api.example.com"

	iconRetriever := newMockBuddyIconRetriever(t)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		IconSource:     BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()},
		Logger:         slog.Default(),
	}

	rr := getPresence(t, handler, sess, "&t=sneaky")
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			Data struct {
				Users []struct {
					State     string `json:"state"`
					BuddyIcon string `json:"buddyIcon"`
					StatusMsg string `json:"statusMsg"`
					AwayMsg   string `json:"awayMsg"`
				} `json:"users"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got.Response.Data.Users, 1)

	user := got.Response.Data.Users[0]
	assert.Equal(t, "offline", user.State)
	assert.Empty(t, user.BuddyIcon)
	assert.Empty(t, user.StatusMsg)
	assert.Empty(t, user.AwayMsg)

	iconRetriever.AssertNotCalled(t, "BuddyIconMetadata", mock.Anything, mock.Anything)
}
