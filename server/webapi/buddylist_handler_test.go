package webapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// newBuddyListHandler returns a BuddyListHandler for tests.
func newBuddyListHandler(t *testing.T) *BuddyListHandler {
	return &BuddyListHandler{
		BuddyListManager: NewBuddyListManager(newTestIconSource(t), slog.Default()),
		Logger:           slog.Default(),
	}
}

// serveBuddyList serves a buddy list method with params for session.
func serveBuddyList(method func(http.ResponseWriter, *http.Request, *Session), params url.Values, session *Session) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/buddylist/method?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	method(rr, req, session)
	return rr
}

// rejectChanges answers every feedbag change with an error SNAC.
func rejectChanges(wire.SNACMessage) []wire.SNACMessage {
	return []wire.SNACMessage{snacErr(wire.Feedbag, wire.ErrorCodeNotSupportedByHost)}
}

// buddyListCase is a buddy list method call against a feedbag.
type buddyListCase struct {
	name   string
	params url.Values
	// feedbag is the feedbag the OSCAR server holds.
	feedbag []wire.FeedbagItem
	// status answers feedbag changes in place of accepting them.
	status func(wire.SNACMessage) []wire.SNACMessage
	// limited gates the feedbag rate class.
	limited          bool
	wantStatusCode   int
	wantResponse     string
	wantStored       func(t *testing.T, stored []wire.FeedbagItem)
	wantNoneSent     bool
	wantMirrorStored bool
}

// runBuddyListCases runs each case against method.
func runBuddyListCases(t *testing.T, method func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session), tests []buddyListCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFeedbagServer(tt.feedbag...)
			server.status = tt.status
			session, conn := newFeedbagSession(t, server)
			if tt.limited {
				limitRateClass(session, wire.Feedbag, wire.FeedbagInsertItem)
				limitRateClass(session, wire.Feedbag, wire.FeedbagUpdateItem)
				limitRateClass(session, wire.Feedbag, wire.FeedbagDeleteItem)
			}

			rr := serveBuddyList(method(newBuddyListHandler(t)), tt.params, session)

			assert.Equal(t, tt.wantStatusCode, rr.Code)
			assert.JSONEq(t, tt.wantResponse, rr.Body.String())
			if tt.wantNoneSent {
				assert.Empty(t, sentFeedbagChanges(conn))
			}
			if tt.wantStored != nil {
				tt.wantStored(t, server.stored())
			}
			if tt.wantMirrorStored {
				assert.Equal(t, server.stored(), session.Feedbag())
			}
		})
	}
}

const (
	okResponse            = `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`
	alreadyExistsResponse = `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"alreadyExists"}}}`
	notFoundResponse      = `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`
	errorResponse         = `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"error"}}}`
	rateLimitedResponse   = `{"response":{"statusCode":430,"statusText":"rate limit exceeded","data":{}}}`
)

// listsBuddy reports whether items list buddy in the group named group.
func listsBuddy(items []wire.FeedbagItem, group, buddy string) bool {
	fl := state.NewFeedbagList(items, nil)
	for _, g := range fl.Groups() {
		if g.Name != group {
			continue
		}
		for _, b := range fl.Buddies(g) {
			if b.Name == buddy {
				return true
			}
		}
	}
	return false
}

// groupNames returns the names of the group rows in items, other than the
// root group's.
func groupNames(items []wire.FeedbagItem) []string {
	var names []string
	for _, item := range items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID != 0 {
			names = append(names, item.Name)
		}
	}
	return names
}

func TestBuddyListHandler_AddBuddy(t *testing.T) {
	friends := []wire.FeedbagItem{
		{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
	}

	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.AddBuddy
	}, []buddyListCase{
		{
			name:           "Success_AddBuddyToExistingGroup",
			params:         url.Values{"buddy": {"newbuddy"}, "group": {"Friends"}},
			feedbag:        friends,
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				assert.True(t, listsBuddy(stored, "Friends", "newbuddy"))
			},
			wantMirrorStored: true,
		},
		{
			name:           "Success_AddBuddyToNewGroup",
			params:         url.Values{"buddy": {"newbuddy"}, "group": {"Work"}},
			feedbag:        friends,
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				assert.True(t, listsBuddy(stored, "Work", "newbuddy"))
			},
			wantMirrorStored: true,
		},
		{
			name:   "Error_BuddyAlreadyExists",
			params: url.Values{"buddy": {"existingbuddy"}, "group": {"Friends"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "existingbuddy"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   alreadyExistsResponse,
			wantNoneSent:   true,
		},
		{
			name:           "Error_MissingBuddyParameter",
			params:         url.Values{"group": {"Friends"}},
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			name:             "Error_ChangeRejected",
			params:           url.Values{"buddy": {"newbuddy"}, "group": {"Friends"}},
			feedbag:          friends,
			status:           rejectChanges,
			wantStatusCode:   http.StatusOK,
			wantResponse:     errorResponse,
			wantMirrorStored: true,
		},
		{
			name:           "Error_RateLimited",
			params:         url.Values{"buddy": {"newbuddy"}, "group": {"Friends"}},
			feedbag:        friends,
			limited:        true,
			wantStatusCode: http.StatusOK,
			wantResponse:   rateLimitedResponse,
			wantNoneSent:   true,
		},
	})
}

func TestBuddyListHandler_AddGroup(t *testing.T) {
	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.AddGroup
	}, []buddyListCase{
		{
			name:           "Error_MissingGroupParam",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing group parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			// Empty feedbag — AddGroup creates the root and NewGroup.
			name:           "Success_GroupAdded",
			params:         url.Values{"group": {"NewGroup"}},
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				assert.Equal(t, []string{"NewGroup"}, groupNames(stored))
			},
			wantMirrorStored: true,
		},
		{
			name:   "Success_GroupAlreadyExists",
			params: url.Values{"group": {"Friends"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   alreadyExistsResponse,
			wantNoneSent:   true,
		},
		{
			name:             "Error_ChangeRejected",
			params:           url.Values{"group": {"NewGroup"}},
			status:           rejectChanges,
			wantStatusCode:   http.StatusOK,
			wantResponse:     errorResponse,
			wantMirrorStored: true,
		},
		{
			name:           "Error_RateLimited",
			params:         url.Values{"group": {"NewGroup"}},
			limited:        true,
			wantStatusCode: http.StatusOK,
			wantResponse:   rateLimitedResponse,
			wantNoneSent:   true,
		},
	})
}

func TestBuddyListHandler_RemoveBuddy(t *testing.T) {
	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.RemoveBuddy
	}, []buddyListCase{
		{
			name:           "Error_MissingBuddyParam",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			name:   "Success_BuddyRemoved",
			params: url.Values{"buddy": {"someBuddy"}, "group": {"Friends"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "someBuddy"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				assert.False(t, listsBuddy(stored, "Friends", "someBuddy"))
			},
			wantMirrorStored: true,
		},
		{
			name:   "Success_BuddyNotFound",
			params: url.Values{"buddy": {"ghost"}, "group": {"Friends"}},
			// Group exists but "ghost" is not in it
			feedbag: []wire.FeedbagItem{
				{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   notFoundResponse,
			wantNoneSent:   true,
		},
		{
			name:           "Success_GroupNotFound",
			params:         url.Values{"buddy": {"someBuddy"}, "group": {"NoSuchGroup"}},
			wantStatusCode: http.StatusOK,
			wantResponse:   notFoundResponse,
			wantNoneSent:   true,
		},
	})
}

func TestBuddyListHandler_RemoveGroup(t *testing.T) {
	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.RemoveGroup
	}, []buddyListCase{
		{
			name:           "Error_MissingGroupParam",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing group parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			// Root order record + Friends group; DeleteGroup deletes Friends and
			// updates the root.
			name:   "Success_GroupRemoved",
			params: url.Values{"group": {"Friends"}},
			feedbag: []wire.FeedbagItem{
				{
					GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "",
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1}),
					}},
				},
				{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				assert.Empty(t, groupNames(stored))
			},
			wantMirrorStored: true,
		},
		{
			name:           "Success_GroupNotFound",
			params:         url.Values{"group": {"NoSuchGroup"}},
			wantStatusCode: http.StatusOK,
			wantResponse:   notFoundResponse,
			wantNoneSent:   true,
		},
	})
}

func TestRequireSession(t *testing.T) {
	tests := []struct {
		name               string
		aimsid             string
		setupMocks         func(*mockSessionResolver, string)
		expectedStatusCode int
		expectedResponse   string
		expectNextCalled   bool
	}{
		{
			name:               "Error_MissingAimsid",
			aimsid:             "",
			setupMocks:         func(sm *mockSessionResolver, aimsid string) {},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing aimsid parameter","data":{}}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Error_SessionNotFound",
			aimsid: "unknown-session",
			setupMocks: func(sm *mockSessionResolver, aimsid string) {
				sm.EXPECT().GetSession(mock.Anything, aimsid).Return(nil, ErrNoWebAPISession)
			},
			expectedStatusCode: http.StatusUnauthorized,
			expectedResponse:   `{"response":{"statusCode":401,"statusText":"invalid or expired session","data":{}}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Error_SessionExpired",
			aimsid: "expired-session",
			setupMocks: func(sm *mockSessionResolver, aimsid string) {
				sm.EXPECT().GetSession(mock.Anything, aimsid).Return(nil, ErrWebAPISessionExpired)
			},
			expectedStatusCode: http.StatusUnauthorized,
			expectedResponse:   `{"response":{"statusCode":401,"statusText":"invalid or expired session","data":{}}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Error_InternalSessionError",
			aimsid: "some-session",
			setupMocks: func(sm *mockSessionResolver, aimsid string) {
				sm.EXPECT().GetSession(mock.Anything, aimsid).Return(nil, errors.New("db error"))
			},
			expectedStatusCode: http.StatusUnauthorized,
			expectedResponse:   `{"response":{"statusCode":401,"statusText":"invalid or expired session","data":{}}}`,
			expectNextCalled:   false,
		},
		{
			name:   "Success_PassesSessionToNext",
			aimsid: "valid-session",
			setupMocks: func(sm *mockSessionResolver, aimsid string) {
				sess := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					LastAccessed: time.Now(),
				}
				sm.EXPECT().GetSession(mock.Anything, aimsid).Return(sess, nil)
				sm.EXPECT().TouchSession(mock.Anything, aimsid).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
			expectNextCalled:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := newMockSessionResolver(t)
			tt.setupMocks(sm, tt.aimsid)

			nextCalled := false
			next := func(w http.ResponseWriter, r *http.Request, session *Session) {
				nextCalled = true
				resp := BaseResponse{}
				resp.Response.StatusCode = 200
				resp.Response.StatusText = "Ok"
				SendResponse(w, r, resp, slog.Default())
			}

			authMiddleware := NewAuthMiddleware(slog.Default())
			wrapped := authMiddleware.RequireSession(sm, next)

			reqURL := "/buddylist/test"
			if tt.aimsid != "" {
				reqURL += "?aimsid=" + tt.aimsid
			}
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())
			assert.Equal(t, tt.expectNextCalled, nextCalled)
		})
	}
}

func TestBuddyListHandler_RenameGroup(t *testing.T) {
	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.RenameGroup
	}, []buddyListCase{
		{
			name:           "Error_MissingParam",
			params:         url.Values{"oldGroup": {"Friends"}},
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing oldGroup or newGroup parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			name:   "Success",
			params: url.Values{"oldGroup": {"Friends"}, "newGroup": {"Pals"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
				{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				assert.Equal(t, []string{"Pals"}, groupNames(stored))
			},
			wantMirrorStored: true,
		},
		{
			name:           "NotFound",
			params:         url.Values{"oldGroup": {"Ghost"}, "newGroup": {"Pals"}},
			wantStatusCode: http.StatusOK,
			wantResponse:   notFoundResponse,
			wantNoneSent:   true,
		},
	})
}

func TestBuddyListHandler_MoveBuddy(t *testing.T) {
	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.MoveBuddy
	}, []buddyListCase{
		{
			name:           "Error_MissingBuddy",
			params:         url.Values{"group": {"Friends"}},
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			name:   "Success_Reorder",
			params: url.Values{"buddy": {"bob"}, "group": {"Friends"}, "beforeBuddy": {"alice"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends",
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10, 20}),
					}}},
				{GroupID: 1, ItemID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "alice"},
				{GroupID: 1, ItemID: 20, ClassID: wire.FeedbagClassIdBuddy, Name: "bob"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				fl := state.NewFeedbagList(stored, nil)
				var order []string
				for _, g := range fl.Groups() {
					for _, b := range fl.Buddies(g) {
						order = append(order, b.Name)
					}
				}
				assert.Equal(t, []string{"bob", "alice"}, order)
			},
			wantMirrorStored: true,
		},
		{
			name:   "NotFound_Buddy",
			params: url.Values{"buddy": {"ghost"}, "group": {"Friends"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   notFoundResponse,
			wantNoneSent:   true,
		},
	})
}

func TestBuddyListHandler_SetBuddyAttribute(t *testing.T) {
	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.SetBuddyAttribute
	}, []buddyListCase{
		{
			name:           "Error_MissingT",
			params:         url.Values{"friendly": {"Al"}},
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing t parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			name:   "Success",
			params: url.Values{"t": {"alice"}, "friendly": {"Al"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				{GroupID: 1, ItemID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "alice"},
			},
			wantStatusCode: http.StatusOK,
			wantResponse:   okResponse,
			wantStored: func(t *testing.T, stored []wire.FeedbagItem) {
				alias, _ := stored[1].String(wire.FeedbagAttributesAlias)
				assert.Equal(t, "Al", alias)
			},
			wantMirrorStored: true,
		},
		{
			name:           "NotFound",
			params:         url.Values{"t": {"ghost"}, "friendly": {"Al"}},
			wantStatusCode: http.StatusOK,
			wantResponse:   notFoundResponse,
			wantNoneSent:   true,
		},
	})
}

func TestBuddyListHandler_SetGroupAttribute(t *testing.T) {
	runBuddyListCases(t, func(h *BuddyListHandler) func(http.ResponseWriter, *http.Request, *Session) {
		return h.SetGroupAttribute
	}, []buddyListCase{
		{
			name:           "Error_MissingCollapsed",
			params:         url.Values{"group": {"Friends"}},
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"response":{"statusCode":400,"statusText":"missing collapsed parameter","data":{}}}`,
			wantNoneSent:   true,
		},
		{
			name:   "Success",
			params: url.Values{"group": {"Friends"}, "collapsed": {"true"}},
			feedbag: []wire.FeedbagItem{
				{GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
				{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
			},
			wantStatusCode:   http.StatusOK,
			wantResponse:     okResponse,
			wantMirrorStored: true,
		},
		{
			name:           "NotFound",
			params:         url.Values{"group": {"NoSuch"}, "collapsed": {"true"}},
			wantStatusCode: http.StatusOK,
			wantResponse:   notFoundResponse,
			wantNoneSent:   true,
		},
	})
}

// A session sends one feedbag change at a time, and each edit diffs against
// the feedbag the edits before it left, so two adds to a new group create it
// once.
func TestBuddyListHandler_AddBuddy_ConcurrentEditsSeeEachOther(t *testing.T) {
	server := newFeedbagServer()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server.status = func(req wire.SNACMessage) []wire.SNACMessage {
		once.Do(func() {
			close(started)
			<-release
		})
		return acceptChange(req)
	}
	session, conn := newFeedbagSession(t, server)
	h := newBuddyListHandler(t)

	var wg sync.WaitGroup
	add := func(buddy string) {
		defer wg.Done()
		rr := serveBuddyList(h.AddBuddy, url.Values{"buddy": {buddy}, "group": {"Work"}}, session)
		assert.JSONEq(t, okResponse, rr.Body.String())
	}
	wg.Add(2)
	go add("alice")
	<-started
	go add("bob")

	// bob's edit waits for alice's change to be answered.
	time.Sleep(20 * time.Millisecond)
	assert.Len(t, sentFeedbagChanges(conn), 1)

	close(release)
	wg.Wait()

	stored := server.stored()
	assert.Equal(t, []string{"Work"}, groupNames(stored))
	assert.True(t, listsBuddy(stored, "Work", "alice"))
	assert.True(t, listsBuddy(stored, "Work", "bob"))
	assert.Equal(t, stored, session.Feedbag())
}

func TestBuddyListHandler_AddBuddy_PreAuthorized(t *testing.T) {
	tests := []struct {
		name          string
		screenName    string
		buddy         string
		preAuthorized string
		authMsg       string
		grantFails    bool
		wantGrant     bool
		// wantPending follows the account pairing alone: the two icq->icq cases
		// differ only in preAuthorized yet expect the same value.
		wantPending bool
	}{
		{
			name:          "no grant without preAuthorized",
			screenName:    "100002",
			buddy:         "100001",
			preAuthorized: "",
			wantGrant:     false,
			wantPending:   true,
		},
		{
			name:          "icq->icq grant carries the authorization message",
			screenName:    "100002",
			buddy:         "100001",
			preAuthorized: "1",
			authMsg:       "Hello! Please add me to your buddylist.",
			wantGrant:     true,
			wantPending:   true,
		},
		{
			// The grant is not gated on protocol: the store no-ops for a user who
			// cannot hold one, so an aim->aim add is granted the same way.
			name:          "aim->aim is granted too",
			screenName:    "mike",
			buddy:         "joemama",
			preAuthorized: "1",
			wantGrant:     true,
			wantPending:   false,
		},
		{
			// The buddy is on the list either way. Reporting an error here would
			// only make the client retry an add that already succeeded.
			name:          "a failed grant does not fail the add",
			screenName:    "100002",
			buddy:         "100001",
			preAuthorized: "1",
			grantFails:    true,
			wantGrant:     true,
			wantPending:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFeedbagServer(wire.FeedbagItem{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"})
			conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
				if _, ok := req.Body.(wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy); ok && tt.grantFails {
					return []wire.SNACMessage{snacErr(wire.Feedbag, wire.ErrorCodeNotSupportedByHost)}
				}
				return server.respond(req)
			})
			session := newTestSessionAs(t, state.DisplayScreenName(tt.screenName), conn)
			loadTestFeedbag(t, session)

			params := url.Values{"buddy": {tt.buddy}, "group": {"Friends"}}
			if tt.preAuthorized != "" {
				params.Set("preAuthorized", tt.preAuthorized)
			}
			if tt.authMsg != "" {
				params.Set("authorizationMsg", tt.authMsg)
			}
			rr := serveBuddyList(newBuddyListHandler(t).AddBuddy, params, session)

			assert.Equal(t, http.StatusOK, rr.Code)
			// The handler claims no outcome either way; whether the item was
			// stored is conveyed by the async buddylist event, not this reply.
			assert.JSONEq(t, okResponse, rr.Body.String())
			buddy, ok := addedBuddy(conn)
			require.True(t, ok, "expected a buddy item to be inserted")
			assert.Equal(t, tt.wantPending, buddy.HasTag(wire.FeedbagAttributesPending),
				"the pending flag must follow the account pairing, not preAuthorized")

			grants := conn.sentOf(wire.Feedbag, wire.FeedbagPreAuthorizeBuddy)
			if !tt.wantGrant {
				assert.Empty(t, grants)
				return
			}
			// The grant flows from the caller to the buddy they added: the buddy
			// may now add the caller back without a prompt.
			assert.Equal(t, []any{wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{
				ScreenName: tt.buddy,
				Message:    tt.authMsg,
			}}, grants)
		})
	}
}

// addedBuddy returns the buddy item inserted on conn.
func addedBuddy(conn *fakeConn) (wire.FeedbagItem, bool) {
	for _, change := range sentFeedbagChanges(conn) {
		if change.SubGroup != wire.FeedbagInsertItem {
			continue
		}
		for _, item := range change.Items {
			if item.ClassID == wire.FeedbagClassIdBuddy {
				return item, true
			}
		}
	}
	return wire.FeedbagItem{}, false
}

// icq->icq adds are marked pending up front so the item is stored either way:
// the decline a web client never sees would otherwise leave it holding a buddy
// no roster lists. The other pairings already store the item, where a stray flag
// would publish them as awaiting an authorization nobody requested.
func TestBuddyListHandler_AddBuddy_PendingFlagFollowsPairing(t *testing.T) {
	tests := []struct {
		name        string
		screenName  string
		buddy       string
		wantPending bool
	}{
		{
			name:        "icq->icq is marked pending",
			screenName:  "100002",
			buddy:       "100001",
			wantPending: true,
		},
		{
			name:       "icq->aim is not",
			screenName: "100002",
			buddy:      "mike",
		},
		{
			name:       "aim->icq is not; the feedbag service marks it itself",
			screenName: "mike",
			buddy:      "100001",
		},
		{
			name:       "aim->aim is not",
			screenName: "mike",
			buddy:      "joemama",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFeedbagServer(wire.FeedbagItem{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"})
			session, conn := newFeedbagSessionAs(t, state.DisplayScreenName(tt.screenName), server)

			rr := serveBuddyList(newBuddyListHandler(t).AddBuddy,
				url.Values{"buddy": {tt.buddy}, "group": {"Friends"}}, session)

			assert.Equal(t, http.StatusOK, rr.Code)
			buddy, ok := addedBuddy(conn)
			require.True(t, ok, "expected a buddy item to be inserted")
			assert.Equal(t, tt.wantPending, buddy.HasTag(wire.FeedbagAttributesPending))
		})
	}
}
