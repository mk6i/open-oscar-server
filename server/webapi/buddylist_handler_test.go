package webapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestBuddyListHandler_AddBuddy(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        map[string][]string
		setupMocks         func(*mockSessionResolver, *mockFeedbagService, *mockFeedbagService, string) *Session
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
			setupMocks: func(sm *mockSessionResolver, fs *mockFeedbagService, blmFs *mockFeedbagService, aimsid string) *Session {
				session := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   NewEventQueue(100),
					LastAccessed: time.Now(),
				}

				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				// addBuddyToFeedbag calls UpsertItem twice: once for group order update, once for buddy insert
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil)
				return session
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name: "Error_BuddyAlreadyExists",
			queryParams: map[string][]string{
				"aimsid": {"test-session"},
				"buddy":  {"existingbuddy"},
				"group":  {"Friends"},
			},
			setupMocks: func(sm *mockSessionResolver, fs *mockFeedbagService, blmFs *mockFeedbagService, aimsid string) *Session {
				session := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   NewEventQueue(100),
					LastAccessed: time.Now(),
				}

				// Friends group with existingbuddy already present
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
					{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "existingbuddy"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
				return session
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"alreadyExists"}}}`,
		},
		{
			name: "Error_MissingBuddyParameter",
			queryParams: map[string][]string{
				"aimsid": {"test-session"},
				"group":  {"Friends"},
			},
			setupMocks: func(sm *mockSessionResolver, fs *mockFeedbagService, blmFs *mockFeedbagService, aimsid string) *Session {
				return &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					EventQueue:   NewEventQueue(100),
					LastAccessed: time.Now(),
				}
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter","data":{}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionManager := newMockSessionResolver(t)
			feedbagService := newMockFeedbagService(t)
			blmFeedbagService := newMockFeedbagService(t)
			blm := NewBuddyListManager(blmFeedbagService, newMockLocateService(t), newTestIconSource(t), slog.Default())
			logger := slog.Default()

			handler := &BuddyListHandler{
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
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())
		})
	}
}

func TestBuddyListHandler_AddGroup(t *testing.T) {
	type setupFunc func(*mockSessionResolver, *mockFeedbagService, *mockFeedbagService, string) *Session

	newSession := func(aimsid string) *Session {
		return &Session{
			AimSID:       aimsid,
			ScreenName:   state.DisplayScreenName("testuser"),
			OSCARSession: state.NewSession().AddInstance(),
			EventQueue:   NewEventQueue(100),
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
			setup: func(sm *mockSessionResolver, fs *mockFeedbagService, blmFs *mockFeedbagService, aimsid string) *Session {
				return newSession(aimsid)
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing group parameter","data":{}}}`,
		},
		{
			name:        "Success_GroupAdded",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NewGroup"}},
			setup: func(sm *mockSessionResolver, fs *mockFeedbagService, blmFs *mockFeedbagService, aimsid string) *Session {
				sess := newSession(aimsid)
				// Empty feedbag — AddGroup will create root + NewGroup in pending
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:        "Success_GroupAlreadyExists",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}},
			setup: func(sm *mockSessionResolver, fs *mockFeedbagService, blmFs *mockFeedbagService, aimsid string) *Session {
				sess := newSession(aimsid)
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"alreadyExists"}}}`,
		},
		{
			name:        "Error_FeedbagQueryFails",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NewGroup"}},
			setup: func(sm *mockSessionResolver, fs *mockFeedbagService, blmFs *mockFeedbagService, aimsid string) *Session {
				sess := newSession(aimsid)
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{}, errors.New("feedbag error"))
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"error"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := newMockSessionResolver(t)
			fs := newMockFeedbagService(t)
			blmFs := newMockFeedbagService(t)
			blm := NewBuddyListManager(blmFs, newMockLocateService(t), newTestIconSource(t), slog.Default())

			aimsid := ""
			if v := tt.queryParams["aimsid"]; len(v) > 0 {
				aimsid = v[0]
			}
			session := tt.setup(sm, fs, blmFs, aimsid)

			handler := &BuddyListHandler{
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
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())
		})
	}
}

func TestBuddyListHandler_RemoveBuddy(t *testing.T) {
	type setupFunc func(*mockSessionResolver, *BuddyListManager, *mockFeedbagService, string) *Session

	newBuddyListManager := func(t *testing.T, fs *mockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
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
			setup: func(sm *mockSessionResolver, blm *BuddyListManager, fs *mockFeedbagService, aimsid string) *Session {
				return &Session{AimSID: aimsid, ScreenName: state.DisplayScreenName("testuser"), LastAccessed: time.Now()}
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter","data":{}}}`,
		},
		{
			name:        "Success_BuddyRemoved",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"someBuddy"}, "group": {"Friends"}},
			setup: func(sm *mockSessionResolver, blm *BuddyListManager, fs *mockFeedbagService, aimsid string) *Session {
				sess := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   NewEventQueue(100),
					LastAccessed: time.Now(),
				}
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
					{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "someBuddy"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.EXPECT().DeleteItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:        "Success_BuddyNotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"ghost"}, "group": {"Friends"}},
			setup: func(sm *mockSessionResolver, blm *BuddyListManager, fs *mockFeedbagService, aimsid string) *Session {
				sess := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					LastAccessed: time.Now(),
				}
				// Group exists but "ghost" is not in it
				items := []wire.FeedbagItem{
					{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`,
		},
		{
			name:        "Success_GroupNotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"someBuddy"}, "group": {"NoSuchGroup"}},
			setup: func(sm *mockSessionResolver, blm *BuddyListManager, fs *mockFeedbagService, aimsid string) *Session {
				sess := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					LastAccessed: time.Now(),
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := newMockSessionResolver(t)
			fs := newMockFeedbagService(t)
			blm := newBuddyListManager(t, fs)

			aimsid := ""
			if v := tt.queryParams["aimsid"]; len(v) > 0 {
				aimsid = v[0]
			}
			session := tt.setup(sm, blm, fs, aimsid)

			handler := &BuddyListHandler{
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
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())
		})
	}
}

func TestBuddyListHandler_RemoveGroup(t *testing.T) {
	type setupFunc func(*mockSessionResolver, *BuddyListManager, *mockFeedbagService, string) *Session

	newBuddyListManager := func(t *testing.T, fs *mockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
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
			setup: func(sm *mockSessionResolver, blm *BuddyListManager, fs *mockFeedbagService, aimsid string) *Session {
				return &Session{AimSID: aimsid, ScreenName: state.DisplayScreenName("testuser"), LastAccessed: time.Now()}
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing group parameter","data":{}}}`,
		},
		{
			name:        "Success_GroupRemoved",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}},
			setup: func(sm *mockSessionResolver, blm *BuddyListManager, fs *mockFeedbagService, aimsid string) *Session {
				sess := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					EventQueue:   NewEventQueue(100),
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
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.EXPECT().DeleteItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:        "Success_GroupNotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NoSuchGroup"}},
			setup: func(sm *mockSessionResolver, blm *BuddyListManager, fs *mockFeedbagService, aimsid string) *Session {
				sess := &Session{
					AimSID:       aimsid,
					ScreenName:   state.DisplayScreenName("testuser"),
					OSCARSession: state.NewSession().AddInstance(),
					LastAccessed: time.Now(),
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil)
				return sess
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := newMockSessionResolver(t)
			fs := newMockFeedbagService(t)
			blm := newBuddyListManager(t, fs)

			aimsid := ""
			if v := tt.queryParams["aimsid"]; len(v) > 0 {
				aimsid = v[0]
			}
			session := tt.setup(sm, blm, fs, aimsid)

			handler := &BuddyListHandler{
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
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())
		})
	}
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
					OSCARSession: state.NewSession().AddInstance(),
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

			authMiddleware := NewAuthMiddleware(nil, slog.Default())
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
	newBLM := func(t *testing.T, fs *mockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	}
	sessWithOSCAR := func(aimsid string) *Session {
		return &Session{
			AimSID:       aimsid,
			ScreenName:   state.DisplayScreenName("testuser"),
			OSCARSession: state.NewSession().AddInstance(),
			EventQueue:   NewEventQueue(100),
			LastAccessed: time.Now(),
		}
	}

	tests := []struct {
		name             string
		queryParams      map[string][]string
		setup            func(*mockFeedbagService, string) *Session
		expectStatusCode int
		expectResponse   string
	}{
		{
			name:        "Error_MissingParam",
			queryParams: map[string][]string{"aimsid": {"sess"}, "oldGroup": {"Friends"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				return &Session{AimSID: aimsid, LastAccessed: time.Now()}
			},
			expectStatusCode: http.StatusBadRequest,
			expectResponse:   `{"response":{"statusCode":400,"statusText":"missing oldGroup or newGroup parameter","data":{}}}`,
		},
		{
			name:        "Success",
			queryParams: map[string][]string{"aimsid": {"sess"}, "oldGroup": {"Friends"}, "newGroup": {"Pals"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				items := []wire.FeedbagItem{
					{GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
					{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:        "NotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "oldGroup": {"Ghost"}, "newGroup": {"Pals"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newMockFeedbagService(t)
			session := tt.setup(fs, "sess")
			handler := &BuddyListHandler{BuddyListManager: newBLM(t, fs), Logger: slog.Default()}

			values := url.Values{}
			for k, vs := range tt.queryParams {
				for _, v := range vs {
					values.Add(k, v)
				}
			}
			req, _ := http.NewRequest("GET", "/buddylist/renameGroup?"+values.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.RenameGroup(rr, req, session)

			assert.Equal(t, tt.expectStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectResponse, rr.Body.String())
		})
	}
}

func TestBuddyListHandler_MoveBuddy(t *testing.T) {
	newBLM := func(t *testing.T, fs *mockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	}
	sessWithOSCAR := func(aimsid string) *Session {
		return &Session{
			AimSID:       aimsid,
			ScreenName:   state.DisplayScreenName("testuser"),
			OSCARSession: state.NewSession().AddInstance(),
			EventQueue:   NewEventQueue(100),
			LastAccessed: time.Now(),
		}
	}

	tests := []struct {
		name             string
		queryParams      map[string][]string
		setup            func(*mockFeedbagService, string) *Session
		expectStatusCode int
		expectResponse   string
	}{
		{
			name:        "Error_MissingBuddy",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				return &Session{AimSID: aimsid, LastAccessed: time.Now()}
			},
			expectStatusCode: http.StatusBadRequest,
			expectResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy parameter","data":{}}}`,
		},
		{
			name:        "Success_Reorder",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"bob"}, "group": {"Friends"}, "beforeBuddy": {"alice"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				items := []wire.FeedbagItem{
					{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends",
						TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
							wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10, 20}),
						}}},
					{GroupID: 1, ItemID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "alice"},
					{GroupID: 1, ItemID: 20, ClassID: wire.FeedbagClassIdBuddy, Name: "bob"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:        "NotFound_Buddy",
			queryParams: map[string][]string{"aimsid": {"sess"}, "buddy": {"ghost"}, "group": {"Friends"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				items := []wire.FeedbagItem{
					{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newMockFeedbagService(t)
			session := tt.setup(fs, "sess")
			handler := &BuddyListHandler{BuddyListManager: newBLM(t, fs), Logger: slog.Default()}

			values := url.Values{}
			for k, vs := range tt.queryParams {
				for _, v := range vs {
					values.Add(k, v)
				}
			}
			req, _ := http.NewRequest("GET", "/buddylist/moveBuddy?"+values.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.MoveBuddy(rr, req, session)

			assert.Equal(t, tt.expectStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectResponse, rr.Body.String())
		})
	}
}

func TestBuddyListHandler_SetBuddyAttribute(t *testing.T) {
	newBLM := func(t *testing.T, fs *mockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	}
	sessWithOSCAR := func(aimsid string) *Session {
		return &Session{
			AimSID:       aimsid,
			ScreenName:   state.DisplayScreenName("testuser"),
			OSCARSession: state.NewSession().AddInstance(),
			EventQueue:   NewEventQueue(100),
			LastAccessed: time.Now(),
		}
	}

	tests := []struct {
		name             string
		queryParams      map[string][]string
		setup            func(*mockFeedbagService, string) *Session
		expectStatusCode int
		expectResponse   string
	}{
		{
			name:        "Error_MissingT",
			queryParams: map[string][]string{"aimsid": {"sess"}, "friendly": {"Al"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				return &Session{AimSID: aimsid, LastAccessed: time.Now()}
			},
			expectStatusCode: http.StatusBadRequest,
			expectResponse:   `{"response":{"statusCode":400,"statusText":"missing t parameter","data":{}}}`,
		},
		{
			name:        "Success",
			queryParams: map[string][]string{"aimsid": {"sess"}, "t": {"alice"}, "friendly": {"Al"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				items := []wire.FeedbagItem{
					{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
					{GroupID: 1, ItemID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "alice"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:        "NotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "t": {"ghost"}, "friendly": {"Al"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newMockFeedbagService(t)
			session := tt.setup(fs, "sess")
			handler := &BuddyListHandler{BuddyListManager: newBLM(t, fs), Logger: slog.Default()}

			values := url.Values{}
			for k, vs := range tt.queryParams {
				for _, v := range vs {
					values.Add(k, v)
				}
			}
			req, _ := http.NewRequest("GET", "/buddylist/setBuddyAttribute?"+values.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.SetBuddyAttribute(rr, req, session)

			assert.Equal(t, tt.expectStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectResponse, rr.Body.String())
		})
	}
}

func TestBuddyListHandler_SetGroupAttribute(t *testing.T) {
	newBLM := func(t *testing.T, fs *mockFeedbagService) *BuddyListManager {
		return NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	}
	sessWithOSCAR := func(aimsid string) *Session {
		return &Session{
			AimSID:       aimsid,
			ScreenName:   state.DisplayScreenName("testuser"),
			OSCARSession: state.NewSession().AddInstance(),
			EventQueue:   NewEventQueue(100),
			LastAccessed: time.Now(),
		}
	}

	tests := []struct {
		name             string
		queryParams      map[string][]string
		setup            func(*mockFeedbagService, string) *Session
		expectStatusCode int
		expectResponse   string
	}{
		{
			name:        "Error_MissingCollapsed",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				return &Session{AimSID: aimsid, LastAccessed: time.Now()}
			},
			expectStatusCode: http.StatusBadRequest,
			expectResponse:   `{"response":{"statusCode":400,"statusText":"missing collapsed parameter","data":{}}}`,
		},
		{
			name:        "Success",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"Friends"}, "collapsed": {"true"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				items := []wire.FeedbagItem{
					{GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
					{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
				}
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()
				fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return((*wire.SNACMessage)(nil), nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:        "NotFound",
			queryParams: map[string][]string{"aimsid": {"sess"}, "group": {"NoSuch"}, "collapsed": {"true"}},
			setup: func(fs *mockFeedbagService, aimsid string) *Session {
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: nil}}, nil).Once()
				return sessWithOSCAR(aimsid)
			},
			expectStatusCode: http.StatusOK,
			expectResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"resultCode":"notFound"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newMockFeedbagService(t)
			session := tt.setup(fs, "sess")
			handler := &BuddyListHandler{BuddyListManager: newBLM(t, fs), Logger: slog.Default()}

			values := url.Values{}
			for k, vs := range tt.queryParams {
				for _, v := range vs {
					values.Add(k, v)
				}
			}
			req, _ := http.NewRequest("GET", "/buddylist/setGroupAttribute?"+values.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.SetGroupAttribute(rr, req, session)

			assert.Equal(t, tt.expectStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectResponse, rr.Body.String())
		})
	}
}

func TestBuddyListHandler_AddBuddy_PreAuthorized(t *testing.T) {
	tests := []struct {
		name          string
		screenName    string
		buddy         string
		preAuthorized string
		authMsg       string
		grantErr      error
		wantGrant     bool
	}{
		{
			name:          "no grant without preAuthorized",
			screenName:    "100002",
			buddy:         "100001",
			preAuthorized: "",
			wantGrant:     false,
		},
		{
			name:          "icq->icq grant carries the authorization message",
			screenName:    "100002",
			buddy:         "100001",
			preAuthorized: "1",
			authMsg:       "Hello! Please add me to your buddylist.",
			wantGrant:     true,
		},
		{
			// The grant is not gated on protocol: the store no-ops for a user who
			// cannot hold one, so an aim->aim add is granted the same way.
			name:          "aim->aim is granted too",
			screenName:    "mike",
			buddy:         "joemama",
			preAuthorized: "1",
			wantGrant:     true,
		},
		{
			// The buddy is on the list either way. Reporting an error here would
			// only make the client retry an add that already succeeded.
			name:          "a failed grant does not fail the add",
			screenName:    "100002",
			buddy:         "100001",
			preAuthorized: "1",
			grantErr:      errors.New("record failed"),
			wantGrant:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := newMockSessionResolver(t)
			fs := newMockFeedbagService(t)
			blmFs := newMockFeedbagService(t)

			// The grant is recorded against the caller, so the instance has to
			// carry their identity.
			oscarSess := state.NewSession()
			oscarSess.SetIdentScreenName(state.NewIdentScreenName(tt.screenName))

			session := &Session{
				AimSID:       "sid",
				OSCARSession: oscarSess.AddInstance(),
				ScreenName:   state.DisplayScreenName(tt.screenName),
				EventQueue:   NewEventQueue(100),
				LastAccessed: time.Now(),
			}
			sm.EXPECT().GetSession(mock.Anything, "sid").Return(session, nil)
			sm.EXPECT().TouchSession(mock.Anything, "sid").Return(nil).Maybe()

			items := []wire.FeedbagItem{
				{GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
			}
			fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
				Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil).Once()

			// The pending flag is what this used to set. Capture it to confirm it
			// is gone, whatever preAuthorized says.
			var sawPending, sawBuddyItem bool
			fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				RunAndReturn(func(_ context.Context, _ *state.SessionInstance, _ wire.SNACFrame, upserted []wire.FeedbagItem) (*wire.SNACMessage, error) {
					for _, item := range upserted {
						if item.ClassID != wire.FeedbagClassIdBuddy {
							continue
						}
						sawBuddyItem = true
						if item.HasTag(wire.FeedbagAttributesPending) {
							sawPending = true
						}
						break
					}
					return nil, nil
				})

			// No expectation in the ungranted case: an unexpected call fails the
			// test, which is the assertion.
			var grants int
			var gotGrantor state.IdentScreenName
			var gotFrame wire.SNACFrame
			var gotBody wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy
			if tt.wantGrant {
				fs.EXPECT().PreAuthorizeBuddy(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					RunAndReturn(func(_ context.Context, instance *state.SessionInstance, frame wire.SNACFrame, body wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy) (*wire.SNACMessage, error) {
						grants++
						gotGrantor = instance.IdentScreenName()
						gotFrame = frame
						gotBody = body
						return nil, tt.grantErr
					}).Once()
			}

			h := &BuddyListHandler{
				FeedbagService: fs,
				BuddyListManager: &BuddyListManager{
					feedbagService: blmFs,
					iconSource:     newTestIconSource(t),
					logger:         slog.Default(),
				},
				Logger: slog.Default(),
			}

			query := "aimsid=sid&buddy=" + tt.buddy + "&group=Friends"
			if tt.preAuthorized != "" {
				query += "&preAuthorized=" + tt.preAuthorized
			}
			if tt.authMsg != "" {
				query += "&authorizationMsg=" + url.QueryEscape(tt.authMsg)
			}
			req := httptest.NewRequest(http.MethodGet, "/buddylist/addBuddy?"+query, nil)
			rr := httptest.NewRecorder()
			requireSession(sm, h.AddBuddy).ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			// The handler claims no outcome either way; whether the item was
			// stored is conveyed by the async buddylist event, not this reply.
			assert.JSONEq(t, `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`, rr.Body.String())
			assert.True(t, sawBuddyItem, "expected a buddy item to be upserted")
			assert.False(t, sawPending, "preAuthorized must not mark the stored item pending")

			if !tt.wantGrant {
				return
			}
			assert.Equal(t, 1, grants, "expected exactly one pre-authorization")
			assert.Equal(t, wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagPreAuthorizeBuddy}, gotFrame)
			// The grant flows from the caller to the buddy they added: the buddy
			// may now add the caller back without a prompt.
			assert.Equal(t, state.NewIdentScreenName(tt.screenName), gotGrantor)
			assert.Equal(t, tt.buddy, gotBody.ScreenName)
			assert.Equal(t, tt.authMsg, gotBody.Message)
		})
	}
}
