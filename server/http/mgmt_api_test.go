package http

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/retro-aim-server/config"
	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

func TestSessionHandler_GET(t *testing.T) {
	fnNewSess := func(screenName string, uin uint32) *state.Session {
		sess := state.NewSession()
		sess.SetIdentScreenName(state.NewIdentScreenName(screenName))
		sess.SetDisplayScreenName(state.DisplayScreenName(screenName))
		sess.SetUIN(uin)
		ip, _ := netip.ParseAddrPort("1.2.3.4:1234")
		sess.SetRemoteAddr(&ip)
		return sess
	}
	tt := []struct {
		name          string
		want          string
		statusCode    int
		timeSinceFunc func(t time.Time) time.Duration
		mockParams    mockParams
	}{
		{
			name:       "without sessions",
			want:       `{"count":0,"sessions":[]}`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					sessionRetrieverAllSessionsParams: sessionRetrieverAllSessionsParams{
						{
							result: []*state.Session{},
						},
					},
				},
			},
		},
		{
			name:          "with sessions",
			want:          `{"count":3,"sessions":[{"id":"usera","screen_name":"userA","online_seconds":0,"away_message":"","idle_seconds":0,"is_icq":false,"remote_addr":"1.2.3.4","remote_port":1234},{"id":"userb","screen_name":"userB","online_seconds":0,"away_message":"","idle_seconds":0,"is_icq":false,"remote_addr":"1.2.3.4","remote_port":1234},{"id":"100003","screen_name":"100003","online_seconds":0,"away_message":"","idle_seconds":0,"is_icq":true,"remote_addr":"1.2.3.4","remote_port":1234}]}`,
			statusCode:    http.StatusOK,
			timeSinceFunc: func(t time.Time) time.Duration { t0 := time.Now(); return t0.Sub(t0) },
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					sessionRetrieverAllSessionsParams: sessionRetrieverAllSessionsParams{
						{
							result: []*state.Session{
								fnNewSess("userA", 0),
								fnNewSess("userB", 0),
								fnNewSess("100003", 100003),
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/session", nil)
			responseRecorder := httptest.NewRecorder()

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tc.mockParams.sessionRetrieverParams.sessionRetrieverAllSessionsParams {
				sessionRetriever.EXPECT().
					AllSessions().
					Return(params.result)
			}

			getSessionHandler(responseRecorder, request, sessionRetriever, tc.timeSinceFunc)

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestSessionHandlerScreenname_GET(t *testing.T) {
	fnNewSess := func(screenName string, uin uint32) *state.Session {
		sess := state.NewSession()
		sess.SetIdentScreenName(state.NewIdentScreenName(screenName))
		sess.SetDisplayScreenName(state.DisplayScreenName(screenName))
		sess.SetUIN(uin)
		ip, _ := netip.ParseAddrPort("1.2.3.4:1234")
		sess.SetRemoteAddr(&ip)
		return sess
	}
	tt := []struct {
		name              string
		sessions          []*state.Session
		requestScreenName state.IdentScreenName
		want              string
		statusCode        int
		timeSinceFunc     func(t time.Time) time.Duration
		mockParams        mockParams
	}{
		{
			name:              "no session for screenname",
			sessions:          []*state.Session{},
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `session not found`,
			statusCode:        http.StatusNotFound,
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
						},
					},
				},
			},
		},
		{
			name:              "active session found for screenname",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `{"count":1,"sessions":[{"id":"usera","screen_name":"userA","online_seconds":0,"away_message":"","idle_seconds":0,"is_icq":false,"remote_addr":"1.2.3.4","remote_port":1234}]}`,
			statusCode:        http.StatusOK,
			timeSinceFunc:     func(t time.Time) time.Duration { t0 := time.Now(); return t0.Sub(t0) },
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     fnNewSess("userA", 0),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/session/"+tc.requestScreenName.String(), nil)
			request.SetPathValue("screenname", tc.requestScreenName.String())
			responseRecorder := httptest.NewRecorder()

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tc.mockParams.sessionRetrieverParams.retrieveSessionByNameParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}

			getSessionHandler(responseRecorder, request, sessionRetriever, tc.timeSinceFunc)

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestSessionHandlerScreenname_DELETE(t *testing.T) {
	fnNewSess := func(screenName string) *state.Session {
		sess := state.NewSession()
		sess.SetIdentScreenName(state.NewIdentScreenName(screenName))
		sess.SetDisplayScreenName(state.DisplayScreenName(screenName))
		ip, _ := netip.ParseAddrPort("1.2.3.4:1234")
		sess.SetRemoteAddr(&ip)
		return sess
	}
	tt := []struct {
		name              string
		session           *state.Session
		requestScreenName state.IdentScreenName
		statusCode        int
		mockParams        mockParams
	}{
		{
			name:              "delete an active session",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNoContent,
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     fnNewSess("userA"),
						},
					},
				},
			},
		},
		{
			name:              "delete a non-existent session",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNotFound,
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
						},
					},
				},
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "/session/"+tc.requestScreenName.String(), nil)
			request.SetPathValue("screenname", tc.requestScreenName.String())
			responseRecorder := httptest.NewRecorder()

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tc.mockParams.sessionRetrieverParams.retrieveSessionByNameParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}

			deleteSessionHandler(responseRecorder, request, sessionRetriever)

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}
		})
	}
}

func TestUserAccountHandler_GET(t *testing.T) {
	tt := []struct {
		name              string
		requestScreenName state.IdentScreenName
		want              string
		statusCode        int
		mockParams        mockParams
	}{
		{
			name:              "invalid account",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `user not found`,
			statusCode:        http.StatusNotFound,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
						},
					},
				},
			},
		},
		{
			name:              "valid aim account",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `{"id":"usera","screen_name":"userA","profile":"My Profile Text","email_address":"\u003cuserA@aol.com\u003e","reg_status":2,"confirmed":true,"is_icq":false,"suspended_status":"","is_bot":false}`,
			statusCode:        http.StatusOK,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   0x0,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					EmailAddressParams: EmailAddressParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &mail.Address{
								Address: "userA@aol.com",
							},
						},
					},
					RegStatusParams: RegStatusParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     uint16(0x02),
						},
					},
					ConfirmStatusParams: ConfirmStatusParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     true,
						},
					},
				},
				profileRetrieverParams: profileRetrieverParams{
					retrieveProfileParams: retrieveProfileParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     "My Profile Text",
						},
					},
				},
			},
		},
		{
			name:              "valid aim bot account",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `{"id":"usera","screen_name":"userA","profile":"My Profile Text","email_address":"\u003cuserA@aol.com\u003e","reg_status":2,"confirmed":true,"is_icq":false,"suspended_status":"","is_bot":true}`,
			statusCode:        http.StatusOK,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   0x0,
								IsBot:             true,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					EmailAddressParams: EmailAddressParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &mail.Address{
								Address: "userA@aol.com",
							},
						},
					},
					RegStatusParams: RegStatusParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     uint16(0x02),
						},
					},
					ConfirmStatusParams: ConfirmStatusParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     true,
						},
					},
				},
				profileRetrieverParams: profileRetrieverParams{
					retrieveProfileParams: retrieveProfileParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     "My Profile Text",
						},
					},
				},
			},
		},
		{
			name:              "suspended aim account",
			requestScreenName: state.NewIdentScreenName("userB"),
			want:              `{"id":"userb","screen_name":"userB","profile":"My Profile Text","email_address":"\u003cuserB@aol.com\u003e","reg_status":2,"confirmed":true,"is_icq":false,"suspended_status":"suspended","is_bot":false}`,
			statusCode:        http.StatusOK,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userB"),
							result: &state.User{
								DisplayScreenName: "userB",
								IdentScreenName:   state.NewIdentScreenName("userB"),
								SuspendedStatus:   wire.LoginErrSuspendedAccount,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					EmailAddressParams: EmailAddressParams{
						{
							screenName: state.NewIdentScreenName("userB"),
							result: &mail.Address{
								Address: "userB@aol.com",
							},
						},
					},
					RegStatusParams: RegStatusParams{
						{
							screenName: state.NewIdentScreenName("userB"),
							result:     uint16(0x02),
						},
					},
					ConfirmStatusParams: ConfirmStatusParams{
						{
							screenName: state.NewIdentScreenName("userB"),
							result:     true,
						},
					},
				},
				profileRetrieverParams: profileRetrieverParams{
					retrieveProfileParams: retrieveProfileParams{
						{
							screenName: state.NewIdentScreenName("userB"),
							result:     "My Profile Text",
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/user/"+tc.requestScreenName.String()+"/account", nil)
			request.SetPathValue("screenname", tc.requestScreenName.String())
			responseRecorder := httptest.NewRecorder()

			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			accountManager := newMockAccountManager(t)
			for _, params := range tc.mockParams.accountManagerParams.EmailAddressParams {
				accountManager.EXPECT().
					EmailAddress(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			for _, params := range tc.mockParams.accountManagerParams.RegStatusParams {
				accountManager.EXPECT().
					RegStatus(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			for _, params := range tc.mockParams.accountManagerParams.ConfirmStatusParams {
				accountManager.EXPECT().
					ConfirmStatus(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			profileRetriever := newMockProfileRetriever(t)
			for _, params := range tc.mockParams.profileRetrieverParams.retrieveProfileParams {
				profileRetriever.EXPECT().
					Profile(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			getUserAccountHandler(responseRecorder, request, userManager, accountManager, profileRetriever, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestUserAccountHandler_PATCH(t *testing.T) {
	tt := []struct {
		name              string
		requestScreenName state.IdentScreenName
		want              string
		body              string
		statusCode        int
		mockParams        mockParams
	}{
		{
			name:              "suspending a non-existent account",
			requestScreenName: state.NewIdentScreenName("userA"),
			body:              `{"suspended_status":"suspended"}`,
			want:              `user not found`,
			statusCode:        http.StatusNotFound,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
						},
					},
				},
			},
		},
		{
			name:              "patching with invalid suspended_status value",
			requestScreenName: state.NewIdentScreenName("userA"),
			body:              `{"suspended_status":"thisisinvalid"}`,
			want:              `{"message":"suspended_status must be empty str or one of deleted,expired,suspended,suspended_age"}`,
			statusCode:        http.StatusBadRequest,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     &state.User{},
						},
					},
				},
			},
		},
		{
			name:              "suspending an active aim account",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNoContent,
			body:              `{"suspended_status":"suspended"}`,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   0x0,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					updateSuspendedStatusParams: updateSuspendedStatusParams{
						{
							suspendedStatus: wire.LoginErrSuspendedAccount,
							screenName:      state.NewIdentScreenName("userA"),
							err:             nil,
						},
					},
				},
			},
		},
		{
			name:              "unsuspending a suspended aim account",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNoContent,
			body:              `{"suspended_status":""}`,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   wire.LoginErrSuspendedAccount,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					updateSuspendedStatusParams: updateSuspendedStatusParams{
						{
							suspendedStatus: 0x0,
							screenName:      state.NewIdentScreenName("userA"),
							err:             nil,
						},
					},
				},
			},
		},
		{
			name:              "suspending an already suspended aim account",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNotModified,
			body:              `{"suspended_status":"suspended"}`,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   wire.LoginErrSuspendedAccount,
							},
						},
					},
				},
			},
		},
		{
			name:              "setting bot flag (before: false, after: true)",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNoContent,
			body:              `{"is_bot":true}`,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   0x0,
								IsBot:             false,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					setBotStatusParams: setBotStatusParams{
						{
							isBot:      true,
							screenName: state.NewIdentScreenName("userA"),
							err:        nil,
						},
					},
				},
			},
		},
		{
			name:              "setting bot flag (before: true, after: false)",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNoContent,
			body:              `{"is_bot":false}`,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   0x0,
								IsBot:             true,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					setBotStatusParams: setBotStatusParams{
						{
							isBot:      false,
							screenName: state.NewIdentScreenName("userA"),
							err:        nil,
						},
					},
				},
			},
		},
		{
			name:              "setting bot flag (before: true, after: true)",
			requestScreenName: state.NewIdentScreenName("userA"),
			statusCode:        http.StatusNotModified,
			body:              `{"is_bot":true}`,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
								SuspendedStatus:   0x0,
								IsBot:             true,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPatch, "/user/"+tc.requestScreenName.String()+"/account", strings.NewReader(tc.body))
			request.SetPathValue("screenname", tc.requestScreenName.String())
			responseRecorder := httptest.NewRecorder()

			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			accountManager := newMockAccountManager(t)
			for _, params := range tc.mockParams.accountManagerParams.updateSuspendedStatusParams {
				accountManager.EXPECT().
					UpdateSuspendedStatus(matchContext(), params.suspendedStatus, params.screenName).
					Return(params.err)
			}
			for _, params := range tc.mockParams.accountManagerParams.setBotStatusParams {
				accountManager.EXPECT().
					SetBotStatus(matchContext(), params.isBot, params.screenName).
					Return(params.err)
			}

			patchUserAccountHandler(responseRecorder, request, userManager, accountManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestUserBuddyIconHandler_GET(t *testing.T) {
	sampleGIF := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x32, 0x00, 0x32, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
		0x32, 0x00, 0x32, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b}

	sampleJPG := []byte{0xFF, 0xD8, 0xFF, 0x43, 0x13, 0x37}
	tt := []struct {
		name              string
		requestScreenName state.IdentScreenName
		want              string
		statusCode        int
		contentType       string
		mockParams        mockParams
	}{
		{
			name:              "invalid account",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `user not found`,
			statusCode:        http.StatusNotFound,
			contentType:       "text/plain; charset=utf-8",
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
						},
					},
				},
			},
		},
		{
			name:              "account with gif buddy icon",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              string(sampleGIF),
			statusCode:        http.StatusOK,
			contentType:       "image/gif",
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
						},
					},
				},
				feedBagRetrieverParams: feedBagRetrieverParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &wire.BARTID{
								Type: wire.BARTTypesBuddyIcon,
								BARTInfo: wire.BARTInfo{
									Flags: 0x00,
									Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
								},
							},
						},
					},
				},
				bartRetrieverParams: bartRetrieverParams{
					bartRetrieveParams: bartRetrieveParams{
						{
							itemHash: []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result:   sampleGIF,
						},
					},
				},
			},
		},
		{
			name:              "account with jpg buddy icon",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              string(sampleJPG),
			statusCode:        http.StatusOK,
			contentType:       "image/jpeg",
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
						},
					},
				},
				feedBagRetrieverParams: feedBagRetrieverParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &wire.BARTID{
								Type: wire.BARTTypesBuddyIcon,
								BARTInfo: wire.BARTInfo{
									Flags: 0x00,
									Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
								},
							},
						},
					},
				},
				bartRetrieverParams: bartRetrieverParams{
					bartRetrieveParams: bartRetrieveParams{
						{
							itemHash: []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result:   sampleJPG,
						},
					},
				},
			},
		},
		{
			name:              "account with unknown format buddy icon",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              string([]byte{0x13, 0x37, 0x13, 0x37, 0x13, 0x37}),
			statusCode:        http.StatusOK,
			contentType:       "application/octet-stream",
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
						},
					},
				},
				feedBagRetrieverParams: feedBagRetrieverParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &wire.BARTID{
								Type: wire.BARTTypesBuddyIcon,
								BARTInfo: wire.BARTInfo{
									Flags: 0x00,
									Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
								},
							},
						},
					},
				},
				bartRetrieverParams: bartRetrieverParams{
					bartRetrieveParams: bartRetrieveParams{
						{
							itemHash: []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result:   []byte{0x13, 0x37, 0x13, 0x37, 0x13, 0x37},
						},
					},
				},
			},
		},
		{
			name:              "account with cleared buddy icon",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              "icon not found",
			statusCode:        http.StatusNotFound,
			contentType:       "text/plain; charset=utf-8",
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
						},
					},
				},
				feedBagRetrieverParams: feedBagRetrieverParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &wire.BARTID{
								Type: wire.BARTTypesBuddyIcon,
								BARTInfo: wire.BARTInfo{
									Flags: 0x00,
									Hash:  wire.GetClearIconHash(),
								},
							},
						},
					},
				},
			},
		},
		{
			name:              "account with no buddy icon",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              "icon not found",
			statusCode:        http.StatusNotFound,
			contentType:       "text/plain; charset=utf-8",
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: &state.User{
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
						},
					},
				},
				feedBagRetrieverParams: feedBagRetrieverParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/user/"+tc.requestScreenName.String()+"/icon", nil)
			request.SetPathValue("screenname", tc.requestScreenName.String())
			responseRecorder := httptest.NewRecorder()

			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			feedbagRetriever := newMockFeedBagRetriever(t)
			for _, params := range tc.mockParams.feedBagRetrieverParams.buddyIconMetadataParams {
				feedbagRetriever.EXPECT().
					BuddyIconMetadata(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			bartRetriever := newMockBuddyIconRetriever(t)
			for _, params := range tc.mockParams.bartRetrieverParams.bartRetrieveParams {
				bartRetriever.EXPECT().
					BuddyIcon(matchContext(), params.itemHash).
					Return(params.result, params.err)
			}

			getUserBuddyIconHandler(responseRecorder, request, userManager, feedbagRetriever, bartRetriever, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			contentType := responseRecorder.Header().Get("Content-Type")
			if contentType != tc.contentType {
				t.Errorf("Want content type '%s', got '%s'", tc.contentType, contentType)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestUserHandler_GET(t *testing.T) {
	tt := []struct {
		name       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "empty user store",
			want:       `[]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					allUsersParams: allUsersParams{
						{
							result: []state.User{},
						},
					},
				},
			},
		},
		{
			name:       "user store containing 3 users",
			want:       `[{"id":"usera","screen_name":"userA","is_icq":false,"suspended_status":"","is_bot":false},{"id":"userb","screen_name":"userB","is_icq":false,"suspended_status":"","is_bot":true},{"id":"100003","screen_name":"100003","is_icq":true,"suspended_status":"","is_bot":false}]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					allUsersParams: allUsersParams{
						{
							result: []state.User{
								{
									DisplayScreenName: "userA",
									IdentScreenName:   state.NewIdentScreenName("userA"),
								},
								{
									DisplayScreenName: "userB",
									IdentScreenName:   state.NewIdentScreenName("userB"),
									IsBot:             true,
								},
								{
									DisplayScreenName: "100003",
									IdentScreenName:   state.NewIdentScreenName("100003"),
									IsICQ:             true,
								},
							},
						},
					},
				},
			},
		},
		{
			name:       "user handler error",
			want:       `internal server error`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					allUsersParams: allUsersParams{
						{
							result: []state.User{},
							err:    io.EOF,
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/user", nil)
			responseRecorder := httptest.NewRecorder()

			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.allUsersParams {
				userManager.EXPECT().
					AllUsers(matchContext()).
					Return(params.result, params.err)
			}

			getUserHandler(responseRecorder, request, userManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestUserHandler_POST(t *testing.T) {
	tt := []struct {
		name       string
		body       string
		UUID       uuid.UUID
		want       string
		password   string
		statusCode int
		mockParams mockParams
	}{
		{
			name: "with valid AIM user",
			body: `{"screen_name":"userA", "password":"thepassword"}`,
			UUID: uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),

			want:       `User account created successfully.`,
			password:   "thepassword",
			statusCode: http.StatusCreated,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					insertUserParams: insertUserParams{
						{
							u: state.User{
								AuthKey:           uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b").String(),
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
							err: nil,
						},
					},
				},
			},
		},
		{
			name:       "with valid ICQ user",
			body:       `{"screen_name":"100003", "password":"thepass"}`,
			UUID:       uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),
			want:       `User account created successfully.`,
			password:   "thepass",
			statusCode: http.StatusCreated,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					insertUserParams: insertUserParams{
						{
							u: state.User{
								AuthKey:           uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b").String(),
								DisplayScreenName: "100003",
								IdentScreenName:   state.NewIdentScreenName("100003"),
								IsICQ:             true,
							},
							err: nil,
						},
					},
				},
			},
		},
		{
			name:       "with malformed body",
			body:       `{"screen_name":"userA", "password":"thepassword"`, // missing closing }
			want:       `malformed input`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "user handler error",
			body:       `{"screen_name":"userA", "password":"thepassword"}`,
			UUID:       uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),
			want:       `internal server error`,
			password:   "thepassword",
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					insertUserParams: insertUserParams{
						{
							u: state.User{
								AuthKey:           uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b").String(),
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
							err: io.EOF,
						},
					},
				},
			},
		},
		{
			name:       "duplicate user",
			body:       `{"screen_name":"userA", "password":"thepassword"}`,
			UUID:       uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),
			want:       `user already exists`,
			password:   "thepassword",
			statusCode: http.StatusConflict,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					insertUserParams: insertUserParams{
						{
							u: state.User{
								AuthKey:           uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b").String(),
								DisplayScreenName: "userA",
								IdentScreenName:   state.NewIdentScreenName("userA"),
							},
							err: state.ErrDupUser,
						},
					},
				},
			},
		},
		{
			name:       "invalid AIM screen name",
			body:       `{"screen_name":"a", "password":"thepassword"}`,
			UUID:       uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),
			want:       `invalid screen name: screen name must be between 3 and 16 characters`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "invalid AIM password",
			body:       `{"screen_name":"userA", "password":"1"}`,
			UUID:       uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),
			want:       `invalid password: invalid password length: password length must be between 4-16 characters`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "invalid ICQ UIN",
			body:       `{"screen_name":"1000", "password":"thepass"}`,
			UUID:       uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),
			want:       `invalid uin: uin must be a number in the range 10000-2147483646`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "invalid ICQ password",
			body:       `{"screen_name":"100003", "password":"thelongpassword"}`,
			UUID:       uuid.MustParse("07c70701-ba68-49a9-9f9b-67a53816e37b"),
			want:       `invalid password: invalid password length: password must be between 6-8 characters`,
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/user", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.insertUserParams {
				assert.NoError(t, params.u.HashPassword(tc.password))
				userManager.EXPECT().
					InsertUser(matchContext(), params.u).
					Return(params.err)
			}

			newUUID := func() uuid.UUID { return tc.UUID }
			postUserHandler(responseRecorder, request, userManager, newUUID, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestUserHandler_DELETE(t *testing.T) {
	tt := []struct {
		name       string
		body       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "with valid user",
			body:       `{"screen_name":"userA"}`,
			want:       `User account successfully deleted.`,
			statusCode: http.StatusNoContent,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					deleteUserParams: deleteUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
						},
					},
				},
			},
		},
		{
			name:       "with non-existent user",
			body:       `{"screen_name":"userA"}`,
			want:       `user does not exist`,
			statusCode: http.StatusNotFound,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					deleteUserParams: deleteUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							err:        state.ErrNoUser,
						},
					},
				},
			},
		},
		{
			name:       "with malformed body",
			body:       `{"screen_name":"userA"`, // missing closing }
			want:       `malformed input`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "user handler error",
			body:       `{"screen_name":"userA"}`,
			want:       `internal server error`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					deleteUserParams: deleteUserParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							err:        io.EOF,
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "/user", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.deleteUserParams {
				userManager.EXPECT().
					DeleteUser(matchContext(), params.screenName).
					Return(params.err)
			}

			deleteUserHandler(responseRecorder, request, userManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestUserPasswordHandler_PUT(t *testing.T) {
	tt := []struct {
		name       string
		body       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "user with valid password",
			body:       `{"screen_name":"userA", "password":"thenewpassword"}`,
			want:       `Password successfully reset.`,
			statusCode: http.StatusNoContent,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					setUserPasswordParams: setUserPasswordParams{
						{
							screenName:  state.NewIdentScreenName("userA"),
							newPassword: "thenewpassword",
						},
					},
				},
			},
		},
		{
			name:       "user with invalid password",
			body:       `{"screen_name":"userA", "password":"a"}`,
			want:       `invalid password length`,
			statusCode: http.StatusBadRequest,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					setUserPasswordParams: setUserPasswordParams{
						{
							screenName:  state.NewIdentScreenName("userA"),
							newPassword: "a",
							err:         state.ErrPasswordInvalid,
						},
					},
				},
			},
		},
		{
			name:       "with malformed body",
			body:       `{"screen_name":"userA", "password":"thepassword"`, // missing closing }
			want:       `malformed input`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "password updater returns runtime error",
			body:       `{"screen_name":"userA", "password":"thepassword"}`,
			want:       `internal server error`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					setUserPasswordParams: setUserPasswordParams{
						{
							screenName:  state.NewIdentScreenName("userA"),
							newPassword: "thepassword",
							err:         io.EOF,
						},
					},
				},
			},
		},
		{
			name:       "user doesn't exist",
			body:       `{"screen_name":"userA", "password":"thepassword"}`,
			want:       `user does not exist`,
			statusCode: http.StatusNotFound,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					setUserPasswordParams: setUserPasswordParams{
						{
							screenName:  state.NewIdentScreenName("userA"),
							newPassword: "thepassword",
							err:         state.ErrNoUser,
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/user", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.setUserPasswordParams {
				userManager.EXPECT().
					SetUserPassword(matchContext(), params.screenName, params.newPassword).
					Return(params.err)
			}

			putUserPasswordHandler(responseRecorder, request, userManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestPublicChatHandler_GET(t *testing.T) {
	fnNewSess := func(screenName string) *state.Session {
		sess := state.NewSession()
		sess.SetIdentScreenName(state.NewIdentScreenName(screenName))
		sess.SetDisplayScreenName(state.DisplayScreenName(screenName))
		return sess
	}

	chatRoom1 := state.NewChatRoom("chat-room-1-name", state.NewIdentScreenName("chat-room-1-creator"), state.PublicExchange)
	chatRoom2 := state.NewChatRoom("chat-room-2-name", state.NewIdentScreenName("chat-room-1-creator"), state.PublicExchange)

	tt := []struct {
		name       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "multiple chat rooms with participants",
			want:       `[{"name":"chat-room-1-name","create_time":"0001-01-01T00:00:00Z","url":"aim:gochat?roomname=chat-room-1-name&exchange=5","participants":[{"id":"usera","screen_name":"userA"},{"id":"userb","screen_name":"userB"}]},{"name":"chat-room-2-name","create_time":"0001-01-01T00:00:00Z","url":"aim:gochat?roomname=chat-room-2-name&exchange=5","participants":[{"id":"userc","screen_name":"userC"},{"id":"userd","screen_name":"userD"}]}]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				chatRoomRetrieverParams: chatRoomRetrieverParams{
					allChatRoomsParams: allChatRoomsParams{
						{
							exchange: state.PublicExchange,
							result: []state.ChatRoom{
								chatRoom1,
								chatRoom2,
							},
						},
					},
				},
				chatSessionRetrieverParams: chatSessionRetrieverParams{
					chatSessionRetrieverAllSessionsParams: chatSessionRetrieverAllSessionsParams{
						{
							cookie: chatRoom1.Cookie(),
							result: []*state.Session{
								fnNewSess("userA"),
								fnNewSess("userB"),
							},
						},
						{
							cookie: chatRoom2.Cookie(),
							result: []*state.Session{
								fnNewSess("userC"),
								fnNewSess("userD"),
							},
						},
					},
				},
			},
		},
		{
			name:       "chat room without participants",
			want:       `[{"name":"chat-room-1-name","create_time":"0001-01-01T00:00:00Z","url":"aim:gochat?roomname=chat-room-1-name&exchange=5","participants":[]}]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				chatRoomRetrieverParams: chatRoomRetrieverParams{
					allChatRoomsParams: allChatRoomsParams{
						{
							exchange: state.PublicExchange,
							result: []state.ChatRoom{
								chatRoom1,
							},
						},
					},
				},
				chatSessionRetrieverParams: chatSessionRetrieverParams{
					chatSessionRetrieverAllSessionsParams: chatSessionRetrieverAllSessionsParams{
						{
							cookie: chatRoom1.Cookie(),
							result: []*state.Session{},
						},
					},
				},
			},
		},
		{
			name:       "no chat rooms",
			want:       `[]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				chatRoomRetrieverParams: chatRoomRetrieverParams{
					allChatRoomsParams: allChatRoomsParams{
						{
							exchange: state.PublicExchange,
							result:   []state.ChatRoom{},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/chat/room/public", nil)
			responseRecorder := httptest.NewRecorder()

			chatRoomRetriever := newMockChatRoomRetriever(t)
			for _, params := range tc.mockParams.chatRoomRetrieverParams.allChatRoomsParams {
				chatRoomRetriever.EXPECT().
					AllChatRooms(matchContext(), params.exchange).
					Return(params.result, params.err)
			}

			chatSessionRetriever := newMockChatSessionRetriever(t)
			for _, params := range tc.mockParams.chatSessionRetrieverParams.chatSessionRetrieverAllSessionsParams {
				chatSessionRetriever.EXPECT().
					AllSessions(params.cookie).
					Return(params.result)
			}

			getPublicChatHandler(responseRecorder, request, chatRoomRetriever, chatSessionRetriever, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestPrivateChatHandler_GET(t *testing.T) {
	fnNewSess := func(screenName string) *state.Session {
		sess := state.NewSession()
		sess.SetIdentScreenName(state.NewIdentScreenName(screenName))
		sess.SetDisplayScreenName(state.DisplayScreenName(screenName))
		return sess
	}

	chatRoom1 := state.NewChatRoom("chat-room-1-name", state.NewIdentScreenName("chat-room-1-creator"), state.PrivateExchange)
	chatRoom2 := state.NewChatRoom("chat-room-2-name", state.NewIdentScreenName("chat-room-2-creator"), state.PrivateExchange)

	tt := []struct {
		name       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "multiple chat rooms with participants",
			want:       `[{"name":"chat-room-1-name","create_time":"0001-01-01T00:00:00Z","creator_id":"chat-room-1-creator","url":"aim:gochat?roomname=chat-room-1-name&exchange=4","participants":[{"id":"usera","screen_name":"userA"},{"id":"userb","screen_name":"userB"}]},{"name":"chat-room-2-name","create_time":"0001-01-01T00:00:00Z","creator_id":"chat-room-2-creator","url":"aim:gochat?roomname=chat-room-2-name&exchange=4","participants":[{"id":"userc","screen_name":"userC"},{"id":"userd","screen_name":"userD"}]}]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				chatRoomRetrieverParams: chatRoomRetrieverParams{
					allChatRoomsParams: allChatRoomsParams{
						{
							exchange: state.PrivateExchange,
							result: []state.ChatRoom{
								chatRoom1,
								chatRoom2,
							},
						},
					},
				},
				chatSessionRetrieverParams: chatSessionRetrieverParams{
					chatSessionRetrieverAllSessionsParams: chatSessionRetrieverAllSessionsParams{
						{
							cookie: chatRoom1.Cookie(),
							result: []*state.Session{
								fnNewSess("userA"),
								fnNewSess("userB"),
							},
						},
						{
							cookie: chatRoom2.Cookie(),
							result: []*state.Session{
								fnNewSess("userC"),
								fnNewSess("userD"),
							},
						},
					},
				},
			},
		},
		{
			name:       "chat room without participants",
			want:       `[{"name":"chat-room-1-name","create_time":"0001-01-01T00:00:00Z","creator_id":"chat-room-1-creator","url":"aim:gochat?roomname=chat-room-1-name&exchange=4","participants":[]}]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				chatRoomRetrieverParams: chatRoomRetrieverParams{
					allChatRoomsParams: allChatRoomsParams{
						{
							exchange: state.PrivateExchange,
							result: []state.ChatRoom{
								chatRoom1,
							},
						},
					},
				},
				chatSessionRetrieverParams: chatSessionRetrieverParams{
					chatSessionRetrieverAllSessionsParams: chatSessionRetrieverAllSessionsParams{
						{
							cookie: chatRoom1.Cookie(),
							result: []*state.Session{},
						},
					},
				},
			},
		},
		{
			name:       "no chat rooms",
			want:       `[]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				chatRoomRetrieverParams: chatRoomRetrieverParams{
					allChatRoomsParams: allChatRoomsParams{
						{
							exchange: state.PrivateExchange,
							result:   []state.ChatRoom{},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/chat/room/private", nil)
			responseRecorder := httptest.NewRecorder()

			chatRoomRetriever := newMockChatRoomRetriever(t)
			for _, params := range tc.mockParams.chatRoomRetrieverParams.allChatRoomsParams {
				chatRoomRetriever.EXPECT().
					AllChatRooms(matchContext(), params.exchange).
					Return(params.result, params.err)
			}

			chatSessionRetriever := newMockChatSessionRetriever(t)
			for _, params := range tc.mockParams.chatSessionRetrieverParams.chatSessionRetrieverAllSessionsParams {
				chatSessionRetriever.EXPECT().
					AllSessions(params.cookie).
					Return(params.result)
			}

			getPrivateChatHandler(responseRecorder, request, chatRoomRetriever, chatSessionRetriever, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestInstantMessageHandler_POST(t *testing.T) {
	type relayToScreenNameInputs struct {
		sender    state.IdentScreenName
		recipient state.IdentScreenName
		msg       string
	}

	tt := []struct {
		name                    string
		relayToScreenNameInputs []relayToScreenNameInputs
		body                    string
		want                    string
		statusCode              int
	}{
		{
			name: "send an instant message",
			relayToScreenNameInputs: []relayToScreenNameInputs{
				{
					sender:    state.NewIdentScreenName("sender_sn"),
					recipient: state.NewIdentScreenName("recip_sn"),
					msg:       "hello world!",
				},
			},
			body:       `{"from":"sender_sn","to":"recip_sn","text":"hello world!"}`,
			want:       `Message sent successfully.`,
			statusCode: http.StatusOK,
		},
		{
			name:       "with malformed body",
			body:       `{"screen_name":"userA", "password":"thepassword"`,
			want:       `malformed input`,
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/user", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			messageRelayer := newMockMessageRelayer(t)

			for _, params := range tc.relayToScreenNameInputs {
				validateSNAC := func(msg wire.SNACMessage) bool {
					body := msg.Body.(wire.SNAC_0x04_0x07_ICBMChannelMsgToClient)
					assert.Equal(t, params.sender.String(), body.TLVUserInfo.ScreenName)

					b, ok := body.Bytes(wire.ICBMTLVAOLIMData)
					assert.True(t, ok)

					txt, err := wire.UnmarshalICBMMessageText(b)
					assert.NoError(t, err)
					assert.Equal(t, params.msg, txt)
					return true
				}
				messageRelayer.EXPECT().
					RelayToScreenName(mock.Anything, params.recipient, mock.MatchedBy(validateSNAC))
			}

			postInstantMessageHandler(responseRecorder, request, messageRelayer, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestVersionHandler_GET(t *testing.T) {
	tt := []struct {
		name       string
		want       string
		statusCode int
		buildInfo  config.Build
	}{
		{
			name:       "get ras version",
			want:       `{"version":"13.3.7","commit":"asdfASDF12345678","date":"2024-03-01"}`,
			statusCode: http.StatusOK,
			buildInfo: config.Build{
				Version: "13.3.7",
				Commit:  "asdfASDF12345678",
				Date:    "2024-03-01",
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			responseRecorder := httptest.NewRecorder()

			getVersionHandler(responseRecorder, tc.buildInfo)

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestDirectoryCategoryHandler_GET(t *testing.T) {
	tt := []struct {
		name       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "no categories",
			want:       `[]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					categoriesParams: categoriesParams{
						{
							result: nil,
						},
					},
				},
			},
		},
		{
			name:       "error fetching categories",
			want:       `{"message":"internal server error"}`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					categoriesParams: categoriesParams{
						{
							result: nil,
							err:    errors.New("error fetching categories"),
						},
					},
				},
			},
		},
		{
			name:       "fetch some categories",
			want:       `[{"id":1,"name":"category-1"},{"id":2,"name":"category-2"}]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					categoriesParams: categoriesParams{
						{
							result: []state.Category{
								{
									ID:   1,
									Name: "category-1",
								},
								{
									ID:   2,
									Name: "category-2",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			responseRecorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/directory/category", nil)

			directoryManager := newMockDirectoryManager(t)
			for _, params := range tc.mockParams.categoriesParams {
				directoryManager.EXPECT().
					Categories(matchContext()).
					Return(params.result, params.err)
			}

			getDirectoryCategoryHandler(responseRecorder, request, directoryManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestDirectoryCategoryKeywordHandler_GET(t *testing.T) {
	tt := []struct {
		name       string
		categoryID int
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "category not found",
			categoryID: 1,
			want:       `{"message":"category not found"}`,
			statusCode: http.StatusNotFound,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					keywordsByCategoryParams: keywordsByCategoryParams{
						{
							categoryID: 1,
							result:     nil,
							err:        state.ErrKeywordCategoryNotFound,
						},
					},
				},
			},
		},
		{
			name:       "error fetching keywords by category",
			categoryID: 1,
			want:       `{"message":"internal server error"}`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					keywordsByCategoryParams: keywordsByCategoryParams{
						{
							categoryID: 1,
							result:     nil,
							err:        errors.New("error fetching keywords by category"),
						},
					},
				},
			},
		},
		{
			name:       "invalid category ID",
			categoryID: -1,
			want:       `{"message":"invalid category ID"}`,
			statusCode: http.StatusBadRequest,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					keywordsByCategoryParams: keywordsByCategoryParams{},
				},
			},
		},
		{
			name:       "no keywords",
			categoryID: 1,
			want:       `[]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					keywordsByCategoryParams: keywordsByCategoryParams{
						{
							categoryID: 1,
							result:     nil,
						},
					},
				},
			},
		},
		{
			name:       "fetch some keywords by category",
			categoryID: 1,
			want:       `[{"id":1,"name":"keyword-1"},{"id":2,"name":"keyword-2"}]`,
			statusCode: http.StatusOK,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					keywordsByCategoryParams: keywordsByCategoryParams{
						{
							categoryID: 1,
							result: []state.Keyword{
								{
									ID:   1,
									Name: "keyword-1",
								},
								{
									ID:   2,
									Name: "keyword-2",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/directory/category/%d/keyword", tc.categoryID), nil)
			request.SetPathValue("id", fmt.Sprintf("%d", tc.categoryID))
			responseRecorder := httptest.NewRecorder()

			directoryManager := newMockDirectoryManager(t)
			for _, params := range tc.mockParams.keywordsByCategoryParams {
				directoryManager.EXPECT().
					KeywordsByCategory(matchContext(), params.categoryID).
					Return(params.result, params.err)
			}

			getDirectoryCategoryKeywordHandler(responseRecorder, request, directoryManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestDirectoryCategoryHandler_DELETE(t *testing.T) {
	tt := []struct {
		name       string
		categoryID int
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "category not found",
			categoryID: 1,
			want:       `{"message":"category not found"}`,
			statusCode: http.StatusNotFound,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteCategoryParams: deleteCategoryParams{
						{
							categoryID: 1,
							err:        state.ErrKeywordCategoryNotFound,
						},
					},
				},
			},
		},
		{
			name:       "keyword in use by user",
			categoryID: 1,
			want:       `{"message":"can't delete because category in use by a user"}`,
			statusCode: http.StatusConflict,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteCategoryParams: deleteCategoryParams{
						{
							categoryID: 1,
							err:        state.ErrKeywordInUse,
						},
					},
				},
			},
		},
		{
			name:       "runtime error",
			categoryID: 1,
			want:       `{"message":"internal server error"}`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteCategoryParams: deleteCategoryParams{
						{
							categoryID: 1,
							err:        errors.New("error deleting keyword"),
						},
					},
				},
			},
		},
		{
			name:       "successful deletion",
			categoryID: 1,
			want:       ``,
			statusCode: http.StatusNoContent,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteCategoryParams: deleteCategoryParams{
						{
							categoryID: 1,
						},
					},
				},
			},
		},
		{
			name:       "invalid category ID",
			categoryID: -1,
			want:       `invalid category ID`,
			statusCode: http.StatusBadRequest,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteCategoryParams: deleteCategoryParams{},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/directory/category/%d/keyword", tc.categoryID), nil)
			request.SetPathValue("id", fmt.Sprintf("%d", tc.categoryID))
			responseRecorder := httptest.NewRecorder()

			directoryManager := newMockDirectoryManager(t)
			for _, params := range tc.mockParams.deleteCategoryParams {
				directoryManager.EXPECT().
					DeleteCategory(matchContext(), params.categoryID).
					Return(params.err)
			}

			deleteDirectoryCategoryHandler(responseRecorder, request, directoryManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestDirectoryCategoryHandler_POST(t *testing.T) {
	tt := []struct {
		name       string
		body       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "category already exists",
			body:       `{"name":"the_category"}`,
			want:       `{"message":"category already exists"}`,
			statusCode: http.StatusConflict,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createCategoryParams: createCategoryParams{
						{
							name: "the_category",
							err:  state.ErrKeywordCategoryExists,
						},
					},
				},
			},
		},
		{
			name:       "runtime error",
			body:       `{"name":"the_category"}`,
			want:       `{"message":"internal server error"}`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createCategoryParams: createCategoryParams{
						{
							name: "the_category",
							err:  errors.New("error creating category"),
						},
					},
				},
			},
		},
		{
			name:       "bad input",
			body:       `{"name":"the_category"`,
			want:       `{"message":"malformed input"}`,
			statusCode: http.StatusBadRequest,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createCategoryParams: createCategoryParams{},
				},
			},
		},
		{
			name:       "successful creation",
			body:       `{"name":"the_category"}`,
			want:       `{"id":1,"name":"the_category"}`,
			statusCode: http.StatusCreated,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createCategoryParams: createCategoryParams{
						{
							name: "the_category",
							result: state.Category{
								ID:   1,
								Name: "the_category",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/directory/category", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			directoryManager := newMockDirectoryManager(t)
			for _, params := range tc.mockParams.createCategoryParams {
				directoryManager.EXPECT().
					CreateCategory(matchContext(), params.name).
					Return(params.result, params.err)
			}

			postDirectoryCategoryHandler(responseRecorder, request, directoryManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestDirectoryKeywordHandler_POST(t *testing.T) {
	tt := []struct {
		name       string
		body       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "keyword already exists",
			body:       `{"category_id":1,"name":"the_keyword"}`,
			want:       `{"message":"keyword already exists"}`,
			statusCode: http.StatusConflict,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createKeywordParams: createKeywordParams{
						{
							name:       "the_keyword",
							categoryID: 1,
							err:        state.ErrKeywordExists,
						},
					},
				},
			},
		},
		{
			name:       "category not found",
			body:       `{"category_id":1,"name":"the_keyword"}`,
			want:       `{"message":"category not found"}`,
			statusCode: http.StatusNotFound,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createKeywordParams: createKeywordParams{
						{
							name:       "the_keyword",
							categoryID: 1,
							err:        state.ErrKeywordCategoryNotFound,
						},
					},
				},
			},
		},
		{
			name:       "runtime error",
			body:       `{"category_id":1,"name":"the_keyword"}`,
			want:       `{"message":"internal server error"}`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createKeywordParams: createKeywordParams{
						{
							name:       "the_keyword",
							categoryID: 1,
							err:        errors.New("error creating keyword"),
						},
					},
				},
			},
		},
		{
			name:       "bad input",
			body:       `{"category_id":1,"name":"the_keyword"`,
			want:       `{"message":"malformed input"}`,
			statusCode: http.StatusBadRequest,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createKeywordParams: createKeywordParams{},
				},
			},
		},
		{
			name:       "successful creation",
			body:       `{"category_id":1,"name":"the_keyword"}`,
			want:       `{"id":1,"name":"the_keyword"}`,
			statusCode: http.StatusCreated,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					createKeywordParams: createKeywordParams{
						{
							name:       "the_keyword",
							categoryID: 1,
							result: state.Keyword{
								ID:   1,
								Name: "the_keyword",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/directory/keyword", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			directoryManager := newMockDirectoryManager(t)
			for _, params := range tc.mockParams.createKeywordParams {
				directoryManager.EXPECT().
					CreateKeyword(matchContext(), params.name, params.categoryID).
					Return(params.result, params.err)
			}

			postDirectoryKeywordHandler(responseRecorder, request, directoryManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestDirectoryKeywordHandler_DELETE(t *testing.T) {
	tt := []struct {
		name       string
		categoryID int
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "keyword not found",
			categoryID: 1,
			want:       `{"message":"keyword not found"}`,
			statusCode: http.StatusNotFound,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteKeywordParams: deleteKeywordParams{
						{
							id:  1,
							err: state.ErrKeywordNotFound,
						},
					},
				},
			},
		},
		{
			name:       "keyword in use by user",
			categoryID: 1,
			want:       `{"message":"can't delete because category in use by a user"}`,
			statusCode: http.StatusConflict,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteKeywordParams: deleteKeywordParams{
						{
							id:  1,
							err: state.ErrKeywordInUse,
						},
					},
				},
			},
		},
		{
			name:       "runtime error",
			categoryID: 1,
			want:       `{"message":"internal server error"}`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteKeywordParams: deleteKeywordParams{
						{
							id:  1,
							err: errors.New("error deleting keyword"),
						},
					},
				},
			},
		},
		{
			name:       "successful deletion",
			categoryID: 1,
			want:       ``,
			statusCode: http.StatusNoContent,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteKeywordParams: deleteKeywordParams{
						{
							id: 1,
						},
					},
				},
			},
		},
		{
			name:       "invalid keyword ID",
			categoryID: -1,
			want:       `{"message":"invalid keyword ID"}`,
			statusCode: http.StatusBadRequest,
			mockParams: mockParams{
				directoryManagerParams: directoryManagerParams{
					deleteKeywordParams: deleteKeywordParams{},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/directory/keyword/%d", tc.categoryID), nil)
			request.SetPathValue("id", fmt.Sprintf("%d", tc.categoryID))
			responseRecorder := httptest.NewRecorder()

			directoryManager := newMockDirectoryManager(t)
			for _, params := range tc.mockParams.deleteKeywordParams {
				directoryManager.EXPECT().
					DeleteKeyword(matchContext(), params.id).
					Return(params.err)
			}

			deleteDirectoryKeywordHandler(responseRecorder, request, directoryManager, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("Want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("Want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}
