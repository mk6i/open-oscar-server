package http

import (
	"context"
	"encoding/json"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestSessionHandler_GET(t *testing.T) {
	// Fixed time for testing: 2024-01-01 12:00:00 UTC
	fixedNow := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return fixedNow }

	tt := []struct {
		name           string
		want           string
		statusCode     int
		createSessions func() []*state.Session
	}{
		{
			name:       "without sessions",
			want:       `{"count":0,"sessions":[]}`,
			statusCode: http.StatusOK,
			createSessions: func() []*state.Session {
				return []*state.Session{}
			},
		},
		{
			name:       "with sessions",
			want:       `{"count":3,"sessions":[{"id":"usera","screen_name":"userA","online_seconds":100,"is_away":false,"away_message":"","idle_seconds":0,"is_invisible":false,"is_icq":false,"instance_count":2,"instances":[{"num":1,"idle_seconds":30,"is_away":false,"away_message":"","is_invisible":false,"remote_addr":"1.2.3.4","remote_port":1234},{"num":2,"idle_seconds":0,"is_away":false,"away_message":"","is_invisible":true,"remote_addr":"5.6.7.8","remote_port":5678}]},{"id":"userb","screen_name":"userB","online_seconds":200,"is_away":false,"away_message":"","idle_seconds":0,"is_invisible":true,"is_icq":false,"instance_count":2,"instances":[{"num":1,"idle_seconds":0,"is_away":false,"away_message":"","is_invisible":true,"remote_addr":"9.10.11.12","remote_port":9012},{"num":2,"idle_seconds":0,"is_away":false,"away_message":"","is_invisible":true,"remote_addr":"13.14.15.16","remote_port":1314}]},{"id":"100003","screen_name":"100003","online_seconds":300,"is_away":false,"away_message":"","idle_seconds":0,"is_invisible":false,"is_icq":true,"instance_count":1,"instances":[{"num":1,"idle_seconds":0,"is_away":false,"away_message":"","is_invisible":false,"remote_addr":"1.2.3.4","remote_port":1234}]}]}`,
			statusCode: http.StatusOK,
			createSessions: func() []*state.Session {
				// userA: 2 instances - one idle (30s), one invisible
				userA := state.NewSession()
				userA.SetIdentScreenName(state.NewIdentScreenName("userA"))
				userA.SetDisplayScreenName(state.DisplayScreenName("userA"))
				userA.SetUIN(0)
				userA.SetNowFn(nowFn)
				userA.SetSignonTime(fixedNow.Add(-100 * time.Second))
				inst1 := userA.AddInstance()
				inst1.SetSignonComplete()
				inst1.SetIdle(30 * time.Second)
				ip1, _ := netip.ParseAddrPort("1.2.3.4:1234")
				inst1.SetRemoteAddr(&ip1)
				inst2 := userA.AddInstance()
				inst2.SetSignonComplete()
				inst2.SetUserStatusBitmask(wire.OServiceUserStatusInvisible)
				ip2, _ := netip.ParseAddrPort("5.6.7.8:5678")
				inst2.SetRemoteAddr(&ip2)

				// userB: 2 instances - both invisible
				userB := state.NewSession()
				userB.SetIdentScreenName(state.NewIdentScreenName("userB"))
				userB.SetDisplayScreenName(state.DisplayScreenName("userB"))
				userB.SetUIN(0)
				userB.SetNowFn(nowFn)
				userB.SetSignonTime(fixedNow.Add(-200 * time.Second))
				inst3 := userB.AddInstance()
				inst3.SetSignonComplete()
				inst3.SetUserStatusBitmask(wire.OServiceUserStatusInvisible)
				ip3, _ := netip.ParseAddrPort("9.10.11.12:9012")
				inst3.SetRemoteAddr(&ip3)
				inst4 := userB.AddInstance()
				inst4.SetSignonComplete()
				inst4.SetUserStatusBitmask(wire.OServiceUserStatusInvisible)
				ip4, _ := netip.ParseAddrPort("13.14.15.16:1314")
				inst4.SetRemoteAddr(&ip4)

				// 100003: 1 instance - normal
				icqUser := state.NewSession()
				icqUser.SetIdentScreenName(state.NewIdentScreenName("100003"))
				icqUser.SetDisplayScreenName(state.DisplayScreenName("100003"))
				icqUser.SetUIN(100003)
				icqUser.SetNowFn(nowFn)
				icqUser.SetSignonTime(fixedNow.Add(-300 * time.Second))
				inst5 := icqUser.AddInstance()
				inst5.SetSignonComplete()
				ip5, _ := netip.ParseAddrPort("1.2.3.4:1234")
				inst5.SetRemoteAddr(&ip5)

				return []*state.Session{userA, userB, icqUser}
			},
		},
		{
			name:       "with away sessions",
			want:       `{"count":2,"sessions":[{"id":"usera","screen_name":"userA","online_seconds":100,"is_away":false,"away_message":"","idle_seconds":0,"is_invisible":false,"is_icq":false,"instance_count":2,"instances":[{"num":1,"idle_seconds":0,"is_away":true,"away_message":"Away message 1","is_invisible":false,"remote_addr":"1.2.3.4","remote_port":1234},{"num":2,"idle_seconds":0,"is_away":false,"away_message":"","is_invisible":false,"remote_addr":"5.6.7.8","remote_port":5678}]},{"id":"userb","screen_name":"userB","online_seconds":200,"is_away":true,"away_message":"Away message 2","idle_seconds":0,"is_invisible":false,"is_icq":false,"instance_count":2,"instances":[{"num":1,"idle_seconds":0,"is_away":true,"away_message":"Away message 2","is_invisible":false,"remote_addr":"9.10.11.12","remote_port":9012},{"num":2,"idle_seconds":0,"is_away":true,"away_message":"Away message 2","is_invisible":false,"remote_addr":"13.14.15.16","remote_port":1314}]}]}`,
			statusCode: http.StatusOK,
			createSessions: func() []*state.Session {
				// userA: 2 instances - one away, one not away (away_message should be "")
				userA := state.NewSession()
				userA.SetIdentScreenName(state.NewIdentScreenName("userA"))
				userA.SetDisplayScreenName(state.DisplayScreenName("userA"))
				userA.SetUIN(0)
				userA.SetNowFn(nowFn)
				userA.SetSignonTime(fixedNow.Add(-100 * time.Second))
				inst1 := userA.AddInstance()
				inst1.SetSignonComplete()
				inst1.SetUserStatusBitmask(wire.OServiceUserStatusAway)
				inst1.SetAwayMessage("Away message 1")
				ip1, _ := netip.ParseAddrPort("1.2.3.4:1234")
				inst1.SetRemoteAddr(&ip1)
				inst2 := userA.AddInstance()
				inst2.SetSignonComplete()
				ip2, _ := netip.ParseAddrPort("5.6.7.8:5678")
				inst2.SetRemoteAddr(&ip2)

				// userB: 2 instances - both away (away_message should be populated)
				userB := state.NewSession()
				userB.SetIdentScreenName(state.NewIdentScreenName("userB"))
				userB.SetDisplayScreenName(state.DisplayScreenName("userB"))
				userB.SetUIN(0)
				userB.SetNowFn(nowFn)
				userB.SetSignonTime(fixedNow.Add(-200 * time.Second))
				inst3 := userB.AddInstance()
				inst3.SetSignonComplete()
				inst3.SetUserStatusBitmask(wire.OServiceUserStatusAway)
				inst3.SetAwayMessage("Away message 2")
				ip3, _ := netip.ParseAddrPort("9.10.11.12:9012")
				inst3.SetRemoteAddr(&ip3)
				inst4 := userB.AddInstance()
				inst4.SetSignonComplete()
				inst4.SetUserStatusBitmask(wire.OServiceUserStatusAway)
				inst4.SetAwayMessage("Away message 2")
				ip4, _ := netip.ParseAddrPort("13.14.15.16:1314")
				inst4.SetRemoteAddr(&ip4)

				return []*state.Session{userA, userB}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/session", nil)
			responseRecorder := httptest.NewRecorder()

			sessionRetriever := newMockSessionRetriever(t)
			sessions := tc.createSessions()
			sessionRetriever.EXPECT().
				AllSessions().
				Return(sessions)

			getSessionHandler(responseRecorder, request, sessionRetriever, nowFn)

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
	// Fixed time for testing: 2024-01-01 12:00:00 UTC
	fixedNow := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return fixedNow }

	tt := []struct {
		name              string
		requestScreenName state.IdentScreenName
		want              string
		statusCode        int
		createSession     func() *state.Session
	}{
		{
			name:              "no session for screenname",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `session not found`,
			statusCode:        http.StatusNotFound,
			createSession: func() *state.Session {
				return nil
			},
		},
		{
			name:              "active session found for screenname",
			requestScreenName: state.NewIdentScreenName("userA"),
			want:              `{"count":1,"sessions":[{"id":"usera","screen_name":"userA","online_seconds":150,"is_away":false,"away_message":"","idle_seconds":0,"is_invisible":false,"is_icq":false,"instance_count":1,"instances":[{"num":1,"idle_seconds":0,"is_away":false,"away_message":"","is_invisible":false,"remote_addr":"1.2.3.4","remote_port":1234}]}]}`,
			statusCode:        http.StatusOK,
			createSession: func() *state.Session {
				sess := state.NewSession()
				sess.SetIdentScreenName(state.NewIdentScreenName("userA"))
				sess.SetDisplayScreenName(state.DisplayScreenName("userA"))
				sess.SetUIN(0)
				sess.SetNowFn(nowFn)
				sess.SetSignonTime(fixedNow.Add(-150 * time.Second))
				instance := sess.AddInstance()
				instance.SetSignonComplete()
				ip, _ := netip.ParseAddrPort("1.2.3.4:1234")
				instance.SetRemoteAddr(&ip)
				return sess
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/session/"+tc.requestScreenName.String(), nil)
			request.SetPathValue("screenname", tc.requestScreenName.String())
			responseRecorder := httptest.NewRecorder()

			sessionRetriever := newMockSessionRetriever(t)
			session := tc.createSession()
			sessionRetriever.EXPECT().
				RetrieveSession(tc.requestScreenName).
				Return(session)

			getSessionHandler(responseRecorder, request, sessionRetriever, nowFn)

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
		instance := sess.AddInstance()
		instance.SetSignonComplete()
		ip, _ := netip.ParseAddrPort("1.2.3.4:1234")
		instance.SetRemoteAddr(&ip)
		return sess
	}
	tt := []struct {
		name              string
		session           *state.SessionInstance
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
							result:     state.UserProfile{ProfileText: "My Profile Text"},
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
							result:     state.UserProfile{ProfileText: "My Profile Text"},
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
							result:     state.UserProfile{ProfileText: "My Profile Text"},
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
				bartAssetManagerParams: bartAssetManagerParams{
					bartItemParams: bartItemParams{
						{
							hash:   []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result: sampleGIF,
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
				bartAssetManagerParams: bartAssetManagerParams{
					bartItemParams: bartItemParams{
						{
							hash:   []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result: sampleJPG,
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
				bartAssetManagerParams: bartAssetManagerParams{
					bartItemParams: bartItemParams{
						{
							hash:   []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result: []byte{0x13, 0x37, 0x13, 0x37, 0x13, 0x37},
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

			bartRetriever := newMockBARTAssetManager(t)
			for _, params := range tc.mockParams.bartAssetManagerParams.bartItemParams {
				bartRetriever.EXPECT().
					BARTItem(matchContext(), params.hash).
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
		name          string
		body          string
		want          string
		statusCode    int
		createAccount state.CreateAccountFunc
	}{
		{
			name:       "with valid AIM user",
			body:       `{"screen_name":"userA", "password":"thepassword"}`,
			want:       `User account created successfully.`,
			statusCode: http.StatusCreated,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("userA"), screenName)
				assert.Equal(t, "thepassword", password)
				return nil
			},
		},
		{
			name:       "with valid ICQ user",
			body:       `{"screen_name":"100003", "password":"thepass"}`,
			want:       `User account created successfully.`,
			statusCode: http.StatusCreated,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("100003"), screenName)
				assert.Equal(t, "thepass", password)
				return nil
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
			want:       `internal server error`,
			statusCode: http.StatusInternalServerError,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("userA"), screenName)
				assert.Equal(t, "thepassword", password)
				return io.EOF
			},
		},
		{
			name:       "duplicate user",
			body:       `{"screen_name":"userA", "password":"thepassword"}`,
			want:       `user already exists`,
			statusCode: http.StatusConflict,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("userA"), screenName)
				assert.Equal(t, "thepassword", password)
				return state.ErrDupUser
			},
		},
		{
			name:       "invalid AIM screen name",
			body:       `{"screen_name":"a", "password":"thepassword"}`,
			want:       `invalid screen name: screen name must be between 3 and 16 characters`,
			statusCode: http.StatusBadRequest,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("a"), screenName)
				assert.Equal(t, "thepassword", password)
				return state.ErrAIMHandleLength
			},
		},
		{
			name:       "invalid AIM password",
			body:       `{"screen_name":"userA", "password":"1"}`,
			want:       `invalid password: invalid password length: password length must be between 4-16 characters`,
			statusCode: http.StatusBadRequest,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("userA"), screenName)
				assert.Equal(t, "1", password)
				return fmt.Errorf("%w: password length must be between 4-16 characters", state.ErrPasswordInvalid)
			},
		},
		{
			name:       "invalid ICQ UIN",
			body:       `{"screen_name":"1000", "password":"thepass"}`,
			want:       `invalid uin: uin must be a number in the range 10000-2147483646`,
			statusCode: http.StatusBadRequest,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("1000"), screenName)
				assert.Equal(t, "thepass", password)
				return state.ErrICQUINInvalidFormat
			},
		},
		{
			name:       "invalid ICQ password",
			body:       `{"screen_name":"100003", "password":"thelongpassword"}`,
			want:       `invalid password: invalid password length: password must be between 6-8 characters`,
			statusCode: http.StatusBadRequest,
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("100003"), screenName)
				assert.Equal(t, "thelongpassword", password)
				return fmt.Errorf("%w: password must be between 6-8 characters", state.ErrPasswordInvalid)
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/user", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			postUserHandler(responseRecorder, request, tc.createAccount, slog.Default())

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
		instance := sess.AddInstance()
		instance.SetSignonComplete()
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

func TestDeletePublicChatHandler(t *testing.T) {
	tt := []struct {
		name       string
		body       string
		want       string
		statusCode int
		mockParams mockParams
	}{
		{
			name:       "successful deletion of single chat room",
			body:       `{"names":["TestRoom"]}`,
			want:       `Chat rooms deleted successfully.`,
			statusCode: http.StatusNoContent,
			mockParams: mockParams{
				chatRoomDeleterParams: chatRoomDeleterParams{
					deleteChatRoomsParams: deleteChatRoomsParams{
						{
							exchange: state.PublicExchange,
							names:    []string{"TestRoom"},
						},
					},
				},
			},
		},
		{
			name:       "successful deletion of multiple chat rooms",
			body:       `{"names":["Room1", "Room2", "Room3"]}`,
			want:       `Chat rooms deleted successfully.`,
			statusCode: http.StatusNoContent,
			mockParams: mockParams{
				chatRoomDeleterParams: chatRoomDeleterParams{
					deleteChatRoomsParams: deleteChatRoomsParams{
						{
							exchange: state.PublicExchange,
							names:    []string{"Room1", "Room2", "Room3"},
						},
					},
				},
			},
		},
		{
			name:       "empty names array",
			body:       `{"names":[]}`,
			want:       `no chat room names provided`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "malformed JSON",
			body:       `{"names":["Room1"`, // missing closing brackets
			want:       `malformed input`,
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "deletion error",
			body:       `{"names":["TestRoom"]}`,
			want:       `internal server error`,
			statusCode: http.StatusInternalServerError,
			mockParams: mockParams{
				chatRoomDeleterParams: chatRoomDeleterParams{
					deleteChatRoomsParams: deleteChatRoomsParams{
						{
							exchange: state.PublicExchange,
							names:    []string{"TestRoom"},
							err:      errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "/chat/room/public", strings.NewReader(tc.body))
			responseRecorder := httptest.NewRecorder()

			chatRoomDeleter := newMockChatRoomDeleter(t)
			for _, params := range tc.mockParams.chatRoomDeleterParams.deleteChatRoomsParams {
				chatRoomDeleter.EXPECT().
					DeleteChatRooms(matchContext(), params.exchange, params.names).
					Return(params.err)
			}

			deletePublicChatHandler(responseRecorder, request, chatRoomDeleter, slog.Default())

			if responseRecorder.Code != tc.statusCode {
				t.Errorf("want status '%d', got '%d'", tc.statusCode, responseRecorder.Code)
			}

			if strings.TrimSpace(responseRecorder.Body.String()) != tc.want {
				t.Errorf("want '%s', got '%s'", tc.want, responseRecorder.Body)
			}
		})
	}
}

func TestPrivateChatHandler_GET(t *testing.T) {
	fnNewSess := func(screenName string) *state.Session {
		sess := state.NewSession()
		sess.SetIdentScreenName(state.NewIdentScreenName(screenName))
		sess.SetDisplayScreenName(state.DisplayScreenName(screenName))
		instance := sess.AddInstance()
		instance.SetSignonComplete()
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

func TestBARTByTypeHandler_GET(t *testing.T) {
	tt := []struct {
		name           string
		queryParams    string
		wantStatusCode int
		wantResponse   string
		mockParams     mockParams
	}{
		{
			name:           "success with items",
			queryParams:    "?type=1",
			wantStatusCode: http.StatusOK,
			wantResponse:   `[{"hash":"2B000001E4","type":1},{"hash":"2B000001B7","type":1}]`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					listBARTItemsParams: listBARTItemsParams{
						{
							itemType: 1,
							result: []state.BARTItem{
								{Hash: "2B000001E4", Type: 1},
								{Hash: "2B000001B7", Type: 1},
							},
							err: nil,
						},
					},
				},
			},
		},
		{
			name:           "success with empty list",
			queryParams:    "?type=2",
			wantStatusCode: http.StatusOK,
			wantResponse:   `[]`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					listBARTItemsParams: listBARTItemsParams{
						{
							itemType: 2,
							result:   []state.BARTItem{},
							err:      nil,
						},
					},
				},
			},
		},
		{
			name:           "missing type parameter",
			queryParams:    "",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"type query parameter is required"}`,
		},
		{
			name:           "invalid type parameter",
			queryParams:    "?type=invalid",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid type ID"}`,
		},
		{
			name:           "internal server error",
			queryParams:    "?type=1",
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					listBARTItemsParams: listBARTItemsParams{
						{
							itemType: 1,
							result:   nil,
							err:      errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/bart"+tc.queryParams, nil)
			responseRecorder := httptest.NewRecorder()

			mockBARTManager := newMockBARTAssetManager(t)
			for _, params := range tc.mockParams.bartAssetManagerParams.listBARTItemsParams {
				mockBARTManager.EXPECT().
					ListBARTItems(matchContext(), params.itemType).
					Return(params.result, params.err)
			}

			getBARTByTypeHandler(responseRecorder, request, mockBARTManager, slog.Default())

			assert.Equal(t, tc.wantStatusCode, responseRecorder.Code)
			assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
		})
	}
}

func TestBARTHandler_GET(t *testing.T) {
	tt := []struct {
		name           string
		hash           string
		wantStatusCode int
		wantResponse   string
		wantHeaders    map[string]string
		mockParams     mockParams
	}{
		{
			name:           "success with valid hash",
			hash:           "2B000001E4",
			wantStatusCode: http.StatusOK,
			wantResponse:   "binary data",
			wantHeaders:    map[string]string{"Content-Type": "application/octet-stream"},
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					bartItemParams: bartItemParams{
						{
							hash:   []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							result: []byte("binary data"),
							err:    nil,
						},
					},
				},
			},
		},
		{
			name:           "missing hash parameter",
			hash:           "",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"hash is required"}`,
		},
		{
			name:           "invalid hash format",
			hash:           "invalid-hex",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid hash format"}`,
		},
		{
			name:           "asset not found",
			hash:           "2B000001E4",
			wantStatusCode: http.StatusNotFound,
			wantResponse:   `{"message":"BART asset not found"}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					bartItemParams: bartItemParams{
						{
							hash:   []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							result: []byte{},
							err:    nil,
						},
					},
				},
			},
		},
		{
			name:           "internal server error",
			hash:           "2B000001E4",
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					bartItemParams: bartItemParams{
						{
							hash:   []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							result: nil,
							err:    errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/bart/"+tc.hash, nil)
			// Set the path value manually for testing
			if tc.hash != "" {
				request.SetPathValue("hash", tc.hash)
			}
			responseRecorder := httptest.NewRecorder()

			mockBARTManager := newMockBARTAssetManager(t)
			for _, params := range tc.mockParams.bartAssetManagerParams.bartItemParams {
				mockBARTManager.EXPECT().
					BARTItem(matchContext(), params.hash).
					Return(params.result, params.err)
			}

			getBARTHandler(responseRecorder, request, mockBARTManager, slog.Default())

			assert.Equal(t, tc.wantStatusCode, responseRecorder.Code)

			if tc.wantHeaders != nil {
				for key, value := range tc.wantHeaders {
					assert.Equal(t, value, responseRecorder.Header().Get(key))
				}
			}

			if tc.wantStatusCode == http.StatusOK {
				assert.Equal(t, tc.wantResponse, responseRecorder.Body.String())
			} else {
				assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
			}
		})
	}
}

func TestBARTHandler_POST(t *testing.T) {
	tt := []struct {
		name           string
		hash           string
		queryParams    string
		requestBody    string
		wantStatusCode int
		wantResponse   string
		mockParams     mockParams
	}{
		{
			name:           "success with valid data",
			hash:           "2B000001E4",
			queryParams:    "?type=1",
			requestBody:    "binary data",
			wantStatusCode: http.StatusCreated,
			wantResponse:   `{"hash":"2b000001e4","type":1}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					insertBARTItemParams: insertBARTItemParams{
						{
							hash:     []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							blob:     []byte("binary data"),
							itemType: 1,
							err:      nil,
						},
					},
				},
			},
		},
		{
			name:           "missing hash parameter",
			hash:           "",
			queryParams:    "?type=1",
			requestBody:    "binary data",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"hash path parameter is required"}`,
		},
		{
			name:           "invalid hash format",
			hash:           "invalid-hex",
			queryParams:    "?type=1",
			requestBody:    "binary data",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid hash format"}`,
		},
		{
			name:           "missing type parameter",
			hash:           "2B000001E4",
			queryParams:    "",
			requestBody:    "binary data",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"type query parameter is required"}`,
		},
		{
			name:           "invalid type parameter",
			hash:           "2B000001E4",
			queryParams:    "?type=invalid",
			requestBody:    "binary data",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid type ID"}`,
		},
		{
			name:           "failed to read request body",
			hash:           "2B000001E4",
			queryParams:    "?type=1",
			requestBody:    "", // This will cause an error when reading
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"failed to read request body"}`,
		},
		{
			name:           "asset already exists",
			hash:           "2B000001E4",
			queryParams:    "?type=1",
			requestBody:    "binary data",
			wantStatusCode: http.StatusConflict,
			wantResponse:   `{"message":"BART asset already exists"}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					insertBARTItemParams: insertBARTItemParams{
						{
							hash:     []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							blob:     []byte("binary data"),
							itemType: 1,
							err:      state.ErrBARTItemExists,
						},
					},
				},
			},
		},
		{
			name:           "internal server error",
			hash:           "2B000001E4",
			queryParams:    "?type=1",
			requestBody:    "binary data",
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					insertBARTItemParams: insertBARTItemParams{
						{
							hash:     []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							blob:     []byte("binary data"),
							itemType: 1,
							err:      errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var requestBody io.Reader
			if tc.requestBody != "" {
				requestBody = strings.NewReader(tc.requestBody)
			} else {
				requestBody = &errorReader{}
			}

			request := httptest.NewRequest(http.MethodPost, "/bart/"+tc.hash+tc.queryParams, requestBody)
			// Set the path value manually for testing
			if tc.hash != "" {
				request.SetPathValue("hash", tc.hash)
			}
			responseRecorder := httptest.NewRecorder()

			mockBARTManager := newMockBARTAssetManager(t)
			for _, params := range tc.mockParams.bartAssetManagerParams.insertBARTItemParams {
				mockBARTManager.EXPECT().
					InsertBARTItem(matchContext(), params.hash, params.blob, params.itemType).
					Return(params.err)
			}

			postBARTHandler(responseRecorder, request, mockBARTManager, slog.Default())

			assert.Equal(t, tc.wantStatusCode, responseRecorder.Code)
			assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
		})
	}
}

func TestBARTHandler_DELETE(t *testing.T) {
	tt := []struct {
		name           string
		hash           string
		wantStatusCode int
		wantResponse   string
		mockParams     mockParams
	}{
		{
			name:           "success with valid hash",
			hash:           "2B000001E4",
			wantStatusCode: http.StatusOK,
			wantResponse:   `{"message":"BART asset deleted successfully."}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					deleteBARTItemParams: deleteBARTItemParams{
						{
							hash: []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							err:  nil,
						},
					},
				},
			},
		},
		{
			name:           "missing hash parameter",
			hash:           "",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"hash path parameter is required"}`,
		},
		{
			name:           "invalid hash format",
			hash:           "invalid-hex",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid hash format"}`,
		},
		{
			name:           "asset not found",
			hash:           "2B000001E4",
			wantStatusCode: http.StatusNotFound,
			wantResponse:   `{"message":"BART asset not found"}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					deleteBARTItemParams: deleteBARTItemParams{
						{
							hash: []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							err:  state.ErrBARTItemNotFound,
						},
					},
				},
			},
		},
		{
			name:           "internal server error",
			hash:           "2B000001E4",
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				bartAssetManagerParams: bartAssetManagerParams{
					deleteBARTItemParams: deleteBARTItemParams{
						{
							hash: []byte{0x2B, 0x00, 0x00, 0x01, 0xE4},
							err:  errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "/bart/"+tc.hash, nil)
			// Set the path value manually for testing
			if tc.hash != "" {
				request.SetPathValue("hash", tc.hash)
			}
			responseRecorder := httptest.NewRecorder()

			mockBARTManager := newMockBARTAssetManager(t)
			for _, params := range tc.mockParams.bartAssetManagerParams.deleteBARTItemParams {
				mockBARTManager.EXPECT().
					DeleteBARTItem(matchContext(), params.hash).
					Return(params.err)
			}

			deleteBARTHandler(responseRecorder, request, mockBARTManager, slog.Default())

			assert.Equal(t, tc.wantStatusCode, responseRecorder.Code)
			assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
		})
	}
}

// errorReader is a helper type that always returns an error when reading
type errorReader struct{}

func (er *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestFeedbagBuddyHandler_GET(t *testing.T) {
	tt := []struct {
		name           string
		screenName     string
		wantStatusCode int
		wantResponse   string
		mockParams     mockParams
	}{
		{
			name:           "empty feedbag",
			screenName:     "userA",
			wantStatusCode: http.StatusNotFound,
			wantResponse:   `{"message":"feedbag not found"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     wire.FeedbagItems{},
							err:        nil,
						},
					},
				},
			},
		},
		{
			name:           "feedbag with buddies in groups",
			screenName:     "userA",
			wantStatusCode: http.StatusOK,
			wantResponse:   `[{"group_id":1,"group_name":"Friends","buddies":[{"name":"buddy1","item_id":10},{"name":"buddy2","item_id":11}]},{"group_id":2,"group_name":"Work","buddies":[{"name":"buddy3","item_id":20}]}]`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  0,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "",
									GroupID: 0,
								},
								{
									ItemID:  1,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
								{
									ItemID:  2,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Work",
									GroupID: 2,
								},
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
								{
									ItemID:  11,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy2",
									GroupID: 1,
								},
								{
									ItemID:  20,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy3",
									GroupID: 2,
								},
							},
							err: nil,
						},
					},
				},
			},
		},
		{
			name:           "feedbag with no groups (besides root)",
			screenName:     "userA",
			wantStatusCode: http.StatusOK,
			wantResponse:   `[]`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  0,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "",
									GroupID: 0,
								},
							},
							err: nil,
						},
					},
				},
			},
			// Note: Root groups (GroupID == 0) are skipped by the implementation,
			// so the response will be an empty array []
		},
		{
			name:           "missing screen_name",
			screenName:     "",
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"screen_name is required"}`,
		},
		{
			name:           "internal server error",
			screenName:     "userA",
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
							err:        errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/feedbag/"+tc.screenName+"/group", nil)
			if tc.screenName != "" {
				request.SetPathValue("screen_name", tc.screenName)
			}
			responseRecorder := httptest.NewRecorder()

			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedbagManagerParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			getFeedbagBuddyHandler(responseRecorder, request, feedbagManager, slog.Default())

			assert.Equal(t, tc.wantStatusCode, responseRecorder.Code)
			assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
		})
	}
}

func TestFeedbagBuddyHandler_PUT(t *testing.T) {
	tt := []struct {
		name           string
		screenName     string
		groupID        string
		requestBody    string
		wantStatusCode int
		wantResponse   string
		mockParams     mockParams
	}{
		{
			name:           "add a buddy to an empty group, user not signed in",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"newbuddy"}`,
			wantStatusCode: http.StatusOK,
			wantResponse:   `{"name":"newbuddy","group_id":1,"item_id":1000}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									Name:    "newbuddy",
									GroupID: 1,
									ItemID:  1000,
									ClassID: wire.FeedbagClassIdBuddy,
								},
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1000}),
										},
									},
								},
							},
							err: nil,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     state.NewSession(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: wire.FeedbagItems{
										{
											Name:    "newbuddy",
											GroupID: 1,
											ItemID:  1000,
											ClassID: wire.FeedbagClassIdBuddy,
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagUpdateItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: wire.FeedbagItems{
										{
											ClassID: wire.FeedbagClassIdGroup,
											Name:    "Friends",
											GroupID: 1,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1000}),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "add a buddy to a non-empty group, user not signed in",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"newbuddy2"}`,
			wantStatusCode: http.StatusOK,
			wantResponse:   `{"name":"newbuddy2","group_id":1,"item_id":1000}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{12345}),
										},
									},
								},
								{
									ItemID:  12345,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "existingbuddy",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									Name:    "newbuddy2",
									GroupID: 1,
									ItemID:  1000,
									ClassID: wire.FeedbagClassIdBuddy,
								},
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{12345, 1000}),
										},
									},
								},
							},
							err: nil,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     state.NewSession(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: wire.FeedbagItems{
										{
											Name:    "newbuddy2",
											GroupID: 1,
											ItemID:  1000,
											ClassID: wire.FeedbagClassIdBuddy,
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagUpdateItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: wire.FeedbagItems{
										{
											ClassID: wire.FeedbagClassIdGroup,
											Name:    "Friends",
											GroupID: 1,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{12345, 1000}),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "add a buddy that already exists in a group",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"ExistingBuddy"}`,
			wantStatusCode: http.StatusOK,
			wantResponse:   `{"name":"ExistingBuddy","group_id":1,"item_id":12345}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{12345}),
										},
									},
								},
								{
									ItemID:  12345,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "ExistingBuddy",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					// No FeedbagUpsert should be called when buddy already exists
				},
				// No session retrieval or message relaying should occur
			},
		},
		{
			name:           "add a buddy to an empty group, user signed in",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"newbuddy"}`,
			wantStatusCode: http.StatusOK,
			wantResponse:   `{"name":"newbuddy","group_id":1,"item_id":1000}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									Name:    "newbuddy",
									GroupID: 1,
									ItemID:  1000,
									ClassID: wire.FeedbagClassIdBuddy,
								},
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1000}),
										},
									},
								},
							},
							err: nil,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: func() *state.Session {
								sess := state.NewSession()
								sess.SetIdentScreenName(state.NewIdentScreenName("userA"))
								inst := sess.AddInstance()
								inst.SetSignonComplete()
								return sess
							}(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: wire.FeedbagItems{
										{
											Name:    "newbuddy",
											GroupID: 1,
											ItemID:  1000,
											ClassID: wire.FeedbagClassIdBuddy,
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagUpdateItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: wire.FeedbagItems{
										{
											ClassID: wire.FeedbagClassIdGroup,
											Name:    "Friends",
											GroupID: 1,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1000}),
												},
											},
										},
									},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							you:            nil, // Not used in expectation, matched with mock.AnythingOfType
							filter:         []state.IdentScreenName{state.NewIdentScreenName("newbuddy")},
							sendDepartures: false,
							err:            nil,
						},
					},
				},
			},
		},
		{
			name:           "invalid group_id - non-numeric",
			screenName:     "userA",
			groupID:        "invalid",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid group_id"}`,
		},
		{
			name:           "invalid group_id - out of range",
			screenName:     "userA",
			groupID:        "99999",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid group_id"}`,
		},
		{
			name:           "can't add buddies to root group",
			screenName:     "userA",
			groupID:        "0",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"can't add buddies to root group"}`,
		},
		{
			name:           "empty screen_name",
			screenName:     "",
			groupID:        "1",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"screen_name is required"}`,
		},
		{
			name:           "malformed JSON input",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `invalid json`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"buddy_screen_name is required"}`,
		},
		{
			name:           "empty name in request body",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":""}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"buddy_screen_name is required"}`,
		},
		{
			name:           "missing name in request body",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"buddy_screen_name is required"}`,
		},
		{
			name:           "invalid UIN - too low",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"9999"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid uin: uin must be a number in the range 10000-2147483646"}`,
		},
		{
			name:           "invalid UIN - too high",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"2147483647"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid uin: uin must be a number in the range 10000-2147483646"}`,
		},
		{
			name:           "invalid AIM handle - too short",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"Us"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid screen name: screen name must be between 3 and 16 characters"}`,
		},
		{
			name:           "invalid AIM handle - too long",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"ThisIsAReallyLongScreenName"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid screen name: screen name must be between 3 and 16 characters"}`,
		},
		{
			name:           "error retrieving feedbag",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
							err:        errors.New("database error"),
						},
					},
				},
			},
		},
		{
			name:           "too many buddies in group - max 30",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"newbuddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"too many buddies in group. max: 30"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: func() wire.FeedbagItems {
								items := wire.FeedbagItems{
									{
										ClassID: wire.FeedbagClassIdGroup,
										Name:    "Friends",
										GroupID: 1,
									},
								}
								// Add 30 buddies to the group
								for i := 1; i <= 30; i++ {
									items = append(items, wire.FeedbagItem{
										ItemID:  uint16(i),
										ClassID: wire.FeedbagClassIdBuddy,
										Name:    fmt.Sprintf("buddy%d", i),
										GroupID: 1,
									})
								}
								return items
							}(),
							err: nil,
						},
					},
				},
			},
		},
		{
			name:           "group not found",
			screenName:     "userA",
			groupID:        "999",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusNotFound,
			wantResponse:   `{"message":"group not found"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
				},
			},
		},

		{
			name:           "error inserting feedbag item",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									Name:    "buddy",
									GroupID: 1,
									ItemID:  1000,
									ClassID: wire.FeedbagClassIdBuddy,
								},
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1000}),
										},
									},
								},
							},
							err: errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Extract buddy name from requestBody JSON
			var buddyName string
			if tc.requestBody != "" {
				var input struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal([]byte(tc.requestBody), &input); err == nil {
					buddyName = input.Name
				}
			}
			request := httptest.NewRequest(http.MethodPut, "/feedbag/"+tc.screenName+"/group/"+tc.groupID+"/buddy/"+buddyName, nil)
			if tc.screenName != "" {
				request.SetPathValue("screen_name", tc.screenName)
			}
			if tc.groupID != "" {
				request.SetPathValue("group_id", tc.groupID)
			}
			request.SetPathValue("buddy_screen_name", buddyName)
			responseRecorder := httptest.NewRecorder()

			feedbagManager := newMockFeedbagManager(t)
			sessionRetriever := newMockSessionRetriever(t)
			messageRelayer := newMockMessageRelayer(t)
			buddyBroadcaster := newMockBuddyBroadcaster(t)

			for _, params := range tc.mockParams.feedbagManagerParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			for _, params := range tc.mockParams.feedbagManagerParams.feedbagUpsertParams {
				feedbagManager.EXPECT().
					FeedbagUpsert(matchContext(), params.screenName, params.items).
					Return(params.err)
			}
			for _, params := range tc.mockParams.sessionRetrieverParams.retrieveSessionByNameParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}
			for _, params := range tc.mockParams.messageRelayerParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(matchContext(), params.screenName, params.msg)
			}
			for _, params := range tc.mockParams.buddyBroadcasterParams.broadcastVisibilityParams {
				// Use mock.MatchedBy to match any SessionInstance, since we're mainly verifying filter and sendDepartures
				buddyBroadcaster.EXPECT().
					BroadcastVisibility(
						matchContext(),
						mock.AnythingOfType("*state.SessionInstance"),
						params.filter,
						params.sendDepartures,
					).
					Return(params.err)
			}

			deterministicItemID := func(n int) int {
				return 1000
			}
			putFeedbagBuddyHandler(responseRecorder, request, buddyBroadcaster, feedbagManager, sessionRetriever, messageRelayer, slog.Default(), deterministicItemID)

			assert.Equal(t, tc.wantStatusCode, responseRecorder.Code)
			if tc.wantStatusCode == http.StatusOK {
				assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
			} else {
				assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
			}
		})
	}
}

func TestFeedbagBuddyHandler_DELETE(t *testing.T) {
	tt := []struct {
		name           string
		screenName     string
		groupID        string
		requestBody    string
		wantStatusCode int
		wantResponse   string
		mockParams     mockParams
	}{
		{
			name:           "delete existing buddy, user not signed in",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"buddy1"}`,
			wantStatusCode: http.StatusNoContent,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  1,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagDeleteParams: feedbagDeleteParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     state.NewSession(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagDeleteItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
									Items: wire.FeedbagItems{
										{
											ItemID:  10,
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "buddy1",
											GroupID: 1,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "delete existing buddy, user signed in",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"buddy1"}`,
			wantStatusCode: http.StatusNoContent,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  1,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagDeleteParams: feedbagDeleteParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: func() *state.Session {
								sess := state.NewSession()
								sess.SetIdentScreenName(state.NewIdentScreenName("userA"))
								inst := sess.AddInstance()
								inst.SetSignonComplete()
								return sess
							}(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagDeleteItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
									Items: wire.FeedbagItems{
										{
											ItemID:  10,
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "buddy1",
											GroupID: 1,
										},
									},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							you:            nil, // Not used in expectation, matched with mock.AnythingOfType
							filter:         []state.IdentScreenName{state.NewIdentScreenName("buddy1")},
							sendDepartures: true,
							err:            nil,
						},
					},
				},
			},
		},
		{
			name:           "delete buddy from a group with multiple buddies, user not signed in",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"buddy1"}`,
			wantStatusCode: http.StatusNoContent,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  1,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10, 20}),
										},
									},
								},
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
								{
									ItemID:  20,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy2",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagDeleteParams: feedbagDeleteParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionByNameParams: retrieveSessionByNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     state.NewSession(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagDeleteItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
									Items: wire.FeedbagItems{
										{
											ItemID:  10,
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "buddy1",
											GroupID: 1,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "can't delete buddy from root group",
			screenName:     "userA",
			groupID:        "0",
			requestBody:    `{"name":"rootbuddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"can't add buddies to root group"}`,
		},
		{
			name:           "missing screen_name",
			screenName:     "",
			groupID:        "1",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"screen_name is required"}`,
		},
		{
			name:           "group not found",
			screenName:     "userA",
			groupID:        "999",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusNotFound,
			wantResponse:   `{"message":"group not found"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  1,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 0,
								},
							},
							err: nil,
						},
					},
				},
			},
		},
		{
			name:           "invalid group_id",
			screenName:     "userA",
			groupID:        "invalid",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"invalid group_id"}`,
		},
		{
			name:           "malformed request body",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `invalid json`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"buddy_screen_name is required"}`,
		},
		{
			name:           "missing name in request body",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{}`,
			wantStatusCode: http.StatusBadRequest,
			wantResponse:   `{"message":"buddy_screen_name is required"}`,
		},
		{
			name:           "buddy not found",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"nonexistent"}`,
			wantStatusCode: http.StatusNotFound,
			wantResponse:   `{"message":"buddy not found"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  1,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "otherbuddy",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
				},
			},
		},
		{
			name:           "internal server error on feedbag retrieval",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"buddy"}`,
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result:     nil,
							err:        errors.New("database error"),
						},
					},
				},
			},
		},
		{
			name:           "internal server error on delete",
			screenName:     "userA",
			groupID:        "1",
			requestBody:    `{"name":"buddy1"}`,
			wantStatusCode: http.StatusInternalServerError,
			wantResponse:   `{"message":"internal server error"}`,
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							result: wire.FeedbagItems{
								{
									ItemID:  1,
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "Friends",
									GroupID: 1,
								},
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
							},
							err: nil,
						},
					},
					feedbagDeleteParams: feedbagDeleteParams{
						{
							screenName: state.NewIdentScreenName("userA"),
							items: wire.FeedbagItems{
								{
									ItemID:  10,
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
									GroupID: 1,
								},
							},
							err: errors.New("database error"),
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Extract buddy name from requestBody JSON
			var buddyName string
			if tc.requestBody != "" {
				var input struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal([]byte(tc.requestBody), &input); err == nil {
					buddyName = input.Name
				}
			}
			request := httptest.NewRequest(http.MethodDelete, "/feedbag/"+tc.screenName+"/group/"+tc.groupID+"/buddy/"+buddyName, nil)
			if tc.screenName != "" {
				request.SetPathValue("screen_name", tc.screenName)
			}
			if tc.groupID != "" {
				request.SetPathValue("group_id", tc.groupID)
			}
			request.SetPathValue("buddy_screen_name", buddyName)
			responseRecorder := httptest.NewRecorder()

			feedbagManager := newMockFeedbagManager(t)
			sessionRetriever := newMockSessionRetriever(t)
			messageRelayer := newMockMessageRelayer(t)
			buddyBroadcaster := newMockBuddyBroadcaster(t)

			for _, params := range tc.mockParams.feedbagManagerParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			for _, params := range tc.mockParams.feedbagManagerParams.feedbagDeleteParams {
				feedbagManager.EXPECT().
					FeedbagDelete(matchContext(), params.screenName, params.items).
					Return(params.err)
			}
			for _, params := range tc.mockParams.sessionRetrieverParams.retrieveSessionByNameParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}
			for _, params := range tc.mockParams.messageRelayerParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(matchContext(), params.screenName, params.msg)
			}
			for _, params := range tc.mockParams.buddyBroadcasterParams.broadcastVisibilityParams {
				buddyBroadcaster.EXPECT().
					BroadcastVisibility(
						matchContext(),
						mock.AnythingOfType("*state.SessionInstance"),
						params.filter,
						params.sendDepartures,
					).
					Return(params.err)
			}

			deleteFeedbagBuddyHandler(responseRecorder, request, buddyBroadcaster, feedbagManager, sessionRetriever, messageRelayer, slog.Default())

			assert.Equal(t, tc.wantStatusCode, responseRecorder.Code)
			if tc.wantResponse != "" {
				assert.JSONEq(t, tc.wantResponse, responseRecorder.Body.String())
			}
		})
	}
}

