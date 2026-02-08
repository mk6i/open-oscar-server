package foodgroup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthService_BUCPLoginRequest(t *testing.T) {
	user := state.User{
		IdentScreenName:   state.NewIdentScreenName("screenName"),
		DisplayScreenName: "screenName",
		AuthKey:           "auth_key",
	}
	assert.NoError(t, user.HashPassword("the_password"))

	cases := []struct {
		// name is the unit test name
		name string
		// advertisedHost is the BOS host the client will connect to upon successful login
		advertisedHost string
		// cfg is the app configuration
		cfg config.Config
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNAC_0x17_0x02_BUCPLoginRequest
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// createAccount is the function that creates a new user account
		createAccount state.CreateAccountFunc
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
		// wantErr is the error we expect from the method
		wantErr error
		// maxConcurrentLoginsPerUser is the maximum concurrent logins per user (only set for MultiConnFlagsRecentClient tests)
		maxConcurrentLoginsPerUser int
	}{
		{
			name:           "AIM account exists, correct password, login OK, no concurrent logins",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
						wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName:    user.DisplayScreenName,
									MultiConnFlag: uint8(wire.MultiConnFlagsRecentClient),
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: user.IdentScreenName,
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
							wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			maxConcurrentLoginsPerUser: 2,
		},
		{
			name:           "AIM account exists, correct password, login OK, concurrent logins under limit",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
						wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName:    user.DisplayScreenName,
									MultiConnFlag: uint8(wire.MultiConnFlagsRecentClient),
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: user.IdentScreenName,
							result: func() *state.Session {
								// Create a session with 1 instance, under the limit
								sess := state.NewSession()
								sess.SetIdentScreenName(user.IdentScreenName)
								sess.SetDisplayScreenName(user.DisplayScreenName)
								sess.AddInstance()
								return sess
							}(),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
							wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			maxConcurrentLoginsPerUser: 2,
		},

		{
			name:           "login fails when concurrent login limit is reached",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
						wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: user.IdentScreenName,
							result: func() *state.Session {
								// Create a session with 2 instances (the max allowed)
								// This will cause InstanceCount() to return 2, which equals the limit of 2
								sess := state.NewSession()
								sess.SetIdentScreenName(user.IdentScreenName)
								sess.SetDisplayScreenName(user.DisplayScreenName)
								sess.AddInstance()
								sess.AddInstance()
								return sess
							}(),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: []wire.TLV{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrRateLimitExceeded),
						},
					},
				},
			},
			maxConcurrentLoginsPerUser: 2,
		},
		{
			name:           "ICQ account exists, correct password, login OK",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, "ICQ 2000b"),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
									ClientID:   "ICQ 2000b",
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
							wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
		},
		{
			name:           "AIM account exists, incorrect password, login fails",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, []byte("bad_password")),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: []wire.TLV{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidPassword),
						},
					},
				},
			},
		},
		{
			name:           "AIM account doesn't exist, login fails",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, []byte("password")),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("non_existent_screen_name")),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("non_existent_screen_name"),
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: []wire.TLV{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, state.NewIdentScreenName("non_existent_screen_name")),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword),
						},
					},
				},
			},
		},
		{
			name:           "AIM account is suspended",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, []byte("password")),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("suspended_screen_name")),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("suspended_screen_name"),
							result: &state.User{
								SuspendedStatus: wire.LoginErrSuspendedAccount,
							},
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: []wire.TLV{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, state.NewIdentScreenName("suspended_screen_name")),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrSuspendedAccount),
						},
					},
				},
			},
		},
		{
			name:           "ICQ account doesn't exist, login fails",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, []byte("password")),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("100003")),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: []wire.TLV{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, state.NewIdentScreenName("100003")),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrICQUserErr),
						},
					},
				},
			},
		},
		{
			name:           "account doesn't exist, authentication is disabled, account is created, login succeeds",
			advertisedHost: "127.0.0.1:5190",
			cfg: config.Config{
				DisableAuth: true,
			},
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     nil,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, user.DisplayScreenName, screenName)
				assert.Equal(t, "welcome1", password)
				return nil
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
							wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
		},
		{
			name:           "AIM account doesn't exist, authentication is disabled, screen name has bad format, login fails",
			advertisedHost: "127.0.0.1:5190",
			cfg: config.Config{
				DisableAuth: true,
			},
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, "2coolforschool"),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("2coolforschool"),
							result:     nil,
						},
					},
				},
			},
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("2coolforschool"), screenName)
				assert.Equal(t, "welcome1", password)
				return state.ErrAIMHandleInvalidFormat
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, state.NewIdentScreenName("2coolforschool")),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword),
						},
					},
				},
			},
		},
		{
			name:           "ICQ account doesn't exist, authentication is disabled, UIN has bad format, login fails",
			advertisedHost: "127.0.0.1:5190",
			cfg: config.Config{
				DisableAuth: true,
			},
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, "99"),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("99"),
							result:     nil,
						},
					},
				},
			},
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, state.DisplayScreenName("99"), screenName)
				assert.Equal(t, "welcome1", password)
				return state.ErrICQUINInvalidFormat
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, state.NewIdentScreenName("99")),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrICQUserErr),
						},
					},
				},
			},
		},
		{
			name:           "account exists, password is invalid, authentication is disabled, login succeeds",
			advertisedHost: "127.0.0.1:5190",
			cfg: config.Config{
				DisableAuth: true,
			},
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, []byte("bad-password-hash")),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
							wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
		},
		{
			name: "login fails on user manager lookup",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, user.StrongMD5Pass),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							err:        io.EOF,
						},
					},
				},
			},
			wantErr: io.EOF,
		},
		{
			name:           "login with TOC client - success",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, wire.RoastTOCPassword([]byte("the_password"))),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
							wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
							wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
		},
		{
			name:           "login with TOC client - failed",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x02_BUCPLoginRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, wire.RoastTOCPassword([]byte("the_wrong_password"))),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsScreenName, "screenName"),
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidPassword),
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			cookieBaker := newMockCookieBaker(t)
			for _, params := range tc.mockParams.cookieIssueParams {
				cookieBaker.EXPECT().
					Issue(params.dataIn).
					Return(params.cookieOut, params.err)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tc.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}

			svc := AuthService{
				config:                     tc.cfg,
				cookieBaker:                cookieBaker,
				userManager:                userManager,
				sessionRetriever:           sessionRetriever,
				maxConcurrentLoginsPerUser: 2,
				createAccount:              tc.createAccount,
				logger:                     slog.Default(),
			}
			outputSNAC, err := svc.BUCPLogin(context.Background(), tc.inputSNAC, tc.advertisedHost)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestAuthService_FLAPLogin(t *testing.T) {
	user := state.User{
		AuthKey:           "auth_key",
		DisplayScreenName: "screenName",
		IdentScreenName:   state.NewIdentScreenName("screenName"),
	}
	assert.NoError(t, user.HashPassword("the_password"))

	cases := []struct {
		// name is the unit test name
		name string
		// advertisedHost is the BOS host the client will connect to upon successful login
		advertisedHost string
		// cfg is the app configuration
		cfg config.Config
		// inputSNAC is the authentication FLAP frame sent from the client to the server
		inputSNAC wire.FLAPSignonFrame
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// createAccount is the function that creates a new user account
		createAccount state.CreateAccountFunc
		// expectOutput is the response sent from the server to client
		expectOutput wire.TLVRestBlock
		// wantErr is the error we expect from the method
		wantErr error
	}{
		{
			name:           "AIM account exists, correct password, login OK",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARPassword([]byte("the_password"))),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
					wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
					wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
				},
			},
		},
		{
			name:           "ICQ account exists, correct password, login OK",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, "ICQ 2000b"),
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARPassword([]byte("the_password"))),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
									ClientID:   "ICQ 2000b",
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
					wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
					wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
				},
			},
		},
		{
			name:           "AIM account exists, incorrect password, login fails",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, []byte("bad_roasted_password")),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: []wire.TLV{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidPassword),
				},
			},
		},
		{
			name:           "AIM account doesn't exist, login fails",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARPassword([]byte("the_password"))),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("non_existent_screen_name")),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("non_existent_screen_name"),
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: []wire.TLV{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, state.NewIdentScreenName("non_existent_screen_name")),
					wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword),
				},
			},
		},
		{
			name:           "ICQ account doesn't exist, login fails",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, "ICQ 2000b"),
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARPassword([]byte("the_password"))),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, []byte("100003")),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: []wire.TLV{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, state.NewIdentScreenName("100003")),
					wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrICQUserErr),
				},
			},
		},
		{
			name:           "account doesn't exist, authentication is disabled, account is created, login succeeds",
			advertisedHost: "127.0.0.1:5190",
			cfg: config.Config{
				DisableAuth: true,
			},
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARPassword([]byte("the_password"))),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     nil,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			createAccount: func(ctx context.Context, screenName state.DisplayScreenName, password string) error {
				assert.Equal(t, user.DisplayScreenName, screenName)
				assert.Equal(t, "welcome1", password)
				return nil
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
					wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
					wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
				},
			},
		},
		{
			name:           "account exists, password is invalid, authentication is disabled, login succeeds",
			advertisedHost: "127.0.0.1:5190",
			cfg: config.Config{
				DisableAuth: true,
			},
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, "bad-roasted-password"),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
					wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
					wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
				},
			},
		},
		{
			name: "login fails on user manager lookup",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARPassword([]byte("the_password"))),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							err:        io.EOF,
						},
					},
				},
			},
			wantErr: io.EOF,
		},
		{
			name:           "login with AIM 1.1.19 for Java - success",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, "AOL Instant Messenger (TM) version 1.1.19 for Java"),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARJavaPassword([]byte("the_password"))),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									ScreenName: user.DisplayScreenName,
									ClientID:   "AOL Instant Messenger (TM) version 1.1.19 for Java",
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
					wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "127.0.0.1:5190"),
					wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("the-cookie")),
					wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
				},
			},
		},
		{
			name:           "login with AIM 1.1.19 for Java - failed",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.FLAPSignonFrame{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, "AOL Instant Messenger (TM) version 1.1.19 for Java"),
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, user.DisplayScreenName),
						wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARJavaPassword([]byte("the_wrong_password"))),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
			},
			expectOutput: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsScreenName, "screenName"),
					wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidPassword),
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			cookieBaker := newMockCookieBaker(t)
			for _, params := range tc.mockParams.cookieIssueParams {
				cookieBaker.EXPECT().
					Issue(params.dataIn).
					Return(params.cookieOut, params.err)
			}
			svc := AuthService{
				config:        tc.cfg,
				cookieBaker:   cookieBaker,
				userManager:   userManager,
				createAccount: tc.createAccount,
				logger:        slog.Default(),
			}
			outputSNAC, err := svc.FLAPLogin(context.Background(), tc.inputSNAC, tc.advertisedHost)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestAuthService_KerberosLogin(t *testing.T) {
	user := state.User{
		AuthKey:           "auth_key",
		DisplayScreenName: "screenName",
		IdentScreenName:   state.NewIdentScreenName("screenName"),
	}
	assert.NoError(t, user.HashPassword("the_password"))

	cases := []struct {
		// name is the unit test name
		name string
		// advertisedHost is the BOS host the client will connect to upon successful login
		advertisedHost string
		// cfg is the app configuration
		cfg config.Config
		// inputSNAC is the kerberos SNAC sent from the client to the server
		inputSNAC wire.SNAC_0x050C_0x0002_KerberosLoginRequest
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// createAccount is the function that creates a new user account
		createAccount state.CreateAccountFunc
		// expectOutput is the response sent from the server to client
		expectOutput wire.SNACMessage
		// wantErr is the error we expect from the method
		wantErr error
		// timeNow returns a canned time value
		timeNow func() time.Time
	}{
		{
			name:           "AIM account exists, correct password, login OK",
			advertisedHost: "127.0.0.1:5190",
			timeNow: func() time.Time {
				return time.Unix(1000, 0)
			},
			inputSNAC: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
				RequestID:       54321,
				ClientPrincipal: user.DisplayScreenName.String(),
				TicketRequestMetadata: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.KerberosTLVTicketRequest, wire.KerberosLoginRequestTicket{
							Password: []byte("the_password"),
						}),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									Service:       wire.BOS,
									ScreenName:    user.DisplayScreenName,
									ClientID:      "",
									MultiConnFlag: uint8(wire.MultiConnFlagsRecentClient),
									KerberosAuth:  1,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: user.IdentScreenName,
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginSuccessResponse,
				},
				Body: wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse{
					RequestID:       54321,
					Epoch:           1000,
					ClientPrincipal: user.DisplayScreenName.String(),
					ClientRealm:     "AOL",
					Tickets: []wire.KerberosTicket{
						{
							PVNO:             0x5,
							EncTicket:        []uint8{},
							TicketRealm:      "AOL",
							ServicePrincipal: "im/boss",
							ClientRealm:      "AOL",
							ClientPrincipal:  user.DisplayScreenName.String(),
							AuthTime:         1000,
							StartTime:        1000,
							EndTime:          87400,
							Unknown4:         0x60000000,
							Unknown5:         0x40000000,
							ConnectionMetadata: wire.TLVBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.KerberosTLVBOSServerInfo, wire.KerberosBOSServerInfo{
										Unknown: 1,
										ConnectionInfo: wire.TLVBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.KerberosTLVHostname, "127.0.0.1:5190"),
												wire.NewTLVBE(wire.KerberosTLVCookie, []byte("the-cookie")),
												wire.NewTLVBE(wire.KerberosTLVConnSettings, wire.KerberosConnUseSSL),
											},
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "AIM account exists, incorrect password, login failed",
			advertisedHost: "127.0.0.1:5190",
			timeNow: func() time.Time {
				return time.Unix(1000, 0)
			},
			inputSNAC: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
				RequestID:       54321,
				ClientPrincipal: user.DisplayScreenName.String(),
				TicketRequestMetadata: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.KerberosTLVTicketRequest, wire.KerberosLoginRequestTicket{
							Password: []byte("the_WRONG_password"),
						}),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosKerberosLoginErrResponse,
				},
				Body: wire.SNAC_0x050C_0x0004_KerberosLoginErrResponse{
					KerbRequestID: 54321,
					ScreenName:    user.DisplayScreenName.String(),
					ErrCode:       wire.KerberosErrAuthFailure,
					Message:       "Auth failure",
				},
			},
		},
		{
			name:           "AIM account exists, correct roasted password, login OK",
			advertisedHost: "127.0.0.1:5190",
			timeNow: func() time.Time {
				return time.Unix(1000, 0)
			},
			inputSNAC: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
				RequestID:       54321,
				ClientPrincipal: user.DisplayScreenName.String(),
				TicketRequestMetadata: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.KerberosTLVTicketRequest, wire.KerberosLoginRequestTicket{
							Version:  4,
							Password: wire.RoastKerberosPassword([]byte("the_password")),
						}),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: func() []byte {
								loginCookie := state.ServerCookie{
									Service:       wire.BOS,
									ScreenName:    user.DisplayScreenName,
									ClientID:      "",
									MultiConnFlag: uint8(wire.MultiConnFlagsRecentClient),
									KerberosAuth:  1,
								}
								buf := &bytes.Buffer{}
								assert.NoError(t, wire.MarshalBE(loginCookie, buf))
								return buf.Bytes()
							}(),
							cookieOut: []byte("the-cookie"),
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: user.IdentScreenName,
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginSuccessResponse,
				},
				Body: wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse{
					RequestID:       54321,
					Epoch:           1000,
					ClientPrincipal: user.DisplayScreenName.String(),
					ClientRealm:     "AOL",
					Tickets: []wire.KerberosTicket{
						{
							PVNO:             0x5,
							EncTicket:        []uint8{},
							TicketRealm:      "AOL",
							ServicePrincipal: "im/boss",
							ClientRealm:      "AOL",
							ClientPrincipal:  user.DisplayScreenName.String(),
							AuthTime:         1000,
							StartTime:        1000,
							EndTime:          87400,
							Unknown4:         0x60000000,
							Unknown5:         0x40000000,
							ConnectionMetadata: wire.TLVBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.KerberosTLVBOSServerInfo, wire.KerberosBOSServerInfo{
										Unknown: 1,
										ConnectionInfo: wire.TLVBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.KerberosTLVHostname, "127.0.0.1:5190"),
												wire.NewTLVBE(wire.KerberosTLVCookie, []byte("the-cookie")),
												wire.NewTLVBE(wire.KerberosTLVConnSettings, wire.KerberosConnUseSSL),
											},
										},
									}),
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "AIM account exists, incorrect roasted password, login failed",
			advertisedHost: "127.0.0.1:5190",
			timeNow: func() time.Time {
				return time.Unix(1000, 0)
			},
			inputSNAC: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
				RequestID:       54321,
				ClientPrincipal: user.DisplayScreenName.String(),
				TicketRequestMetadata: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.KerberosTLVTicketRequest, wire.KerberosLoginRequestTicket{
							Version:  4,
							Password: wire.RoastKerberosPassword([]byte("the_WRONG_password")),
						}),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: user.IdentScreenName,
							result:     &user,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosKerberosLoginErrResponse,
				},
				Body: wire.SNAC_0x050C_0x0004_KerberosLoginErrResponse{
					KerbRequestID: 54321,
					ScreenName:    user.DisplayScreenName.String(),
					ErrCode:       wire.KerberosErrAuthFailure,
					Message:       "Auth failure",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			cookieBaker := newMockCookieBaker(t)
			for _, params := range tc.mockParams.cookieIssueParams {
				cookieBaker.EXPECT().
					Issue(params.dataIn).
					Return(params.cookieOut, params.err)
			}
			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tc.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}
			svc := AuthService{
				config:                     tc.cfg,
				cookieBaker:                cookieBaker,
				userManager:                userManager,
				sessionRetriever:           sessionRetriever,
				timeNow:                    tc.timeNow,
				maxConcurrentLoginsPerUser: 2,
				createAccount:              tc.createAccount,
				logger:                     slog.Default(),
			}
			outputSNAC, err := svc.KerberosLogin(context.Background(), tc.inputSNAC, tc.advertisedHost)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestAuthService_BUCPChallengeRequest(t *testing.T) {
	sessUUID := uuid.UUID{1, 2, 3}
	cases := []struct {
		// name is the unit test name
		name string
		// advertisedHost is the BOS host the client will connect to upon successful login
		advertisedHost string
		// cfg is the app configuration
		cfg config.Config
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNAC_0x17_0x06_BUCPChallengeRequest
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
		// wantErr is the error we expect from the method
		wantErr error
	}{
		{
			name:           "login with valid username, expect OK login response",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x06_BUCPChallengeRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, "sn_user_a"),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("sn_user_a"),
							result: &state.User{
								IdentScreenName: state.NewIdentScreenName("sn_user_a"),
								AuthKey:         "auth_key_user_a",
							},
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPChallengeResponse,
				},
				Body: wire.SNAC_0x17_0x07_BUCPChallengeResponse{
					AuthKey: "auth_key_user_a",
				},
			},
		},
		{
			name:           "login with invalid username, expect OK login response (Cfg.DisableAuth=true)",
			advertisedHost: "127.0.0.1:5190",
			cfg: config.Config{
				DisableAuth: true,
			},
			inputSNAC: wire.SNAC_0x17_0x06_BUCPChallengeRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, "sn_user_b"),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("sn_user_b"),
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPChallengeResponse,
				},
				Body: wire.SNAC_0x17_0x07_BUCPChallengeResponse{
					AuthKey: sessUUID.String(),
				},
			},
		},
		{
			name:           "login with invalid username, expect failed login response (Cfg.DisableAuth=false)",
			advertisedHost: "127.0.0.1:5190",
			inputSNAC: wire.SNAC_0x17_0x06_BUCPChallengeRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, "sn_user_b"),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("sn_user_b"),
							result:     nil,
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, uint16(0x01)),
						},
					},
				},
			},
		},
		{
			name: "login fails on user manager lookup",
			inputSNAC: wire.SNAC_0x17_0x06_BUCPChallengeRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsScreenName, "sn_user_b"),
					},
				},
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("sn_user_b"),
							err:        io.EOF,
						},
					},
				},
			},
			wantErr: io.EOF,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			svc := AuthService{
				config:      tc.cfg,
				userManager: userManager,
				logger:      slog.Default(),
			}
			fnNewUUID := func() uuid.UUID {
				return sessUUID
			}
			outputSNAC, err := svc.BUCPChallenge(context.Background(), tc.inputSNAC, fnNewUUID)
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestAuthService_RegisterChatSession_HappyPath(t *testing.T) {
	instance := newTestInstance("ScreenName")

	serverCookie := state.ServerCookie{
		ChatCookie: "the-chat-cookie",
		ScreenName: instance.DisplayScreenName(),
	}

	chatSessionRegistry := newMockChatSessionRegistry(t)
	chatSessionRegistry.EXPECT().
		AddSession(mock.Anything, serverCookie.ChatCookie, instance.DisplayScreenName()).
		Return(instance, nil)

	chatCookieBuf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(serverCookie, chatCookieBuf))

	svc := NewAuthService(config.Config{}, nil, nil, chatSessionRegistry, nil, nil, nil, nil, nil, wire.DefaultRateLimitClasses(), nil, slog.Default())

	have, err := svc.RegisterChatSession(context.Background(), serverCookie)
	assert.NoError(t, err)
	assert.Equal(t, instance, have)
}

func TestAuthService_RegisterBOSSession(t *testing.T) {
	screenName := state.DisplayScreenName("UserScreenName")
	aimAuthCookie := state.ServerCookie{
		ScreenName: screenName,
	}
	uin := state.DisplayScreenName("100003")
	icqAuthCookie := state.ServerCookie{
		ScreenName: uin,
	}

	cases := []struct {
		// name is the unit test name
		name string
		// cookieOut is the auth cookieOut that contains session information
		cookie state.ServerCookie
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantSess asserts the values of one or more session properties
		wantSess func(*state.SessionInstance) bool
		// wantErr is the error we expect from the method
		wantErr error
	}{
		{
			name:   "successfully register an AIM session",
			cookie: aimAuthCookie,
			mockParams: mockParams{
				sessionRegistryParams: sessionRegistryParams{
					addSessionParams: addSessionParams{
						{
							screenName:  screenName,
							doMultiSess: false,
							result:      newTestInstance(screenName),
						},
					},
				},
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: screenName.IdentScreenName(),
							result: &state.User{
								IdentScreenName:   screenName.IdentScreenName(),
								DisplayScreenName: screenName,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					accountManagerConfirmStatusParams: accountManagerConfirmStatusParams{
						{
							screenName:    screenName.IdentScreenName(),
							confirmStatus: true,
						},
					},
				},
				bartItemManagerParams: bartItemManagerParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: screenName.IdentScreenName(),
							result: &wire.BARTID{
								Type: wire.BARTTypesBuddyIcon,
								BARTInfo: wire.BARTInfo{
									Flags: wire.BARTFlagsKnown,
									Hash:  []byte{'m', 'y', 'i', 'c', 'o', 'n'},
								},
							},
						},
					},
				},
			},
			wantSess: func(instance *state.SessionInstance) bool {
				want := wire.BARTID{
					Type: wire.BARTTypesBuddyIcon,
					BARTInfo: wire.BARTInfo{
						Flags: wire.BARTFlagsKnown,
						Hash:  []byte{'m', 'y', 'i', 'c', 'o', 'n'},
					},
				}
				has, hasIcon := instance.Session().BuddyIcon()
				return assert.True(t, hasIcon) && assert.Equal(t, want, has)
			},
		},
		{
			name:   "successfully register an AIM bot session",
			cookie: aimAuthCookie,
			mockParams: mockParams{
				sessionRegistryParams: sessionRegistryParams{
					addSessionParams: addSessionParams{
						{
							screenName:  screenName,
							doMultiSess: false,
							result:      newTestInstance(screenName),
						},
					},
				},
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: screenName.IdentScreenName(),
							result: &state.User{
								IdentScreenName:   screenName.IdentScreenName(),
								DisplayScreenName: screenName,
								IsBot:             true,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					accountManagerConfirmStatusParams: accountManagerConfirmStatusParams{
						{
							screenName:    screenName.IdentScreenName(),
							confirmStatus: true,
						},
					},
				},
				bartItemManagerParams: bartItemManagerParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: screenName.IdentScreenName(),
							result:     nil,
						},
					},
				},
			},
			wantSess: func(instance *state.SessionInstance) bool {
				return instance.Session().AllUserInfoBitmask(wire.OServiceUserFlagBot)
			},
		},
		{
			name:   "successfully register an ICQ session",
			cookie: icqAuthCookie,
			mockParams: mockParams{
				sessionRegistryParams: sessionRegistryParams{
					addSessionParams: addSessionParams{
						{
							screenName: uin,
							result:     newTestInstance(uin),
						},
					},
				},
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{
							screenName: uin.IdentScreenName(),
							result: &state.User{
								IdentScreenName:   uin.IdentScreenName(),
								DisplayScreenName: uin,
							},
						},
					},
				},
				accountManagerParams: accountManagerParams{
					accountManagerConfirmStatusParams: accountManagerConfirmStatusParams{
						{
							screenName:    uin.IdentScreenName(),
							confirmStatus: true,
						},
					},
				},
				bartItemManagerParams: bartItemManagerParams{
					buddyIconMetadataParams: buddyIconMetadataParams{
						{
							screenName: uin.IdentScreenName(),
							result:     nil,
						},
					},
				},
			},
			wantSess: func(instance *state.SessionInstance) bool {
				uinMatches := fmt.Sprintf("%d", instance.UIN()) == uin.String()
				flagsMatch := instance.Session().AllUserInfoBitmask(wire.OServiceUserFlagICQ)
				return uinMatches && flagsMatch
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessionRegistry := newMockSessionRegistry(t)
			for _, params := range tc.mockParams.addSessionParams {
				sessionRegistry.EXPECT().
					AddSession(mock.Anything, params.screenName, params.doMultiSess).
					Return(params.result, params.err)
			}
			userManager := newMockUserManager(t)
			for _, params := range tc.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, nil)
			}
			accountManager := newMockAccountManager(t)
			for _, params := range tc.mockParams.accountManagerConfirmStatusParams {
				accountManager.EXPECT().
					ConfirmStatus(matchContext(), params.screenName).
					Return(params.confirmStatus, nil)
			}
			bartItemManager := newMockBARTItemManager(t)
			for _, params := range tc.mockParams.buddyIconMetadataParams {
				bartItemManager.EXPECT().
					BuddyIconMetadata(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			svc := NewAuthService(config.Config{}, sessionRegistry, nil, nil, userManager, nil, nil, accountManager, bartItemManager, wire.DefaultRateLimitClasses(), nil, slog.Default())

			have, err := svc.RegisterBOSSession(context.Background(), tc.cookie)
			assert.NoError(t, err)

			if tc.wantSess != nil {
				assert.True(t, tc.wantSess(have))
			}
		})
	}

}

func TestAuthService_RetrieveBOSSession_HappyPath(t *testing.T) {
	instance := newTestInstance("screenName", sessOptSignonComplete)

	aimAuthCookie := state.ServerCookie{
		ScreenName: instance.DisplayScreenName(),
		SessionNum: instance.Num(),
	}

	sessionRetriever := newMockSessionRetriever(t)
	sessionRetriever.EXPECT().
		RetrieveSession(instance.IdentScreenName()).
		Return(instance.Session())

	userManager := newMockUserManager(t)
	userManager.EXPECT().
		User(matchContext(), instance.IdentScreenName()).
		Return(&state.User{IdentScreenName: instance.IdentScreenName()}, nil)

	svc := NewAuthService(config.Config{}, nil, sessionRetriever, nil, userManager, nil, nil, nil, nil, wire.DefaultRateLimitClasses(), nil, slog.Default())

	have, err := svc.RetrieveBOSSession(context.Background(), aimAuthCookie)
	assert.NoError(t, err)
	assert.Equal(t, instance, have)
}

func TestAuthService_RetrieveBOSSession_SessionNotFound(t *testing.T) {
	instance := newTestInstance("screenName")

	aimAuthCookie := state.ServerCookie{
		ScreenName: instance.DisplayScreenName(),
		SessionNum: instance.Num(),
	}

	sessionRetriever := newMockSessionRetriever(t)
	sessionRetriever.EXPECT().
		RetrieveSession(instance.IdentScreenName()).
		Return(nil)

	userManager := newMockUserManager(t)
	userManager.EXPECT().
		User(matchContext(), instance.IdentScreenName()).
		Return(&state.User{IdentScreenName: instance.IdentScreenName()}, nil)

	svc := NewAuthService(config.Config{}, nil, sessionRetriever, nil, userManager, nil, nil, nil, nil, wire.DefaultRateLimitClasses(), nil, slog.Default())

	have, err := svc.RetrieveBOSSession(context.Background(), aimAuthCookie)
	assert.NoError(t, err)
	assert.Nil(t, have)
}

func TestAuthService_SignoutChat(t *testing.T) {
	tests := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user signing out
		instance *state.SessionInstance
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "user signs out of chat room, room is empty after user leaves",
			instance: newTestInstance("me", sessOptCannedSignonTime, sessOptChatRoomCookie("the-chat-cookie")),
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatUsersLeft,
								},
								Body: wire.SNAC_0x0E_0x04_ChatUsersLeft{
									Users: []wire.TLVUserInfo{
										newTestInstance("me", sessOptCannedSignonTime, sessOptChatRoomCookie("the-chat-cookie")).Session().TLVUserInfo(),
									},
								},
							},
						},
					},
				},
				sessionRegistryParams: sessionRegistryParams{
					removeSessionParams: removeSessionParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
				},
			},
		},
		{
			name:     "user signs out of chat room, room is not empty after user leaves",
			instance: newTestInstance("me", sessOptCannedSignonTime, sessOptChatRoomCookie("the-chat-cookie")),
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatUsersLeft,
								},
								Body: wire.SNAC_0x0E_0x04_ChatUsersLeft{
									Users: []wire.TLVUserInfo{
										newTestInstance("me", sessOptCannedSignonTime, sessOptChatRoomCookie("the-chat-cookie")).Session().TLVUserInfo(),
									},
								},
							},
						},
					},
				},
				sessionRegistryParams: sessionRegistryParams{
					removeSessionParams: removeSessionParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chatMessageRelayer := newMockChatMessageRelayer(t)
			for _, params := range tt.mockParams.chatRelayToAllExceptParams {
				chatMessageRelayer.EXPECT().
					RelayToAllExcept(matchContext(), tt.instance.ChatRoomCookie(), params.screenName, params.message)
			}
			sessionManager := newMockChatSessionRegistry(t)
			for _, params := range tt.mockParams.removeSessionParams {
				sessionManager.EXPECT().
					RemoveSession(matchSession(params.screenName))
			}

			svc := NewAuthService(config.Config{}, nil, nil, sessionManager, nil, nil, chatMessageRelayer, nil, nil, wire.DefaultRateLimitClasses(), nil, slog.Default())
			svc.SignoutChat(context.Background(), tt.instance)
		})
	}
}

func TestAuthService_Signout(t *testing.T) {
	tests := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user signing out
		instance *state.SessionInstance
		// wantErr is the error we expect from the method
		wantErr error
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "user signs out of chat room, room is empty after user leaves",
			instance: newTestInstance("me", sessOptCannedSignonTime),
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyDepartedParams: broadcastBuddyDepartedParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
				},
				sessionRegistryParams: sessionRegistryParams{
					removeSessionParams: removeSessionParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionManager := newMockSessionRegistry(t)
			for _, params := range tt.mockParams.removeSessionParams {
				sessionManager.EXPECT().RemoveSession(matchSession(params.screenName))
			}
			svc := NewAuthService(config.Config{}, sessionManager, nil, nil, nil, nil, nil, nil, nil, wire.DefaultRateLimitClasses(), nil, slog.Default())

			svc.Signout(context.Background(), tt.instance)
		})
	}
}
