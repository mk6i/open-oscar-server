package toc

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/errgroup"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestOSCARProxy_RecvClientCmd_AddBuddy(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully add buddies",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_buddy friend1 friend2 friend3"),
			mockParams: mockParams{
				buddyParams: buddyParams{
					addBuddiesParams: addBuddiesParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x03_0x04_BuddyAddBuddies{
								Buddies: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
									{ScreenName: "friend2"},
									{ScreenName: "friend3"},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "add buddies with empty list",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_buddy"),
			mockParams: mockParams{
				buddyParams: buddyParams{
					addBuddiesParams: addBuddiesParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x03_0x04_BuddyAddBuddies{},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "add buddies, receive error from buddy service",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_buddy friend1"),
			mockParams: mockParams{
				buddyParams: buddyParams{
					addBuddiesParams: addBuddiesParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x03_0x04_BuddyAddBuddies{
								Buddies: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			buddySvc := newMockBuddyService(t)
			for _, params := range tc.mockParams.addBuddiesParams {
				buddySvc.EXPECT().
					AddBuddies(ctx, matchSession(params.me), mock.Anything, params.inBody).
					Return(nil, params.err)
			}

			svc := OSCARProxy{
				Logger:       slog.Default(),
				BuddyService: buddySvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_AddPermit(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully permit buddies",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_permit friend1 friend2 friend3"),
			mockParams: mockParams{
				permitDenyParams: permitDenyParams{
					addPermListEntriesParams: addPermListEntriesParams{
						{
							me: state.NewIdentScreenName("me"),
							body: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
								Users: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
									{ScreenName: "friend2"},
									{ScreenName: "friend3"},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "permit buddies, receive error from buddy service",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_permit friend1"),
			mockParams: mockParams{
				permitDenyParams: permitDenyParams{
					addPermListEntriesParams: addPermListEntriesParams{
						{
							me: state.NewIdentScreenName("me"),
							body: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
								Users: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "permit buddies with empty list",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_permit"),
			mockParams: mockParams{
				permitDenyParams: permitDenyParams{
					addPermListEntriesParams: addPermListEntriesParams{
						{
							me:   state.NewIdentScreenName("me"),
							body: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{},
						},
					},
				},
			},
			wantMsg: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			pdSvc := newMockPermitDenyService(t)
			for _, params := range tc.mockParams.addPermListEntriesParams {
				pdSvc.EXPECT().
					AddPermListEntries(ctx, matchSession(params.me), params.body).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:            slog.Default(),
				PermitDenyService: pdSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_AddDeny(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully deny buddies",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_deny friend1 friend2 friend3"),
			mockParams: mockParams{
				permitDenyParams: permitDenyParams{
					addDenyListEntriesParams: addDenyListEntriesParams{
						{
							me: state.NewIdentScreenName("me"),
							body: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
								Users: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
									{ScreenName: "friend2"},
									{ScreenName: "friend3"},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "deny buddies, receive error from buddy service",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_deny friend1"),
			mockParams: mockParams{
				permitDenyParams: permitDenyParams{
					addDenyListEntriesParams: addDenyListEntriesParams{
						{
							me: state.NewIdentScreenName("me"),
							body: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
								Users: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "deny buddies with empty list",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_add_deny"),
			mockParams: mockParams{
				permitDenyParams: permitDenyParams{
					addDenyListEntriesParams: addDenyListEntriesParams{
						{
							me:   state.NewIdentScreenName("me"),
							body: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{},
						},
					},
				},
			},
			wantMsg: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			pdSvc := newMockPermitDenyService(t)
			for _, params := range tc.mockParams.addDenyListEntriesParams {
				pdSvc.EXPECT().
					AddDenyListEntries(ctx, matchSession(params.me), params.body).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:            slog.Default(),
				PermitDenyService: pdSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_FormatNickname(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully change screen name format",
			me:       newTestSession("myScreenName"),
			givenCmd: []byte("toc_format_nickname mYsCrEeNnAmE"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("myScreenName"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "mYsCrEeNnAmE"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "mYsCrEeNnAmE"),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ADMIN_NICK_STATUS:0", "NICK:mYsCrEeNnAmE"},
		},
		{
			name:     "format nickname - invalid length",
			me:       newTestSession("sn"),
			givenCmd: []byte("toc_format_nickname sN"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("sn"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "sN"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorInvalidNickNameLength),
											wire.NewTLVBE(wire.AdminTLVUrl, ""),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:911"},
		},
		{
			name:     "format nickname - invalid screen name",
			me:       newTestSession("sn"),
			givenCmd: []byte("toc_format_nickname sN"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("sn"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "sN"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorInvalidNickName),
											wire.NewTLVBE(wire.AdminTLVUrl, ""),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:911"},
		},
		{
			name:     "format nickname - catch-all error",
			me:       newTestSession("sn"),
			givenCmd: []byte("toc_format_nickname sN"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("sn"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "sN"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorValidateNickName),
											wire.NewTLVBE(wire.AdminTLVUrl, ""),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:913"},
		},
		{
			name:     "format nickname - runtime error from admin svc",
			me:       newTestSession("myScreenName"),
			givenCmd: []byte("toc_format_nickname mYsCrEeNnAmE"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("myScreenName"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "mYsCrEeNnAmE"),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "change password - unexpected response from admin svc",
			me:       newTestSession("myScreenName"),
			givenCmd: []byte("toc_format_nickname mYsCrEeNnAmE"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("myScreenName"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "mYsCrEeNnAmE"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNACError{},
							},
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_format_nickname`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			adminSvc := newMockAdminService(t)
			for _, params := range tc.mockParams.infoChangeRequestParams {
				adminSvc.EXPECT().
					InfoChangeRequest(ctx, matchSession(params.me), wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				Logger:       slog.Default(),
				AdminService: adminSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatAccept(t *testing.T) {
	navInfo := wire.SNACMessage{
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Cookie: "the-cookie",
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ChatRoomTLVRoomName, "cool room"),
							},
						},
					}),
				},
			},
		},
	}
	svcReq := wire.SNAC_0x01_0x04_OServiceServiceRequest{
		FoodGroup: wire.Chat,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
					Cookie: "the-cookie",
				}),
			},
		},
	}
	svcResp := wire.SNACMessage{
		Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, "chat-auth-cookie"),
				},
			},
		},
	}

	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// givenChatRegistry is the chat registry passed to the function
		givenChatRegistry *ChatRegistry
		// wantMsg is the expected TOC response
		wantMsg []string
		// expectChatSession indicates whether a chat session should be present
		// in the chat registry
		expectChatSession bool
		// checkSession validates the state of the registered chat session (chat ID 0)
		checkSession func(*testing.T, *state.SessionInstance)
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully accept chat",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_accept 0`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Cookie:   "the-cookie",
					Exchange: 4,
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					requestRoomInfoParams: requestRoomInfoParams{
						{
							inBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
								Cookie:         "the-cookie",
								Exchange:       4,
								InstanceNumber: 0,
							},
							msg: navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
					clientOnlineParams: clientOnlineParams{
						{
							body: wire.SNAC_0x01_0x02_OServiceClientOnline{},
							me:   state.NewIdentScreenName("me"),
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
						},
					},
				},
			},
			wantMsg:           []string{"CHAT_JOIN:0:cool room"},
			expectChatSession: true,
		},
		{
			name:     "accept chat - TOC2 with encoded messaging propagates to chat session",
			me:       newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) }),
			givenCmd: []byte(`toc_chat_accept 0`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Cookie:   "the-cookie",
					Exchange: 4,
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					requestRoomInfoParams: requestRoomInfoParams{
						{
							inBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
								Cookie:         "the-cookie",
								Exchange:       4,
								InstanceNumber: 0,
							},
							msg: navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
					clientOnlineParams: clientOnlineParams{
						{
							body: wire.SNAC_0x01_0x02_OServiceClientOnline{},
							me:   state.NewIdentScreenName("me"),
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
						},
					},
				},
			},
			wantMsg:           []string{"CHAT_JOIN:0:cool room"},
			expectChatSession: true,
			checkSession: func(t *testing.T, sess *state.SessionInstance) {
				assert.NotNil(t, sess, "chat session should be registered")
				assert.True(t, sess.IsTOC2(), "chat session should have TOC2 set")
				assert.True(t, sess.SupportsTOC2MsgEnc(), "chat session should have TOC2 msg enc set")
			},
		},
		{
			name:     "accept chat, receive error from client online",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_accept 0`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Cookie:   "the-cookie",
					Exchange: 4,
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					requestRoomInfoParams: requestRoomInfoParams{
						{
							inBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
								Cookie:         "the-cookie",
								Exchange:       4,
								InstanceNumber: 0,
							},
							msg: navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
					clientOnlineParams: clientOnlineParams{
						{
							body: wire.SNAC_0x01_0x02_OServiceClientOnline{},
							me:   state.NewIdentScreenName("me"),
							err:  io.EOF,
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:     "accept chat, receive error from register chat session",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_accept 0`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Cookie:   "the-cookie",
					Exchange: 4,
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					requestRoomInfoParams: requestRoomInfoParams{
						{
							inBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
								Cookie:         "the-cookie",
								Exchange:       4,
								InstanceNumber: 0,
							},
							msg: navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
							err:        io.EOF,
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:     "accept chat, receive error from BOS oservice svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_accept 0`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Cookie:   "the-cookie",
					Exchange: 4,
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					requestRoomInfoParams: requestRoomInfoParams{
						{
							inBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
								Cookie:         "the-cookie",
								Exchange:       4,
								InstanceNumber: 0,
							},
							msg: navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							err:    io.EOF,
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:     "accept chat, receive error from chat nav svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_accept 0`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Cookie:   "the-cookie",
					Exchange: 4,
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					requestRoomInfoParams: requestRoomInfoParams{
						{
							inBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
								Cookie:         "the-cookie",
								Exchange:       4,
								InstanceNumber: 0,
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:              "bad command",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_accept`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:              "bad exchange number",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_accept four`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			chatNavSvc := newMockChatNavService(t)
			for _, params := range tc.mockParams.requestRoomInfoParams {
				chatNavSvc.EXPECT().
					RequestRoomInfo(ctx, wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}
			oServiceSvc := newMockOServiceService(t)
			for _, params := range tc.mockParams.oServiceParams.serviceRequestParams {
				oServiceSvc.EXPECT().
					ServiceRequest(ctx, wire.BOS, matchSession(params.me), wire.SNACFrame{}, params.bodyIn, config.Listener{}).
					Return(params.msg, params.err)
			}
			for _, params := range tc.mockParams.oServiceParams.clientOnlineParams {
				oServiceSvc.EXPECT().
					ClientOnline(ctx, wire.Chat, params.body, matchSession(params.me)).
					Return(params.err)
			}
			authSvc := newMockAuthService(t)
			for _, params := range tc.mockParams.authParams.registerChatSessionParams {
				authSvc.EXPECT().
					RegisterChatSession(ctx, params.authCookie, mock.Anything).
					Return(params.instance, params.err)
			}
			for _, params := range tc.mockParams.authParams.crackCookieParams {
				authSvc.EXPECT().
					CrackCookie(params.cookieIn).
					Return(params.cookieOut, params.err)
			}

			svc := OSCARProxy{
				AuthService:     authSvc,
				ChatNavService:  chatNavSvc,
				Logger:          slog.Default(),
				OServiceService: oServiceSvc,
			}

			g := &errgroup.Group{}
			tc.me.CloseInstance()

			msg := svc.RecvClientCmd(ctx, tc.me, tc.givenChatRegistry, tc.givenCmd, nil, g.Go)

			assert.NoError(t, g.Wait())
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.expectChatSession, len(tc.givenChatRegistry.Sessions()) == 1)
			if tc.checkSession != nil {
				tc.checkSession(t, tc.givenChatRegistry.RetrieveSess(0))
			}
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatInvite(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// givenChatRegistry is the chat registry passed to the function
		givenChatRegistry *ChatRegistry
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully send chat invitation",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_invite 0 "join my chat! :\)" friend1`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Exchange: 4,
					Cookie:   "the-cookie",
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelRendezvous,
								ScreenName: "friend1",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(0x05, wire.ICBMCh2Fragment{
											Type:       0,
											Capability: wire.CapChat,
											TLVRestBlock: wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(10, uint16(1)),
													wire.NewTLVBE(12, "join my chat! :)"),
													wire.NewTLVBE(13, "us-ascii"),
													wire.NewTLVBE(14, "en"),
													wire.NewTLVBE(10001, wire.ICBMRoomInfo{
														Exchange: 4,
														Cookie:   "the-cookie",
														Instance: 0,
													}),
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
			wantMsg: []string{},
		},
		{
			name:     "send chat invitation, receive error from ICBM svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_invite 0 "join my chat!" friend1`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.Add(wire.ICBMRoomInfo{
					Exchange: 4,
					Cookie:   "the-cookie",
					Instance: 0,
				})
				return reg
			}(),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelRendezvous,
								ScreenName: "friend1",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(0x05, wire.ICBMCh2Fragment{
											Type:       0,
											Capability: wire.CapChat,
											TLVRestBlock: wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(10, uint16(1)),
													wire.NewTLVBE(12, "join my chat!"),
													wire.NewTLVBE(13, "us-ascii"),
													wire.NewTLVBE(14, "en"),
													wire.NewTLVBE(10001, wire.ICBMRoomInfo{
														Exchange: 4,
														Cookie:   "the-cookie",
														Instance: 0,
													}),
												},
											},
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:              "send chat invitation to non-existent room",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_invite 0 "join my chat!" friend1`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
		},
		{
			name:     "bad chat room ID",
			givenCmd: []byte(`toc_chat_invite zero "join my chat!" friend1`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_invite`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			icbmSvc := newMockICBMService(t)
			for _, params := range tc.mockParams.channelMsgToHostParamsICBM {
				icbmSvc.EXPECT().
					ChannelMsgToHost(ctx, matchSession(params.sender), wire.SNACFrame{}, params.inBody).
					Return(nil, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ICBMService: icbmSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, tc.givenChatRegistry, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatJoin(t *testing.T) {
	roomInfo := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
		Exchange: 4,
		Cookie:   "create",
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ChatRoomTLVRoomName, "cool room :)"),
			},
		},
	}
	navInfo := wire.SNACMessage{
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Cookie: "the-cookie",
					}),
				},
			},
		},
	}
	svcReq := wire.SNAC_0x01_0x04_OServiceServiceRequest{
		FoodGroup: wire.Chat,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
					Cookie: "the-cookie",
				}),
			},
		},
	}
	svcResp := wire.SNACMessage{
		Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, "chat-auth-cookie"),
				},
			},
		},
	}

	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// givenChatRegistry is the chat registry passed to the function
		givenChatRegistry *ChatRegistry
		// wantMsg is the expected TOC response
		wantMsg []string
		// expectChatSession indicates whether a chat session should be present
		// in the chat registry
		expectChatSession bool
		// checkSession validates the state of the registered chat session (chat ID 0)
		checkSession func(*testing.T, *state.SessionInstance)
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:              "successfully join chat",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_join 4 "cool room :\)"`),
			givenChatRegistry: NewChatRegistry(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					createRoomParams: createRoomParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: roomInfo,
							msg:    navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
					clientOnlineParams: clientOnlineParams{
						{
							body: wire.SNAC_0x01_0x02_OServiceClientOnline{},
							me:   state.NewIdentScreenName("me"),
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
						},
					},
				},
			},
			wantMsg:           []string{"CHAT_JOIN:0:cool room :)"},
			expectChatSession: true,
		},
		{
			name:              "successfully join chat - TOC2 with encoded messaging propagates to chat session",
			me:                newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) }),
			givenCmd:          []byte(`toc_chat_join 4 "cool room :\)"`),
			givenChatRegistry: NewChatRegistry(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					createRoomParams: createRoomParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: roomInfo,
							msg:    navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
					clientOnlineParams: clientOnlineParams{
						{
							body: wire.SNAC_0x01_0x02_OServiceClientOnline{},
							me:   state.NewIdentScreenName("me"),
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
						},
					},
				},
			},
			wantMsg:           []string{"CHAT_JOIN:0:cool room :)"},
			expectChatSession: true,
			checkSession: func(t *testing.T, sess *state.SessionInstance) {
				assert.NotNil(t, sess, "chat session should be registered")
				assert.True(t, sess.IsTOC2(), "chat session should have TOC2 set")
				assert.True(t, sess.SupportsTOC2MsgEnc(), "chat session should have TOC2 msg enc set")
			},
		},
		{
			name:              "accept chat, receive error from client online",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_join 4 "cool room :\)"`),
			givenChatRegistry: NewChatRegistry(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					createRoomParams: createRoomParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: roomInfo,
							msg:    navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
					clientOnlineParams: clientOnlineParams{
						{
							body: wire.SNAC_0x01_0x02_OServiceClientOnline{},
							me:   state.NewIdentScreenName("me"),
							err:  io.EOF,
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:              "join chat, receive error from register chat session",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_join 4 "cool room :\)"`),
			givenChatRegistry: NewChatRegistry(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					createRoomParams: createRoomParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: roomInfo,
							msg:    navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							msg:    svcResp,
						},
					},
				},
				authParams: authParams{
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("chat-auth-cookie"),
							cookieOut: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
						},
					},
					registerChatSessionParams: registerChatSessionParams{
						{
							authCookie: state.ServerCookie{ChatCookie: "chat-auth-cookie"},
							instance:   newTestSession("me"),
							err:        io.EOF,
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:              "join chat, receive error from service request",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_join 4 "cool room :\)"`),
			givenChatRegistry: NewChatRegistry(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					createRoomParams: createRoomParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: roomInfo,
							msg:    navInfo,
						},
					},
				},
				oServiceParams: oServiceParams{
					serviceRequestParams: serviceRequestParams{
						{
							me:     state.NewIdentScreenName("me"),
							bodyIn: svcReq,
							err:    io.EOF,
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:              "join chat, receive error from chat nav svc",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_join 4 "cool room :\)"`),
			givenChatRegistry: NewChatRegistry(),
			mockParams: mockParams{
				chatNavParams: chatNavParams{
					createRoomParams: createRoomParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: roomInfo,
							err:    io.EOF,
						},
					},
				},
			},
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:              "bad command",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_join`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
		{
			name:              "bad exchange number",
			me:                newTestSession("me"),
			givenCmd:          []byte(`toc_chat_join four "cool room :\)"`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
			expectChatSession: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			chatNavSvc := newMockChatNavService(t)
			for _, params := range tc.mockParams.createRoomParams {
				chatNavSvc.EXPECT().
					CreateRoom(ctx, matchSession(params.me), wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}
			bosOServiceSvc := newMockOServiceService(t)
			for _, params := range tc.mockParams.oServiceParams.serviceRequestParams {
				bosOServiceSvc.EXPECT().
					ServiceRequest(ctx, wire.BOS, matchSession(params.me), wire.SNACFrame{}, params.bodyIn, config.Listener{}).
					Return(params.msg, params.err)
			}
			for _, params := range tc.mockParams.oServiceParams.clientOnlineParams {
				bosOServiceSvc.EXPECT().
					ClientOnline(ctx, wire.Chat, params.body, matchSession(params.me)).
					Return(params.err)
			}
			authSvc := newMockAuthService(t)
			for _, params := range tc.mockParams.authParams.registerChatSessionParams {
				authSvc.EXPECT().
					RegisterChatSession(ctx, params.authCookie, mock.Anything).
					Return(params.instance, params.err)
			}
			for _, params := range tc.mockParams.authParams.crackCookieParams {
				authSvc.EXPECT().
					CrackCookie(params.cookieIn).
					Return(params.cookieOut, params.err)
			}

			svc := OSCARProxy{
				AuthService:     authSvc,
				ChatNavService:  chatNavSvc,
				Logger:          slog.Default(),
				OServiceService: bosOServiceSvc,
			}

			g := &errgroup.Group{}
			tc.me.CloseInstance()

			msg := svc.RecvClientCmd(ctx, tc.me, tc.givenChatRegistry, tc.givenCmd, nil, g.Go)

			assert.NoError(t, g.Wait())
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.expectChatSession, len(tc.givenChatRegistry.Sessions()) == 1)
			if tc.checkSession != nil {
				tc.checkSession(t, tc.givenChatRegistry.RetrieveSess(0))
			}
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatLeave(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// givenChatRegistry is the chat registry passed to the function
		givenChatRegistry *ChatRegistry
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully leave chat",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_leave 0`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me"))
				return reg
			}(),
			wantMsg: []string{"CHAT_LEFT:0"},
		},
		{
			name:     "chat room ID with invalid format",
			givenCmd: []byte(`toc_chat_leave zero`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:              "missing chat session",
			givenCmd:          []byte(`toc_chat_leave 0`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_leave`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			svc := OSCARProxy{
				Logger: slog.Default(),
			}
			msg := svc.RecvClientCmd(ctx, nil, tc.givenChatRegistry, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatSend(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// givenChatRegistry is the chat registry passed to the function
		givenChatRegistry *ChatRegistry
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully send chat message",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_send 0 "Hello world! :\)"`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me"))
				return reg
			}(),
			mockParams: mockParams{
				chatParams: chatParams{
					channelMsgToHostParamsChat: channelMsgToHostParamsChat{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
								Channel: wire.ICBMChannelMIME,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)),
										wire.NewTLVBE(wire.ChatTLVSenderInformation, newTestSession("me").Session().TLVUserInfo()),
										wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
										wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world! :)"),
											},
										}),
									},
								},
							},
							result: &wire.SNACMessage{
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Channel: wire.ICBMChannelMIME,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation,
												newTestSession("me").Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world! :)"),
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"CHAT_IN:0:me:F:Hello world! :)"},
		},
		{
			name:     "successfully send chat message - TOC2 encoded returns CHAT_IN_ENC",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_send 0 "Hello world! :\)"`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) }))
				return reg
			}(),
			mockParams: mockParams{
				chatParams: chatParams{
					channelMsgToHostParamsChat: channelMsgToHostParamsChat{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
								Channel: wire.ICBMChannelMIME,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)),
										wire.NewTLVBE(wire.ChatTLVSenderInformation, newTestSession("me").Session().TLVUserInfo()),
										wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
										wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world! :)"),
											},
										}),
									},
								},
							},
							result: &wire.SNACMessage{
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Channel: wire.ICBMChannelMIME,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation,
												newTestSession("me").Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world! :)"),
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"CHAT_IN_ENC:0:me:F:A:en:Hello world! :)"},
		},
		{
			name:     "send chat message, receive error from chat svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_send 0 "Hello world!"`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me"))
				return reg
			}(),
			mockParams: mockParams{
				chatParams: chatParams{
					channelMsgToHostParamsChat: channelMsgToHostParamsChat{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
								Channel: wire.ICBMChannelMIME,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)),
										wire.NewTLVBE(wire.ChatTLVSenderInformation, newTestSession("me").Session().TLVUserInfo()),
										wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
										wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world!"),
											},
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "send chat message, receive nil response from chat svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_send 0 "Hello world!"`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me"))
				return reg
			}(),
			mockParams: mockParams{
				chatParams: chatParams{
					channelMsgToHostParamsChat: channelMsgToHostParamsChat{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
								Channel: wire.ICBMChannelMIME,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)),
										wire.NewTLVBE(wire.ChatTLVSenderInformation, newTestSession("me").Session().TLVUserInfo()),
										wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
										wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world!"),
											},
										}),
									},
								},
							},
							result: nil,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "send chat message, receive unexpected response from chat svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_send 0 "Hello world!"`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me"))
				return reg
			}(),
			mockParams: mockParams{
				chatParams: chatParams{
					channelMsgToHostParamsChat: channelMsgToHostParamsChat{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
								Channel: wire.ICBMChannelMIME,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)),
										wire.NewTLVBE(wire.ChatTLVSenderInformation, newTestSession("me").Session().TLVUserInfo()),
										wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
										wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world!"),
											},
										}),
									},
								},
							},
							result: &wire.SNACMessage{
								Body: wire.SNACError{},
							},
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "chat room ID with invalid format",
			givenCmd: []byte(`toc_chat_send zero "Hello world!"`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:              "missing chat session",
			givenCmd:          []byte(`toc_chat_send 0 "Hello world!"`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_send`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			chatSvc := newMockChatService(t)
			for _, params := range tc.mockParams.channelMsgToHostParamsChat {
				chatSvc.EXPECT().
					ChannelMsgToHost(ctx, matchSession(params.sender), wire.SNACFrame{}, params.inBody).
					Return(params.result, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ChatService: chatSvc,
			}
			msg := svc.RecvClientCmd(ctx, nil, tc.givenChatRegistry, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatWhisper(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// givenChatRegistry is the chat registry passed to the function
		givenChatRegistry *ChatRegistry
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully send chat whisper",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_whisper 0 them "Hello world! :\)"`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me"))
				return reg
			}(),
			mockParams: mockParams{
				chatParams: chatParams{
					channelMsgToHostParamsChat: channelMsgToHostParamsChat{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
								Channel: wire.ICBMChannelMIME,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ChatTLVSenderInformation, newTestSession("me").Session().TLVUserInfo()),
										wire.NewTLVBE(wire.ChatTLVWhisperToUser, "them"),
										wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world! :)"),
											},
										}),
									},
								},
							},
							result: nil,
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "send chat whisper, receive error from chat svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_whisper 0 them "Hello world!"`),
			givenChatRegistry: func() *ChatRegistry {
				reg := NewChatRegistry()
				reg.RegisterSess(0, newTestSession("me"))
				return reg
			}(),
			mockParams: mockParams{
				chatParams: chatParams{
					channelMsgToHostParamsChat: channelMsgToHostParamsChat{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
								Channel: wire.ICBMChannelMIME,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ChatTLVSenderInformation, newTestSession("me").Session().TLVUserInfo()),
										wire.NewTLVBE(wire.ChatTLVWhisperToUser, "them"),
										wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello world!"),
											},
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "chat room ID with invalid format",
			givenCmd: []byte(`toc_chat_whisper zero them "Hello world!"`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:              "missing chat session",
			givenCmd:          []byte(`toc_chat_whisper 0 them "Hello world!"`),
			givenChatRegistry: NewChatRegistry(),
			wantMsg:           []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_chat_whisper`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			chatSvc := newMockChatService(t)
			for _, params := range tc.mockParams.channelMsgToHostParamsChat {
				chatSvc.EXPECT().
					ChannelMsgToHost(ctx, matchSession(params.sender), wire.SNACFrame{}, params.inBody).
					Return(params.result, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ChatService: chatSvc,
			}
			msg := svc.RecvClientCmd(ctx, nil, tc.givenChatRegistry, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_Evil(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully warn normally",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_evil them norm`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					evilRequestParams: evilRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
								SendAs:     0,
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x04_0x09_ICBMEvilReply{},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully warn anonymously",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_evil them anon`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					evilRequestParams: evilRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
								SendAs:     1,
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x04_0x09_ICBMEvilReply{},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "warn, receive error from ICBM service",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_evil them anon`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					evilRequestParams: evilRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
								SendAs:     1,
								ScreenName: "them",
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "warn, receive snac err",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_evil them anon`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					evilRequestParams: evilRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
								SendAs:     1,
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNACError{},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:902"},
		},
		{
			name:     "warn, ICBM svc returns unexpected snac type",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_evil them anon`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					evilRequestParams: evilRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
								SendAs:     1,
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{},
							},
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "warn with incorrect type",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_evil them blah`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_evil`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			icbmSvc := newMockICBMService(t)
			for _, params := range tc.mockParams.evilRequestParams {
				icbmSvc.EXPECT().
					EvilRequest(ctx, matchSession(params.me), wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ICBMService: icbmSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ClientEvent(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:     "send typing status 0 (no activity)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event friend 0"),
			mockParams: mockParams{
				icbmParams: icbmParams{
					clientEventParams: clientEventParams{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x14_ICBMClientEvent{
								Cookie:     0,
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "friend",
								Event:      0,
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "send typing status 1 (typing paused)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event buddy 1"),
			mockParams: mockParams{
				icbmParams: icbmParams{
					clientEventParams: clientEventParams{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x14_ICBMClientEvent{
								Cookie:     0,
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "buddy",
								Event:      1,
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "send typing status 2 (currently typing)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event chatter 2"),
			mockParams: mockParams{
				icbmParams: icbmParams{
					clientEventParams: clientEventParams{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x14_ICBMClientEvent{
								Cookie:     0,
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "chatter",
								Event:      2,
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "ICBM ClientEvent returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event friend 2"),
			mockParams: mockParams{
				icbmParams: icbmParams{
					clientEventParams: clientEventParams{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x14_ICBMClientEvent{
								Cookie:     0,
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "friend",
								Event:      2,
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "missing args",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event"),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "missing typing status",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event friend"),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "invalid typing status (must be 0, 1, or 2)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event friend 3"),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "invalid typing status non-numeric",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_client_event friend typing"),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			icbmSvc := newMockICBMService(t)
			for _, params := range tc.mockParams.clientEventParams {
				icbmSvc.EXPECT().
					ClientEvent(ctx, matchSession(params.sender), wire.SNACFrame{}, params.inBody).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ICBMService: icbmSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChangePassword(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully change password",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_change_passwd oldpa\\$\\$ newpa\\$\\$"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVOldPassword, "oldpa$$"),
										wire.NewTLVBE(wire.AdminTLVNewPassword, "newpa$$"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVNewPassword, []byte{}),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ADMIN_PASSWD_STATUS:0"},
		},
		{
			name:     "change password - invalid password length",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_change_passwd oldpass np"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVOldPassword, "oldpass"),
										wire.NewTLVBE(wire.AdminTLVNewPassword, "np"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVNewPassword, []byte{}),
											wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorInvalidPasswordLength),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:911"},
		},
		{
			name:     "change password - incorrect password",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_change_passwd oldpass baddpass"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVOldPassword, "oldpass"),
										wire.NewTLVBE(wire.AdminTLVNewPassword, "baddpass"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVNewPassword, []byte{}),
											wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorValidatePassword),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:980"},
		},
		{
			name:     "change password - catch-all error response",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_change_passwd oldpass baddpass"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVOldPassword, "oldpass"),
										wire.NewTLVBE(wire.AdminTLVNewPassword, "baddpass"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x07_0x05_AdminChangeReply{
									Permissions: wire.AdminInfoPermissionsReadWrite,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.AdminTLVNewPassword, []byte{}),
											wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorAllOtherErrors),
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:913"},
		},
		{
			name:     "change password - runtime error from admin svc",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_change_passwd oldpass baddpass"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVOldPassword, "oldpass"),
										wire.NewTLVBE(wire.AdminTLVNewPassword, "baddpass"),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "change password - unexpected response from admin svc",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_change_passwd oldpass baddpass"),
			mockParams: mockParams{
				adminParams: adminParams{
					infoChangeRequestParams: infoChangeRequestParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.AdminTLVOldPassword, "oldpass"),
										wire.NewTLVBE(wire.AdminTLVNewPassword, "baddpass"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNACError{},
							},
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_change_passwd`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			adminSvc := newMockAdminService(t)
			for _, params := range tc.mockParams.infoChangeRequestParams {
				adminSvc.EXPECT().
					InfoChangeRequest(ctx, matchSession(params.me), wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				Logger:       slog.Default(),
				AdminService: adminSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_GetDirSearchURL(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully request user info",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_dir_search "first \[name\]":"middle name":"last name":"maiden name":"city":"state":"country":"email"`),
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					issueParams: issueParams{
						{
							data:       []byte("me"),
							returnData: []byte("monster"),
						},
					},
				},
			},
			wantMsg: []string{"GOTO_URL:search results:dir_search?city=city&cookie=6d6f6e73746572&country=country&email=email&first_name=first+%5Bname%5D&last_name=last+name&maiden_name=maiden+name&middle_name=middle+name&state=state"},
		},
		{
			name:     "successfully request user info by keywords",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_dir_search ::::::::::"searchkw"`),
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					issueParams: issueParams{
						{
							data:       []byte("me"),
							returnData: []byte("monster"),
						},
					},
				},
			},
			wantMsg: []string{"GOTO_URL:search results:dir_search?cookie=6d6f6e73746572&keyword=searchkw"},
		},
		{
			name:     "request user info with too many params",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_dir_search ::::::::::::::::::::"searchkw"`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "request user info, get cookie issue error",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_dir_search them`),
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					issueParams: issueParams{
						{
							data:      []byte("me"),
							returnErr: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_dir_search`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			cookieBaker := newMockCookieBaker(t)
			for _, params := range tc.mockParams.issueParams {
				cookieBaker.EXPECT().
					Issue(params.data).
					Return(params.returnData, params.returnErr)
			}

			svc := OSCARProxy{
				Logger:         slog.Default(),
				CookieBaker:    cookieBaker,
				SNACRateLimits: wire.DefaultSNACRateLimits(),
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_GetDirURL(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully request user dir info",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_get_dir them`),
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					issueParams: issueParams{
						{
							data:       []byte("me"),
							returnData: []byte("monster"),
						},
					},
				},
			},
			wantMsg: []string{"GOTO_URL:directory info:dir_info?cookie=6d6f6e73746572&user=them"},
		},
		{
			name:     "request user info, get cookie issue error",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_get_dir them`),
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					issueParams: issueParams{
						{
							data:      []byte("me"),
							returnErr: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_get_dir`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			cookieBaker := newMockCookieBaker(t)
			for _, params := range tc.mockParams.issueParams {
				cookieBaker.EXPECT().
					Issue(params.data).
					Return(params.returnData, params.returnErr)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				CookieBaker: cookieBaker,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_GetInfoURL(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully request user info",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_get_info them`),
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					issueParams: issueParams{
						{
							data:       []byte("me"),
							returnData: []byte("monster"),
						},
					},
				},
			},
			wantMsg: []string{"GOTO_URL:profile:info?cookie=6d6f6e73746572&from=me&user=them"},
		},
		{
			name:     "request user info, get cookie issue error",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_get_info them`),
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					issueParams: issueParams{
						{
							data:      []byte("me"),
							returnErr: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_get_info`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			cookieBaker := newMockCookieBaker(t)
			for _, params := range tc.mockParams.issueParams {
				cookieBaker.EXPECT().
					Issue(params.data).
					Return(params.returnData, params.returnErr)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				CookieBaker: cookieBaker,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_GetStatus(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully request status",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_get_status them"),
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
									TLVUserInfo: wire.TLVUserInfo{
										ScreenName:   "them",
										WarningLevel: 0,
										TLVBlock: wire.TLVBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
												wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
												wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"UPDATE_BUDDY:them:T:0:1234:5678: O "},
		},
		{
			name:     "request status, receive err from locate svc",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_get_status them"),
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								ScreenName: "them",
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "request status, user not online",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_get_status them"),
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNACError{
									Code: wire.ErrorCodeNotLoggedOn,
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:901:them"},
		},
		{
			name:     "request status, receive unexpected error code",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_get_status them"),
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNACError{
									Code: wire.ErrorCodeInvalidSnac,
								},
							},
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "request status, unexpected response from locate svc",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_get_status them"),
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0E_0x04_ChatUsersLeft{},
							},
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_get_status`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			locateSvc := newMockLocateService(t)
			for _, params := range tc.mockParams.userInfoQueryParams {
				locateSvc.EXPECT().
					UserInfoQuery(mock.Anything, matchSession(params.me), wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				Logger:        slog.Default(),
				LocateService: locateSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_InitDone(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully initialize connection",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_init_done`),
			mockParams: mockParams{
				oServiceParams: oServiceParams{
					clientOnlineParams: clientOnlineParams{
						{
							me:      state.NewIdentScreenName("me"),
							body:    wire.SNAC_0x01_0x02_OServiceClientOnline{},
							service: wire.BOS,
						},
					},
				},
				feedBagParams: feedBagParams{
					useFeedbagParams: useFeedbagParams{
						{
							me: state.NewIdentScreenName("me"),
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "initialize connection, receive err from BOS oservice svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_init_done`),
			mockParams: mockParams{
				oServiceParams: oServiceParams{
					clientOnlineParams: clientOnlineParams{
						{
							me:      state.NewIdentScreenName("me"),
							body:    wire.SNAC_0x01_0x02_OServiceClientOnline{},
							service: wire.BOS,
							err:     io.EOF,
						},
					},
				},
				feedBagParams: feedBagParams{
					useFeedbagParams: useFeedbagParams{
						{
							me: state.NewIdentScreenName("me"),
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			oSvc := newMockOServiceService(t)
			for _, params := range tc.mockParams.oServiceParams.clientOnlineParams {
				oSvc.EXPECT().
					ClientOnline(ctx, params.service, params.body, matchSession(params.me)).
					Return(params.err)
			}

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.useFeedbagParams {
				fbMgr.EXPECT().
					UseFeedbag(ctx, params.me).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:          slog.Default(),
				OServiceService: oSvc,
				FeedbagManager:  fbMgr,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_RemoveBuddy(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully remove buddies",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_remove_buddy friend1 friend2 friend3"),
			mockParams: mockParams{
				buddyParams: buddyParams{
					delBuddiesParams: delBuddiesParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x03_0x05_BuddyDelBuddies{
								Buddies: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
									{ScreenName: "friend2"},
									{ScreenName: "friend3"},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "remove buddies with empty list",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_remove_buddy"),
			mockParams: mockParams{
				buddyParams: buddyParams{
					delBuddiesParams: delBuddiesParams{
						{
							me:     state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x03_0x05_BuddyDelBuddies{},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "remove buddies, receive error from buddy service",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_remove_buddy friend1"),
			mockParams: mockParams{
				buddyParams: buddyParams{
					delBuddiesParams: delBuddiesParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x03_0x05_BuddyDelBuddies{
								Buddies: []struct {
									ScreenName string `oscar:"len_prefix=uint8"`
								}{
									{ScreenName: "friend1"},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			buddySvc := newMockBuddyService(t)
			for _, params := range tc.mockParams.delBuddiesParams {
				buddySvc.EXPECT().
					DelBuddies(ctx, matchSession(params.me), params.inBody).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:       slog.Default(),
				BuddyService: buddySvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_NewBuddies(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:     "add new users to existing group",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:mike\nb:mk6i\ng:Family\nb:alice\nb:bob\n}"),
			wantMsg:  []string{"NEW_BUDDY_REPLY2:mike:added", "NEW_BUDDY_REPLY2:mk6i:added", "NEW_BUDDY_REPLY2:alice:added", "NEW_BUDDY_REPLY2:bob:added"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 21827, 29709})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								{Name: "Co-Workers", GroupID: 21827, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mike", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mk6i", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}},
								},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 29709, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 4, ClassID: wire.FeedbagClassIdBuddy, GroupID: 29709, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{3, 4})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "empty feedbag: add new group and buddies",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:mike\nb:mk6i\n}"),
			wantMsg:  []string{"NEW_BUDDY_REPLY2:mike:added", "NEW_BUDDY_REPLY2:mk6i:added"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						// First: insert the two buddy items (deterministic randIntn gives GroupID 1, ItemIDs 2 and 3)
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "mike", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "mk6i", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
						// Second: insert the new Buddies group with Order listing the buddy item IDs
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 3})}},
								},
							},
							msg: nil, err: nil,
						},
						// Third: insert the root group so its Order lists the new group ID
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "add new group and buddies",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Co-Workers\nb:carol\nb:dan\ng:Family\nb:alice\nb:bob\n}"),
			wantMsg:  []string{"NEW_BUDDY_REPLY2:carol:added", "NEW_BUDDY_REPLY2:dan:added", "NEW_BUDDY_REPLY2:alice:added", "NEW_BUDDY_REPLY2:bob:added"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "carol", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "dan", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Co-Workers", GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 3})}},
								},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 5, ClassID: wire.FeedbagClassIdBuddy, GroupID: 4, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 6, ClassID: wire.FeedbagClassIdBuddy, GroupID: 4, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Family", GroupID: 4, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{5, 6})}},
								},
							},
							msg: nil, err: nil,
						},
						// Root updated once at end
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 1, 4})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:       "empty config returns error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_new_buddies "),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:       "whitespace-only config returns error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_new_buddies   "),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:       "buddy without group returns parse error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_new_buddies {b:alice\n}"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:       "empty group name returns parse error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_new_buddies {g:\nb:alice\n}"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:       "empty buddy name returns parse error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_new_buddies {g:Buddies\nb:\n}"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:     "group with no buddies does not call UpsertItem",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:EmptyGroup\n}"),
			wantMsg:  nil,
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "FeedbagManager.Feedbag error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:alice\n}"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        errors.New("EOF"),
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "FeedbagService.UpsertItem error on first insert returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:alice\n}"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
								},
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
								},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: errors.New("EOF"),
						},
					},
				},
			},
		},
		{
			name:     "buddy already in group skips and adds only new buddy",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:mike\nb:mk6i\n}"),
			wantMsg:  []string{"NEW_BUDDY_REPLY2:mk6i:added"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mike", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mk6i", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "all buddies already in group returns no replies and no UpsertItem",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:mike\nb:mk6i\n}"),
			wantMsg:  nil,
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}}},
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mike", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mk6i", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "single buddy in new group",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:alice\n}"),
			wantMsg:  []string{"NEW_BUDDY_REPLY2:alice:added"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}},
								},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "buddy with alias and note",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:bob:Bob Smith:::::Friend from work\n}"),
			wantMsg:  []string{"NEW_BUDDY_REPLY2:bob:added"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
								},
								{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}}},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "bob",
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesAlias, "Bob Smith"),
											wire.NewTLVBE(wire.FeedbagAttributesNote, "Friend from work"),
										},
									},
								},
							},
							msg: nil, err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUpsertItemParams {
				fbSvc.EXPECT().
					UpsertItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.items).
					Return(params.msg, params.err)
			}

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
				RandIntn:       randIntn,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_NewGroup(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:     "add new group when feedbag has root and existing groups",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_group Family"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 1})}},
								},
								{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Family"},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "add new group when feedbag is empty creates root and group",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_group Buddies"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdGroup,
									GroupID: 0,
									Name:    "",
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})},
									},
								},
								{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Buddies"},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "group already exists returns success idempotently",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_group Buddies"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "empty group name returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_group"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams:                  feedbagParams{},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "FeedbagManager.Feedbag error returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_group Family"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        assert.AnError,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "FeedbagService.UpsertItem error returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_group Family"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 1})}},
								},
								{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Family"},
							},
							msg: nil, err: assert.AnError,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUpsertItemParams {
				fbSvc.EXPECT().
					UpsertItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.items).
					Return(params.msg, params.err)
			}

			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
				RandIntn:       randIntn,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_DelGroup(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:     "delete existing group",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_del_group Family"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 29709})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1}),
										},
									},
								},
								{Name: "Jane", GroupID: 17724, ItemID: 1, ClassID: wire.FeedbagClassIdBuddy},
								{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 3}),
										},
									},
								},
								{Name: "Joe", GroupID: 29709, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy},
								{Name: "Fred", GroupID: 29709, ItemID: 3, ClassID: wire.FeedbagClassIdBuddy},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
										TLVLBlock: wire.TLVLBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 3}),
											},
										},
									},
									{Name: "Joe", GroupID: 29709, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy},
									{Name: "Fred", GroupID: 29709, ItemID: 3, ClassID: wire.FeedbagClassIdBuddy},
								},
							},
							msg: nil, err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "empty group name returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_del_group"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams:                  feedbagParams{},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
				},
			},
		},
		{
			name:     "group not found returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_del_group Nonexistent"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
				},
			},
		},
		{
			name:     "FeedbagManager.Feedbag error returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_del_group Family"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        assert.AnError,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
				},
			},
		},
		{
			name:     "FeedbagService.DeleteItem error returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_del_group Family"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 29709})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								},
							},
							msg: nil, err: assert.AnError,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceDeleteItemParams {
				fbSvc.EXPECT().
					DeleteItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.inBody).
					Return(params.msg, params.err)
			}
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUpsertItemParams {
				fbSvc.EXPECT().
					UpsertItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.items).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SetPDMode(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:     "empty feedbag creates new Pdinfo with mode 4",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_set_pdmode 4"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdPdinfo,
									GroupID: 0,
									ItemID:  1,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(4)),
										},
									},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "pdinfo already exists but does not have FeedbagAttributesPdMode",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_set_pdmode 2"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdPdinfo,
									GroupID: 0,
									ItemID:  99,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{},
									},
								},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdPdinfo,
									GroupID: 0,
									ItemID:  99,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(2)),
										},
									},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "pdinfo already exists and already has FeedbagAttributesPdMode with same mode",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_set_pdmode 3"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdPdinfo,
									GroupID: 0,
									ItemID:  99,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(3)),
										},
									},
								},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "pdinfo already exists and already has FeedbagAttributesPdMode with different mode",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_set_pdmode 3"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdPdinfo,
									GroupID: 0,
									ItemID:  99,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(1)),
										},
									},
								},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdPdinfo,
									GroupID: 0,
									ItemID:  99,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(3)),
										},
									},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUpsertItemParams {
				fbSvc.EXPECT().
					UpsertItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.items).
					Return(params.msg, params.err)
			}

			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
				RandIntn:       randIntn,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_AddPermit2(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:       "no screennames provided returns internal error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_add_permit"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:     "FeedbagManager.Feedbag error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_permit alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        errors.New("EOF"),
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "FeedbagService.UpsertItem error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_permit alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: errors.New("EOF"),
						},
					},
				},
			},
		},
		{
			name:     "add permits to empty feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_permit alice bob"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "skip existing permit, add only new",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_permit alice bob"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "no-op when permit already in feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_permit alice"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUpsertItemParams {
				fbSvc.EXPECT().
					UpsertItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.items).
					Return(params.msg, params.err)
			}
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
				RandIntn:       randIntn,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_AddDeny2(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:       "no screennames provided returns internal error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_add_deny"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:     "FeedbagManager.Feedbag error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_deny alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        errors.New("EOF"),
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "FeedbagService.UpsertItem error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_deny alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: errors.New("EOF"),
						},
					},
				},
			},
		},
		{
			name:     "add deny to empty feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_deny alice"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "skip existing deny, add only new",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_deny alice bob"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "no-op when deny already in feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_deny alice"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUpsertItemParams {
				fbSvc.EXPECT().
					UpsertItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.items).
					Return(params.msg, params.err)
			}
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
				RandIntn:       randIntn,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_RemoveBuddy2(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:     "removes buddy from group order TLV and upserts group",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_buddy friend2 Buddies"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2, 3})}},
								},
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend1", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend2", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend3", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend2", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							msg: nil, err: nil,
						},
					},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 3})}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:       "parseArgs error returns internal error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_remove_buddy \"unclosed"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:       "missing params returns internal error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_remove_buddy friend1"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:     "group not found returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_buddy friend1 NoSuchGroup"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "FeedbagManager.Feedbag error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_buddy friend1 Buddies"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        errors.New("EOF"),
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
		{
			name:     "no-op when buddy not in group",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_buddy stranger Buddies"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend1", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
					feedbagServiceUpsertItemParams: feedbagServiceUpsertItemParams{},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceDeleteItemParams {
				fbSvc.EXPECT().
					DeleteItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.inBody).
					Return(params.msg, params.err)
			}
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUpsertItemParams {
				fbSvc.EXPECT().
					UpsertItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.items).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_RemovePermit2(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:       "no screennames provided returns internal error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_remove_permit"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:     "FeedbagManager.Feedbag error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_permit alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        errors.New("EOF"),
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
				},
			},
		},
		{
			name:     "FeedbagService.DeleteItem error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_permit alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							msg: nil, err: errors.New("EOF"),
						},
					},
				},
			},
		},
		{
			name:     "remove permits from feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_permit alice bob"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
									{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "remove only existing permits",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_permit alice bob"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "no-op when no permits in feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_permit alice"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceDeleteItemParams {
				fbSvc.EXPECT().
					DeleteItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.inBody).
					Return(params.msg, params.err)
			}
			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_RemoveDeny2(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:       "no screennames provided returns internal error",
			me:         newTestSession("me"),
			givenCmd:   []byte("toc2_remove_deny"),
			wantMsg:    []string{cmdInternalSvcErr},
			mockParams: mockParams{},
		},
		{
			name:     "FeedbagManager.Feedbag error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_deny alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        errors.New("EOF"),
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
				},
			},
		},
		{
			name:     "FeedbagService.DeleteItem error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_deny alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							msg: nil, err: errors.New("EOF"),
						},
					},
				},
			},
		},
		{
			name:     "remove denies from feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_deny alice bob"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
									{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "remove only existing denies",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_deny alice bob"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							msg: nil, err: nil,
						},
					},
				},
			},
		},
		{
			name:     "no-op when no denies in feedbag",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_deny alice"),
			wantMsg:  []string{},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
							err:        nil,
						},
					},
					feedbagServiceDeleteItemParams: feedbagServiceDeleteItemParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(ctx, params.screenName).
					Return(params.results, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceDeleteItemParams {
				fbSvc.EXPECT().
					DeleteItem(ctx, matchSession(tc.me.IdentScreenName()), params.frame, params.inBody).
					Return(params.msg, params.err)
			}
			svc := OSCARProxy{
				Logger:         slog.Default(),
				FeedbagManager: fbMgr,
				FeedbagService: fbSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_RvousAccept(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully send rendezvous request",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_rvous_accept them aGFoYWhhaGE= 09461343-4C7F-11D1-8222-444553540000`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelRendezvous,
								ScreenName: "them",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
											Type:       wire.ICBMRdvMessageAccept,
											Cookie:     [8]byte{'h', 'a', 'h', 'a', 'h', 'a', 'h', 'a'},
											Capability: wire.CapFileTransfer,
										}),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "send rendezvous request, receive error from ICBM service",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_rvous_accept them aGFoYWhhaGE= 09461343-4C7F-11D1-8222-444553540000`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelRendezvous,
								ScreenName: "them",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
											Type:       wire.ICBMRdvMessageAccept,
											Cookie:     [8]byte{'h', 'a', 'h', 'a', 'h', 'a', 'h', 'a'},
											Capability: wire.CapFileTransfer,
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_rvous_accept`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			icbmSvc := newMockICBMService(t)
			for _, params := range tc.mockParams.channelMsgToHostParamsICBM {
				icbmSvc.EXPECT().
					ChannelMsgToHost(ctx, matchSession(params.sender), params.inFrame, params.inBody).
					Return(params.result, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ICBMService: icbmSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_RvousCancel(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully send rendezvous cancellation",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_rvous_cancel them aGFoYWhhaGE= 09461343-4C7F-11D1-8222-444553540000`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelRendezvous,
								ScreenName: "them",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
											Type:       wire.ICBMRdvMessageCancel,
											Cookie:     [8]byte{'h', 'a', 'h', 'a', 'h', 'a', 'h', 'a'},
											Capability: wire.CapFileTransfer,
											TLVRestBlock: wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ICBMRdvTLVTagsCancelReason, wire.ICBMRdvCancelReasonsUserCancel),
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
			wantMsg: []string{},
		},
		{
			name:     "send rendezvous cancellation, receive error from ICBM service",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_rvous_cancel them aGFoYWhhaGE= 09461343-4C7F-11D1-8222-444553540000`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelRendezvous,
								ScreenName: "them",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
											Type:       wire.ICBMRdvMessageCancel,
											Cookie:     [8]byte{'h', 'a', 'h', 'a', 'h', 'a', 'h', 'a'},
											Capability: wire.CapFileTransfer,
											TLVRestBlock: wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ICBMRdvTLVTagsCancelReason, wire.ICBMRdvCancelReasonsUserCancel),
												},
											},
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_rvous_cancel`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			icbmSvc := newMockICBMService(t)
			for _, params := range tc.mockParams.channelMsgToHostParamsICBM {
				icbmSvc.EXPECT().
					ChannelMsgToHost(ctx, matchSession(params.sender), params.inFrame, params.inBody).
					Return(params.result, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ICBMService: icbmSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SendIM(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully send instant message",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_send_im chattingChuck "hello world! :\)"`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "chattingChuck",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
											{
												ID:      5,
												Version: 1,
												Payload: []byte{1, 1, 2},
											},
											{
												ID:      1,
												Version: 1,
												Payload: []byte{
													0x00, 0x00,
													0x00, 0x00,
													'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', ' ', ':', ')',
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
			wantMsg: []string{},
		},
		{
			name:     "successfully auto-reply send instant message",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_send_im chattingChuck "hello world!" auto`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "chattingChuck",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
											{
												ID:      5,
												Version: 1,
												Payload: []byte{1, 1, 2},
											},
											{
												ID:      1,
												Version: 1,
												Payload: []byte{
													0x00, 0x00,
													0x00, 0x00,
													'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
												},
											},
										}),
										wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "send instant message, receive error from ICBM service",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_send_im chattingChuck "hello world!"`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "chattingChuck",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
											{
												ID:      5,
												Version: 1,
												Payload: []byte{1, 1, 2},
											},
											{
												ID:      1,
												Version: 1,
												Payload: []byte{
													0x00, 0x00,
													0x00, 0x00,
													'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
												},
											},
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_send_im`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			icbmSvc := newMockICBMService(t)
			for _, params := range tc.mockParams.channelMsgToHostParamsICBM {
				icbmSvc.EXPECT().
					ChannelMsgToHost(ctx, matchSession(params.sender), params.inFrame, params.inBody).
					Return(params.result, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ICBMService: icbmSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SendIMEnc(t *testing.T) {
	cases := []struct {
		name       string
		me         *state.SessionInstance
		givenCmd   []byte
		wantMsg    []string
		mockParams mockParams
	}{
		{
			name:     "successfully send encoded instant message",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc2_send_im_enc chattingChuck "F" utf-8 en "hello"`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender:  state.NewIdentScreenName("me"),
							inFrame: wire.SNACFrame{},
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "chattingChuck",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
											{
												ID:      5,
												Version: 1,
												Payload: []byte{1, 1, 2},
											},
											{
												ID:      1,
												Version: 1,
												Payload: []byte{
													0x00, 0x00,
													0x00, 0x00,
													'h', 'e', 'l', 'l', 'o',
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
			wantMsg: []string{},
		},
		{
			name:     "successfully send encoded instant message with auto",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc2_send_im_enc chattingChuck "F" utf-8 en "hello" auto`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender:  state.NewIdentScreenName("me"),
							inFrame: wire.SNACFrame{},
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "chattingChuck",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
											{
												ID:      5,
												Version: 1,
												Payload: []byte{1, 1, 2},
											},
											{
												ID:      1,
												Version: 1,
												Payload: []byte{
													0x00, 0x00,
													0x00, 0x00,
													'h', 'e', 'l', 'l', 'o',
												},
											},
										}),
										wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "send encoded instant message, receive error from ICBM service",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc2_send_im_enc chattingChuck "F" utf-8 en "hello"`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{
						{
							sender:  state.NewIdentScreenName("me"),
							inFrame: wire.SNACFrame{},
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelIM,
								ScreenName: "chattingChuck",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
											{
												ID:      5,
												Version: 1,
												Payload: []byte{1, 1, 2},
											},
											{
												ID:      1,
												Version: 1,
												Payload: []byte{
													0x00, 0x00,
													0x00, 0x00,
													'h', 'e', 'l', 'l', 'o',
												},
											},
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "invalid args too few",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc2_send_im_enc`),
			mockParams: mockParams{
				icbmParams: icbmParams{
					channelMsgToHostParamsICBM: channelMsgToHostParamsICBM{},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			icbmSvc := newMockICBMService(t)
			for _, params := range tc.mockParams.channelMsgToHostParamsICBM {
				icbmSvc.EXPECT().
					ChannelMsgToHost(ctx, matchSession(params.sender), params.inFrame, params.inBody).
					Return(params.result, params.err)
			}

			svc := OSCARProxy{
				Logger:      slog.Default(),
				ICBMService: icbmSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SetAway(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully set away with message",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_away "I'm away from my computer right now. :\)"`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "I'm away from my computer right now. :)"),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set away without message",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_away`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, ""),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set away message, receive error from locate service",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_away "I'm away from my computer right now."`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "I'm away from my computer right now."),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			locateSvc := newMockLocateService(t)
			for _, params := range tc.mockParams.setInfoParams {
				locateSvc.EXPECT().
					SetInfo(ctx, matchSession(params.me), params.inBody).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:        slog.Default(),
				LocateService: locateSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SetCaps(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully set capabilities",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_caps 09460000-4C7F-11D1-8222-444553540000 09460001-4C7F-11D1-8222-444553540000`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
											uuid.MustParse("09460000-4C7F-11D1-8222-444553540000"),
											uuid.MustParse("09460001-4C7F-11D1-8222-444553540000"),
											wire.CapChat,
										}),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set capabilities with empty list",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_caps`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
											wire.CapChat,
										}),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set capability, receive error from locate service",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_caps 09460000-4C7F-11D1-8222-444553540000`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
											uuid.MustParse("09460000-4C7F-11D1-8222-444553540000"),
											wire.CapChat,
										}),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "set malformed capability UUID is skipped",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_caps 09460000-`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
											wire.CapChat,
										}),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set capabilities with comma-separated list (TameClone format)",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_caps 748F2420-6287-11D1-8222-444553540000,1348,134B,1341,1343,1FF,1345,1346,1347,`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
											wire.CapChat,              // 748F... from client
											wire.CapFileSharing,       // 1348
											wire.CapBuddyListTransfer, // 134B
											wire.CapVoiceChat,         // 1341
											wire.CapFileTransfer,      // 1343
											wire.CapSmartCaps,         // 1FF
											wire.CapDirectICBM,        // 1345
											wire.CapAvatarService,     // 1346
											wire.CapStocksAddins,      // 1347
											wire.CapChat,              // auto-appended
										}),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			locateSvc := newMockLocateService(t)
			for _, params := range tc.mockParams.setInfoParams {
				locateSvc.EXPECT().
					SetInfo(ctx, matchSession(params.me), params.inBody).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:        slog.Default(),
				LocateService: locateSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SetConfig(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully set permit all config (unquoted)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_set_config {m 1\ng Buddies\nb friend1\nb friend2\n}\n"),
			mockParams: mockParams{
				tocConfigParams: tocConfigParams{
					setTOCConfigParams: setTOCConfigParams{
						{
							user:   state.NewIdentScreenName("me"),
							config: "{m 1\ng Buddies\nb friend1\nb friend2\n}\n",
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set permit all config (double-quoted)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_set_config \"{m 1\ng Buddies\nb friend1\nb friend2\n}\n\""),
			mockParams: mockParams{
				tocConfigParams: tocConfigParams{
					setTOCConfigParams: setTOCConfigParams{
						{
							user:   state.NewIdentScreenName("me"),
							config: "{m 1\ng Buddies\nb friend1\nb friend2\n}\n",
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set permit all config (single-quoted)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_set_config '{m 1\ng Buddies\nb friend1\nb friend2\n}\n'"),
			mockParams: mockParams{
				tocConfigParams: tocConfigParams{
					setTOCConfigParams: setTOCConfigParams{
						{
							user:   state.NewIdentScreenName("me"),
							config: "{m 1\ng Buddies\nb friend1\nb friend2\n}\n",
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set permit all config (double-quoted with spaces)",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_set_config \" {m 1\ng Buddies\nb friend1\nb friend2\n}\n \""),
			mockParams: mockParams{
				tocConfigParams: tocConfigParams{
					setTOCConfigParams: setTOCConfigParams{
						{
							user:   state.NewIdentScreenName("me"),
							config: "{m 1\ng Buddies\nb friend1\nb friend2\n}\n",
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set config, receive error from toc config store",
			me:       newTestSession("me"),
			givenCmd: []byte("toc_set_config {m 1\ng Buddies\nb friend1\nb friend2\n}\n"),
			mockParams: mockParams{
				tocConfigParams: tocConfigParams{
					setTOCConfigParams: setTOCConfigParams{
						{
							user:   state.NewIdentScreenName("me"),
							config: "{m 1\ng Buddies\nb friend1\nb friend2\n}\n",
							err:    io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_config`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			pdSvc := newMockPermitDenyService(t)
			for _, params := range tc.mockParams.addDenyListEntriesParams {
				pdSvc.EXPECT().
					AddDenyListEntries(ctx, matchSession(params.me), params.body).
					Return(params.err)
			}
			for _, params := range tc.mockParams.addPermListEntriesParams {
				pdSvc.EXPECT().
					AddPermListEntries(ctx, matchSession(params.me), params.body).
					Return(params.err)
			}
			buddySvc := newMockBuddyService(t)
			for _, params := range tc.mockParams.addBuddiesParams {
				buddySvc.EXPECT().
					AddBuddies(ctx, matchSession(params.me), mock.Anything, params.inBody).
					Return(nil, params.err)
			}
			tocConfigSvc := newMockTOCConfigStore(t)
			for _, params := range tc.mockParams.setTOCConfigParams {
				tocConfigSvc.EXPECT().
					SetTOCConfig(matchContext(), params.user, params.config).
					Return(params.err)
			}

			svc := OSCARProxy{
				BuddyService:      buddySvc,
				Logger:            slog.Default(),
				PermitDenyService: pdSvc,
				TOCConfigStore:    tocConfigSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SetDir(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully set directory info with quoted fields",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_dir "first name\$":"middle name":"last name":"maiden name":"city":"state":"country":"email":"allow web searches"`),
			mockParams: mockParams{
				locateParams: locateParams{
					setDirInfoParams: setDirInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x09_LocateSetDirInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVFirstName, "first name$"),
										wire.NewTLVBE(wire.ODirTLVMiddleName, "middle name"),
										wire.NewTLVBE(wire.ODirTLVLastName, "last name"),
										wire.NewTLVBE(wire.ODirTLVMaidenName, "maiden name"),
										wire.NewTLVBE(wire.ODirTLVCountry, "country"),
										wire.NewTLVBE(wire.ODirTLVState, "state"),
										wire.NewTLVBE(wire.ODirTLVCity, "city"),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set directory info with some blank fields",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_dir "first name"::"last name"::"city":"state":"country":"email":"allow web searches"`),
			mockParams: mockParams{
				locateParams: locateParams{
					setDirInfoParams: setDirInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x09_LocateSetDirInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVFirstName, "first name"),
										wire.NewTLVBE(wire.ODirTLVMiddleName, ""),
										wire.NewTLVBE(wire.ODirTLVLastName, "last name"),
										wire.NewTLVBE(wire.ODirTLVMaidenName, ""),
										wire.NewTLVBE(wire.ODirTLVCountry, "country"),
										wire.NewTLVBE(wire.ODirTLVState, "state"),
										wire.NewTLVBE(wire.ODirTLVCity, "city"),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set directory info with last two fields absent",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_dir "first name"::"last name"::"city":"state":"country"`),
			mockParams: mockParams{
				locateParams: locateParams{
					setDirInfoParams: setDirInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x09_LocateSetDirInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVFirstName, "first name"),
										wire.NewTLVBE(wire.ODirTLVMiddleName, ""),
										wire.NewTLVBE(wire.ODirTLVLastName, "last name"),
										wire.NewTLVBE(wire.ODirTLVMaidenName, ""),
										wire.NewTLVBE(wire.ODirTLVCountry, "country"),
										wire.NewTLVBE(wire.ODirTLVState, "state"),
										wire.NewTLVBE(wire.ODirTLVCity, "city"),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set directory info, receive error from locate svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_dir "first name":"middle name":"last name":"maiden name":"city":"state":"country":"email":"allow web searches"`),
			mockParams: mockParams{
				locateParams: locateParams{
					setDirInfoParams: setDirInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x09_LocateSetDirInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVFirstName, "first name"),
										wire.NewTLVBE(wire.ODirTLVMiddleName, "middle name"),
										wire.NewTLVBE(wire.ODirTLVLastName, "last name"),
										wire.NewTLVBE(wire.ODirTLVMaidenName, "maiden name"),
										wire.NewTLVBE(wire.ODirTLVCountry, "country"),
										wire.NewTLVBE(wire.ODirTLVState, "state"),
										wire.NewTLVBE(wire.ODirTLVCity, "city"),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "set directory with too many fields present",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_dir "first name"::"last name"::"city":"state":"country":"email":"allow web searches":"extra":"extra"`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_dir`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			locateSvc := newMockLocateService(t)
			for _, params := range tc.mockParams.setDirInfoParams {
				locateSvc.EXPECT().
					SetDirInfo(ctx, matchSession(params.me), wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				Logger:        slog.Default(),
				LocateService: locateSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SetIdle(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully set idle status",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_idle 10`),
			mockParams: mockParams{
				oServiceParams: oServiceParams{
					idleNotificationParams: idleNotificationParams{
						{
							me: state.NewIdentScreenName("me"),
							bodyIn: wire.SNAC_0x01_0x11_OServiceIdleNotification{
								IdleTime: uint32(10),
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set idle status, receive err from BOS oservice svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_idle 10`),
			mockParams: mockParams{
				oServiceParams: oServiceParams{
					idleNotificationParams: idleNotificationParams{
						{
							me: state.NewIdentScreenName("me"),
							bodyIn: wire.SNAC_0x01_0x11_OServiceIdleNotification{
								IdleTime: uint32(10),
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad secs param",
			givenCmd: []byte(`toc_set_idle zero`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_idle`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			oServiceSvc := newMockOServiceService(t)
			for _, params := range tc.mockParams.oServiceParams.idleNotificationParams {
				oServiceSvc.EXPECT().
					IdleNotification(ctx, matchSession(params.me), params.bodyIn).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:          slog.Default(),
				OServiceService: oServiceSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_RecvClientCmd_SetInfo(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "successfully set profile",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_info "my profile! :\)"`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "my profile! :)"),
									},
								},
							},
						},
					},
				},
			},
			wantMsg: []string{},
		},
		{
			name:     "set profile, receive error from locate svc",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_info "my profile!"`),
			mockParams: mockParams{
				locateParams: locateParams{
					setInfoParams: setInfoParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "my profile!"),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			me:       newTestSession("me"),
			givenCmd: []byte(`toc_set_info`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			locateSvc := newMockLocateService(t)
			for _, params := range tc.mockParams.setInfoParams {
				locateSvc.EXPECT().
					SetInfo(ctx, matchSession(params.me), params.inBody).
					Return(params.err)
			}

			svc := OSCARProxy{
				Logger:        slog.Default(),
				LocateService: locateSvc,
			}
			msg := svc.RecvClientCmd(ctx, tc.me, nil, tc.givenCmd, nil, nil)

			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

func TestOSCARProxy_Signon(t *testing.T) {
	roastedPass := wire.RoastTOCPassword([]byte("thepass"))

	cases := []struct {
		// name is the unit test name
		name string
		// checkSession validates the session returned from Signon when non-nil; leave nil for error cases
		checkSession func(*testing.T, *state.SessionInstance)
		// givenCmd is the TOC command
		givenCmd []byte
		// wantMsg is the expected TOC response
		wantMsg []string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name: "successfully login TOC1",
			checkSession: func(t *testing.T, s *state.SessionInstance) {
				assert.Equal(t, state.NewIdentScreenName("me"), s.IdentScreenName())
				assert.Equal(t, [][16]byte{wire.CapChat}, s.Session().Caps())
				assert.False(t, s.IsTOC2())
			},
			givenCmd: []byte(`toc_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{
							user: state.NewIdentScreenName("me"),
						},
					},
				},
				tocConfigParams: tocConfigParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("me"),
							returnedUser: &state.User{
								TOCConfig: "my-toc-config",
							},
						},
					},
				},
			},
			wantMsg: []string{"SIGN_ON:TOC1.0", "CONFIG:my-toc-config", "NICK:me"},
		},
		{
			name: "successfully login TOC2",
			checkSession: func(t *testing.T, s *state.SessionInstance) {
				assert.Equal(t, state.NewIdentScreenName("me"), s.IdentScreenName())
				assert.Equal(t, [][16]byte{wire.CapChat}, s.Session().Caps())
				assert.True(t, s.IsTOC2())
			},
			givenCmd: []byte(`toc2_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
										wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{
							user: state.NewIdentScreenName("me"),
						},
					},
				},
				feedBagParams: feedBagParams{
					feedbagServiceUseParams: feedbagServiceUseParams{{err: nil}},
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        nil,
						},
					},
				},
			},
			wantMsg: []string{"SIGN_ON:TOC2.0", "NICK:me", "CONFIG2:done:\n"},
		},
		{
			name: "successfully login toc2_login (TOC2 with encoded messaging)",
			checkSession: func(t *testing.T, s *state.SessionInstance) {
				assert.Equal(t, state.NewIdentScreenName("me"), s.IdentScreenName())
				assert.Equal(t, [][16]byte{wire.CapChat}, s.Session().Caps())
				assert.True(t, s.IsTOC2())
				assert.True(t, s.SupportsTOC2MsgEnc())
			},
			givenCmd: []byte(`toc2_login "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
										wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{
							user: state.NewIdentScreenName("me"),
						},
					},
				},
				feedBagParams: feedBagParams{
					feedbagServiceUseParams: feedbagServiceUseParams{{err: nil}},
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        nil,
						},
					},
				},
			},
			wantMsg: []string{"SIGN_ON:TOC2.0", "NICK:me", "CONFIG2:done:\n"},
		},
		{
			name: "login TOC2, receive error from FeedbagService.Use",
			// Signon returns (sess, err) on feedbag errors, so session is non-nil; use no-op check
			checkSession: func(*testing.T, *state.SessionInstance) {},
			givenCmd:     []byte(`toc2_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
										wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{user: state.NewIdentScreenName("me")},
					},
				},
				feedBagParams: feedBagParams{
					feedbagServiceUseParams: feedbagServiceUseParams{{err: io.EOF}},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name: "login TOC2, receive error from FeedbagManager.Feedbag",
			// Signon returns (sess, err) on feedbag errors, so session is non-nil; use no-op check
			checkSession: func(*testing.T, *state.SessionInstance) {},
			givenCmd:     []byte(`toc2_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
										wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{user: state.NewIdentScreenName("me")},
					},
				},
				feedBagParams: feedBagParams{
					feedbagServiceUseParams: feedbagServiceUseParams{{err: nil}},
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    nil,
							err:        io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "login, receive error from auth svc FLAP login",
			givenCmd: []byte(`toc_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "login, receive error from auth svc registration",
			givenCmd: []byte(`toc_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							err:        io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "login, receive error from buddy list registry",
			givenCmd: []byte(`toc_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{
							user: state.NewIdentScreenName("me"),
							err:  io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "login, receive error from TOC config store",
			givenCmd: []byte(`toc_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{
							user: state.NewIdentScreenName("me"),
						},
					},
				},
				tocConfigParams: tocConfigParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("me"),
							err:        io.EOF,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "login, user not found after login",
			givenCmd: []byte(`toc_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("thecookie")),
								},
							},
						},
					},
					crackCookieParams: crackCookieParams{
						{
							cookieIn:  []byte("thecookie"),
							cookieOut: state.ServerCookie{Service: wire.BOS},
						},
					},
					registerBOSSessionParams: registerBOSSessionParams{
						{
							authCookie: state.ServerCookie{Service: wire.BOS},
							instance:   newTestSession("me"),
						},
					},
				},
				buddyListRegistryParams: buddyListRegistryParams{
					registerBuddyListParams: registerBuddyListParams{
						{
							user: state.NewIdentScreenName("me"),
						},
					},
				},
				tocConfigParams: tocConfigParams{
					userParams: userParams{
						{
							screenName:   state.NewIdentScreenName("me"),
							returnedUser: nil,
						},
					},
				},
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "login with bad credentials",
			givenCmd: []byte(`toc_signon "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			mockParams: mockParams{
				authParams: authParams{
					flapLoginParams: flapLoginParams{
						{
							frame: wire.FLAPSignonFrame{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
										wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
									},
								},
							},
							tlv: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword),
								},
							},
						},
					},
				},
			},
			wantMsg: []string{"ERROR:980"},
		},
		{
			name:     "bad command",
			givenCmd: []byte(`toc_bad "" "" me "0x` + hex.EncodeToString(roastedPass) + `"`),
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			authSvc := newMockAuthService(t)
			for _, params := range tc.mockParams.flapLoginParams {
				authSvc.EXPECT().
					FLAPLogin(matchContext(), params.frame, "").
					Return(params.tlv, params.err)
			}
			for _, params := range tc.mockParams.crackCookieParams {
				authSvc.EXPECT().
					CrackCookie(params.cookieIn).
					Return(params.cookieOut, params.err)
			}
			for _, params := range tc.mockParams.registerBOSSessionParams {
				authSvc.EXPECT().
					RegisterBOSSession(matchContext(), params.authCookie, mock.Anything).
					Return(params.instance, params.err)
			}
			buddyRegistry := newMockBuddyListRegistry(t)
			for _, params := range tc.mockParams.registerBuddyListParams {
				buddyRegistry.EXPECT().
					RegisterBuddyList(matchContext(), params.user).
					Return(params.err)
			}
			tocCfg := newMockTOCConfigStore(t)
			for _, params := range tc.mockParams.userParams {
				tocCfg.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.returnedUser, params.err)
			}
			fbSvc := newMockFeedbagService(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagServiceUseParams {
				fbSvc.EXPECT().
					Use(matchContext(), mock.Anything).
					Return(params.err)
			}
			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.results, params.err)
			}

			buddySvc := newMockBuddyService(t)

			chatSessionMgr := newMockChatSessionManager(t)
			for _, params := range tc.mockParams.removeUserFromAllChatsParams {
				chatSessionMgr.EXPECT().
					RemoveUserFromAllChats(params.user)
			}

			svc := OSCARProxy{
				AuthService:        authSvc,
				BuddyListRegistry:  buddyRegistry,
				BuddyService:       buddySvc,
				ChatSessionManager: chatSessionMgr,
				Logger:             slog.Default(),
				TOCConfigStore:     tocCfg,
				FeedbagService:     fbSvc,
				FeedbagManager:     fbMgr,
			}
			sess, msg := svc.Signon(ctx, tc.givenCmd,
				func(ctx context.Context, instance *state.SessionInstance) error { return nil },
				func(ctx context.Context, instance *state.SessionInstance) {},
				NewChatRegistry(),
			)

			assert.Equal(t, tc.wantMsg, msg)
			if tc.checkSession != nil {
				tc.checkSession(t, sess)
			} else {
				assert.Nil(t, sess)
			}
		})
	}
}

func TestOSCARProxy_RecvClientCmd_UnknownCmd(t *testing.T) {
	ctx := context.Background()

	svc := OSCARProxy{
		Logger: slog.Default(),
	}
	cmd := []byte("toc_unknown_cmd")
	msg := svc.RecvClientCmd(ctx, nil, nil, cmd, nil, nil)

	assert.Equal(t, cmdInternalSvcErr, msg[0])
}

func Test_parseArgs(t *testing.T) {
	type testCase struct {
		name         string
		givenPayload string
		givenArgs    []*string
		wantVarArgs  []string
		wantArgs     []string
		wantErrMsg   string
	}

	tests := []testCase{
		{
			name:         "no positional args or varargs",
			givenPayload: ``,
			givenArgs:    nil,
			wantVarArgs:  []string{},
		},
		{
			name:         "positional args with varargs",
			givenPayload: `1234 "Join me!" user1 user2 user3`,
			givenArgs:    []*string{new(string), new(string)},
			wantVarArgs:  []string{"user1", "user2", "user3"},
			wantArgs:     []string{"1234", "Join me!"},
		},
		{
			name:         "nil positional argument placeholders should get skipped",
			givenPayload: `1234 "Join me!" user1 user2 user3`,
			givenArgs:    []*string{nil, nil}, // still 2 placeholders, both nil
			wantVarArgs:  []string{"user1", "user2", "user3"},
			wantArgs:     []string{"", ""},
		},
		{
			name:         "positional args with no varargs",
			givenPayload: `1234 "Join me!"`,
			givenArgs:    []*string{new(string), new(string)}, // roomID + msg
			wantVarArgs:  []string{},
			wantArgs:     []string{"1234", "Join me!"},
		},
		{
			name:         "varargs only",
			givenPayload: `user1 user2 user3`,
			givenArgs:    nil,
			wantVarArgs:  []string{"user1", "user2", "user3"},
		},
		{
			name:         "too many positional arg placeholders",
			givenPayload: `toc_chat_invite`,
			givenArgs:    []*string{new(string), new(string)},
			wantVarArgs:  []string{},
			wantErrMsg:   "command contains fewer arguments than expected",
		},
		{
			name:         "CSV parser error",
			givenPayload: ``,
			givenArgs:    []*string{nil},
			wantVarArgs:  []string{},
			wantErrMsg:   "CSV reader error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			varArgs, err := parseArgs([]byte(tt.givenPayload), tt.givenArgs...)

			if tt.wantErrMsg != "" {
				assert.ErrorContains(t, err, tt.wantErrMsg)
				return
			}

			assert.NoError(t, err)

			// verify the placeholder pointers got populated
			for i, want := range tt.wantArgs {
				if want == "" {
					assert.Nil(t, tt.givenArgs[i])
				} else {
					got := *tt.givenArgs[i]
					assert.Equal(t, want, got)
				}
			}

			// verify we have the same varargs
			assert.Equal(t, tt.wantVarArgs, varArgs)
			assert.Equal(t, len(tt.wantArgs), len(tt.givenArgs))

		})
	}
}

func TestBuildToc2Config(t *testing.T) {
	tests := []struct {
		name    string
		fb      []wire.FeedbagItem
		want    []string // CONFIG2 command string(s), each starts with "CONFIG2:"
		wantErr string
	}{
		{
			name: "root group missing order attribute returns error",
			fb: []wire.FeedbagItem{
				{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, TLVLBlock: wire.TLVLBlock{}},
			},
			wantErr: "root group missing order attribute",
		},
		{
			name: "empty buddylist yields only done",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
			},
			want: []string{"CONFIG2:done:\n"},
		},
		{
			name: "single group with buddies",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "user1", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "user2", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []string{"CONFIG2:g:Buddies\nb:user1\nb:user2\ndone:\n"},
		},
		{
			name: "blocked user (d:) and private user (p:)",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
				{ClassID: wire.FeedbagClassIDDeny, Name: "blockeduser"},
				{ClassID: wire.FeedbagClassIDPermit, Name: "allowuser"},
			},
			want: []string{"CONFIG2:d:blockeduser\np:allowuser\ndone:\n"},
		},
		{
			name: "privacy level (m:) from pdinfo",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
				{
					ClassID:   wire.FeedbagClassIdPdinfo,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(3))}},
				},
			},
			want: []string{"CONFIG2:m:3\ndone:\n"},
		},
		{
			name: "buddy with alias",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{
					ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "bob",
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, "Bob Smith")}},
				},
			},
			want: []string{"CONFIG2:g:Buddies\nb:bob:Bob Smith\ndone:\n"},
		},
		{
			name: "buddy with note (comment) uses five colons before note",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{
					ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice",
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesNote, "Friend from work")}},
				},
			},
			want: []string{"CONFIG2:g:Buddies\nb:alice:::::Friend from work\ndone:\n"},
		},
		{
			name: "multiple groups in root order",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100, 200})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{Name: "Family", GroupID: 200, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend1", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 200, Name: "mom", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []string{"CONFIG2:g:Buddies\nb:friend1\ng:Family\nb:mom\ndone:\n"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildToc2Config(tt.fb)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestUnescape tests the unescape function
func TestUnescape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"No Escapes", "Hello World", "Hello World"},
		{"Escaped Brace", "Hello \\{World\\}", "Hello {World}"},
		{"Escaped Parentheses", "Test\\(123\\)", "Test(123)"},
		{"Escaped Brackets", "\\[List\\]", "[List]"},
		{"Escaped Dollar", "Price: \\$100", "Price: $100"},
		{"Escaped Quote", "She said \\\"Hello\\\"", "She said \"Hello\""},
		{"Multiple Escapes", "One\\, Two\\, Three", "One, Two, Three"},
		{"Consecutive Escapes", "\\\\\\$100", "\\$100"},
		{"Only Escape Character", "\\", ""},
		{"Empty Input", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := unescape(tt.input)
			if result != tt.expected {
				t.Errorf("unescape(%q) = %q; want %q", tt.input, result, tt.expected)
			}
		})
	}
}
