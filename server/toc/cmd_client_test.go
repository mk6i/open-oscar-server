package toc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// cmdTestCase is a TOC command and the SNACs and replies it should produce.
type cmdTestCase struct {
	// name is the unit test name
	name string
	// givenCmd is the TOC command
	givenCmd string
	// sendErrs are the errors returned by each SNAC send, in order
	sendErrs []error
	// wantSNACs are the SNACs the command sends to the BOS server
	wantSNACs []wire.SNACMessage
	// wantCacheData is the request context cached with the first SNAC
	wantCacheData any
	// wantMsg is the expected TOC response
	wantMsg []string
}

// runCmdTests runs TOC commands that only send SNACs over the BOS connection.
// TOC2 commands run on a TOC2 connection.
func runCmdTests(t *testing.T, cases []cmdTestCase) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me, bos := newTestTOCConn(newTestSession("me"))
			me.isTOC2 = strings.HasPrefix(tc.givenCmd, "toc2_")
			bos.sendErrs = tc.sendErrs

			svc := OSCARProxy{
				Logger: slog.Default(),
			}
			msg := svc.RecvClientCmd(context.Background(), me, []byte(tc.givenCmd))

			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.wantSNACs, bos.sentSNACs())
			if tc.wantCacheData != nil {
				req, ok := me.cache.take(wire.SNACFrame{FoodGroup: tc.wantSNACs[0].Frame.FoodGroup, RequestID: 1})
				assert.True(t, ok)
				assert.Equal(t, tc.wantCacheData, req.data)
			}
		})
	}
}

func TestOSCARProxy_send(t *testing.T) {
	t.Run("caches the request until its reply arrives", func(t *testing.T) {
		me, bos := newTestTOCConn(newTestSession("me"))
		svc := OSCARProxy{Logger: slog.Default()}

		msg := svc.send(context.Background(), me, bos, wire.Locate, wire.LocateUserInfoQuery, struct{}{}, getStatusReqCtx{screenName: "them"})
		assert.Nil(t, msg)

		req, ok := me.cache.take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: 1})
		assert.True(t, ok)
		assert.Equal(t, wire.LocateUserInfoQuery, req.frame.SubGroup)
		assert.Equal(t, getStatusReqCtx{screenName: "them"}, req.data)
	})

	t.Run("drops the cached request when the send fails", func(t *testing.T) {
		me, bos := newTestTOCConn(newTestSession("me"))
		bos.sendErrs = []error{io.EOF}
		svc := OSCARProxy{Logger: slog.Default()}

		msg := svc.send(context.Background(), me, bos, wire.Locate, wire.LocateUserInfoQuery, struct{}{}, nil)
		assert.Equal(t, []string{cmdInternalSvcErr}, msg)

		_, ok := me.cache.take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: 1})
		assert.False(t, ok)
	})
}

func TestOSCARProxy_RecvClientCmd_AddBuddy(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully add buddies",
			givenCmd: "toc_add_buddy friend1 friend2 friend3",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Buddy, wire.BuddyAddBuddies, 1, wire.SNAC_0x03_0x04_BuddyAddBuddies{
					Buddies: []struct {
						ScreenName string `oscar:"len_prefix=uint8"`
					}{
						{ScreenName: "friend1"},
						{ScreenName: "friend2"},
						{ScreenName: "friend3"},
					},
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "add buddies with empty list",
			givenCmd: "toc_add_buddy",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Buddy, wire.BuddyAddBuddies, 1, wire.SNAC_0x03_0x04_BuddyAddBuddies{}),
			},
			wantMsg: []string{},
		},
		{
			name:     "add buddies, send fails",
			givenCmd: "toc_add_buddy friend1",
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Buddy, wire.BuddyAddBuddies, 1, wire.SNAC_0x03_0x04_BuddyAddBuddies{
					Buddies: []struct {
						ScreenName string `oscar:"len_prefix=uint8"`
					}{
						{ScreenName: "friend1"},
					},
				}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_AddPermit(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully permit buddies",
			givenCmd: "toc_add_permit friend1 friend2",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.PermitDeny, wire.PermitDenyAddPermListEntries, 1, wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
					Users: []struct {
						ScreenName string `oscar:"len_prefix=uint8"`
					}{
						{ScreenName: "friend1"},
						{ScreenName: "friend2"},
					},
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "permit buddies with empty list",
			givenCmd: "toc_add_permit",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.PermitDeny, wire.PermitDenyAddPermListEntries, 1, wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{}),
			},
			wantMsg: []string{},
		},
		{
			name:     "permit buddies, send fails",
			givenCmd: "toc_add_permit",
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.PermitDeny, wire.PermitDenyAddPermListEntries, 1, wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_AddDeny(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully deny buddies",
			givenCmd: "toc_add_deny friend1 friend2",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.PermitDeny, wire.PermitDenyAddDenyListEntries, 1, wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
					Users: []struct {
						ScreenName string `oscar:"len_prefix=uint8"`
					}{
						{ScreenName: "friend1"},
						{ScreenName: "friend2"},
					},
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "deny buddies with empty list",
			givenCmd: "toc_add_deny",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.PermitDeny, wire.PermitDenyAddDenyListEntries, 1, wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{}),
			},
			wantMsg: []string{},
		},
		{
			name:     "deny buddies, send fails",
			givenCmd: "toc_add_deny",
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.PermitDeny, wire.PermitDenyAddDenyListEntries, 1, wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_RemoveBuddy(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully remove buddies",
			givenCmd: "toc_remove_buddy friend1 friend2",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Buddy, wire.BuddyDelBuddies, 1, wire.SNAC_0x03_0x05_BuddyDelBuddies{
					Buddies: []struct {
						ScreenName string `oscar:"len_prefix=uint8"`
					}{
						{ScreenName: "friend1"},
						{ScreenName: "friend2"},
					},
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "remove buddies with empty list",
			givenCmd: "toc_remove_buddy",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Buddy, wire.BuddyDelBuddies, 1, wire.SNAC_0x03_0x05_BuddyDelBuddies{}),
			},
			wantMsg: []string{},
		},
		{
			name:     "remove buddies, send fails",
			givenCmd: "toc_remove_buddy",
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Buddy, wire.BuddyDelBuddies, 1, wire.SNAC_0x03_0x05_BuddyDelBuddies{}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_ChangePassword(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully request password change",
			givenCmd: `toc_change_passwd "old\$pass" newpass`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Admin, wire.AdminInfoChangeRequest, 1, wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.AdminTLVOldPassword, "old$pass"),
							wire.NewTLVBE(wire.AdminTLVNewPassword, "newpass"),
						},
					},
				}),
			},
			wantCacheData: changePasswdReqCtx{},
			wantMsg:       []string{},
		},
		{
			name:     "request password change, send fails",
			givenCmd: `toc_change_passwd oldpass newpass`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Admin, wire.AdminInfoChangeRequest, 1, wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.AdminTLVOldPassword, "oldpass"),
							wire.NewTLVBE(wire.AdminTLVNewPassword, "newpass"),
						},
					},
				}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_change_passwd`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_FormatNickname(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully request screen name format change",
			givenCmd: `toc_format_nickname "{M E}"`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Admin, wire.AdminInfoChangeRequest, 1, wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "M E"),
						},
					},
				}),
			},
			wantCacheData: formatNickReqCtx{},
			wantMsg:       []string{},
		},
		{
			name:     "bad command",
			givenCmd: `toc_format_nickname`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_Evil(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully warn normally",
			givenCmd: `toc_evil them norm`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ICBM, wire.ICBMEvilRequest, 1, wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     0,
					ScreenName: "them",
				}),
			},
			wantCacheData: evilReqCtx{},
			wantMsg:       []string{},
		},
		{
			name:     "successfully warn anonymously",
			givenCmd: `toc_evil them anon`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ICBM, wire.ICBMEvilRequest, 1, wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     1,
					ScreenName: "them",
				}),
			},
			wantCacheData: evilReqCtx{},
			wantMsg:       []string{},
		},
		{
			name:     "warn with incorrect type",
			givenCmd: `toc_evil them blah`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_evil`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_GetStatus(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully request status",
			givenCmd: `toc_get_status them`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Locate, wire.LocateUserInfoQuery, 1, wire.SNAC_0x02_0x05_LocateUserInfoQuery{
					ScreenName: "them",
				}),
			},
			wantCacheData: getStatusReqCtx{screenName: "them"},
			wantMsg:       []string{},
		},
		{
			name:     "request status, send fails",
			givenCmd: `toc_get_status them`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Locate, wire.LocateUserInfoQuery, 1, wire.SNAC_0x02_0x05_LocateUserInfoQuery{
					ScreenName: "them",
				}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_get_status`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_ChatJoin(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully request room creation",
			givenCmd: `toc_chat_join 4 "my \$room"`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ChatNav, wire.ChatNavCreateRoom, 1, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
					Exchange: 4,
					Cookie:   "create",
					TLVBlock: wire.TLVBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatRoomTLVRoomName, "my $room"),
						},
					},
				}),
			},
			wantCacheData: chatJoinReqCtx{},
			wantMsg:       []string{},
		},
		{
			name:     "request room creation, send fails",
			givenCmd: `toc_chat_join 4 room`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ChatNav, wire.ChatNavCreateRoom, 1, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
					Exchange: 4,
					Cookie:   "create",
					TLVBlock: wire.TLVBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatRoomTLVRoomName, "room"),
						},
					},
				}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_chat_join`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad exchange number",
			givenCmd: `toc_chat_join four room`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_ChatAccept(t *testing.T) {
	room := wire.ICBMRoomInfo{
		Exchange: 4,
		Cookie:   "4-0-the room",
		Instance: 0,
	}

	cases := []struct {
		name          string
		givenCmd      string
		wantSNACs     []wire.SNACMessage
		wantCacheData any
		wantMsg       []string
	}{
		{
			name:     "successfully request room info",
			givenCmd: `toc_chat_accept 0`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ChatNav, wire.ChatNavRequestRoomInfo, 1, wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
					Cookie:         "4-0-the room",
					Exchange:       4,
					InstanceNumber: 0,
				}),
			},
			wantCacheData: chatAcceptReqCtx{chatID: 0},
			wantMsg:       []string{},
		},
		{
			name:     "accept invitation to unknown room",
			givenCmd: `toc_chat_accept 1`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad chat room ID",
			givenCmd: `toc_chat_accept zero`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_chat_accept`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me, bos := newTestTOCConn(newTestSession("me"))
			me.chats.Add(room)

			svc := OSCARProxy{
				Logger: slog.Default(),
			}
			msg := svc.RecvClientCmd(context.Background(), me, []byte(tc.givenCmd))

			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.wantSNACs, bos.sentSNACs())
			if tc.wantCacheData != nil {
				req, ok := me.cache.take(wire.SNACFrame{FoodGroup: wire.ChatNav, RequestID: 1})
				assert.True(t, ok)
				assert.Equal(t, tc.wantCacheData, req.data)
			}
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatInvite(t *testing.T) {
	room := wire.ICBMRoomInfo{
		Exchange: 4,
		Cookie:   "4-0-the room",
		Instance: 0,
	}
	invite := func(reqID uint32, guest string) wire.SNACMessage {
		return newSNAC(wire.ICBM, wire.ICBMChannelMsgToHost, reqID, wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			ChannelID:  wire.ICBMChannelRendezvous,
			ScreenName: guest,
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
						Type:       wire.ICBMRdvMessagePropose,
						Capability: wire.CapChat,
						TLVRestBlock: wire.TLVRestBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsInvitation, "join $us"),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMECharset, "us-ascii"),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMELang, "en"),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, room),
							},
						},
					}),
				},
			},
		})
	}

	cases := []struct {
		name      string
		givenCmd  string
		sendErrs  []error
		wantSNACs []wire.SNACMessage
		wantMsg   []string
	}{
		{
			name:     "successfully send chat invitations",
			givenCmd: `toc_chat_invite 0 "join \$us" friend1 friend2`,
			wantSNACs: []wire.SNACMessage{
				invite(1, "friend1"),
				invite(2, "friend2"),
			},
			wantMsg: []string{},
		},
		{
			name:     "send chat invitations, first send fails",
			givenCmd: `toc_chat_invite 0 "join \$us" friend1 friend2`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				invite(1, "friend1"),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "send chat invitation to unknown room",
			givenCmd: `toc_chat_invite 1 "join us" friend1`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad chat room ID",
			givenCmd: `toc_chat_invite zero "join us" friend1`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_chat_invite`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me, bos := newTestTOCConn(newTestSession("me"))
			bos.sendErrs = tc.sendErrs
			me.chats.Add(room)

			svc := OSCARProxy{
				Logger: slog.Default(),
			}
			msg := svc.RecvClientCmd(context.Background(), me, []byte(tc.givenCmd))

			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.wantSNACs, bos.sentSNACs())
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatLeave(t *testing.T) {
	cases := []struct {
		name          string
		givenCmd      string
		wantMsg       []string
		wantConnClose bool
	}{
		{
			name:          "successfully leave chat",
			givenCmd:      `toc_chat_leave 0`,
			wantMsg:       []string{"CHAT_LEFT:0"},
			wantConnClose: true,
		},
		{
			name:     "chat room ID with invalid format",
			givenCmd: `toc_chat_leave zero`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "missing chat session",
			givenCmd: `toc_chat_leave 1`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_chat_leave`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me, _ := newTestTOCConn(newTestSession("me"))
			chatConn := newFakeOSCARConn()
			me.chats.RegisterConn(0, chatConn)

			svc := OSCARProxy{
				Logger: slog.Default(),
			}
			msg := svc.RecvClientCmd(context.Background(), me, []byte(tc.givenCmd))

			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.wantConnClose, chatConn.isClosed())
			if tc.wantConnClose {
				assert.Nil(t, me.chats.RetrieveConn(0))
			}
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatSend(t *testing.T) {
	cases := []struct {
		name      string
		givenCmd  string
		sendErrs  []error
		wantSNACs []wire.SNACMessage
		wantMsg   []string
	}{
		{
			name:     "successfully send chat message",
			givenCmd: `toc_chat_send 0 "Hello \$world"`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Chat, wire.ChatChannelMsgToHost, 1, wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Channel: wire.ICBMChannelMIME,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)),
							wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello $world"),
								},
							}),
						},
					},
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "send chat message, send fails",
			givenCmd: `toc_chat_send 0 "Hello"`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Chat, wire.ChatChannelMsgToHost, 1, wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Channel: wire.ICBMChannelMIME,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)),
							wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello"),
								},
							}),
						},
					},
				}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "chat room ID with invalid format",
			givenCmd: `toc_chat_send zero "Hello"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "missing chat session",
			givenCmd: `toc_chat_send 1 "Hello"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_chat_send`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me, bos := newTestTOCConn(newTestSession("me"))
			chatConn := newFakeOSCARConn()
			chatConn.sendErrs = tc.sendErrs
			me.chats.RegisterConn(0, chatConn)

			svc := OSCARProxy{
				Logger: slog.Default(),
			}
			msg := svc.RecvClientCmd(context.Background(), me, []byte(tc.givenCmd))

			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.wantSNACs, chatConn.sentSNACs())
			assert.Empty(t, bos.sentSNACs())
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ChatWhisper(t *testing.T) {
	cases := []struct {
		name      string
		givenCmd  string
		sendErrs  []error
		wantSNACs []wire.SNACMessage
		wantMsg   []string
	}{
		{
			name:     "successfully send chat whisper",
			givenCmd: `toc_chat_whisper 0 them "Hello \$world"`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Chat, wire.ChatChannelMsgToHost, 1, wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Channel: wire.ICBMChannelMIME,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVWhisperToUser, "them"),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello $world"),
								},
							}),
						},
					},
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "send chat whisper, send fails",
			givenCmd: `toc_chat_whisper 0 them "Hello"`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.Chat, wire.ChatChannelMsgToHost, 1, wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Channel: wire.ICBMChannelMIME,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVWhisperToUser, "them"),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello"),
								},
							}),
						},
					},
				}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "chat room ID with invalid format",
			givenCmd: `toc_chat_whisper zero them "Hello"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "missing chat session",
			givenCmd: `toc_chat_whisper 1 them "Hello"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_chat_whisper`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me, _ := newTestTOCConn(newTestSession("me"))
			chatConn := newFakeOSCARConn()
			chatConn.sendErrs = tc.sendErrs
			me.chats.RegisterConn(0, chatConn)

			svc := OSCARProxy{
				Logger: slog.Default(),
			}
			msg := svc.RecvClientCmd(context.Background(), me, []byte(tc.givenCmd))

			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, tc.wantSNACs, chatConn.sentSNACs())
		})
	}
}

func TestOSCARProxy_RecvClientCmd_ClientEvent(t *testing.T) {
	event := func(status uint16) wire.SNACMessage {
		return newSNAC(wire.ICBM, wire.ICBMClientEvent, 1, wire.SNAC_0x04_0x14_ICBMClientEvent{
			ChannelID:  wire.ICBMChannelIM,
			ScreenName: "them",
			Event:      status,
		})
	}
	runCmdTests(t, []cmdTestCase{
		{
			name:      "send typing status 0 (no activity)",
			givenCmd:  `toc2_client_event them 0`,
			wantSNACs: []wire.SNACMessage{event(0)},
			wantMsg:   []string{},
		},
		{
			name:      "send typing status 1 (typing paused)",
			givenCmd:  `toc2_client_event them 1`,
			wantSNACs: []wire.SNACMessage{event(1)},
			wantMsg:   []string{},
		},
		{
			name:      "send typing status 2 (currently typing)",
			givenCmd:  `toc2_client_event them 2`,
			wantSNACs: []wire.SNACMessage{event(2)},
			wantMsg:   []string{},
		},
		{
			name:      "send typing status, send fails",
			givenCmd:  `toc2_client_event them 2`,
			sendErrs:  []error{io.EOF},
			wantSNACs: []wire.SNACMessage{event(2)},
			wantMsg:   []string{cmdInternalSvcErr},
		},
		{
			name:     "missing args",
			givenCmd: `toc2_client_event`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "missing typing status",
			givenCmd: `toc2_client_event them`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "invalid typing status (must be 0, 1, or 2)",
			givenCmd: `toc2_client_event them 3`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "invalid typing status non-numeric",
			givenCmd: `toc2_client_event them x`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_InitDone(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully initialize connection",
			givenCmd: "toc_init_done",
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.OService, wire.OServiceClientOnline, 1, wire.SNAC_0x01_0x02_OServiceClientOnline{}),
			},
			wantMsg: []string{},
		},
		{
			name:     "initialize connection, send fails",
			givenCmd: "toc_init_done",
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.OService, wire.OServiceClientOnline, 1, wire.SNAC_0x01_0x02_OServiceClientOnline{}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_RvousAccept(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully send rendezvous accept",
			givenCmd: `toc_rvous_accept them aGFoYWhhaGE= 09461343-4C7F-11D1-8222-444553540000`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ICBM, wire.ICBMChannelMsgToHost, 1, wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
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
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "bad cookie",
			givenCmd: `toc_rvous_accept them @@@ 09461343-4C7F-11D1-8222-444553540000`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad capability",
			givenCmd: `toc_rvous_accept them aGFoYWhhaGE= notauuid`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_rvous_accept`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_RvousCancel(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully send rendezvous cancellation",
			givenCmd: `toc_rvous_cancel them aGFoYWhhaGE= 09461343-4C7F-11D1-8222-444553540000`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ICBM, wire.ICBMChannelMsgToHost, 1, wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
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
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "bad cookie",
			givenCmd: `toc_rvous_cancel them @@@ 09461343-4C7F-11D1-8222-444553540000`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_rvous_cancel`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

// asciiIM returns the ICBM channel 1 message a TOC IM command sends for text.
func asciiIM(reqID uint32, recip string, text string, autoReply bool) wire.SNACMessage {
	payload := append([]byte{0x00, 0x00, 0x00, 0x00}, text...)
	body := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: recip,
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
						Payload: payload,
					},
				}),
			},
		},
	}
	if autoReply {
		body.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
	}
	return newSNAC(wire.ICBM, wire.ICBMChannelMsgToHost, reqID, body)
}

func TestOSCARProxy_RecvClientCmd_SendIM(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:      "successfully send instant message",
			givenCmd:  `toc_send_im chattingChuck "hello \$world"`,
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello $world", false)},
			wantMsg:   []string{},
		},
		{
			name:      "successfully send TOC2 instant message",
			givenCmd:  `toc2_send_im chattingChuck "hello"`,
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", false)},
			wantMsg:   []string{},
		},
		{
			name:      "successfully auto-reply send instant message",
			givenCmd:  `toc_send_im chattingChuck "hello" auto`,
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", true)},
			wantMsg:   []string{},
		},
		{
			name:      "send instant message, send fails",
			givenCmd:  `toc_send_im chattingChuck "hello"`,
			sendErrs:  []error{io.EOF},
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", false)},
			wantMsg:   []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_send_im`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_SendIMEnc(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:      "successfully send encoded instant message",
			givenCmd:  `toc2_send_im_enc chattingChuck "F" utf-8 en "hello"`,
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", false)},
			wantMsg:   []string{},
		},
		{
			name:      "successfully send ASCII-encoded instant message",
			givenCmd:  `toc2_send_im_enc chattingChuck "F" A en "hello"`,
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", false)},
			wantMsg:   []string{},
		},
		{
			name:     "successfully send UTF-8-encoded non-ASCII instant message as unicode",
			givenCmd: `toc2_send_im_enc chattingChuck "F" U en "привет"`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.ICBM, wire.ICBMChannelMsgToHost, 1, wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "chattingChuck",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
								{
									ID:      5,
									Version: 1,
									Payload: []byte{1, 6},
								},
								{
									ID:      1,
									Version: 1,
									Payload: []byte{
										0x00, 0x02,
										0x00, 0x00,
										0x04, 0x3F, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42,
									},
								},
							}),
						},
					},
				}),
			},
			wantMsg: []string{},
		},
		{
			name:      "successfully send UTF-8-encoded ASCII instant message as ASCII",
			givenCmd:  `toc2_send_im_enc chattingChuck "F" U en "hello"`,
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", false)},
			wantMsg:   []string{},
		},
		{
			name:      "successfully send encoded instant message with auto",
			givenCmd:  `toc2_send_im_enc chattingChuck "F" utf-8 en "hello" auto`,
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", true)},
			wantMsg:   []string{},
		},
		{
			name:      "send encoded instant message, send fails",
			givenCmd:  `toc2_send_im_enc chattingChuck "F" utf-8 en "hello"`,
			sendErrs:  []error{io.EOF},
			wantSNACs: []wire.SNACMessage{asciiIM(1, "chattingChuck", "hello", false)},
			wantMsg:   []string{cmdInternalSvcErr},
		},
		{
			name:     "invalid args too few",
			givenCmd: `toc2_send_im_enc`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

// setInfoSNAC returns the locate set info SNAC a TOC command sends.
func setInfoSNAC(reqID uint32, tlv wire.TLV) wire.SNACMessage {
	return newSNAC(wire.Locate, wire.LocateSetInfo, reqID, wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{tlv},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_SetAway(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully set away with message",
			givenCmd: `toc_set_away "brb \$5"`,
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "brb $5")),
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set away without message",
			givenCmd: `toc_set_away`,
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "")),
			},
			wantMsg: []string{},
		},
		{
			name:     "set away message, send fails",
			givenCmd: `toc_set_away "brb"`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "brb")),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_SetCaps(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully set capabilities",
			givenCmd: `toc_set_caps 09460000-4C7F-11D1-8222-444553540000 09460001-4C7F-11D1-8222-444553540000`,
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
					uuid.MustParse("09460000-4C7F-11D1-8222-444553540000"),
					uuid.MustParse("09460001-4C7F-11D1-8222-444553540000"),
					wire.CapChat,
				})),
			},
			wantMsg: []string{},
		},
		{
			name:     "set capabilities with empty list",
			givenCmd: `toc_set_caps`,
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
					wire.CapChat,
				})),
			},
			wantMsg: []string{},
		},
		{
			name:     "set capability, send fails",
			givenCmd: `toc_set_caps 09460000-4C7F-11D1-8222-444553540000`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
					uuid.MustParse("09460000-4C7F-11D1-8222-444553540000"),
					wire.CapChat,
				})),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "set malformed capability UUID is skipped",
			givenCmd: `toc_set_caps 09460000-`,
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
					wire.CapChat,
				})),
			},
			wantMsg: []string{},
		},
		{
			name:     "set capabilities with comma-separated list (TameClone format)",
			givenCmd: `toc_set_caps 748F2420-6287-11D1-8222-444553540000,1348,134B,1341,1343,1FF,1345,1346,1347,`,
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{
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
				})),
			},
			wantMsg: []string{},
		},
	})
}

// setDirSNAC returns the locate set dir info SNAC a toc_set_dir command
// sends for the given fields.
func setDirSNAC(reqID uint32, first, middle, last, maiden, city, state, country string) wire.SNACMessage {
	return newSNAC(wire.Locate, wire.LocateSetDirInfo, reqID, wire.SNAC_0x02_0x09_LocateSetDirInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ODirTLVFirstName, first),
				wire.NewTLVBE(wire.ODirTLVMiddleName, middle),
				wire.NewTLVBE(wire.ODirTLVLastName, last),
				wire.NewTLVBE(wire.ODirTLVMaidenName, maiden),
				wire.NewTLVBE(wire.ODirTLVCountry, country),
				wire.NewTLVBE(wire.ODirTLVState, state),
				wire.NewTLVBE(wire.ODirTLVCity, city),
			},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_SetDir(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully set directory info with quoted fields",
			givenCmd: `toc_set_dir "first name\$":"middle name":"last name":"maiden name":"city":"state":"country":"email":"allow web searches"`,
			wantSNACs: []wire.SNACMessage{
				setDirSNAC(1, "first name$", "middle name", "last name", "maiden name", "city", "state", "country"),
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set directory info with some blank fields",
			givenCmd: `toc_set_dir "first name"::"last name"::"city":"state":"country":"email":"allow web searches"`,
			wantSNACs: []wire.SNACMessage{
				setDirSNAC(1, "first name", "", "last name", "", "city", "state", "country"),
			},
			wantMsg: []string{},
		},
		{
			name:     "successfully set directory info with last two fields absent",
			givenCmd: `toc_set_dir "first name"::"last name"::"city":"state":"country"`,
			wantSNACs: []wire.SNACMessage{
				setDirSNAC(1, "first name", "", "last name", "", "city", "state", "country"),
			},
			wantMsg: []string{},
		},
		{
			name:     "set directory info, send fails",
			givenCmd: `toc_set_dir "first name":"middle name":"last name":"maiden name":"city":"state":"country":"email":"allow web searches"`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				setDirSNAC(1, "first name", "middle name", "last name", "maiden name", "city", "state", "country"),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "set directory with too many fields present",
			givenCmd: `toc_set_dir "first name"::"last name"::"city":"state":"country":"email":"allow web searches":"extra":"extra"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_set_dir`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_SetIdle(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully set idle status",
			givenCmd: `toc_set_idle 10`,
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.OService, wire.OServiceIdleNotification, 1, wire.SNAC_0x01_0x11_OServiceIdleNotification{
					IdleTime: 10,
				}),
			},
			wantMsg: []string{},
		},
		{
			name:     "set idle status, send fails",
			givenCmd: `toc_set_idle 10`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.OService, wire.OServiceIdleNotification, 1, wire.SNAC_0x01_0x11_OServiceIdleNotification{
					IdleTime: 10,
				}),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad secs param",
			givenCmd: `toc_set_idle ten`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_set_idle`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_SetInfo(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "successfully set profile",
			givenCmd: `toc_set_info "my profile costs \$5"`,
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "my profile costs $5")),
			},
			wantMsg: []string{},
		},
		{
			name:     "set profile, send fails",
			givenCmd: `toc_set_info "my profile"`,
			sendErrs: []error{io.EOF},
			wantSNACs: []wire.SNACMessage{
				setInfoSNAC(1, wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "my profile")),
			},
			wantMsg: []string{cmdInternalSvcErr},
		},
		{
			name:     "bad command",
			givenCmd: `toc_set_info`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
}

func TestOSCARProxy_RecvClientCmd_UnknownCmd(t *testing.T) {
	runCmdTests(t, []cmdTestCase{
		{
			name:     "unknown command",
			givenCmd: `toc_does_not_exist`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	})
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 21827, 29709})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								{Name: "Co-Workers", GroupID: 21827, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mike", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mk6i", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}},
								},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 29709, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 4, ClassID: wire.FeedbagClassIdBuddy, GroupID: 29709, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{3, 4})}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						// First: insert the two buddy items (deterministic randIntn gives GroupID 1, ItemIDs 2 and 3)
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "mike", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "mk6i", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
						// Second: insert the root group so its Order lists the new group ID
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							err: nil,
						},
						// Third: insert the new Buddies group with Order listing the buddy item IDs
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 3})}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "carol", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "dan", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
						// Root updated once, before the new groups
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 1, 4})}},
								},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Co-Workers", GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 3})}},
								},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 5, ClassID: wire.FeedbagClassIdBuddy, GroupID: 4, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 6, ClassID: wire.FeedbagClassIdBuddy, GroupID: 4, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Family", GroupID: 4, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{5, 6})}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{},
				},
			},
		},
		{
			name:     "feedbag upsert send error on first insert returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_buddies {g:Buddies\nb:alice\n}"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
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
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: errors.New("EOF"),
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mike", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 17724, Name: "mk6i", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}},
								},
							},
							err: nil,
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
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{},
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
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 1, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
								},
								{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}}},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
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
							err: nil,
						},
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
								},
							},
							err: nil,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 1})}},
								},
								{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Family"},
							},
							err: nil,
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
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
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
							err: nil,
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{},
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
					feedbagParams:       feedbagParams{},
					upsertFeedbagParams: upsertFeedbagParams{},
				},
			},
		},
		{
			name:     "feedbag upsert send error returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_new_group Family"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 1})}},
								},
								{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Family"},
							},
							err: assert.AnError,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
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
							err: nil,
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
							},
							err: nil,
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
					feedbagParams:       feedbagParams{},
					deleteFeedbagParams: deleteFeedbagParams{},
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
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{},
				},
			},
		},
		{
			name:     "feedbag delete send error returns error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_del_group Family"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							results: []wire.FeedbagItem{
								{
									Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{17724, 29709})}},
								},
								{Name: "Buddies", GroupID: 17724, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{Name: "Family", GroupID: 29709, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
								},
							},
							err: assert.AnError,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
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
							err: nil,
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
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
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
							err: nil,
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
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{},
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
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
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
							err: nil,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
			name:     "feedbag upsert send error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_permit alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: errors.New("EOF"),
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
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
			name:     "feedbag upsert send error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_add_deny alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: errors.New("EOF"),
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
							results: []wire.FeedbagItem{},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
							items: []wire.FeedbagItem{
								{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
							results: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2, 3})}},
								},
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend1", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend2", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend3", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend2", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							err: nil,
						},
					},
					upsertFeedbagParams: upsertFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
							items: []wire.FeedbagItem{
								{
									Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 3})}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{},
					upsertFeedbagParams: upsertFeedbagParams{},
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
							results: []wire.FeedbagItem{
								{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
									TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
								{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend1", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{},
					upsertFeedbagParams: upsertFeedbagParams{},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
			name:     "feedbag delete send error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_permit alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							err: errors.New("EOF"),
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
									{ItemID: 2, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
			name:     "feedbag delete send error returns internal error",
			me:       newTestSession("me"),
			givenCmd: []byte("toc2_remove_deny alice"),
			wantMsg:  []string{cmdInternalSvcErr},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							err: errors.New("EOF"),
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
									{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{
								{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
							},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{
						{
							frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
							inBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
								Items: []wire.FeedbagItem{
									{ItemID: 1, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "alice", TLVLBlock: wire.TLVLBlock{}},
								},
							},
							err: nil,
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
							results: []wire.FeedbagItem{},
						},
					},
					deleteFeedbagParams: deleteFeedbagParams{},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			me, bos := newTestTOCConn(tc.me)
			me.isTOC2 = true
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}
			wantSNACs, sendErrs := feedbagSNACs(tc.mockParams.feedBagParams)
			bos.sendErrs = sendErrs

			// Deterministic item ID: increment by 1 per call so IDs are unique and predictable per test.
			var randCall int
			randIntn := func(n int) int {
				randCall++
				return randCall
			}
			svc := OSCARProxy{
				Logger:   slog.Default(),
				RandIntn: randIntn,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)
			assert.Equal(t, tc.wantMsg, msg)
			assert.Equal(t, wantSNACs, bos.sentSNACs())
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
					Issue(params.data, state.DefaultCookieTTL).
					Return(params.returnData, params.returnErr)
			}

			me, bos := newTestTOCConn(tc.me)
			svc := OSCARProxy{
				Logger:      slog.Default(),
				CookieBaker: cookieBaker,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)

			assert.Equal(t, tc.wantMsg, msg)
			assert.Empty(t, bos.sentSNACs())
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
					Issue(params.data, state.DefaultCookieTTL).
					Return(params.returnData, params.returnErr)
			}

			me, bos := newTestTOCConn(tc.me)
			svc := OSCARProxy{
				Logger:      slog.Default(),
				CookieBaker: cookieBaker,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)

			assert.Equal(t, tc.wantMsg, msg)
			assert.Empty(t, bos.sentSNACs())
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
					Issue(params.data, state.DefaultCookieTTL).
					Return(params.returnData, params.returnErr)
			}

			me, bos := newTestTOCConn(tc.me)
			svc := OSCARProxy{
				Logger:      slog.Default(),
				CookieBaker: cookieBaker,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)

			assert.Equal(t, tc.wantMsg, msg)
			assert.Empty(t, bos.sentSNACs())
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

			tocConfigSvc := newMockTOCConfigStore(t)
			for _, params := range tc.mockParams.setTOCConfigParams {
				tocConfigSvc.EXPECT().
					SetTOCConfig(matchContext(), params.user, params.config).
					Return(params.err)
			}

			me, bos := newTestTOCConn(tc.me)
			svc := OSCARProxy{
				Logger:         slog.Default(),
				TOCConfigStore: tocConfigSvc,
			}
			msg := svc.RecvClientCmd(ctx, me, tc.givenCmd)

			assert.Equal(t, tc.wantMsg, msg)
			assert.Empty(t, bos.sentSNACs())
		})
	}
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
		{
			name: "group order listing a missing buddy skips it",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend2", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []string{"CONFIG2:g:Buddies\nb:friend2\ndone:\n"},
		},
		{
			name: "root order listing a missing group skips it",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100, 200})}},
				},
				{Name: "Family", GroupID: 200, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
			},
			want: []string{"CONFIG2:g:Family\ndone:\n"},
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

func TestOSCARProxy_Signon(t *testing.T) {
	clientAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}
	roastedPass := []byte{0x24, 0x08, 0x10, 0x5c, 0x23, 0x00, 0x11, 0x30}
	cookie := []byte("the-cookie")

	// bosReply answers signon queries the way the BOS server does.
	bosReply := func(feedbag []wire.FeedbagItem) func(frame wire.SNACFrame) []wire.SNACMessage {
		return func(frame wire.SNACFrame) []wire.SNACMessage {
			switch {
			case frame.FoodGroup == wire.OService && frame.SubGroup == wire.OServiceUserInfoQuery:
				return []wire.SNACMessage{newSNAC(wire.OService, wire.OServiceUserInfoUpdate, frame.RequestID,
					wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{
						UserInfo: []wire.TLVUserInfo{{ScreenName: "M E"}},
					})}
			case frame.FoodGroup == wire.Feedbag && frame.SubGroup == wire.FeedbagQuery:
				return []wire.SNACMessage{newSNAC(wire.Feedbag, wire.FeedbagReply, frame.RequestID,
					wire.SNAC_0x13_0x06_FeedbagReply{Items: feedbag})}
			}
			return nil
		}
	}
	signonSNACs := func(t *testing.T) []receivedSNAC {
		return []receivedSNAC{
			newReceivedSNAC(t, wire.OService, wire.OServiceRateParamsSubAdd, 1, wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
				ClassIDs: []uint16{1, 2, 3, 4, 5},
			}),
			newReceivedSNAC(t, wire.Locate, wire.LocateSetInfo, 2, wire.SNAC_0x02_0x04_LocateSetInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{wire.CapChat}),
					},
				},
			}),
			newReceivedSNAC(t, wire.OService, wire.OServiceUserInfoQuery, 3, struct{}{}),
		}
	}
	authOK := []wire.TLV{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
		wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, cookie),
	}
	toc1AuthTLVs := wire.TLVList{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
		wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, roastedPass),
	}
	toc2AuthTLVs := append(append(wire.TLVList{}, toc1AuthTLVs...),
		wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))

	cases := []struct {
		// name is the unit test name
		name string
		// givenCmd is the signon command
		givenCmd string
		// authReply are the TLVs the auth service replies with, nil when TOC
		// shouldn't connect to it
		authReply []wire.TLV
		// bos is the BOS service, nil when TOC shouldn't connect to it
		bos *fakeService
		// tocConfig is the stored TOC1 config, or tocConfigErr its lookup error
		tocConfig    *state.User
		tocConfigErr error
		// wantAuthTLVs are the TLVs TOC sends the auth service
		wantAuthTLVs wire.TLVList
		// wantBOSSNACs returns the SNACs TOC sends the BOS service
		wantBOSSNACs func(t *testing.T) []receivedSNAC
		// wantMsg is the expected TOC response
		wantMsg []string
		// wantTOC2 and wantMsgEnc are the TOC version of a successful signon
		wantTOC2, wantMsgEnc bool
		// wantBacklog is the number of BOS SNACs kept for RecvBOS
		wantBacklog int
		// wantFeedbag is the feedbag mirror after signon
		wantFeedbag []wire.FeedbagItem
		// bucpAuth makes the auth service reply the way it does to an address
		// that recently used BUCP login
		bucpAuth bool
	}{
		{
			name:         "successfully login TOC1",
			givenCmd:     `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    authOK,
			bos:          &fakeService{reply: bosReply(nil)},
			tocConfig:    &state.User{TOCConfig: "m 1\ng Buddies"},
			wantAuthTLVs: toc1AuthTLVs,
			wantBOSSNACs: signonSNACs,
			wantMsg:      []string{"SIGN_ON:TOC1.0", "CONFIG:m 1\ng Buddies", "NICK:M E"},
		},
		{
			name:         "successfully login TOC2",
			givenCmd:     `toc2_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    authOK,
			bos:          &fakeService{reply: bosReply(nil)},
			wantAuthTLVs: toc2AuthTLVs,
			wantBOSSNACs: func(t *testing.T) []receivedSNAC {
				return append(signonSNACs(t),
					newReceivedSNAC(t, wire.Feedbag, wire.FeedbagUse, 4, struct{}{}),
					newReceivedSNAC(t, wire.Feedbag, wire.FeedbagQuery, 5, struct{}{}),
				)
			},
			wantMsg:  []string{"SIGN_ON:TOC2.0", "NICK:M E", "CONFIG2:done:\n"},
			wantTOC2: true,
		},
		{
			name:      "successfully login toc2_login (TOC2 with encoded messaging)",
			givenCmd:  `toc2_login localhost 9898 me 0x2408105c23001130 english "TIC:TOC" 160 US "" "" 3 0 30303 -kentucky -utf8 103547776`,
			authReply: authOK,
			bos: &fakeService{reply: bosReply([]wire.FeedbagItem{
				{
					ClassID:   wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
				},
				{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Buddies"},
			})},
			wantAuthTLVs: toc2AuthTLVs,
			wantBOSSNACs: func(t *testing.T) []receivedSNAC {
				return append(signonSNACs(t),
					newReceivedSNAC(t, wire.Feedbag, wire.FeedbagUse, 4, struct{}{}),
					newReceivedSNAC(t, wire.Feedbag, wire.FeedbagQuery, 5, struct{}{}),
				)
			},
			wantMsg:    []string{"SIGN_ON:TOC2.0", "NICK:M E", "CONFIG2:g:Buddies\ndone:\n"},
			wantTOC2:   true,
			wantMsgEnc: true,
			wantFeedbag: []wire.FeedbagItem{
				{
					ClassID:   wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}},
				},
				{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Buddies"},
			},
		},
		{
			name:      "SNACs that arrive during signon are kept for later",
			givenCmd:  `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply: authOK,
			bos: &fakeService{
				greeting: []wire.SNACMessage{
					newSNAC(wire.Buddy, wire.BuddyArrived, wire.ReqIDFromServer, wire.SNAC_0x03_0x0B_BuddyArrived{
						TLVUserInfo: wire.TLVUserInfo{ScreenName: "them"},
					}),
				},
				reply: bosReply(nil),
			},
			tocConfig:    &state.User{},
			wantAuthTLVs: toc1AuthTLVs,
			wantBOSSNACs: signonSNACs,
			wantMsg:      []string{"SIGN_ON:TOC1.0", "CONFIG:", "NICK:M E"},
			wantBacklog:  1,
		},
		{
			name:         "login with bad credentials",
			givenCmd:     `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    []wire.TLV{wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidUsernameOrPassword)},
			wantAuthTLVs: toc1AuthTLVs,
			wantMsg:      []string{"ERROR:" + wire.TOCErrorAuthIncorrectNickOrPassword},
		},
		{
			name:         "login rate limited",
			givenCmd:     `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    []wire.TLV{wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrRateLimitExceeded)},
			wantAuthTLVs: toc1AuthTLVs,
			wantMsg:      []string{"ERROR:" + wire.TOCErrorAuthRatedFromLogin},
		},
		{
			name:         "login rate limited at an address that recently used BUCP login",
			givenCmd:     `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    []wire.TLV{wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrRateLimitExceeded)},
			bucpAuth:     true,
			wantAuthTLVs: toc1AuthTLVs,
			wantMsg:      []string{"ERROR:" + wire.TOCErrorAuthRatedFromLogin},
		},
		{
			name:         "login reply missing cookie",
			givenCmd:     `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    []wire.TLV{wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me")},
			wantAuthTLVs: toc1AuthTLVs,
			wantMsg:      []string{cmdInternalSvcErr},
		},
		{
			name:         "BOS service refuses the session",
			givenCmd:     `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    authOK,
			bos:          &fakeService{refuse: true},
			wantAuthTLVs: toc1AuthTLVs,
			wantBOSSNACs: func(t *testing.T) []receivedSNAC { return nil },
			wantMsg:      []string{cmdInternalSvcErr},
		},
		{
			name:      "user info query fails",
			givenCmd:  `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply: authOK,
			bos: &fakeService{reply: func(frame wire.SNACFrame) []wire.SNACMessage {
				if frame.SubGroup == wire.OServiceUserInfoQuery {
					return []wire.SNACMessage{newSNAC(wire.OService, wire.OServiceErr, frame.RequestID,
						wire.SNACError{Code: wire.ErrorCodeServiceUnavailable})}
				}
				return nil
			}},
			wantAuthTLVs: toc1AuthTLVs,
			wantBOSSNACs: signonSNACs,
			wantMsg:      []string{cmdInternalSvcErr},
		},
		{
			name:         "TOC1 config lookup fails",
			givenCmd:     `toc_signon localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			authReply:    authOK,
			bos:          &fakeService{reply: bosReply(nil)},
			tocConfigErr: io.EOF,
			wantAuthTLVs: toc1AuthTLVs,
			wantBOSSNACs: signonSNACs,
			wantMsg:      []string{cmdInternalSvcErr},
		},
		{
			name:     "unknown signon command",
			givenCmd: `toc_bogus localhost 9898 me 0x2408105c23001130 english "TIC:TOC"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "password too short",
			givenCmd: `toc_signon localhost 9898 me 0x english "TIC:TOC"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
		{
			name:     "password not hex",
			givenCmd: `toc_signon localhost 9898 me 0xzz english "TIC:TOC"`,
			wantMsg:  []string{cmdInternalSvcErr},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			var gotAuth wire.FLAPSignonFrame
			oscarServer := &fakeOSCARServer{}
			switch {
			case tc.bucpAuth:
				oscarServer.handlers = append(oscarServer.handlers, fakeAuthBUCP(&gotAuth, tc.authReply...))
			case tc.authReply != nil:
				oscarServer.handlers = append(oscarServer.handlers, fakeAuth(&gotAuth, tc.authReply...))
			}
			if tc.bos != nil {
				tc.bos.ended = make(chan struct{})
				oscarServer.handlers = append(oscarServer.handlers, tc.bos.handle)
			}

			tocConfigStore := newMockTOCConfigStore(t)
			if tc.tocConfig != nil || tc.tocConfigErr != nil {
				tocConfigStore.EXPECT().
					User(ctx, state.NewIdentScreenName("me")).
					Return(tc.tocConfig, tc.tocConfigErr)
			}

			svc := OSCARProxy{
				Logger:         slog.Default(),
				OSCARServer:    oscarServer,
				TOCConfigStore: tocConfigStore,
			}
			me, msg := svc.Signon(ctx, []byte(tc.givenCmd), clientAddr)
			assert.Equal(t, tc.wantMsg, msg)

			if tc.authReply != nil {
				assert.Equal(t, tc.wantAuthTLVs, gotAuth.TLVList)
			}
			if tc.bos != nil {
				gotCookie, gotSNACs := tc.bos.received()
				assert.Equal(t, cookie, gotCookie)
				assert.Equal(t, tc.wantBOSSNACs(t), gotSNACs)
			}

			oscarServer.mu.Lock()
			assert.Empty(t, oscarServer.handlers, "TOC didn't open every expected connection")
			for _, addr := range oscarServer.clientAddrs {
				assert.Equal(t, clientAddr, addr)
			}
			oscarServer.mu.Unlock()

			if me == nil {
				if tc.bos != nil {
					// a failed signon doesn't leave the user signed on
					select {
					case <-tc.bos.ended:
					case <-time.After(time.Second):
						t.Fatal("BOS connection still open after failed signon")
					}
				}
				return
			}
			assert.Equal(t, state.NewIdentScreenName("me"), me.IdentScreenName())
			assert.Equal(t, tc.wantTOC2, me.IsTOC2())
			assert.Equal(t, tc.wantMsgEnc, me.SupportsTOC2MsgEnc())
			assert.Len(t, me.backlog, tc.wantBacklog)
			assert.Equal(t, tc.wantFeedbag, me.feedbag.snapshot())
			me.bos.Close()
		})
	}
}

func TestOSCARProxy_RecvClientCmd_LocalRateLimit(t *testing.T) {
	cookieBaker := newMockCookieBaker(t)
	cookieBaker.EXPECT().
		Issue([]byte("me"), state.DefaultCookieTTL).
		Return([]byte("cookie"), nil).
		Times(5)

	me, bos := newTestTOCConn(newTestSession("me"))
	svc := OSCARProxy{
		Logger:      slog.Default(),
		CookieBaker: cookieBaker,
	}

	// commands that don't reach the OSCAR server are limited locally
	for range 5 {
		msg := svc.RecvClientCmd(context.Background(), me, []byte("toc_get_info them"))
		assert.Len(t, msg, 1)
		assert.Contains(t, msg[0], "GOTO_URL:profile:")
	}
	msg := svc.RecvClientCmd(context.Background(), me, []byte("toc_get_info them"))
	assert.Equal(t, []string{rateLimitExceededErr}, msg)
	assert.Empty(t, bos.sentSNACs())
}

func TestOSCARProxy_RecvClientCmd_FeedbagMirrorFollowsChanges(t *testing.T) {
	me, bos := newTestTOCConn(newTestSession("me"))
	me.isTOC2 = true
	me.feedbag.reset([]wire.FeedbagItem{
		{
			ClassID:   wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
		},
	})

	var randCall int
	svc := OSCARProxy{
		Logger: slog.Default(),
		RandIntn: func(n int) int {
			randCall++
			return randCall
		},
	}

	// the second command sees the group the first one added
	assert.Equal(t, []string{}, svc.RecvClientCmd(context.Background(), me, []byte("toc2_new_group Family")))
	assert.Equal(t, []string{"NEW_BUDDY_REPLY2:alice:added"},
		svc.RecvClientCmd(context.Background(), me, []byte("toc2_new_buddies {g:Family\nb:alice\n}")))

	sent := bos.sentSNACs()
	assert.Len(t, sent, 3)
	assert.Equal(t, wire.FeedbagInsertItem, sent[0].Frame.SubGroup)
	assert.Equal(t, wire.FeedbagUpdateItem, sent[1].Frame.SubGroup)
	assert.Equal(t, []wire.FeedbagItem{
		{
			ClassID:   wire.FeedbagClassIdGroup,
			GroupID:   1,
			Name:      "Family",
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}},
		},
	}, sent[1].Body.(wire.SNAC_0x13_0x09_FeedbagUpdateItem).Items)
	assert.Equal(t, wire.FeedbagInsertItem, sent[2].Frame.SubGroup)

	names := me.feedbag.groupNames()
	assert.Equal(t, "Family", names[1])

	// deleting the group removes it from the mirror
	assert.Equal(t, []string{}, svc.RecvClientCmd(context.Background(), me, []byte("toc2_del_group Family")))
	_, hasFamily := me.feedbag.groupNames()[1]
	assert.False(t, hasFamily)

	// a change that fails to send is forgotten
	before := me.feedbag.snapshot()
	bos.sendErrs = append(make([]error, len(bos.sentSNACs())), io.EOF)
	assert.Equal(t, []string{cmdInternalSvcErr}, svc.RecvClientCmd(context.Background(), me, []byte("toc2_new_group Work")))
	assert.Equal(t, before, me.feedbag.snapshot())
}

func TestOSCARProxy_RecvClientCmd_TOC2CmdFromTOC1(t *testing.T) {
	cases := []struct {
		name     string
		givenCmd string
	}{
		{name: "toc2_send_im", givenCmd: `toc2_send_im them "hello"`},
		{name: "toc2_client_event", givenCmd: `toc2_client_event them 1`},
		{name: "toc2_new_buddies", givenCmd: "toc2_new_buddies {g:Friends\nb:alice\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			me, bos := newTestTOCConn(newTestSession("me"))
			svc := OSCARProxy{Logger: slog.Default()}
			msg := svc.RecvClientCmd(context.Background(), me, []byte(tc.givenCmd))
			assert.Equal(t, []string{cmdInternalSvcErr}, msg)
			assert.Empty(t, bos.sentSNACs())
		})
	}
}
