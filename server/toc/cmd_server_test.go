package toc

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestOSCARProxy_RecvBOS_ChatIn(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *tocConn
		// chatID is the chat ID
		chatID int
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd string
	}{
		{
			name:   "send chat message - plain CHAT_IN",
			me:     testConn(),
			chatID: 0,
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVSenderInformation, wire.TLVUserInfo{
								ScreenName: "them",
							}),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText, "<p>hello world!</p>"),
								},
							}),
						},
					},
				},
			},
			wantCmd: "CHAT_IN:0:them:F:<p>hello world!</p>",
		},
		{
			name:   "send chat message - TOC2 encoded CHAT_IN_ENC",
			me:     testConn(withTOC2(true)),
			chatID: 0,
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVSenderInformation, wire.TLVUserInfo{
								ScreenName: "them",
							}),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText, "<p>hello world!</p>"),
								},
							}),
						},
					},
				},
			},
			wantCmd: "CHAT_IN_ENC:0:them:F:A:en:<p>hello world!</p>",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := OSCARProxy{
				Logger: slog.Default(),
			}

			ch := make(chan []string)
			tc.me.toCh = ch
			chatConn := newFakeOSCARConn()
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, chatConn, tc.chatID)
			}()

			chatConn.msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd, gotCmd[0])

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_ChatUpdateBuddyArrived(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *tocConn
		// chatID is the chat ID
		chatID int
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send chat participant arrival",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x0E_0x03_ChatUsersJoined{
					Users: []wire.TLVUserInfo{
						{ScreenName: "user1"},
						{ScreenName: "user2"},
					},
				},
			},
			wantCmd: []string{"CHAT_UPDATE_BUDDY:0:T:user1:user2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := OSCARProxy{
				Logger: slog.Default(),
			}

			ch := make(chan []string)
			tc.me.toCh = ch
			chatConn := newFakeOSCARConn()
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, chatConn, tc.chatID)
			}()

			chatConn.msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd[0], gotCmd[0])

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_ChatUpdateBuddyLeft(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *tocConn
		// chatID is the chat ID
		chatID int
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send chat participant departure",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x0E_0x04_ChatUsersLeft{
					Users: []wire.TLVUserInfo{
						{ScreenName: "user1"},
						{ScreenName: "user2"},
					},
				},
			},
			wantCmd: []string{"CHAT_UPDATE_BUDDY:0:F:user1:user2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := OSCARProxy{
				Logger: slog.Default(),
			}

			ch := make(chan []string)
			tc.me.toCh = ch
			chatConn := newFakeOSCARConn()
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, chatConn, tc.chatID)
			}()

			chatConn.msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd[0], gotCmd[0])

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_Eviled(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *tocConn
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// chatRegistry is the chat registry for the current session
		chatRegistry *ChatRegistry
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "anonymous warning - 10%",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x01_0x10_OServiceEvilNotification{
					NewEvil: 100,
				},
			},
			wantCmd: []string{"EVILED:10:"},
		},
		{
			name: "normal warning - 10%",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x01_0x10_OServiceEvilNotification{
					NewEvil: 100,
					Snitcher: &struct {
						wire.TLVUserInfo
					}{
						TLVUserInfo: wire.TLVUserInfo{
							ScreenName: "them",
						},
					},
				},
			},
			wantCmd: []string{"EVILED:10:them"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []string)
			tc.me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me)
				assert.NoError(t, err)
			}()

			tc.me.bos.(*fakeOSCARConn).msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd[0], gotCmd[0])

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_IMIn(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *tocConn
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send IM",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
					ChannelID: wire.ICBMChannelIM,
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "them",
					},
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
								{
									ID:      0x5,
									Version: 0x1,
									Payload: []uint8{0x1, 0x1, 0x2},
								},
								{
									ID:      0x1,
									Version: 0x1,
									Payload: []uint8{
										0x0, 0x0, // charset
										0x0, 0x0, // lang
										'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
									},
								},
							}),
						},
					},
				},
			},
			wantCmd: []string{"IM_IN:them:F:hello world!"},
		},
		{
			name: "send IM - auto-response",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
					ChannelID: wire.ICBMChannelIM,
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "them",
					},
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
								{
									ID:      0x5,
									Version: 0x1,
									Payload: []uint8{0x1, 0x1, 0x2},
								},
								{
									ID:      0x1,
									Version: 0x1,
									Payload: []uint8{
										0x0, 0x0, // charset
										0x0, 0x0, // lang
										'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!',
									},
								},
							}),
						},
					},
				},
			},
			wantCmd: []string{"IM_IN:them:T:hello world!"},
		},
		{
			name: "send IM - TOC2 (IM_IN2)",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
					ChannelID: wire.ICBMChannelIM,
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "them",
					},
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
								{ID: 0x5, Version: 0x1, Payload: []uint8{0x1, 0x1, 0x2}},
								{ID: 0x1, Version: 0x1, Payload: []uint8{0x0, 0x0, 0x0, 0x0, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'}},
							}),
						},
					},
				},
			},
			wantCmd: []string{"IM_IN2:them:F:F:hello world!"},
		},
		{
			name: "send IM - TOC2 with encoded messaging (IM_IN_ENC2)",
			me:   testConn(withTOC2(true)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
					ChannelID: wire.ICBMChannelIM,
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "them",
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree),
							},
						},
					},
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
								{ID: 0x5, Version: 0x1, Payload: []uint8{0x1, 0x1, 0x2}},
								{ID: 0x1, Version: 0x1, Payload: []uint8{0x0, 0x0, 0x0, 0x0, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'}},
							}),
						},
					},
				},
			},
			wantCmd: []string{"IM_IN_ENC2:them:F:F:T: O :F:L:en:hello world!"},
		},
		{
			name: "send IM - TOC2 encoded messaging missing OServiceUserInfoUserFlags returns empty",
			me:   testConn(withTOC2(true)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
					ChannelID: wire.ICBMChannelIM,
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "them",
						// no TLVList / OServiceUserInfoUserFlags
					},
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVAOLIMData, []wire.ICBMCh1Fragment{
								{ID: 0x5, Version: 0x1, Payload: []uint8{0x1, 0x1, 0x2}},
								{ID: 0x1, Version: 0x1, Payload: []uint8{0x0, 0x0, 0x0, 0x0, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'}},
							}),
						},
					},
				},
			},
			wantCmd: []string{"IM_IN_ENC2:them:F:F:T:   :F:L:en:hello world!"},
		},
		{
			name: "send chat invitation",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
					ChannelID: wire.ICBMChannelRendezvous,
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "them",
					},
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVData, []wire.ICBMCh2Fragment{
								{
									Capability: wire.CapChat,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMRdvTLVTagsInvitation, "join my chat!"),
											wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, wire.ICBMRoomInfo{
												Cookie: "a-b-the room",
											}),
										},
									},
								},
							}),
						},
					},
				},
			},
			wantCmd: []string{"CHAT_INVITE:the room:0:them:join my chat!"},
		},
		{
			name: "receive file transfer rendezvous IM",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
					ChannelID:   wire.ICBMChannelRendezvous,
					TLVUserInfo: newTestSession("them").Session().TLVUserInfo(),
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVWantEvents, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
								Cookie:     [8]byte{'h', 'a', 'h', 'a', 'h', 'a', 'h', 'a'},
								Type:       wire.ICBMRdvMessagePropose,
								Capability: wire.CapFileTransfer,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)),
										wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(4000)),
										wire.NewTLVBE(wire.ICBMRdvTLVTagsRdvIP, net.ParseIP("129.168.0.1").To4()),
										wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, net.ParseIP("129.168.0.2").To4()),
										wire.NewTLVBE(wire.ICBMRdvTLVTagsVerifiedIP, net.ParseIP("129.168.0.3").To4()),
										wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, []byte{'l', 'o', 'l'}),
									},
								},
							}),
						},
					},
				},
			},
			wantCmd: []string{"RVOUS_PROPOSE:them:09461343-4C7F-11D1-8222-444553540000:aGFoYWhhaGE=:1:129.168.0.1:129.168.0.2:129.168.0.3:4000:10001:bG9s"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []string)
			tc.me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me)
				assert.NoError(t, err)
			}()

			tc.me.bos.(*fakeOSCARConn).msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd[0], gotCmd[0])

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_UpdateBuddyArrival(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *tocConn
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send buddy arrival - buddy online",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "me",
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
			wantCmd: []string{"UPDATE_BUDDY:me:T:0:1234:5678: O "},
		},
		{
			name: "send buddy arrival - buddy warned 10%",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "me",
						WarningLevel: 100,
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
			wantCmd: []string{"UPDATE_BUDDY:me:T:10:1234:5678: O "},
		},
		{
			name: "send buddy arrival - buddy away",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "me",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree|wire.OServiceUserFlagUnavailable),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY:me:T:0:1234:5678: OU"},
		},
		{
			name: "send buddy arrival - user class AOL (userClassString uc[0])",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "me",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagAOL),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY:me:T:0:1234:5678:A  "},
		},
		{
			name: "send buddy arrival - user class Administrator (userClassString uc[1])",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "me",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagAdministrator),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY:me:T:0:1234:5678: A "},
		},
		{
			name: "send buddy arrival - user class Wireless (userClassString uc[1])",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "me",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagWireless),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY:me:T:0:1234:5678: C "},
		},
		{
			name: "send buddy arrival - user class Unconfirmed (userClassString uc[1])",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "me",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnconfirmed),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY:me:T:0:1234:5678: U "},
		},
		{
			name: "send buddy arrival - TOC2 no caps (userInfoToBuddyCaps returns empty when no OServiceUserInfoOscarCaps TLV)",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "buddy",
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
			wantCmd: []string{"UPDATE_BUDDY2:buddy:T:0:1234:5678: O :"},
		},
		{
			name: "send buddy arrival - TOC2 caps length not divisible by 16 (userInfoToBuddyCaps returns empty)",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "buddy",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree),
								// Invalid: 8 bytes, not divisible by 16
								wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, []byte{0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4}),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY2:buddy:T:0:1234:5678: O :"},
		},
		{
			name: "send buddy arrival - TOC2 with one capability (userInfoToBuddyCaps formats caps as UUIDs)",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "buddy",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree),
								// One 16-byte cap: UUID 550e8400-e29b-41d4-a716-446655440000
								wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, []byte{
									0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
									0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
								}),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY2:buddy:T:0:1234:5678: O :", "BUDDY_CAPS2:buddy:550e8400-e29b-41d4-a716-446655440000"},
		},
		{
			name: "send buddy arrival - TOC2 with two capabilities",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0B_BuddyArrived{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName:   "buddy",
						WarningLevel: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
								wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(5678)),
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree),
								// Two 16-byte caps
								wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, []byte{
									0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
									0x74, 0x8f, 0x24, 0x20, 0x62, 0x87, 0x11, 0xd1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
								}),
							},
						},
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY2:buddy:T:0:1234:5678: O :", "BUDDY_CAPS2:buddy:550e8400-e29b-41d4-a716-446655440000,748f2420-6287-11d1-8222-444553540000"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []string)
			tc.me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me)
				assert.NoError(t, err)
			}()

			tc.me.bos.(*fakeOSCARConn).msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Len(t, gotCmd, len(tc.wantCmd))
			for i, want := range tc.wantCmd {
				assert.Equal(t, want, gotCmd[i])
			}

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_UpdateBuddyDeparted(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *tocConn
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send buddy departure TOC1",
			me:   testConn(),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "me",
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY:me:F:0:0:0:   "},
		},
		{
			name: "send buddy departure TOC2",
			me:   testConn(withTOC2(true)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "me",
					},
				},
			},
			wantCmd: []string{"UPDATE_BUDDY2:me:F:0:0:0:   :"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []string)
			tc.me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me)
				assert.NoError(t, err)
			}()

			tc.me.bos.(*fakeOSCARConn).msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd[0], gotCmd[0])

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_ClientEvent(t *testing.T) {
	cases := []struct {
		name     string
		me       *tocConn
		givenMsg wire.SNACMessage
		wantCmd  []string
	}{
		{
			name: "TOC2 client receives CLIENT_EVENT2 (typing event)",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
					ScreenName: "buddy",
					Event:      1, // typing
				},
			},
			wantCmd: []string{"CLIENT_EVENT2:buddy:1"},
		},
		{
			name: "TOC2 client receives CLIENT_EVENT2 event 0 (idle)",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
					ScreenName: "alice",
					Event:      0,
				},
			},
			wantCmd: []string{"CLIENT_EVENT2:alice:0"},
		},
		{
			name: "TOC2 client receives CLIENT_EVENT2 event 2 (entered text)",
			me:   testConn(withTOC2(false)),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
					ScreenName: "bob",
					Event:      2,
				},
			},
			wantCmd: []string{"CLIENT_EVENT2:bob:2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []string)
			tc.me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me)
				assert.NoError(t, err)
			}()

			tc.me.bos.(*fakeOSCARConn).msgs <- tc.givenMsg

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd, gotCmd)

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_Inserted2(t *testing.T) {
	buddyWithAlias := wire.FeedbagItem{
		ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice",
		TLVLBlock: wire.TLVLBlock{},
	}
	buddyWithAlias.Append(wire.NewTLVBE(wire.FeedbagAttributesAlias, []byte("Alice N.")))

	cases := []struct {
		name       string
		snac       any
		wantCmd    []string
		mockParams mockParams
	}{
		{
			name: "one buddy - group name from feedbag",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
				},
			},
			wantCmd: []string{"INSERTED2:b::alice:Work"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}}},
					},
				},
			},
		},
		{
			name: "one buddy inserted from another location",
			snac: wire.SNAC_0x13_0x08_FeedbagInsertItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
				},
			},
			wantCmd: []string{"INSERTED2:b::alice:Work"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}}},
					},
				},
			},
		},
		{
			name: "one buddy with alias",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{buddyWithAlias},
			},
			wantCmd: []string{"INSERTED2:b:Alice N.:alice:Work"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}}},
					},
				},
			},
		},
		{
			name: "one buddy - unknown group ID uses Buddies",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 999, Name: "bob"},
				},
			},
			wantCmd: []string{"INSERTED2:b::bob:Buddies"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{}},
					},
				},
			},
		},
		{
			name: "two buddies same group",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
					{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "bob"},
				},
			},
			wantCmd: []string{"INSERTED2:b::alice:Friends", "INSERTED2:b::bob:Friends"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Friends"}}},
					},
				},
			},
		},
		{
			name: "group added",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "NewGroup"},
				},
			},
			wantCmd:    []string{"INSERTED2:g:NewGroup"},
			mockParams: mockParams{},
		},
		{
			name: "permit and deny added",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice"},
					{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob"},
				},
			},
			wantCmd:    []string{"INSERTED2:p:alice", "INSERTED2:d:bob"},
			mockParams: mockParams{},
		},
		{
			name: "all four types - group buddy deny permit",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ClassID: wire.FeedbagClassIdGroup, GroupID: 200, Name: "NewGroup"},
					{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
					{ItemID: 3, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "blockedUser"},
					{ItemID: 4, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "allowedUser"},
				},
			},
			wantCmd: []string{"INSERTED2:g:NewGroup", "INSERTED2:b::alice:Buddies", "INSERTED2:d:blockedUser", "INSERTED2:p:allowedUser"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Buddies"}}},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			me := testConn(withTOC2(true))
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}

			ch := make(chan []string)
			me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, me)
				assert.NoError(t, err)
			}()

			me.bos.(*fakeOSCARConn).msgs <- wire.SNACMessage{Body: tc.snac}

			assertResponse(t, me, ch, tc.wantCmd)

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_Deleted2(t *testing.T) {

	cases := []struct {
		name       string
		snac       wire.SNAC_0x13_0x0A_FeedbagDeleteItem
		wantCmd    []string
		mockParams mockParams
	}{
		{
			name: "one buddy removed",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
				},
			},
			wantCmd: []string{"DELETED2:b:alice:Buddies"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Buddies"}}},
					},
				},
			},
		},
		{
			name: "two buddies removed",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
					{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "bob"},
				},
			},
			wantCmd: []string{"DELETED2:b:alice:Friends", "DELETED2:b:bob:Friends"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Friends"}}},
					},
				},
			},
		},
		{
			name: "one buddy - unknown group ID uses Buddies",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 999, Name: "alice"},
				},
			},
			wantCmd: []string{"DELETED2:b:alice:Buddies"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{}},
					},
				},
			},
		},
		{
			name: "permit and deny removed",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "alice"},
					{ItemID: 2, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "bob"},
				},
			},
			wantCmd:    []string{"DELETED2:p:alice", "DELETED2:d:bob"},
			mockParams: mockParams{},
		},
		{
			name: "group deleted",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"},
				},
			},
			wantCmd:    []string{"DELETED2:g:Work"},
			mockParams: mockParams{},
		},
		{
			name: "mix of buddy permit and deny emitted",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "permitUser"},
					{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "buddyUser"},
				},
			},
			wantCmd: []string{"DELETED2:p:permitUser", "DELETED2:b:buddyUser:Work"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}}},
					},
				},
			},
		},
		{
			name: "all four types - group buddy deny permit",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ClassID: wire.FeedbagClassIdGroup, GroupID: 200, Name: "OldGroup"},
					{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
					{ItemID: 3, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "blockedUser"},
					{ItemID: 4, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "allowedUser"},
				},
			},
			wantCmd: []string{"DELETED2:g:OldGroup", "DELETED2:b:alice:Buddies", "DELETED2:d:blockedUser", "DELETED2:p:allowedUser"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{results: []wire.FeedbagItem{{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Buddies"}}},
					},
				},
			},
		},
		{
			name:       "empty items",
			snac:       wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: nil},
			wantCmd:    nil,
			mockParams: mockParams{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			me := testConn(withTOC2(true))
			for _, params := range tc.mockParams.feedbagParams {
				me.feedbag.reset(params.results)
			}

			ch := make(chan []string)
			me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, me)
				assert.NoError(t, err)
			}()

			me.bos.(*fakeOSCARConn).msgs <- wire.SNACMessage{Body: tc.snac}

			assertResponse(t, me, ch, tc.wantCmd)

			cancel()
			wg.Wait()
		})
	}
}

func testOSCARProxy(t *testing.T) OSCARProxy {
	return OSCARProxy{
		Logger: slog.Default(),
	}
}

// testConn creates a TOC connection for user "me" whose BOS connection is
// a fakeOSCARConn.
func testConn(opts ...func(*tocConn)) *tocConn {
	me, _ := newTestTOCConn(newTestSession("me"))
	for _, opt := range opts {
		opt(me)
	}
	return me
}

// withTOC2 makes a TOC connection speak TOC2, with encoded messaging if
// msgEnc is set.
func withTOC2(msgEnc bool) func(*tocConn) {
	return func(c *tocConn) {
		c.isTOC2 = true
		c.supportsMsgEnc = msgEnc
	}
}

// assertResponse asserts that the SNAC just fed to the BOS connection produced
// want, or no response at all when want is nil. Since SNACs are handled in
// order, a nil want is checked by feeding a sentinel SNAC and expecting its
// response first.
func assertResponse(t *testing.T, me *tocConn, ch <-chan []string, want []string) {
	if want == nil {
		me.bos.(*fakeOSCARConn).msgs <- wire.SNACMessage{
			Body: wire.SNAC_0x01_0x10_OServiceEvilNotification{NewEvil: 0},
		}
		want = []string{"EVILED:0:"}
	}
	assert.Equal(t, want, <-ch)
}

func TestOSCARProxy_RecvBOS_Replies(t *testing.T) {
	roomInfo := func(cookie string, name string) wire.SNAC_0x0D_0x09_ChatNavNavInfo {
		return wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Exchange:       4,
						Cookie:         cookie,
						InstanceNumber: 0,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ChatRoomTLVRoomName, name),
							},
						},
					}),
				},
			},
		}
	}
	adminReply := func(tlvs ...wire.TLV) wire.SNAC_0x07_0x05_AdminChangeReply {
		return wire.SNAC_0x07_0x05_AdminChangeReply{
			TLVBlock: wire.TLVBlock{TLVList: tlvs},
		}
	}
	serviceRequest := func(cookie string) wire.SNAC_0x01_0x04_OServiceServiceRequest {
		return wire.SNAC_0x01_0x04_OServiceServiceRequest{
			FoodGroup: wire.Chat,
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
						Cookie: cookie,
					}),
				},
			},
		}
	}

	cases := []struct {
		// name is the unit test name
		name string
		// reqFrame is the cached request the reply answers, as request ID 1
		reqFrame *wire.SNACFrame
		// reqData is the cached request context
		reqData any
		// givenRoom is a chat room the user was invited to, as chat ID 0
		givenRoom *wire.ICBMRoomInfo
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response, nil for none
		wantCmd []string
		// wantSNACs are the follow-up SNACs sent to the BOS server
		wantSNACs []wire.SNACMessage
		// wantCached are the requests still cached afterward, by request ID
		wantCached map[uint32]any
	}{
		{
			name:     "toc_get_status reply",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery},
			reqData:  getStatusReqCtx{screenName: "them"},
			givenMsg: newSNAC(wire.Locate, wire.LocateUserInfoReply, 1, wire.SNAC_0x02_0x06_LocateUserInfoReply{
				TLVUserInfo: wire.TLVUserInfo{
					ScreenName: "them",
					TLVBlock: wire.TLVBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1234)),
							wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree),
						},
					},
				},
			}),
			wantCmd: []string{"UPDATE_BUDDY:them:T:0:1234:0: O "},
		},
		{
			name:     "toc_get_status for user who is not online",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery},
			reqData:  getStatusReqCtx{screenName: "them"},
			givenMsg: newSNAC(wire.Locate, wire.LocateErr, 1, wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}),
			wantCmd:  []string{"ERROR:901:them"},
		},
		{
			name:     "toc_get_status with unexpected error code",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery},
			reqData:  getStatusReqCtx{screenName: "them"},
			givenMsg: newSNAC(wire.Locate, wire.LocateErr, 1, wire.SNACError{Code: wire.ErrorCodeRequestDenied}),
			wantCmd:  []string{cmdInternalSvcErr},
		},
		{
			name:     "toc_evil reply",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilRequest},
			reqData:  evilReqCtx{},
			givenMsg: newSNAC(wire.ICBM, wire.ICBMEvilReply, 1, wire.SNAC_0x04_0x09_ICBMEvilReply{}),
		},
		{
			name:     "toc_evil error",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilRequest},
			reqData:  evilReqCtx{},
			givenMsg: newSNAC(wire.ICBM, wire.ICBMErr, 1, wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}),
			wantCmd:  []string{"ERROR:" + wire.TOCErrorGeneralWarningUserNotAvailable},
		},
		{
			name:     "instant message error is not reported",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost},
			givenMsg: newSNAC(wire.ICBM, wire.ICBMErr, 1, wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}),
		},
		{
			name:     "error for unknown request is ignored",
			givenMsg: newSNAC(wire.ICBM, wire.ICBMErr, 1, wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}),
		},
		{
			name:       "error from another food group does not match request",
			reqFrame:   &wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery},
			reqData:    getStatusReqCtx{screenName: "them"},
			givenMsg:   newSNAC(wire.ICBM, wire.ICBMErr, 1, wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}),
			wantCached: map[uint32]any{1: getStatusReqCtx{screenName: "them"}},
		},
		{
			name:     "toc_chat_join room creation error",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavCreateRoom},
			reqData:  chatJoinReqCtx{},
			givenMsg: newSNAC(wire.ChatNav, wire.ChatNavErr, 1, wire.SNACError{Code: wire.ErrorCodeNoMatch}),
			wantCmd:  []string{cmdInternalSvcErr},
		},
		{
			name:     "toc_change_passwd success",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  changePasswdReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply()),
			wantCmd:  []string{"ADMIN_PASSWD_STATUS:0"},
		},
		{
			name:     "toc_change_passwd invalid password length",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  changePasswdReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply(
				wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorInvalidPasswordLength),
			)),
			wantCmd: []string{"ERROR:" + wire.TOCErrorAdminInvalidInput},
		},
		{
			name:     "toc_change_passwd incorrect password",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  changePasswdReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply(
				wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorValidatePassword),
			)),
			wantCmd: []string{"ERROR:" + wire.TOCErrorAuthIncorrectNickOrPassword},
		},
		{
			name:     "toc_change_passwd catch-all error",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  changePasswdReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply(
				wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorAllOtherErrors),
			)),
			wantCmd: []string{"ERROR:" + wire.TOCErrorAdminProcessingRequest},
		},
		{
			name:     "toc_format_nickname success",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  formatNickReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply(
				wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "M E"),
			)),
			wantCmd: []string{"ADMIN_NICK_STATUS:0", "NICK:M E"},
		},
		{
			name:     "toc_format_nickname invalid nickname",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  formatNickReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply(
				wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorInvalidNickName),
			)),
			wantCmd: []string{"ERROR:" + wire.TOCErrorAdminInvalidInput},
		},
		{
			name:     "toc_format_nickname catch-all error",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  formatNickReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply(
				wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorAllOtherErrors),
			)),
			wantCmd: []string{"ERROR:" + wire.TOCErrorAdminProcessingRequest},
		},
		{
			name:     "toc_format_nickname reply missing formatted screen name",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
			reqData:  formatNickReqCtx{},
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply()),
			wantCmd:  []string{cmdInternalSvcErr},
		},
		{
			name:     "admin reply for unknown request is ignored",
			givenMsg: newSNAC(wire.Admin, wire.AdminInfoChangeReply, 1, adminReply()),
		},
		{
			name:     "toc_chat_join room info requests a chat connection",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavCreateRoom},
			reqData:  chatJoinReqCtx{},
			givenMsg: newSNAC(wire.ChatNav, wire.ChatNavNavInfo, 1, roomInfo("4-0-my room", "my room")),
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.OService, wire.OServiceServiceRequest, 2, serviceRequest("4-0-my room")),
			},
			wantCached: map[uint32]any{2: chatServiceReqCtx{chatID: 0, roomName: "my room"}},
		},
		{
			name:      "toc_chat_accept room info requests a chat connection",
			reqFrame:  &wire.SNACFrame{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavRequestRoomInfo},
			reqData:   chatAcceptReqCtx{chatID: 0},
			givenRoom: &wire.ICBMRoomInfo{Exchange: 4, Cookie: "4-0-their room"},
			givenMsg:  newSNAC(wire.ChatNav, wire.ChatNavNavInfo, 1, roomInfo("4-0-their room", "their room")),
			wantSNACs: []wire.SNACMessage{
				newSNAC(wire.OService, wire.OServiceServiceRequest, 2, serviceRequest("4-0-their room")),
			},
			wantCached: map[uint32]any{2: chatServiceReqCtx{chatID: 0, roomName: "their room"}},
		},
		{
			name:     "chat room info missing room TLV",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavCreateRoom},
			reqData:  chatJoinReqCtx{},
			givenMsg: newSNAC(wire.ChatNav, wire.ChatNavNavInfo, 1, wire.SNAC_0x0D_0x09_ChatNavNavInfo{}),
			wantCmd:  []string{cmdInternalSvcErr},
		},
		{
			name:     "chat room info missing room name",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavCreateRoom},
			reqData:  chatJoinReqCtx{},
			givenMsg: newSNAC(wire.ChatNav, wire.ChatNavNavInfo, 1, wire.SNAC_0x0D_0x09_ChatNavNavInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{Exchange: 4, Cookie: "4-0-my room"}),
					},
				},
			}),
			wantCmd: []string{cmdInternalSvcErr},
		},
		{
			name:     "failed feedbag change",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
			reqData:  feedbagChangeReqCtx{},
			givenMsg: newSNAC(wire.Feedbag, wire.FeedbagErr, 1, wire.SNACError{Code: wire.ErrorCodeInsufficientRights}),
		},
		{
			name:     "feedbag change acknowledgement",
			reqFrame: &wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
			givenMsg: newSNAC(wire.Feedbag, wire.FeedbagStatus, 1, wire.SNAC_0x13_0x0E_FeedbagStatus{Results: []uint16{0}}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			me := testConn()
			if tc.reqFrame != nil {
				me.cache.add(tc.reqFrame, tc.reqData)
			}
			if tc.givenRoom != nil {
				me.chats.Add(*tc.givenRoom)
			}

			ch := make(chan []string)
			me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NoError(t, testOSCARProxy(t).RecvBOS(ctx, me))
			}()

			bos := me.bos.(*fakeOSCARConn)
			bos.msgs <- tc.givenMsg
			assertResponse(t, me, ch, tc.wantCmd)

			assert.Equal(t, tc.wantSNACs, bos.sentSNACs())

			cached := make(map[uint32]any)
			for id, entry := range me.cache.entries {
				cached[id] = entry.data
			}
			if tc.wantCached == nil {
				tc.wantCached = map[uint32]any{}
			}
			assert.Equal(t, tc.wantCached, cached)

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_ChatServiceResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	chat := &fakeService{
		reply: func(frame wire.SNACFrame) []wire.SNACMessage {
			if frame.FoodGroup == wire.OService && frame.SubGroup == wire.OServiceClientOnline {
				return []wire.SNACMessage{newSNAC(wire.Chat, wire.ChatUsersJoined, wire.ReqIDFromServer,
					wire.SNAC_0x0E_0x03_ChatUsersJoined{
						Users: []wire.TLVUserInfo{{ScreenName: "me"}},
					})}
			}
			return nil
		},
	}
	oscarServer := &fakeOSCARServer{handlers: []func(net.Conn){chat.handle}}
	svc := OSCARProxy{
		Logger:      slog.Default(),
		OSCARServer: oscarServer,
	}

	wg := &sync.WaitGroup{}
	me := testConn()
	// the chat room's message loop gets ctx and must stop when it's cancelled
	me.goAsync = func(f func(ctx context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, f(ctx))
		}()
	}
	me.cache.add(&wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceServiceRequest},
		chatServiceReqCtx{chatID: 0, roomName: "My Room"})
	ch := make(chan []string)
	me.toCh = ch

	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, svc.RecvBOS(ctx, me))
	}()

	me.bos.(*fakeOSCARConn).msgs <- newSNAC(wire.OService, wire.OServiceServiceResponse, 1,
		wire.SNAC_0x01_0x05_OServiceServiceResponse{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("chat-cookie")),
				},
			},
		})

	// the room is announced before anything from the room is relayed
	assert.Equal(t, []string{"CHAT_JOIN:0:My Room"}, <-ch)
	assert.Equal(t, []string{"CHAT_UPDATE_BUDDY:0:T:me"}, <-ch)

	gotCookie, gotSNACs := chat.received()
	assert.Equal(t, []byte("chat-cookie"), gotCookie)
	assert.Equal(t, []receivedSNAC{
		newReceivedSNAC(t, wire.OService, wire.OServiceRateParamsSubAdd, 2, wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
			ClassIDs: []uint16{1, 2, 3, 4, 5},
		}),
		newReceivedSNAC(t, wire.OService, wire.OServiceClientOnline, 3, wire.SNAC_0x01_0x02_OServiceClientOnline{}),
	}, gotSNACs)
	assert.NotNil(t, me.chats.RetrieveConn(0))
	assert.Equal(t, []net.Addr{me.clientAddr}, oscarServer.clientAddrs)

	cancel()
	wg.Wait()
}

func TestOSCARProxy_RecvBOS_RateParamsChange(t *testing.T) {
	cases := []struct {
		name    string
		code    uint16
		wantCmd []string
	}{
		{
			name:    "rate class becomes limited",
			code:    rateParamsChangeLimited,
			wantCmd: []string{rateLimitExceededErr},
		},
		{
			name: "rate class clears",
			code: 4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			me := testConn()
			ch := make(chan []string)
			me.toCh = ch
			wg := &sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NoError(t, testOSCARProxy(t).RecvBOS(ctx, me))
			}()

			me.bos.(*fakeOSCARConn).msgs <- newSNAC(wire.OService, wire.OServiceRateParamChange, wire.ReqIDFromServer,
				wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: tc.code})
			assertResponse(t, me, ch, tc.wantCmd)

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvChat_RateParamsChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	me := testConn()
	ch := make(chan []string)
	me.toCh = ch
	chatConn := newFakeOSCARConn()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		testOSCARProxy(t).RecvChat(ctx, me, chatConn, 0)
	}()

	chatConn.msgs <- newSNAC(wire.OService, wire.OServiceRateParamChange, wire.ReqIDFromServer,
		wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: rateParamsChangeLimited})
	assert.Equal(t, []string{rateLimitExceededErr}, <-ch)

	cancel()
	wg.Wait()
	assert.True(t, chatConn.isClosed())
}

func TestOSCARProxy_RecvBOS_Backlog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	me := testConn()
	me.backlog = []wire.SNACMessage{
		newSNAC(wire.Buddy, wire.BuddyDeparted, wire.ReqIDFromServer, wire.SNAC_0x03_0x0C_BuddyDeparted{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "them"},
		}),
	}
	bos := me.bos.(*fakeOSCARConn)
	bos.msgs = make(chan wire.SNACMessage, 1)
	bos.msgs <- newSNAC(wire.Buddy, wire.BuddyDeparted, wire.ReqIDFromServer, wire.SNAC_0x03_0x0C_BuddyDeparted{
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "other"},
	})
	ch := make(chan []string)
	me.toCh = ch
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, testOSCARProxy(t).RecvBOS(ctx, me))
	}()

	// SNACs received during signon come before anything newer
	assert.Equal(t, []string{"UPDATE_BUDDY:them:F:0:0:0:   "}, <-ch)
	assert.Equal(t, []string{"UPDATE_BUDDY:other:F:0:0:0:   "}, <-ch)

	cancel()
	wg.Wait()
	assert.Nil(t, me.backlog)
}

func TestOSCARProxy_RecvBOS_FeedbagMirror(t *testing.T) {
	work := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}
	alice := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, ItemID: 1, Name: "alice"}
	bob := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, ItemID: 2, Name: "bob"}
	carol := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, ItemID: 3, Name: "carol"}
	dave := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, ItemID: 4, Name: "dave"}

	ctx, cancel := context.WithCancel(context.Background())

	me := testConn(withTOC2(true))
	me.feedbag.reset([]wire.FeedbagItem{work, alice})
	svc := testOSCARProxy(t)

	ch := make(chan []string)
	me.toCh = ch
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, svc.RecvBOS(ctx, me))
	}()
	bos := me.bos.(*fakeOSCARConn)

	// the server confirms the items of a change it accepted
	assert.Nil(t, svc.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, []wire.FeedbagItem{bob, carol}))
	bos.msgs <- newSNAC(wire.Feedbag, wire.FeedbagStatus, 1, wire.SNAC_0x13_0x0E_FeedbagStatus{Results: []uint16{0, 0x0E}})
	assertResponse(t, me, ch, nil)
	assert.False(t, me.feedbag.hasPending())
	assert.Equal(t, []wire.FeedbagItem{work, alice, bob}, me.feedbag.snapshot())

	// changes from other locations update the mirror
	bos.msgs <- newSNAC(wire.Feedbag, wire.FeedbagInsertItem, wire.ReqIDFromServer,
		wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{carol}})
	assert.Equal(t, []string{"INSERTED2:b::carol:Work"}, <-ch)
	// a deleted buddy's group is named from the mirror before the buddy leaves it
	bos.msgs <- newSNAC(wire.Feedbag, wire.FeedbagDeleteItem, wire.ReqIDFromServer,
		wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{alice}})
	assert.Equal(t, []string{"DELETED2:b:alice:Work"}, <-ch)
	assert.Equal(t, []wire.FeedbagItem{work, bob, carol}, me.feedbag.snapshot())

	// a change may be dropped while the server is limiting requests, so the
	// mirror is reloaded once the limit clears
	assert.Nil(t, svc.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, []wire.FeedbagItem{dave}))
	bos.msgs <- newSNAC(wire.OService, wire.OServiceRateParamChange, wire.ReqIDFromServer,
		wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: rateParamsChangeLimited})
	assert.Equal(t, []string{rateLimitExceededErr}, <-ch)
	assert.Len(t, bos.sentSNACs(), 2)
	bos.msgs <- newSNAC(wire.OService, wire.OServiceRateParamChange, wire.ReqIDFromServer,
		wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: rateParamsChangeClear})
	assertResponse(t, me, ch, nil)
	assert.Equal(t, newSNAC(wire.Feedbag, wire.FeedbagQuery, 3, struct{}{}), bos.sentSNACs()[2])

	// the reload drops the change the server dropped
	bos.msgs <- newSNAC(wire.Feedbag, wire.FeedbagReply, 3,
		wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{work, bob, carol}})
	assertResponse(t, me, ch, nil)
	assert.False(t, me.feedbag.hasPending())
	assert.Equal(t, []wire.FeedbagItem{work, bob, carol}, me.feedbag.snapshot())

	// with nothing pending, a cleared limit doesn't reload the mirror
	bos.msgs <- newSNAC(wire.OService, wire.OServiceRateParamChange, wire.ReqIDFromServer,
		wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: rateParamsChangeClear})
	assertResponse(t, me, ch, nil)
	assert.Len(t, bos.sentSNACs(), 3)

	// a change the server rejects is forgotten
	assert.Nil(t, svc.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, []wire.FeedbagItem{dave}))
	bos.msgs <- newSNAC(wire.Feedbag, wire.FeedbagErr, 4, wire.SNACError{Code: wire.ErrorCodeInsufficientRights})
	assertResponse(t, me, ch, nil)
	assert.False(t, me.feedbag.hasPending())
	assert.Equal(t, []wire.FeedbagItem{work, bob, carol}, me.feedbag.snapshot())

	cancel()
	wg.Wait()
	assert.True(t, bos.isClosed())
}
