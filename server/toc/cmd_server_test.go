package toc

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestOSCARProxy_RecvBOS_ChatIn(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// me is the TOC user session
		me *state.SessionInstance
		// chatID is the chat ID
		chatID int
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd string
	}{
		{
			name:   "send chat message - plain CHAT_IN",
			me:     newTestSession("me"),
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
			me:     newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) }),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, tc.chatID, ch)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

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
		me *state.SessionInstance
		// chatID is the chat ID
		chatID int
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send chat participant arrival",
			me:   newTestSession("me"),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, tc.chatID, ch)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

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
		me *state.SessionInstance
		// chatID is the chat ID
		chatID int
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send chat participant departure",
			me:   newTestSession("me"),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, tc.chatID, ch)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

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
		me *state.SessionInstance
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// chatRegistry is the chat registry for the current session
		chatRegistry *ChatRegistry
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "anonymous warning - 10%",
			me:   newTestSession("me"),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x01_0x10_OServiceEvilNotification{
					NewEvil: 100,
				},
			},
			wantCmd: []string{"EVILED:10:"},
		},
		{
			name: "normal warning - 10%",
			me:   newTestSession("me"),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me, NewChatRegistry(), ch)
				assert.NoError(t, err)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

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
		me *state.SessionInstance
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send IM",
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) }),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) }),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me, NewChatRegistry(), ch)
				assert.NoError(t, err)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

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
		me *state.SessionInstance
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send buddy arrival - buddy online",
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me"),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me, NewChatRegistry(), ch)
				assert.NoError(t, err)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

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
		me *state.SessionInstance
		// givenMsg is the incoming SNAC
		givenMsg wire.SNACMessage
		// wantCmd is the expected TOC response
		wantCmd []string
	}{
		{
			name: "send buddy departure TOC1",
			me:   newTestSession("me"),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) }),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me, NewChatRegistry(), ch)
				assert.NoError(t, err)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

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
		me       *state.SessionInstance
		givenMsg wire.SNACMessage
		wantCmd  []string
	}{
		{
			name: "TOC2 client receives CLIENT_EVENT2 (typing event)",
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			me:   newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(false) }),
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
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, tc.me, NewChatRegistry(), ch)
				assert.NoError(t, err)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd, gotCmd)

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_Signout(t *testing.T) {
}

func TestOSCARProxy_RecvBOS_Inserted2(t *testing.T) {
	buddyWithAlias := wire.FeedbagItem{
		ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice",
		TLVLBlock: wire.TLVLBlock{},
	}
	buddyWithAlias.Append(wire.NewTLVBE(wire.FeedbagAttributesAlias, []byte("Alice N.")))

	cases := []struct {
		name       string
		snac       wire.SNAC_0x13_0x09_FeedbagUpdateItem
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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}}, err: nil},
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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}}, err: nil},
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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{}, err: nil},
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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Friends"}}, err: nil},
					},
				},
			},
		},
		{
			name: "group added",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "NewGroup"},
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
					{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 200, Name: "NewGroup"},
					{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
					{ItemID: 3, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "blockedUser"},
					{ItemID: 4, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "allowedUser"},
				},
			},
			wantCmd: []string{"INSERTED2:g:NewGroup", "INSERTED2:b::alice:Buddies", "INSERTED2:d:blockedUser", "INSERTED2:p:allowedUser"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Buddies"}}, err: nil},
					},
				},
			},
		},
		{
			name: "feedbag lookup fails",
			snac: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
				},
			},
			wantCmd: nil,
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{screenName: state.NewIdentScreenName("me"), results: nil, err: assert.AnError},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(mock.Anything, params.screenName).
					Return(params.results, params.err)
			}

			svc := testOSCARProxy(t)
			svc.FeedbagManager = fbMgr

			me := newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) })

			ch := make(chan []string)
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, me, NewChatRegistry(), ch)
				assert.NoError(t, err)
			}()

			status := me.RelayMessageToInstance(wire.SNACMessage{Body: tc.snac})
			assert.Equal(t, state.SessSendOK, status)

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd, gotCmd)

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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Buddies"}}, err: nil},
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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Friends"}}, err: nil},
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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{}, err: nil},
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
					{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"},
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
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Work"}}, err: nil},
					},
				},
			},
		},
		{
			name: "all four types - group buddy deny permit",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 200, Name: "OldGroup"},
					{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
					{ItemID: 3, ClassID: wire.FeedbagClassIDDeny, GroupID: 0, Name: "blockedUser"},
					{ItemID: 4, ClassID: wire.FeedbagClassIDPermit, GroupID: 0, Name: "allowedUser"},
				},
			},
			wantCmd: []string{"DELETED2:g:OldGroup", "DELETED2:b:alice:Buddies", "DELETED2:d:blockedUser", "DELETED2:p:allowedUser"},
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{screenName: state.NewIdentScreenName("me"), results: []wire.FeedbagItem{{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, GroupID: 100, Name: "Buddies"}}, err: nil},
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
		{
			name: "feedbag lookup fails",
			snac: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice"},
				},
			},
			wantCmd: nil,
			mockParams: mockParams{
				feedBagParams: feedBagParams{
					feedbagParams: feedbagParams{
						{screenName: state.NewIdentScreenName("me"), results: nil, err: assert.AnError},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			fbMgr := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedBagParams.feedbagParams {
				fbMgr.EXPECT().
					Feedbag(mock.Anything, params.screenName).
					Return(params.results, params.err)
			}

			svc := testOSCARProxy(t)
			svc.FeedbagManager = fbMgr

			me := newTestSession("me", func(i *state.SessionInstance) { i.SetTOC2(true) })

			ch := make(chan []string)
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				err := svc.RecvBOS(ctx, me, NewChatRegistry(), ch)
				assert.NoError(t, err)
			}()

			status := me.RelayMessageToInstance(wire.SNACMessage{Body: tc.snac})
			assert.Equal(t, state.SessSendOK, status)

			gotCmd := <-ch
			assert.Equal(t, tc.wantCmd, gotCmd)

			cancel()
			wg.Wait()
		})
	}
}

func testOSCARProxy(t *testing.T) OSCARProxy {
	buddyService := newMockBuddyService(t)
	buddyService.EXPECT().
		BroadcastBuddyDeparted(mock.Anything, mock.Anything).
		Maybe().
		Return(nil)
	buddyListRegistry := newMockBuddyListRegistry(t)
	buddyListRegistry.EXPECT().
		UnregisterBuddyList(mock.Anything, mock.Anything).
		Maybe().
		Return(nil)
	authService := newMockAuthService(t)
	authService.EXPECT().
		Signout(mock.Anything, mock.Anything).
		Maybe()
	authService.EXPECT().
		SignoutChat(mock.Anything, mock.Anything).
		Maybe()
	return OSCARProxy{
		AuthService:       authService,
		BuddyListRegistry: buddyListRegistry,
		BuddyService:      buddyService,
		Logger:            slog.Default(),
	}
}
