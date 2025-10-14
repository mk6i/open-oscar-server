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
		wantCmd []byte
	}{
		{
			name:   "send chat message",
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
			wantCmd: []byte("CHAT_IN:0:them:F:<p>hello world!</p>"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := OSCARProxy{
				Logger: slog.Default(),
			}

			ch := make(chan []byte)
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, tc.chatID, ch)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

			gotCmd := <-ch
			assert.Equal(t, string(tc.wantCmd), string(gotCmd))

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
		wantCmd []byte
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
			wantCmd: []byte("CHAT_UPDATE_BUDDY:0:T:user1:user2"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := OSCARProxy{
				Logger: slog.Default(),
			}

			ch := make(chan []byte)
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, tc.chatID, ch)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

			gotCmd := <-ch
			assert.Equal(t, string(tc.wantCmd), string(gotCmd))

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
		wantCmd []byte
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
			wantCmd: []byte("CHAT_UPDATE_BUDDY:0:F:user1:user2"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := OSCARProxy{
				Logger: slog.Default(),
			}

			ch := make(chan []byte)
			wg := &sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				svc.RecvChat(ctx, tc.me, tc.chatID, ch)
			}()

			status := tc.me.RelayMessageToInstance(tc.givenMsg)
			assert.Equal(t, state.SessSendOK, status)

			gotCmd := <-ch
			assert.Equal(t, string(tc.wantCmd), string(gotCmd))

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
		wantCmd []byte
	}{
		{
			name: "anonymous warning - 10%",
			me:   newTestSession("me"),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x01_0x10_OServiceEvilNotification{
					NewEvil: 100,
				},
			},
			wantCmd: []byte("EVILED:10:"),
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
			wantCmd: []byte("EVILED:10:them"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []byte)
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
			assert.Equal(t, string(tc.wantCmd), string(gotCmd))

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
		wantCmd []byte
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
			wantCmd: []byte("IM_IN:them:F:hello world!"),
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
			wantCmd: []byte("IM_IN:them:T:hello world!"),
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
			wantCmd: []byte("CHAT_INVITE:the room:0:them:join my chat!"),
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
			wantCmd: []byte("RVOUS_PROPOSE:them:09461343-4C7F-11D1-8222-444553540000:aGFoYWhhaGE=:1:129.168.0.1:129.168.0.2:129.168.0.3:4000:10001:bG9s"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []byte)
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
			assert.Equal(t, string(tc.wantCmd), string(gotCmd))

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
		wantCmd []byte
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
							},
						},
					},
				},
			},
			wantCmd: []byte("UPDATE_BUDDY:me:T:0:1234:5678: O "),
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
							},
						},
					},
				},
			},
			wantCmd: []byte("UPDATE_BUDDY:me:T:10:1234:5678: O "),
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
								wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable),
							},
						},
					},
				},
			},
			wantCmd: []byte("UPDATE_BUDDY:me:T:0:1234:5678: OU"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []byte)
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
			assert.Equal(t, string(tc.wantCmd), string(gotCmd))

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
		wantCmd []byte
	}{
		{
			name: "send buddy departure",
			me:   newTestSession("me"),
			givenMsg: wire.SNACMessage{
				Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
					TLVUserInfo: wire.TLVUserInfo{
						ScreenName: "me",
					},
				},
			},
			wantCmd: []byte("UPDATE_BUDDY:me:F:0:0:0:   "),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			svc := testOSCARProxy(t)

			ch := make(chan []byte)
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
			assert.Equal(t, string(tc.wantCmd), string(gotCmd))

			cancel()
			wg.Wait()
		})
	}
}

func TestOSCARProxy_RecvBOS_Signout(t *testing.T) {
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
