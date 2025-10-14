package foodgroup

import (
	"context"
	"math"
	"testing"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestChatService_ChannelMsgToHost(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user sending the chat message
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent by the sender client
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectSNACToParticipants is the message the server broadcast to chat
		// room participants (except the sender)
		expectSNACToParticipants wire.SNACMessage
		expectOutput             *wire.SNACMessage
		// randRollDie generates result of rolling a die
		randRollDie func(sides int) int
		wantErr     error
	}{
		{
			name: "send chat room message, expect acknowledgement to sender client",
			instance: newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime,
				sessOptChatRoomCookie("the-chat-cookie")),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Cookie:  1234,
					Channel: 14,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ChatTLVPublicWhisperFlag,
								Value: []byte{},
							},
							{
								Tag:   wire.ChatTLVEnableReflectionFlag,
								Value: []byte{},
							},
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
								},
							}),
						},
					},
				},
			},
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("user_sending_chat_msg"),
							cookie:     "the-chat-cookie",
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatChannelMsgToClient,
								},
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Cookie:  1234,
									Channel: 14,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation,
												newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime).Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoText,
														"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
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
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Chat,
					SubGroup:  wire.ChatChannelMsgToClient,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
					Cookie:  1234,
					Channel: 14,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVSenderInformation,
								newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime).Session().TLVUserInfo()),
							wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
								},
							}),
						},
					},
				},
			},
		},
		{
			name: "send chat whisper",
			instance: newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime,
				sessOptChatRoomCookie("the-chat-cookie")),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Cookie:  1234,
					Channel: 14,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVWhisperToUser, "them"),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
								},
							}),
						},
					},
				},
			},
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToScreenNameParams: chatRelayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("them"),
							cookie:     "the-chat-cookie",
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatChannelMsgToClient,
								},
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Cookie:  1234,
									Channel: 14,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation,
												newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime).Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoText,
														"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
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
			expectOutput: nil,
		},
		{
			name: "send die roll",
			instance: newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime,
				sessOptChatRoomCookie("the-chat-cookie")),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Cookie:  1234,
					Channel: 14,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ChatTLVPublicWhisperFlag,
								Value: []byte{},
							},
							{
								Tag:   wire.ChatTLVEnableReflectionFlag,
								Value: []byte{},
							},
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">//roll-dice3-sides8</FONT></BODY></HTML>"),
								},
							}),
						},
					},
				},
			},
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("user_sending_chat_msg"),
							cookie:     "the-chat-cookie",
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatChannelMsgToClient,
								},
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Cookie:  1234,
									Channel: 14,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation, sessOnlineHost.Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoEncoding, "us-ascii"),
													wire.NewTLVBE(wire.ChatTLVMessageInfoLang, "en"),
													wire.NewTLVBE(wire.ChatTLVMessageInfoText,
														"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">user_sending_chat_msg rolled 3 8-sided dice: 2 4 8</FONT></BODY></HTML>"),
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
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Chat,
					SubGroup:  wire.ChatChannelMsgToClient,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
					Cookie:  1234,
					Channel: 14,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ChatTLVSenderInformation, sessOnlineHost.Session().TLVUserInfo()),
							wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoEncoding, "us-ascii"),
									wire.NewTLVBE(wire.ChatTLVMessageInfoLang, "en"),
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">user_sending_chat_msg rolled 3 8-sided dice: 2 4 8</FONT></BODY></HTML>"),
								},
							}),
						},
					},
				},
			},
			randRollDie: func() func(sides int) int {
				// return multiples of 2 starting with 2
				val := 2
				return func(sides int) int {
					ret := val
					val *= 2
					return ret
				}
			}(),
		},
		{
			name: "send chat room message with macOS client 4.0.9 bug containing bad channel ID, expect message to " +
				"client on MIME channel",
			instance: newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime,
				sessOptChatRoomCookie("the-chat-cookie")),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Cookie:  1234,
					Channel: math.MaxUint16,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ChatTLVPublicWhisperFlag,
								Value: []byte{},
							},
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
								},
							}),
						},
					},
				},
			},
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("user_sending_chat_msg"),
							cookie:     "the-chat-cookie",
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatChannelMsgToClient,
								},
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Cookie:  1234,
									Channel: wire.ICBMChannelMIME,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation,
												newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime).Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoText,
														"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
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
			expectOutput: nil,
		},
		{
			name: "send chat room message, don't expect acknowledgement to sender client",
			instance: newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime,
				sessOptChatRoomCookie("the-chat-cookie")),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Cookie:  1234,
					Channel: 14,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ChatTLVPublicWhisperFlag,
								Value: []byte{},
							},
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
								},
							}),
						},
					},
				},
			},
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("user_sending_chat_msg"),
							cookie:     "the-chat-cookie",
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatChannelMsgToClient,
								},
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Cookie:  1234,
									Channel: 14,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation,
												newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime).Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoText,
														"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
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
		},
		{
			name: "send chat room message, expect that TLVs that crash macos client",
			instance: newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime,
				sessOptChatRoomCookie("the-chat-cookie")),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
					Cookie:  1234,
					Channel: 14,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ChatTLVPublicWhisperFlag,
								Value: []byte{},
							},
							wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ChatTLVMessageInfoText,
										"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
									wire.NewTLVBE(0x04, "remove me"),
									wire.NewTLVBE(0x05, "remove me"),
								},
							}),
						},
					},
				},
			},
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("user_sending_chat_msg"),
							cookie:     "the-chat-cookie",
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatChannelMsgToClient,
								},
								Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
									Cookie:  1234,
									Channel: 14,
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ChatTLVSenderInformation,
												newTestInstance("user_sending_chat_msg", sessOptCannedSignonTime).Session().TLVUserInfo()),
											wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}),
											wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ChatTLVMessageInfoText,
														"<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">Hello</FONT></BODY></HTML>"),
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
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chatMessageRelayer := newMockChatMessageRelayer(t)
			for _, params := range tc.mockParams.chatRelayToAllExceptParams {
				chatMessageRelayer.EXPECT().
					RelayToAllExcept(mock.Anything, params.cookie, params.screenName, params.message)
			}
			for _, params := range tc.mockParams.chatRelayToScreenNameParams {
				chatMessageRelayer.EXPECT().
					RelayToScreenName(mock.Anything, params.cookie, params.screenName, params.message)
			}

			svc := NewChatService(chatMessageRelayer)
			svc.randRollDie = tc.randRollDie
			outputSNAC, err := svc.ChannelMsgToHost(context.Background(), tc.instance, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x0E_0x05_ChatChannelMsgToHost))
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestParseDiceCommand(t *testing.T) {
	tests := []struct {
		input         []byte
		expectedValid bool
		expectedDice  int
		expectedSides int
	}{
		{[]byte("//roll-sides999-dice15"), true, 15, 999},
		{[]byte("//roll-sides999-dice15 "), true, 15, 999},
		{[]byte("//roll-SIDES999-DICE15"), false, 0, 0},
		{[]byte("//roll-sides999-sides15"), false, 0, 0},
		{[]byte("//roll-sides999-dice15 as I was saying"), false, 0, 0},
		{[]byte("i'm gonna roll some dice //roll-sides999-dice15"), false, 0, 0},
		{[]byte("//roll-dice15-sides999"), true, 15, 999},
		{[]byte("//roll-dice15"), true, 15, 6},
		{[]byte("//roll-dice0"), false, 0, 0},
		{[]byte("//roll-sides0"), false, 0, 0},
		{[]byte("//roll-sides999"), true, 2, 999},
		{[]byte("//roll-dice16"), false, 0, 0},
		{[]byte("//roll-sides1000"), false, 0, 0},
		{[]byte("//roll-dice-5"), false, 0, 0},
		{[]byte("//roll-sides-9"), false, 0, 0},
		{[]byte("//roll"), true, 2, 6},
		{[]byte("invalid input"), false, 0, 0},
	}

	for _, test := range tests {
		t.Run(string(test.input), func(t *testing.T) {
			valid, dice, sides := parseDiceCommand(test.input)

			if valid != test.expectedValid {
				t.Errorf("For input '%s', expected valid = %v, got %v", test.input, test.expectedValid, valid)
			}

			if dice != test.expectedDice {
				t.Errorf("For input '%s', expected dice = %d, got %d", test.input, test.expectedDice, dice)
			}

			if sides != test.expectedSides {
				t.Errorf("For input '%s', expected sides = %d, got %d", test.input, test.expectedSides, sides)
			}
		})
	}
}
