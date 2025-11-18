package foodgroup

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestICBMService_ChannelMsgToHost(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// senderSession is the session of the user sending the message
		senderSession *state.Session
		// inputSNAC is the SNAC frame sent from the server to the recipient
		// client
		inputSNAC wire.SNACMessage
		// expectOutput is the expected return SNAC value.
		expectOutput *wire.SNACMessage
		// wantErr is the expected error (nil for success)
		wantErr error
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// timeNow returns the current time
		timeNow func() time.Time
	}{
		{
			name:          "transmit message from sender to recipient, ack message back to sender",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10), sessOptWantTypingEvents),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptWarning(20)),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelIM,
									TLVUserInfo: newTestSession("sender-screen-name", sessOptWarning(10)).TLVUserInfo(),
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											{
												Tag:   wire.ICBMTLVData,
												Value: []byte{1, 2, 3, 4},
											},
											{
												Tag:   wire.ICBMTLVWantEvents,
												Value: []byte{},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ICBMTLVRequestHostAck,
								Value: []byte{},
							},
							{
								Tag:   wire.ICBMTLVData,
								Value: []byte{1, 2, 3, 4},
							},
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMHostAck,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
				},
			},
		},
		{
			name:          "transmit message from sender to recipient, don't ack message back to sender",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10), sessOptWantTypingEvents),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptWarning(20)),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelIM,
									TLVUserInfo: newTestSession("sender-screen-name", sessOptWarning(10)).TLVUserInfo(),
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											{
												Tag:   wire.ICBMTLVData,
												Value: []byte{1, 2, 3, 4},
											},
											{
												Tag:   wire.ICBMTLVWantEvents,
												Value: []byte{},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ICBMTLVData,
								Value: []byte{1, 2, 3, 4},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:          "transmit message from sender to recipient, don't ack message back to sender, don't want typing events",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptWarning(20)),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelIM,
									TLVUserInfo: newTestSession("sender-screen-name", sessOptWarning(10)).TLVUserInfo(),
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											{
												Tag:   wire.ICBMTLVData,
												Value: []byte{1, 2, 3, 4},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ICBMTLVData,
								Value: []byte{1, 2, 3, 4},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:          "don't transmit message from sender to recipient because sender has blocked recipient",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      true,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ICBMTLVRequestHostAck,
								Value: []byte{},
							},
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeInLocalPermitDeny,
				},
			},
		},
		{
			name:          "don't transmit message from sender to recipient because recipient has blocked sender",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     true,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ICBMTLVRequestHostAck,
								Value: []byte{},
							},
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
		},
		{
			name:          "don't transmit message from sender to recipient because recipient doesn't exist",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   wire.ICBMTLVRequestHostAck,
								Value: []byte{},
							},
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
		},
		{
			name:          "send offline message to ICQ recipient",
			senderSession: newTestSession("11111111", sessOptUIN(11111111)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "22222222",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("11111111"),
							them: state.NewIdentScreenName("22222222"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("22222222"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("22222222"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{
						{
							offlineMessageIn: state.OfflineMessage{
								Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
									ChannelID:  wire.ICBMChannelIM,
									ScreenName: "22222222",
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
										},
									},
								},
								Recipient: state.NewIdentScreenName("22222222"),
								Sender:    state.NewIdentScreenName("11111111"),
								Sent:      time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC),
							},
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("22222222"),
							results:    []wire.FeedbagItem{},
						},
					},
				},
			},
		},
		{
			name:          "send offline message to recipient with accept offline IM flag set",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMHostAck,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
				},
			},
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{
						{
							offlineMessageIn: state.OfflineMessage{
								Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
									ChannelID:  wire.ICBMChannelIM,
									ScreenName: "recipient-screen-name",
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
										},
									},
								},
								Recipient: state.NewIdentScreenName("recipient-screen-name"),
								Sender:    state.NewIdentScreenName("sender-screen-name"),
								Sent:      time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC),
							},
							countOut: 1,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
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
			name:          "reject offline message when recipient has opted out of offline messages",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 1}},
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
			name:          "send offline message when offline IM preference is not valid",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMHostAck,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
				},
			},
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{
						{
							offlineMessageIn: state.OfflineMessage{
								Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
									ChannelID:  wire.ICBMChannelIM,
									ScreenName: "recipient-screen-name",
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
										},
									},
								},
								Recipient: state.NewIdentScreenName("recipient-screen-name"),
								Sender:    state.NewIdentScreenName("sender-screen-name"),
								Sent:      time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC),
							},
							countOut: 1,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 7}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
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
			name: "send rendezvous request for file transfer, expect IP TLV override",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10),
				sessRemoteAddr(netip.AddrPortFrom(netip.MustParseAddr("129.168.0.1"), 0))),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptWarning(20)),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelRendezvous,
									TLVUserInfo: newTestSession("sender-screen-name", sessOptWarning(10)).TLVUserInfo(),
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
												Type:       wire.ICBMRdvMessagePropose,
												Capability: wire.CapFileTransfer,
												TLVRestBlock: wire.TLVRestBlock{
													TLVList: wire.TLVList{
														wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(4000)),
														wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, net.ParseIP("129.168.0.1").To4()),
														wire.NewTLVBE(wire.ICBMRdvTLVTagsVerifiedIP, net.ParseIP("129.168.0.1").To4()),
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
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelRendezvous,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
								Type:       wire.ICBMRdvMessagePropose,
								Capability: wire.CapFileTransfer,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(4000)),
										wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, net.ParseIP("127.0.0.1").To4()),
									},
								},
							}),
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name: "send rendezvous rejection for file transfer, expect no IP TLV override",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10),
				sessRemoteAddr(netip.AddrPortFrom(netip.MustParseAddr("129.168.0.1"), 0))),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptWarning(20)),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelRendezvous,
									TLVUserInfo: newTestSession("sender-screen-name", sessOptWarning(10)).TLVUserInfo(),
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
												Type:       wire.ICBMRdvMessageCancel,
												Capability: wire.CapFileTransfer,
											}),
										},
									},
								},
							},
						},
					},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelRendezvous,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
								Type:       wire.ICBMRdvMessageCancel,
								Capability: wire.CapFileTransfer,
							}),
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:          "send rendezvous request for file transfer without IP in session, expect no IP TLV override",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptWarning(20)),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelRendezvous,
									TLVUserInfo: newTestSession("sender-screen-name", sessOptWarning(10)).TLVUserInfo(),
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
												Type:       wire.ICBMRdvMessagePropose,
												Capability: wire.CapFileTransfer,
												TLVRestBlock: wire.TLVRestBlock{
													TLVList: wire.TLVList{
														wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(4000)),
														wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, net.ParseIP("127.0.0.1").To4()),
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
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelRendezvous,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
								Type:       wire.ICBMRdvMessagePropose,
								Capability: wire.CapFileTransfer,
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(4000)),
										wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, net.ParseIP("127.0.0.1").To4()),
									},
								},
							}),
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:          "send offline message when inbox is full, return ICBM error with subcode",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ErrorTLVErrorSubcode, wire.ICBMSubErrOfflineIMExceedMax),
						},
					},
				},
			},
			wantErr: nil,
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{
						{
							offlineMessageIn: state.OfflineMessage{
								Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
									ChannelID:  wire.ICBMChannelIM,
									ScreenName: "recipient-screen-name",
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
										},
									},
								},
								Recipient: state.NewIdentScreenName("recipient-screen-name"),
								Sender:    state.NewIdentScreenName("sender-screen-name"),
								Sent:      time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC),
							},
							err: state.ErrOfflineInboxFull,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
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
			name:          "send offline message when SaveMessage returns generic error",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
						},
					},
				},
			},
			expectOutput: nil,
			wantErr:      assert.AnError,
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{
						{
							offlineMessageIn: state.OfflineMessage{
								Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
									ChannelID:  wire.ICBMChannelIM,
									ScreenName: "recipient-screen-name",
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
										},
									},
								},
								Recipient: state.NewIdentScreenName("recipient-screen-name"),
								Sender:    state.NewIdentScreenName("sender-screen-name"),
								Sent:      time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC),
							},
							err: assert.AnError,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
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
			name:          "send offline message when SaveMessage returns ErrNoUser, return ICBM error",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(10)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: "recipient-screen-name",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
							wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
			wantErr: nil,
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{
						{
							offlineMessageIn: state.OfflineMessage{
								Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
									ChannelID:  wire.ICBMChannelIM,
									ScreenName: "recipient-screen-name",
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
											wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3, 4}),
										},
									},
								},
								Recipient: state.NewIdentScreenName("recipient-screen-name"),
								Sender:    state.NewIdentScreenName("sender-screen-name"),
								Sent:      time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC),
							},
							err: state.ErrNoUser,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
											{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
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
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, item := range tc.mockParams.relationshipFetcherParams.relationshipParams {
				relationshipFetcher.EXPECT().
					Relationship(matchContext(), item.me, item.them).
					Return(item.result, item.err)
			}
			sessionRetriever := newMockSessionRetriever(t)
			for _, item := range tc.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(item.screenName).
					Return(item.result)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, item := range tc.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(mock.Anything, item.screenName, item.message)
			}
			offlineMessageManager := newMockOfflineMessageManager(t)
			for _, params := range tc.mockParams.saveMessageParams {
				offlineMessageManager.EXPECT().
					SaveMessage(matchContext(), params.offlineMessageIn).
					Return(params.countOut, params.err)
			}
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.results, params.err)
			}

			svc := ICBMService{
				relationshipFetcher: relationshipFetcher,
				messageRelayer:      messageRelayer,
				offlineMessageSaver: offlineMessageManager,
				sessionRetriever:    sessionRetriever,
				timeNow:             tc.timeNow,
				convoTracker:        newConvoTracker(),
				feedbagManager:      feedbagManager,
			}

			outputSNAC, err := svc.ChannelMsgToHost(context.Background(), tc.senderSession, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x04_0x06_ICBMChannelMsgToHost))
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestICBMService_ClientEvent(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// senderScreenName is the screen name of the user sending the event
		senderScreenName state.DisplayScreenName
		// inputSNAC is the SNAC sent by the sender client
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:             "transmit message from sender to recipient",
			senderScreenName: "sender-screen-name",
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMClientEvent,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
									Cookie:     12345678,
									ChannelID:  42,
									ScreenName: "sender-screen-name",
									Event:      12,
								},
							},
						},
					},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
					Cookie:     12345678,
					ChannelID:  42,
					ScreenName: "recipient-screen-name",
					Event:      12,
				},
			},
		},
		{
			name:             "don't transmit message from sender to recipient because sender has blocked recipient",
			senderScreenName: "sender-screen-name",
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      true,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
					ScreenName: "recipient-screen-name",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, item := range tc.mockParams.relationshipFetcherParams.relationshipParams {
				relationshipFetcher.EXPECT().
					Relationship(matchContext(), item.me, item.them).
					Return(item.result, item.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, item := range tc.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(matchContext(), item.screenName, item.message)
			}

			senderSession := newTestSession(tc.senderScreenName)
			svc := ICBMService{
				relationshipFetcher: relationshipFetcher,
				messageRelayer:      messageRelayer,
			}
			assert.NoError(t, svc.ClientEvent(context.Background(), senderSession, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x04_0x14_ICBMClientEvent)))
		})
	}
}

func TestICBMService_EvilRequest(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// senderScreenName is the session of the user sending the EvilRequest
		senderSession *state.Session
		// msgsReceived is the # of messages received from the warned user
		msgsReceived int
		// inputSNAC is the SNAC sent by the sender client
		inputSNAC wire.SNACMessage
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// waitForWarnMsg indicates whether to wait for session warn signal
		waitForWarnMsg bool
	}{
		{
			name:          "transmit anonymous warning from sender to recipient",
			senderSession: newTestSession("sender-screen-name"),
			msgsReceived:  1,
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     1, // make it anonymous
					ScreenName: "recipient-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMEvilReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x09_ICBMEvilReply{
					EvilDeltaApplied: 30,
					UpdatedEvilValue: 30,
				},
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptCannedSignonTime),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceEvilNotification,
								},
								Body: wire.SNAC_0x01_0x10_OServiceEvilNotification{
									NewEvil: evilDeltaAnon,
								},
							},
						},
					},
				},
			},
			waitForWarnMsg: true,
		},
		{
			name:          "transmit non-anonymous warning from sender to recipient",
			senderSession: newTestSession("sender-screen-name", sessOptWarning(110)),
			msgsReceived:  1,
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     0, // make it identified
					ScreenName: "recipient-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMEvilReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x09_ICBMEvilReply{
					EvilDeltaApplied: 100,
					UpdatedEvilValue: 100,
				},
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptCannedSignonTime),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceEvilNotification,
								},
								Body: wire.SNAC_0x01_0x10_OServiceEvilNotification{
									NewEvil: evilDelta,
									Snitcher: &struct {
										wire.TLVUserInfo
									}{
										wire.TLVUserInfo{
											ScreenName:   "sender-screen-name",
											WarningLevel: 110,
										},
									},
								},
							},
						},
					},
				},
			},
			waitForWarnMsg: true,
		},
		{
			name:          "don't transmit non-anonymous warning from sender to recipient because sender has blocked recipient",
			senderSession: newTestSession("sender-screen-name"),
			msgsReceived:  1,
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     0, // make it identified
					ScreenName: "recipient-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      true,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
			},
		},
		{
			name:          "don't transmit non-anonymous warning from sender to recipient because recipient has blocked sender",
			senderSession: newTestSession("sender-screen-name"),
			msgsReceived:  1,
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     0, // make it identified
					ScreenName: "recipient-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     true,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
			},
		},
		{
			name:          "can't warn bots",
			senderSession: newTestSession("sender-screen-name"),
			msgsReceived:  1,
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     0, // make it identified
					ScreenName: "recipient-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeRequestDenied,
				},
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     newTestSession("recipient-screen-name", sessOptBot),
						},
					},
				},
			},
		},
		{
			name:          "don't let users warn themselves",
			senderSession: newTestSession("sender-screen-name"),
			msgsReceived:  1,
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     0, // make it identified
					ScreenName: "sender-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotSupportedByHost,
				},
			},
		},
		{
			name:          "don't transmit non-anonymous warning from sender to recipient because recipient is offline",
			senderSession: newTestSession("sender-screen-name"),
			msgsReceived:  1,
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     0, // make it identified
					ScreenName: "recipient-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
		},
		{
			name:          "don't transmit anonymous warning from sender to recipient because recipient is offline",
			senderSession: newTestSession("sender-screen-name"),
			msgsReceived:  1,
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("sender-screen-name"),
							them: state.NewIdentScreenName("recipient-screen-name"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("recipient-screen-name"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnTheirList: false,
								IsOnYourList:  false,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("recipient-screen-name"),
							result:     nil,
						},
					},
				},
			},
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x04_0x08_ICBMEvilRequest{
					SendAs:     1, // make it anonymous
					ScreenName: "recipient-screen-name",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, item := range tc.mockParams.relationshipFetcherParams.relationshipParams {
				relationshipFetcher.EXPECT().
					Relationship(matchContext(), item.me, item.them).
					Return(item.result, item.err)
			}
			sessionRetriever := newMockSessionRetriever(t)
			for _, item := range tc.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(item.screenName).
					Return(item.result)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, item := range tc.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(mock.Anything, item.screenName, item.message)
			}
			offlineMessageManager := newMockOfflineMessageManager(t)
			for _, params := range tc.mockParams.saveMessageParams {
				offlineMessageManager.EXPECT().
					SaveMessage(matchContext(), params.offlineMessageIn).
					Return(params.countOut, params.err)
			}

			svc := ICBMService{
				relationshipFetcher: relationshipFetcher,
				messageRelayer:      messageRelayer,
				offlineMessageSaver: offlineMessageManager,
				sessionRetriever:    sessionRetriever,
				convoTracker:        newConvoTracker(),
				snacRateLimits:      wire.DefaultSNACRateLimits(),
			}

			for i := 0; i < tc.msgsReceived; i++ {
				svc.convoTracker.trackConvo(time.Now(),
					state.NewIdentScreenName(tc.inputSNAC.Body.(wire.SNAC_0x04_0x08_ICBMEvilRequest).ScreenName),
					tc.senderSession.IdentScreenName())
			}

			var wg sync.WaitGroup
			if tc.waitForWarnMsg {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for _, sess := range tc.mockParams.sessionRetrieverParams.retrieveSessionParams {
						<-sess.result.WarningCh()
					}
				}()
			}
			outputSNAC, err := svc.EvilRequest(context.Background(), tc.senderSession, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x04_0x08_ICBMEvilRequest))
			assert.NoError(t, err)
			assert.Equal(t, tc.expectOutput, outputSNAC)

			wg.Wait()
		})
	}
}

func TestICBMService_ParameterQuery(t *testing.T) {
	svc := NewICBMService(nil, nil, nil, nil, nil, nil, nil, wire.DefaultSNACRateLimits(), slog.Default())

	have := svc.ParameterQuery(nil, wire.SNACFrame{RequestID: 1234})
	want := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMParameterReply,
			RequestID: 1234,
		},
		Body: wire.SNAC_0x04_0x05_ICBMParameterReply{
			MaxSlots:             100,
			ICBMFlags:            3,
			MaxIncomingICBMLen:   512,
			MaxSourceEvil:        999,
			MaxDestinationEvil:   999,
			MinInterICBMInterval: 0,
		},
	}

	assert.Equal(t, want, have)
}

func TestICBMService_ClientErr(t *testing.T) {
	sess := newTestSession("theScreenName")

	inBody := wire.SNAC_0x04_0x0B_ICBMClientErr{
		Cookie:     1234,
		ChannelID:  wire.ICBMChannelMIME,
		ScreenName: "recipientScreenName",
		Code:       10,
		ErrInfo:    []byte{1, 2, 3, 4},
	}

	expect := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMClientErr,
			RequestID: 1234,
		},
		Body: wire.SNAC_0x04_0x0B_ICBMClientErr{
			Cookie:     inBody.Cookie,
			ChannelID:  inBody.ChannelID,
			ScreenName: sess.DisplayScreenName().String(),
			Code:       inBody.Code,
			ErrInfo:    inBody.ErrInfo,
		},
	}

	messageRelayer := newMockMessageRelayer(t)
	messageRelayer.EXPECT().
		RelayToScreenName(mock.Anything, state.NewIdentScreenName("recipientScreenName"), expect)

	svc := NewICBMService(nil, messageRelayer, nil, nil, nil, nil, nil, wire.DefaultSNACRateLimits(), slog.Default())

	err := svc.ClientErr(context.Background(), sess, wire.SNACFrame{RequestID: 1234}, inBody)
	assert.NoError(t, err)
}

func TestICBMService_OfflineRetrieve(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// senderSession is the session of the user retrieving messages
		senderSession *state.Session
		// inputSNAC is the input frame (RequestID checked on reply)
		inputSNAC wire.SNACMessage
		// expectOutput is the expected return SNAC value.
		expectOutput wire.SNACMessage
		// wantErr is the expected error (nil for success)
		wantErr error
		// mockParams is the list of params sent to mocks that satisfy this method's dependencies
		mockParams mockParams
	}{
		{
			name:          "relays stored messages and replies",
			senderSession: newTestSession("recipient"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 42},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMOfflineRetrieveReply,
					RequestID: 42,
				},
				Body: wire.SNAC_0x04_0x17_ICBMOfflineRetrieveReply{},
			},
			wantErr: nil,
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					retrieveMessagesParams: retrieveMessagesParams{
						{
							recipIn: state.NewIdentScreenName("recipient"),
							messagesOut: []state.OfflineMessage{
								{
									Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
										Cookie:       1234,
										ChannelID:    wire.ICBMChannelIM,
										TLVRestBlock: wire.TLVRestBlock{TLVList: []wire.TLV{wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3})}},
									},
									Recipient: state.NewIdentScreenName("recipient"),
									Sender:    state.NewIdentScreenName("sender"),
									Sent:      time.Unix(1700000000, 0).UTC(),
								},
							},
						},
					},
					deleteMessagesParams: deleteMessagesParams{
						{
							recipIn: state.NewIdentScreenName("recipient"),
							err:     nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: func() wire.SNAC_0x04_0x07_ICBMChannelMsgToClient {
									msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
										Cookie:    1234,
										ChannelID: wire.ICBMChannelIM,
										TLVUserInfo: wire.TLVUserInfo{
											ScreenName: "sender",
										},
										TLVRestBlock: wire.TLVRestBlock{},
									}
									msg.Append(wire.NewTLVBE(wire.ICBMTLVData, []byte{1, 2, 3}))
									msg.Append(wire.NewTLVBE(wire.ICBMTLVSendTime, uint32(time.Unix(1700000000, 0).UTC().Unix())))
									return msg
								}(),
							},
						},
					},
				},
			},
		},
		{
			name:          "no stored messages returns reply without relays or deletes",
			senderSession: newTestSession("recipient"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 55},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMOfflineRetrieveReply,
					RequestID: 55,
				},
				Body: wire.SNAC_0x04_0x17_ICBMOfflineRetrieveReply{},
			},
			wantErr: nil,
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					retrieveMessagesParams: retrieveMessagesParams{
						{
							recipIn:     state.NewIdentScreenName("recipient"),
							messagesOut: []state.OfflineMessage{},
							err:         nil,
						},
					},
					deleteMessagesParams: deleteMessagesParams{},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
			},
		},
		{
			name:          "delete messages error after relay",
			senderSession: newTestSession("recipient"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 99},
			},
			expectOutput: wire.SNACMessage{},
			wantErr:      assert.AnError,
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					retrieveMessagesParams: retrieveMessagesParams{
						{
							recipIn: state.NewIdentScreenName("recipient"),
							messagesOut: []state.OfflineMessage{
								{
									Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
										Cookie:       4321,
										ChannelID:    wire.ICBMChannelIM,
										TLVRestBlock: wire.TLVRestBlock{TLVList: []wire.TLV{wire.NewTLVBE(wire.ICBMTLVData, []byte{9, 8, 7})}},
									},
									Recipient: state.NewIdentScreenName("recipient"),
									Sender:    state.NewIdentScreenName("sender"),
									Sent:      time.Unix(1700001234, 0).UTC(),
								},
							},
						},
					},
					deleteMessagesParams: deleteMessagesParams{
						{
							recipIn: state.NewIdentScreenName("recipient"),
							err:     assert.AnError,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("recipient"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
									RequestID: wire.ReqIDFromServer,
								},
								Body: func() wire.SNAC_0x04_0x07_ICBMChannelMsgToClient {
									msg := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
										Cookie:    4321,
										ChannelID: wire.ICBMChannelIM,
										TLVUserInfo: wire.TLVUserInfo{
											ScreenName: "sender",
										},
										TLVRestBlock: wire.TLVRestBlock{},
									}
									msg.Append(wire.NewTLVBE(wire.ICBMTLVData, []byte{9, 8, 7}))
									msg.Append(wire.NewTLVBE(wire.ICBMTLVSendTime, uint32(time.Unix(1700001234, 0).UTC().Unix())))
									return msg
								}(),
							},
						},
					},
				},
			},
		},
		{
			name:          "propagates retrieve error",
			senderSession: newTestSession("recipient"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 7},
			},
			expectOutput: wire.SNACMessage{},
			wantErr:      assert.AnError,
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					retrieveMessagesParams: retrieveMessagesParams{
						{
							recipIn:     state.NewIdentScreenName("recipient"),
							messagesOut: nil,
							err:         assert.AnError,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			offlineMessageManager := newMockOfflineMessageManager(t)
			for _, params := range tc.mockParams.retrieveMessagesParams {
				offlineMessageManager.EXPECT().
					RetrieveMessages(matchContext(), params.recipIn).
					Return(params.messagesOut, params.err)
			}
			for _, params := range tc.mockParams.deleteMessagesParams {
				offlineMessageManager.EXPECT().
					DeleteMessages(matchContext(), params.recipIn).
					Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, item := range tc.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(mock.Anything, item.screenName, item.message)
			}

			svc := ICBMService{
				messageRelayer:        messageRelayer,
				offlineMessageManager: offlineMessageManager,
			}

			out, err := svc.OfflineRetrieve(context.Background(), tc.senderSession, tc.inputSNAC.Frame)
			assert.Equal(t, tc.expectOutput, out)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestRingBuffer(t *testing.T) {
	t.Run("new ringBuffer should have zero values", func(t *testing.T) {
		rb := &ringBuffer{}

		// Test val() on empty ringBuffer - should return zero time
		result := rb.val()
		zeroTime := time.Time{}
		assert.Equal(t, zeroTime, result)
	})

	t.Run("val() should return current time", func(t *testing.T) {
		now := time.Now()
		rb := &ringBuffer{
			cur: 1,
			vals: [3]time.Time{
				now.Add(-2 * time.Hour),
				now.Add(-1 * time.Hour),
				now,
			},
		}

		result := rb.val()
		assert.Equal(t, rb.vals[1], result)
	})

	t.Run("set() should store time and advance cursor", func(t *testing.T) {
		rb := &ringBuffer{cur: 0}
		newTime := time.Now()

		// Set the time
		rb.set(newTime)

		// After set, cursor should advance to position 1
		// We can verify this by setting another time and checking that it's stored at position 1
		secondTime := time.Now().Add(time.Hour)
		rb.set(secondTime)

		// Now cursor should be at position 2, so val() should return the time at position 2
		// But since we only set 2 times, position 2 should still be the zero time
		zeroTime := time.Time{}
		assert.Equal(t, zeroTime, rb.val())
	})

	t.Run("set() should wrap around after reaching end of array", func(t *testing.T) {
		rb := &ringBuffer{cur: 2}
		newTime := time.Now()

		// Set the time at position 2
		rb.set(newTime)

		// Cursor should wrap around to position 0
		// We can verify this by setting another time and checking behavior
		rb.set(time.Now().Add(time.Hour))

		// Now cursor should be at position 1, so val() should return the time at position 1
		// But since we only set 2 times, position 1 should still be the zero time
		zeroTime := time.Time{}
		assert.Equal(t, zeroTime, rb.val())
	})

	t.Run("set() should handle multiple insertions correctly", func(t *testing.T) {
		rb := &ringBuffer{}

		// Insert 3 times
		time1 := time.Now()
		time2 := time.Now().Add(time.Hour)
		time3 := time.Now().Add(2 * time.Hour)

		rb.set(time1)
		rb.set(time2)
		rb.set(time3)

		// After 3 insertions, cursor should be at position 0
		// So val() should return the time at position 0
		// This should be time1 since it was the first time set
		assert.Equal(t, time1, rb.val())
	})

	t.Run("set() should overwrite existing values in order", func(t *testing.T) {
		rb := &ringBuffer{}

		// Set 3 times to fill the buffer
		rb.set(time.Now())
		rb.set(time.Now().Add(time.Hour))
		rb.set(time.Now().Add(2 * time.Hour))

		// After 3 sets, cursor is at position 0, val() returns first time
		firstTime := rb.val()
		assert.False(t, firstTime.IsZero())

		// Set a 4th time - should overwrite position 0
		fourthTime := time.Now().Add(3 * time.Hour)
		rb.set(fourthTime)

		// Now cursor is at position 1, val() returns second time
		secondTime := rb.val()
		assert.False(t, secondTime.IsZero())

		// Set a 5th time - should overwrite position 1
		fifthTime := time.Now().Add(4 * time.Hour)
		rb.set(fifthTime)

		// Now cursor is at position 2, val() returns third time
		thirdTime := rb.val()
		assert.False(t, thirdTime.IsZero())

		// Set a 6th time - should overwrite position 2
		sixthTime := time.Now().Add(5 * time.Hour)
		rb.set(sixthTime)

		// Now cursor wraps around to position 0, val() returns fourth time
		assert.Equal(t, fourthTime, rb.val())
	})

	t.Run("val() should return correct time after multiple operations", func(t *testing.T) {
		rb := &ringBuffer{}

		// Insert times and verify val() returns correct current time
		time1 := time.Now()
		time2 := time.Now().Add(time.Hour)

		rb.set(time1)
		rb.set(time2)

		// After 2 sets, cursor is at position 2
		// So val() should return the time at position 2
		// But since we only set 2 times, position 2 should still be the zero time
		zeroTime := time.Time{}
		assert.Equal(t, zeroTime, rb.val())

		// Set one more to wrap around
		time3 := time.Now().Add(2 * time.Hour)
		rb.set(time3)

		// Now cursor is at position 0, so val() should return the time at position 0
		// This should be time1
		assert.Equal(t, time1, rb.val())
	})

	t.Run("ringBuffer should maintain circular behavior over many operations", func(t *testing.T) {
		rb := &ringBuffer{}

		// Perform many operations to test circular behavior
		for i := 0; i < 10; i++ {
			rb.set(time.Now().Add(time.Duration(i) * time.Hour))
		}

		// After 10 operations, cursor should be at position 1 (10 % 3 = 1)
		// So val() should return the time at position 1
		// This should be the 8th time set (at position 1)
		// We can't compare exact times since they're set in a loop, so just verify it's not zero
		assert.False(t, rb.val().IsZero())

		// Set one more to advance cursor to position 2
		rb.set(time.Now().Add(10 * time.Hour))

		// Now cursor is at position 2, so val() should return the time at position 2
		// This should be the 9th time set (at position 2)
		assert.False(t, rb.val().IsZero())

		// Set one more to wrap around to position 0
		rb.set(time.Now().Add(11 * time.Hour))

		// Now cursor is at position 0, so val() should return the time at position 0
		// This should be the 10th time set (at position 0)
		assert.False(t, rb.val().IsZero())
	})

	t.Run("ringBuffer should cycle through all positions correctly", func(t *testing.T) {
		rb := &ringBuffer{}

		// Test cycling through all 3 positions
		times := []time.Time{
			time.Now(),
			time.Now().Add(time.Hour),
			time.Now().Add(2 * time.Hour),
		}

		// Set all 3 times
		for _, t := range times {
			rb.set(t)
		}

		// After 3 sets, cursor should be at position 0
		// So val() should return the time at position 0
		assert.Equal(t, times[0], rb.val())

		// Set one more to advance cursor to position 1
		nextTime := time.Now().Add(3 * time.Hour)
		rb.set(nextTime)

		// Now cursor is at position 1, so val() should return the time at position 1
		// This should be the second time since it was stored at position 1
		assert.Equal(t, times[1], rb.val())
	})
}

func TestConvoTracker(t *testing.T) {
	ct := newConvoTracker()
	sender := state.NewIdentScreenName("sender")
	recip := state.NewIdentScreenName("recipient")
	now := time.Now()

	// can't warn until a message is sent
	assert.False(t, ct.trackWarn(now, recip, sender))

	// can warn 1st time
	ct.trackConvo(now, sender, recip)
	assert.True(t, ct.trackWarn(now, recip, sender))

	// can't warn 2nd time until 2nd message is sent
	assert.False(t, ct.trackWarn(now, recip, sender))

	// can warn 2nd time
	now = now.Add(1 * time.Second)
	ct.trackConvo(now, sender, recip)
	assert.True(t, ct.trackWarn(now, recip, sender))

	// can't warn 3rd time until 3rd message is sent
	assert.False(t, ct.trackWarn(now, recip, sender))

	// can warn 3rd time
	now = now.Add(1 * time.Second)
	ct.trackConvo(now, sender, recip)
	assert.True(t, ct.trackWarn(now, recip, sender))

	// can't warn 4th time
	now = now.Add(1 * time.Second)
	ct.trackConvo(now, sender, recip)
	assert.False(t, ct.trackWarn(now, recip, sender))

	// let an hour pass, we should be able to warn again
	now = now.Add(1 * time.Hour)
	ct.trackConvo(now, sender, recip)
	assert.True(t, ct.trackWarn(now, recip, sender))
}

func TestICBMService_UpdateWarnLevel(t *testing.T) {

	t.Run("happy path", func(t *testing.T) {
		now := time.Now()

		sess := newTestSession("screen-name")
		warnCh := make(chan uint16)

		mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
		mockBuddyBroadcaster.EXPECT().
			BroadcastBuddyArrived(mock.Anything, sess.IdentScreenName(), mock.MatchedBy(func(userInfo wire.TLVUserInfo) bool {
				return userInfo.ScreenName == sess.IdentScreenName().String()
			})).
			Run(func(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) {
				warnCh <- userInfo.WarningLevel
			}).Return(nil)

		u := &state.User{}
		userManager := newMockUserManager(t)
		userManager.EXPECT().
			User(matchContext(), sess.IdentScreenName()).
			Return(u, nil)
		userManager.EXPECT().
			SetWarnLevel(matchContext(), sess.IdentScreenName(), now, uint16(100)).
			Return(nil)
		userManager.EXPECT().
			SetWarnLevel(matchContext(), sess.IdentScreenName(), now, uint16(50)).
			Return(nil)
		userManager.EXPECT().
			SetWarnLevel(matchContext(), sess.IdentScreenName(), now, uint16(30)).
			Return(nil)
		userManager.EXPECT().
			SetWarnLevel(matchContext(), sess.IdentScreenName(), now, uint16(0)).
			Return(nil)

		svc := ICBMService{
			buddyBroadcaster: mockBuddyBroadcaster,
			interval:         1 * time.Millisecond,
			logger:           slog.Default(),
			snacRateLimits:   wire.DefaultSNACRateLimits(),
			timeNow:          func() time.Time { return now },
			userManager:      userManager,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.UpdateWarnLevel(ctx, sess) // do a sync test here?
		}()

		ok, _ := sess.ScaleWarningAndRateLimit(100, 3)
		assert.True(t, ok)
		assert.Equal(t, uint16(100), <-warnCh)
		assert.Equal(t, uint16(50), <-warnCh)
		assert.Equal(t, uint16(0), <-warnCh)

		ok, _ = sess.ScaleWarningAndRateLimit(100, 3)
		assert.True(t, ok)
		assert.Equal(t, uint16(100), <-warnCh)
		assert.Equal(t, uint16(50), <-warnCh)
		assert.Equal(t, uint16(0), <-warnCh)

		sess.ScaleWarningAndRateLimit(30, 3)
		assert.Equal(t, uint16(30), <-warnCh)
		assert.Equal(t, uint16(0), <-warnCh)

		cancel()
		wg.Wait()
	})
}

func TestICBMService_RestoreWarningLevel(t *testing.T) {
	tests := []struct {
		name           string
		lastWarnUpdate time.Duration
		lastWarnLevel  uint16
		expectedWarn   uint16
	}{
		{
			name:           "decays warning when last update is before interval boundary",
			lastWarnUpdate: -15*time.Millisecond - 1*time.Millisecond,
			lastWarnLevel:  250,
			expectedWarn:   100,
		},
		{
			name:           "decays warning when last update is after interval boundary",
			lastWarnUpdate: -15*time.Millisecond + 1*time.Millisecond,
			lastWarnLevel:  250,
			expectedWarn:   150,
		},
		{
			name:           "decays warning when last update is exactly on interval boundary",
			lastWarnUpdate: -15 * time.Millisecond,
			lastWarnLevel:  250,
			expectedWarn:   100,
		},
		{
			name:           "resets warning to zero when time is exactly at decay period",
			lastWarnUpdate: -25 * time.Millisecond,
			lastWarnLevel:  250,
			expectedWarn:   0,
		},
		{
			name:           "resets warning to zero when time far decay period",
			lastWarnUpdate: -1 * time.Second,
			lastWarnLevel:  250,
			expectedWarn:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()

			sess := newTestSession("screen-name")

			u := &state.User{
				LastWarnUpdate: now.Add(tt.lastWarnUpdate),
				LastWarnLevel:  tt.lastWarnLevel,
			}
			userManager := newMockUserManager(t)
			userManager.EXPECT().
				User(matchContext(), sess.IdentScreenName()).
				Return(u, nil)

			svc := ICBMService{
				logger:         slog.Default(),
				interval:       5 * time.Millisecond,
				snacRateLimits: wire.DefaultSNACRateLimits(),
				timeNow:        func() time.Time { return now },
				userManager:    userManager,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			statesBefore := sess.RateLimitStates()

			err := svc.RestoreWarningLevel(ctx, sess)
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedWarn, sess.Warning())

			statesAfter := sess.RateLimitStates()

			if tt.expectedWarn > 0 {
				// make sure the rate limits changed
				assert.NotEqual(t, statesBefore, statesAfter)
			} else {
				// make sure the rate limits have been restored
				assert.Equal(t, statesBefore, statesAfter)
			}
		})
	}
}

func TestICBMService_RestoreWarningLevel_ErrorCases(t *testing.T) {
	t.Run("user does not exist", func(t *testing.T) {
		sess := newTestSession("screen-name")

		userManager := newMockUserManager(t)
		userManager.EXPECT().
			User(matchContext(), sess.IdentScreenName()).
			Return(nil, nil)

		svc := ICBMService{
			logger:         slog.Default(),
			interval:       5 * time.Millisecond,
			snacRateLimits: wire.DefaultSNACRateLimits(),
			timeNow:        time.Now,
			userManager:    userManager,
		}

		err := svc.RestoreWarningLevel(context.Background(), sess)
		assert.ErrorIs(t, err, state.ErrNoUser)
	})

	t.Run("user manager returns error", func(t *testing.T) {
		sess := newTestSession("screen-name")
		expectedErr := errors.New("database connection failed")

		userManager := newMockUserManager(t)
		userManager.EXPECT().
			User(matchContext(), sess.IdentScreenName()).
			Return(nil, expectedErr)

		svc := ICBMService{
			logger:         slog.Default(),
			interval:       5 * time.Millisecond,
			snacRateLimits: wire.DefaultSNACRateLimits(),
			timeNow:        time.Now,
			userManager:    userManager,
		}

		err := svc.RestoreWarningLevel(context.Background(), sess)
		assert.Error(t, err)
		// When user is nil, it returns ErrNoUser regardless of the error
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("user exists with zero warning level", func(t *testing.T) {
		sess := newTestSession("screen-name")

		u := &state.User{
			LastWarnUpdate: time.Now().Add(-10 * time.Millisecond),
			LastWarnLevel:  0, // No warning level
		}
		userManager := newMockUserManager(t)
		userManager.EXPECT().
			User(matchContext(), sess.IdentScreenName()).
			Return(u, nil)

		svc := ICBMService{
			logger:         slog.Default(),
			interval:       5 * time.Millisecond,
			snacRateLimits: wire.DefaultSNACRateLimits(),
			timeNow:        time.Now,
			userManager:    userManager,
		}

		err := svc.RestoreWarningLevel(context.Background(), sess)
		assert.NoError(t, err)
		assert.Equal(t, uint16(0), sess.Warning())
	})
}

func Test_calcWarningLevelChange(t *testing.T) {

	t.Run("active warn level, last modified between intervals", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-15 * time.Millisecond).Add(-1 * time.Millisecond)
		warnDelta := calcElapsedWarningLevel(lastWarn, now, interval)
		assert.Equal(t, int16(-150), warnDelta)
	})

	t.Run("active warn level, last modified between intervals", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-15 * time.Millisecond).Add(1 * time.Millisecond)
		warnDelta := calcElapsedWarningLevel(lastWarn, now, interval)
		assert.Equal(t, int16(-100), warnDelta)
	})

	t.Run("active warn level, last modified exactly on interval", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-15 * time.Millisecond)
		warnDelta := calcElapsedWarningLevel(lastWarn, now, interval)
		assert.Equal(t, int16(-150), warnDelta)
	})

	t.Run("resolved warn level", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-25 * time.Millisecond)
		warnDelta := calcElapsedWarningLevel(lastWarn, now, interval)
		assert.Equal(t, int16(-250), warnDelta)
	})

	t.Run("resolved warn level - time past exceeds maximum window", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-200 * time.Millisecond)
		warnDelta := calcElapsedWarningLevel(lastWarn, now, interval)
		assert.Equal(t, int16(-2000), warnDelta)
	})
}

func Test_calcRefreshInterval(t *testing.T) {

	t.Run("active warn level, last modified between intervals", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-15 * time.Millisecond).Add(-1 * time.Millisecond)
		newInterval := timeTillNextInterval(lastWarn, now, interval)
		assert.Equal(t, 4*time.Millisecond, newInterval)
	})

	t.Run("active warn level, last modified between intervals", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-15 * time.Millisecond).Add(1 * time.Millisecond)
		newInterval := timeTillNextInterval(lastWarn, now, interval)
		assert.Equal(t, 1*time.Millisecond, newInterval)
	})

	t.Run("active warn level, last modified exactly on interval", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-15 * time.Millisecond)
		newInterval := timeTillNextInterval(lastWarn, now, interval)
		assert.Equal(t, 5*time.Millisecond, newInterval)
	})

	t.Run("resolved warn level", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-25 * time.Millisecond)
		newInterval := timeTillNextInterval(lastWarn, now, interval)
		assert.Equal(t, interval, newInterval)
	})

	t.Run("resolved warn level - time past exceeds maximum window", func(t *testing.T) {
		now := time.Now()
		interval := 5 * time.Millisecond
		lastWarn := now.Add(-200 * time.Millisecond)
		newInterval := timeTillNextInterval(lastWarn, now, interval)
		assert.Equal(t, interval, newInterval)
	})
}
