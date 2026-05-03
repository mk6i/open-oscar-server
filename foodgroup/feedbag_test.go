package foodgroup

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestFeedbagService_Query(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user adding to feedbag
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectOutput is the SNAC sent from the server to client
		expectOutput *wire.SNACMessage
	}{
		{
			name:     "retrieve empty feedbag",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
						},
					},
					feedbagLastModifiedParams: feedbagLastModifiedParams{},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x06_FeedbagReply{
					Items: []wire.FeedbagItem{},
				},
			},
		},
		{
			name:     "retrieve feedbag with items",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "buddy1",
								},
								{
									Name: "buddy2",
								},
							},
						},
					},
					feedbagLastModifiedParams: feedbagLastModifiedParams{
						{
							screenName: state.NewIdentScreenName("me"),
							result:     time.UnixMilli(1696472198082),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x06_FeedbagReply{
					Version: 0,
					Items: []wire.FeedbagItem{
						{
							Name: "buddy1",
						},
						{
							Name: "buddy2",
						},
					},
					LastUpdate: uint32(time.UnixMilli(1696472198082).Unix()),
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.results, nil)
			}
			for _, params := range tc.mockParams.feedbagLastModifiedParams {
				feedbagManager.EXPECT().
					FeedbagLastModified(matchContext(), params.screenName).
					Return(params.result, nil)
			}

			svc := FeedbagService{
				feedbagManager: feedbagManager,
			}
			outputSNAC, err := svc.Query(context.Background(), tc.instance, tc.inputSNAC.Frame)
			assert.NoError(t, err)
			assert.Equal(t, *tc.expectOutput, outputSNAC)
		})
	}
}

func TestFeedbagService_QueryIfModified(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user adding to feedbag
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectOutput is the SNAC sent from the server to client
		expectOutput *wire.SNACMessage
	}{
		{
			name:     "retrieve empty feedbag",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
					LastUpdate: uint32(time.UnixMilli(100000).Unix()),
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results:    []wire.FeedbagItem{},
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x06_FeedbagReply{
					Items: []wire.FeedbagItem{},
				},
			},
		},
		{
			name:     "retrieve feedbag with items",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
					LastUpdate: uint32(time.UnixMilli(100000).Unix()),
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "buddy1",
								},
								{
									Name: "buddy2",
								},
							},
						},
					},
					feedbagLastModifiedParams: feedbagLastModifiedParams{
						{
							screenName: state.NewIdentScreenName("me"),
							result:     time.UnixMilli(200000),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x06_FeedbagReply{
					Version: 0,
					Items: []wire.FeedbagItem{
						{
							Name: "buddy1",
						},
						{
							Name: "buddy2",
						},
					},
					LastUpdate: uint32(time.UnixMilli(200000).Unix()),
				},
			},
		},
		{
			name:     "retrieve not-modified response",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
					LastUpdate: uint32(time.UnixMilli(200000).Unix()),
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									Name: "buddy1",
								},
								{
									Name: "buddy2",
								},
							},
						},
					},
					feedbagLastModifiedParams: feedbagLastModifiedParams{
						{
							screenName: state.NewIdentScreenName("me"),
							result:     time.UnixMilli(100000),
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReplyNotModified,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
					LastUpdate: uint32(time.UnixMilli(100000).Unix()),
					Count:      2,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			//
			// initialize dependencies
			//
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.results, nil)
			}
			for _, params := range tc.mockParams.feedbagLastModifiedParams {
				feedbagManager.EXPECT().
					FeedbagLastModified(matchContext(), params.screenName).
					Return(params.result, nil)
			}
			//
			// send input SNAC
			//
			svc := FeedbagService{
				feedbagManager: feedbagManager,
			}
			outputSNAC, err := svc.QueryIfModified(context.Background(), tc.instance, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x13_0x05_FeedbagQueryIfModified))
			assert.NoError(t, err)
			//
			// verify output
			//
			assert.Equal(t, *tc.expectOutput, outputSNAC)
		})
	}
}

func TestFeedbagService_RightsQuery(t *testing.T) {
	svc := NewFeedbagService(nil, nil, nil, nil, nil, nil, nil, nil)

	outputSNAC := svc.RightsQuery(context.Background(), wire.SNACFrame{RequestID: 1234})
	expectSNAC := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagRightsReply,
			RequestID: 1234,
		},
		Body: wire.SNAC_0x13_0x03_FeedbagRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagRightsMaxItemAttrs, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxItemsByClass, []uint16{
						61,
						61,
						100,
						100,
						1,
						1,
						50,
						0x00,
						0x00,
						3,
						0x00,
						0x00,
						0x00,
						128,
						255,
						20,
						200,
						1,
						0x00,
						1,
						200,
					}),
					wire.NewTLVBE(wire.FeedbagRightsMaxClientItems, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxItemNameLen, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxRecentBuddies, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsInteractionBuddies, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsInteractionHalfLife, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsInteractionMaxScore, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxBuddiesPerGroup, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxMegaBots, uint16(200)),
					wire.NewTLVBE(wire.FeedbagRightsMaxSmartGroups, uint16(100)),
				},
			},
		},
	}

	assert.Equal(t, expectSNAC, outputSNAC)
}

func TestFeedbagService_UpsertItem(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user adding to feedbag
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectOutput is the SNAC sent from the server to client
		expectOutput *wire.SNACMessage
		// instanceMatch verifies the session state after completion
		instanceMatch func(instance *state.SessionInstance)
		// expectICBM is true when UpsertItem should call icbmSender
		expectICBM bool
		// wantICBMBody is the expected ICBM body (Cookie zeroed for comparison)
		wantICBMBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	}{
		{
			name:     "add buddies",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIDPermit,
							Name:    "buddy1",
						},
						{
							ClassID: wire.FeedbagClassIDPermit,
							Name:    "buddy2",
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIDPermit,
									Name:    "buddy1",
								},
								{
									ClassID: wire.FeedbagClassIDPermit,
									Name:    "buddy2",
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy1"),
								state.NewIdentScreenName("buddy2"),
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIDPermit,
											Name:    "buddy1",
										},
										{
											ClassID: wire.FeedbagClassIDPermit,
											Name:    "buddy2",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000, 0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:     "add 2 ICQ buddies one that requires authorization",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "123400", // requires authorization
						},
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "123401", // does not require authorization
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("100001"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "123401",
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123401"),
							result:     nil,
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("100001"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("123401"),
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("100001"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "123401",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("100001"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x000E, 0x0000},
								},
							},
						},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("123400"), requester: state.NewIdentScreenName("100001"), result: true},
						{owner: state.NewIdentScreenName("123401"), requester: state.NewIdentScreenName("100001"), result: false},
					},
				},
			},
			expectOutput: nil,
			expectICBM:   true,
			wantICBMBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: "123401",
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         100001,
							MessageType: wire.ICBMMsgTypeAdded,
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name:     "add ICQ buddy auth-required but pre-authorized",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "123400",
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "123400",
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123400"),
							result:     nil,
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("123400"),
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "123400",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("123400"), requester: state.NewIdentScreenName("me"), result: false},
					},
				},
			},
			expectOutput: nil,
			expectICBM:   true,
			wantICBMBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: "123400",
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         0,
							MessageType: wire.ICBMMsgTypeAdded,
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name:     "disable typing events",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddyPrefs,
							TLVLBlock: wire.TLVLBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(0x8000)),
								},
							},
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(0x8000)),
										},
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddyPrefs,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(0x8000)),
												},
											},
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:     "enable typing events",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddyPrefs,
							TLVLBlock: wire.TLVLBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(wire.FeedbagBuddyPrefsWantsTypingEvents)),
								},
							},
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(wire.FeedbagBuddyPrefsWantsTypingEvents)),
										},
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddyPrefs,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(wire.FeedbagBuddyPrefsWantsTypingEvents)),
												},
											},
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
			instanceMatch: func(instance *state.SessionInstance) {
				assert.True(t, instance.TypingEventsEnabled())
			},
		},
		{
			name:     "block buddies",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIDDeny,
							Name:    "buddy1",
						},
						{
							ClassID: wire.FeedbagClassIDDeny,
							Name:    "buddy2",
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIDDeny,
									Name:    "buddy1",
								},
								{
									ClassID: wire.FeedbagClassIDDeny,
									Name:    "buddy2",
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy1"),
								state.NewIdentScreenName("buddy2"),
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIDDeny,
											Name:    "buddy1",
										},
										{
											ClassID: wire.FeedbagClassIDDeny,
											Name:    "buddy2",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000, 0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:     "permit buddies",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIDPermit,
							Name:    "buddy1",
						},
						{
							ClassID: wire.FeedbagClassIDPermit,
							Name:    "buddy2",
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIDPermit,
									Name:    "buddy1",
								},
								{
									ClassID: wire.FeedbagClassIDPermit,
									Name:    "buddy2",
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy1"),
								state.NewIdentScreenName("buddy2"),
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIDPermit,
											Name:    "buddy1",
										},
										{
											ClassID: wire.FeedbagClassIDPermit,
											Name:    "buddy2",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000, 0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:     "set privacy mode",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdPdinfo,
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdPdinfo,
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:   state.NewIdentScreenName("me"),
							filter: nil,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdPdinfo,
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:     "user blocks themselves, receives error",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIDDeny,
							Name:    "me",
						},
					},
				},
			},
			expectOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotSupportedByHost,
				},
			},
		},
		{
			name:     "add icon hash to feedbag, icon doesn't exist in BART store, instruct client to upload icon",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
							ClassID: wire.FeedbagClassIdBart,
							TLVLBlock: wire.TLVLBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
										Flags: wire.BARTFlagsCustom,
										Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
									}),
								},
							},
						},
					},
				},
			},
			mockParams: mockParams{
				bartItemManagerParams: bartItemManagerParams{
					bartItemManagerRetrieveParams: bartItemManagerRetrieveParams{
						{
							itemHash: []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result:   []byte{}, // icon doesn't exist
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
									ClassID: wire.FeedbagClassIdBart,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
												Flags: wire.BARTFlagsCustom,
												Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
											}),
										},
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceUserInfoUpdate,
								},
								Body: func(val any) bool {
									snac, ok := val.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
									if !ok {
										return false
									}
									bartID, exists := snac.UserInfo[0].Bytes(wire.OServiceUserInfoBARTInfo)
									return assert.True(t, exists) &&
										assert.Equal(t, "me", snac.UserInfo[0].ScreenName) &&
										assert.True(t, bytes.Contains(bartID, []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'}), "user info BART hash doesn't match")
								},
							},
						},
					},
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
											ClassID: wire.FeedbagClassIdBart,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
														Flags: wire.BARTFlagsCustom,
														Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
													}),
												},
											},
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceBartReply,
								},
								Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
									BARTID: wire.BARTID{
										Type: wire.BARTTypesBuddyIcon,
										BARTInfo: wire.BARTInfo{
											Flags: wire.BARTFlagsCustom | wire.BARTFlagsUnknown,
											Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
			instanceMatch: func(instance *state.SessionInstance) {
				have, hasIcon := instance.Session().BuddyIcon()
				assert.True(t, hasIcon)
				want := wire.BARTID{
					Type: wire.BARTTypesBuddyIcon,
					BARTInfo: wire.BARTInfo{
						Flags: wire.BARTFlagsCustom | wire.BARTFlagsUnknown,
						Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
					},
				}
				assert.Equal(t, want, have)
			},
		},
		{
			name:     "add icon hash to feedbag, icon already exists in BART store, notify buddies about icon change",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
							ClassID: wire.FeedbagClassIdBart,
							TLVLBlock: wire.TLVLBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
										Flags: wire.BARTFlagsCustom,
										Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
									}),
								},
							},
						},
					},
				},
			},
			mockParams: mockParams{
				bartItemManagerParams: bartItemManagerParams{
					bartItemManagerRetrieveParams: bartItemManagerRetrieveParams{
						{
							itemHash: []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result:   []byte{'i', 'c', 'o', 'n', 'd', 'a', 't', 'a'},
							err:      nil,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
									ClassID: wire.FeedbagClassIdBart,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
												Flags: wire.BARTFlagsCustom,
												Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
											}),
										},
									},
								},
							},
						},
					},
					adjacentUsersParams: adjacentUsersParams{},
					feedbagParams:       feedbagParams{},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceUserInfoUpdate,
								},
								Body: func(val any) bool {
									snac, ok := val.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
									if !ok {
										return false
									}
									bartID, exists := snac.UserInfo[0].Bytes(wire.OServiceUserInfoBARTInfo)
									return assert.True(t, exists) &&
										assert.Equal(t, "me", snac.UserInfo[0].ScreenName) &&
										assert.True(t, bytes.Contains(bartID, []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'}), "user info BART hash doesn't match")
								},
							},
						},
					},
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
											ClassID: wire.FeedbagClassIdBart,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
														Flags: wire.BARTFlagsCustom,
														Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
													}),
												},
											},
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceBartReply,
								},
								Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
									BARTID: wire.BARTID{
										Type: wire.BARTTypesBuddyIcon,
										BARTInfo: wire.BARTInfo{
											Flags: wire.BARTFlagsCustom | wire.BARTFlagsKnown,
											Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.DisplayScreenName("me"),
						},
					},
				},
			},
			expectOutput: nil,
			instanceMatch: func(instance *state.SessionInstance) {
				have, hasIcon := instance.Session().BuddyIcon()
				assert.True(t, hasIcon)
				want := wire.BARTID{
					Type: wire.BARTTypesBuddyIcon,
					BARTInfo: wire.BARTInfo{
						Flags: wire.BARTFlagsCustom | wire.BARTFlagsKnown,
						Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
					},
				}
				assert.Equal(t, want, have)
			},
		},
		{
			name:     "clear icon, notify buddies about icon change",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
							ClassID: wire.FeedbagClassIdBart,
							TLVLBlock: wire.TLVLBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
										Flags: wire.BARTFlagsKnown,
										Hash:  wire.GetClearIconHash(),
									}),
								},
							},
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
									ClassID: wire.FeedbagClassIdBart,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
												Flags: wire.BARTFlagsKnown,
												Hash:  wire.GetClearIconHash(),
											}),
										},
									},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.DisplayScreenName("me"),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											Name:    fmt.Sprintf("%d", wire.BARTTypesBuddyIcon),
											ClassID: wire.FeedbagClassIdBart,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
														Hash: wire.GetClearIconHash(),
													}),
												},
											},
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceBartReply,
								},
								Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
									BARTID: wire.BARTID{
										Type: wire.BARTTypesBuddyIcon,
										BARTInfo: wire.BARTInfo{
											Flags: wire.BARTFlagsKnown,
											Hash:  wire.GetClearIconHash(),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceUserInfoUpdate,
								},
								Body: func(val any) bool {
									snac, ok := val.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
									if !ok {
										return false
									}
									bartID, exists := snac.UserInfo[0].Bytes(wire.OServiceUserInfoBARTInfo)
									return assert.True(t, exists) &&
										assert.Equal(t, "me", snac.UserInfo[0].ScreenName) &&
										assert.True(t, bytes.Contains(bartID, wire.GetClearIconHash()), "user info BART hash doesn't match")
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
			instanceMatch: func(instance *state.SessionInstance) {
				bartInfo, hasIcon := instance.Session().BuddyIcon()
				assert.True(t, hasIcon)
				assert.Equal(t, wire.GetClearIconHash(), bartInfo.Hash)
			},
		},
		{
			name:     "add non-icon to feedbag, icon doesn't exist in BART store, don't broadcast change",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							Name:    fmt.Sprintf("%d", wire.BARTTypesArriveSound),
							ClassID: wire.FeedbagClassIdBart,
							TLVLBlock: wire.TLVLBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
										Flags: wire.BARTFlagsCustom,
										Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
									}),
								},
							},
						},
					},
				},
			},
			mockParams: mockParams{
				bartItemManagerParams: bartItemManagerParams{
					bartItemManagerRetrieveParams: bartItemManagerRetrieveParams{
						{
							itemHash: []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
							result:   []byte{}, // icon doesn't exist
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									Name:    fmt.Sprintf("%d", wire.BARTTypesArriveSound),
									ClassID: wire.FeedbagClassIdBart,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
												Flags: wire.BARTFlagsCustom,
												Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
											}),
										},
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											Name:    fmt.Sprintf("%d", wire.BARTTypesArriveSound),
											ClassID: wire.FeedbagClassIdBart,
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesBartInfo, wire.BARTInfo{
														Flags: wire.BARTFlagsCustom,
														Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
													}),
												},
											},
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceBartReply,
								},
								Body: wire.SNAC_0x01_0x21_OServiceBARTReply{
									BARTID: wire.BARTID{
										Type: wire.BARTTypesArriveSound,
										BARTInfo: wire.BARTInfo{
											Flags: wire.BARTFlagsCustom | wire.BARTFlagsUnknown,
											Hash:  []byte{'t', 'h', 'e', 'h', 'a', 's', 'h'},
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
			instanceMatch: func(instance *state.SessionInstance) {
				_, hasIcon := instance.Session().BuddyIcon()
				assert.False(t, hasIcon)
			},
		},
		{
			name:     "add ICQ buddy online with feedbag: relay FeedbagBuddyAdded",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "123400",
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "123400",
								},
							},
						},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("123400"), requester: state.NewIdentScreenName("me"), result: false},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123400"),
							result: func() *state.Session {
								s := state.NewSession()
								s.SetIdentScreenName(state.NewIdentScreenName("123400"))
								s.SetUsesFeedbag()
								return s
							}(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("123400"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagBuddyAdded,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: "me",
								},
							},
						},
					},
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "123400",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("123400"),
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:     "add ICQ buddy online without feedbag: send legacy ICBM added",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "123400",
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "123400",
								},
							},
						},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("123400"), requester: state.NewIdentScreenName("me"), result: false},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123400"),
							result: func() *state.Session {
								s := state.NewSession()
								s.SetIdentScreenName(state.NewIdentScreenName("123400"))
								return s
							}(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "123400",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("123400"),
							},
						},
					},
				},
			},
			expectOutput: nil,
			expectICBM:   true,
			wantICBMBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: "123400",
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         0,
							MessageType: wire.ICBMMsgTypeAdded,
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name:     "ICQ user adds AIM buddy: expect ICQ user to preauthorize AIM user",
			instance: newTestInstance("100777", sessOptUIN(100777)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "buddyaim",
						},
					},
				},
			},
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{
							owner: state.NewIdentScreenName("100777"),
							buddy: state.NewIdentScreenName("buddyaim"),
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("100777"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddyaim",
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("100777"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "buddyaim",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("100777"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("100777"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddyaim"),
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
		{
			name:     "AIM user adds ICQ buddy pending auth: expect AIM user to send auth request to ICQ user",
			instance: newTestInstance("myaim"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x08_FeedbagInsertItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "990011",
						},
					},
				},
			},
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{
							owner:     state.NewIdentScreenName("990011"),
							requester: state.NewIdentScreenName("myaim"),
							result:    true,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("myaim"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "990011",
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}),
										},
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("myaim"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagInsertItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "990011",
											TLVLBlock: wire.TLVLBlock{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}),
												},
											},
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("myaim"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000},
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("myaim"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("990011"),
							},
						},
					},
				},
			},
			expectOutput: nil,
			expectICBM:   true,
			wantICBMBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: "990011",
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         0,
							MessageType: wire.ICBMMsgTypeAuthReq,
							Message:     "\xFE\xFE\xFE\xFE1\xFE",
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedbagManagerParams.feedbagUpsertParams {
				feedbagManager.EXPECT().
					FeedbagUpsert(matchContext(), params.screenName, params.items).
					Return(nil)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tc.mockParams.messageRelayerParams.relayToScreenNameParams {
				if matcherFn, ok := params.message.Body.(func(val any) bool); ok {
					messageRelayer.EXPECT().
						RelayToScreenName(matchContext(), params.screenName, mock.MatchedBy(func(message wire.SNACMessage) bool {
							return params.message.Frame == message.Frame &&
								matcherFn(message.Body)
						}))
				} else {
					messageRelayer.EXPECT().
						RelayToScreenName(matchContext(), params.screenName, params.message)
				}
			}
			for _, params := range tc.mockParams.messageRelayerParams.relayToOtherInstancesParams {
				messageRelayer.EXPECT().
					RelayToOtherInstances(mock.Anything, mock.Anything, params.message)
			}
			for _, params := range tc.mockParams.messageRelayerParams.relayToSelfParams {
				messageRelayer.EXPECT().
					RelayToSelf(mock.Anything, mock.Anything, params.message)
			}
			bartItemManager := newMockBARTItemManager(t)
			for _, params := range tc.mockParams.bartItemManagerParams.bartItemManagerRetrieveParams {
				bartItemManager.EXPECT().
					BARTItem(matchContext(), params.itemHash).
					Return(params.result, nil)
			}
			buddyUpdateBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tc.mockParams.broadcastBuddyArrivedParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastBuddyArrived(mock.Anything, state.NewIdentScreenName(params.screenName.String()), mock.MatchedBy(func(userInfo wire.TLVUserInfo) bool {
						return userInfo.ScreenName == params.screenName.String()
					})).
					Return(params.err)
			}
			for _, params := range tc.mockParams.broadcastVisibilityParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastVisibility(mock.Anything, matchSession(params.from), params.filter, true).
					Return(params.err)
			}
			contactPreAuth := newMockContactPreAuthorizer(t)
			for _, params := range tc.mockParams.recordPreAuthParams {
				contactPreAuth.EXPECT().RecordPreAuth(matchContext(), params.owner, params.buddy).Return(params.err)
			}
			for _, params := range tc.mockParams.requiresAuthorizationParams {
				contactPreAuth.EXPECT().RequiresAuthorization(matchContext(), params.owner, params.requester).Return(params.result, params.err)
			}
			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tc.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}
			icbmSender := func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
				if !tc.expectICBM {
					t.Fatalf("unexpected icbmSender call")
				}
				wantBody := tc.wantICBMBody
				wantBody.Cookie = 0
				haveBody := inBody
				haveBody.Cookie = 0
				assert.Equal(t, wantBody, haveBody)
				return nil, nil
			}
			svc := NewFeedbagService(slog.Default(), messageRelayer, feedbagManager, bartItemManager, nil, sessionRetriever, contactPreAuth, nil)
			svc.buddyBroadcaster = buddyUpdateBroadcaster
			svc.icbmSender = icbmSender
			output, err := svc.UpsertItem(context.Background(), tc.instance, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x13_0x08_FeedbagInsertItem).Items)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectOutput, output)

			if tc.instanceMatch != nil {
				tc.instanceMatch(tc.instance)
			}
		})
	}
}

func TestFeedbagService_DeleteItem(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user adding to feedbag
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectOutput is the SNAC sent from the server to client
		expectOutput *wire.SNACMessage
	}{
		{
			name:     "delete buddies",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagDeleteItem,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
					Items: []wire.FeedbagItem{
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "buddy1",
						},
						{
							ClassID: wire.FeedbagClassIdBuddy,
							Name:    "buddy2",
						},
						{
							ClassID: wire.FeedbagClassIdGroup,
							Name:    "group",
						},
					},
				},
			},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					feedbagDeleteParams: feedbagDeleteParams{
						{
							screenName: state.NewIdentScreenName("me"),
							items: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy1",
								},
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "buddy2",
								},
								{
									ClassID: wire.FeedbagClassIdGroup,
									Name:    "group",
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy1"),
								state.NewIdentScreenName("buddy2"),
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagDeleteItem,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
									Items: []wire.FeedbagItem{
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "buddy1",
										},
										{
											ClassID: wire.FeedbagClassIdBuddy,
											Name:    "buddy2",
										},
										{
											ClassID: wire.FeedbagClassIdGroup,
											Name:    "group",
										},
									},
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagStatus,
									RequestID: 1234,
								},
								Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
									Results: []uint16{0x0000, 0x0000, 0x0000},
								},
							},
						},
					},
				},
			},
			expectOutput: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tc.mockParams.feedbagManagerParams.feedbagDeleteParams {
				feedbagManager.EXPECT().
					FeedbagDelete(matchContext(), params.screenName, params.items).
					Return(nil)
			}
			buddyUpdateBroadcast := newMockbuddyBroadcaster(t)
			for _, params := range tc.mockParams.broadcastVisibilityParams {
				buddyUpdateBroadcast.EXPECT().
					BroadcastVisibility(mock.Anything, matchSession(params.from), params.filter, true).
					Return(params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tc.mockParams.messageRelayerParams.relayToOtherInstancesParams {
				messageRelayer.EXPECT().
					RelayToOtherInstances(mock.Anything, mock.Anything, params.message)
			}
			for _, params := range tc.mockParams.messageRelayerParams.relayToSelfParams {
				messageRelayer.EXPECT().
					RelayToSelf(mock.Anything, mock.Anything, params.message)
			}

			svc := FeedbagService{
				buddyBroadcaster: buddyUpdateBroadcast,
				feedbagManager:   feedbagManager,
				messageRelayer:   messageRelayer,
			}
			output, err := svc.DeleteItem(context.Background(), tc.instance, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x13_0x0A_FeedbagDeleteItem))
			assert.NoError(t, err)
			assert.Equal(t, output, tc.expectOutput)
		})
	}
}

func TestFeedbagService_Use(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// instance is the user's session
		instance *state.SessionInstance
		// bodyIn is the SNAC body sent from the arriving user's client to the
		// server
		bodyIn wire.SNAC_0x01_0x02_OServiceClientOnline
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// checkSession validates the state of the session after the call
		checkSession func(*testing.T, *state.Session)
		// wantErr indicates an error is expected
		wantErr error
	}{
		{
			name:     "enable user's feedbag, no feedbag buddy params item",
			instance: newTestInstance("me"),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					useParams: useParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
				},
			},
			checkSession: func(t *testing.T, s *state.Session) {
				assert.True(t, s.UsesFeedbag())
				assert.False(t, s.TypingEventsEnabled())
			},
		},
		{
			name:     "enable user's feedbag and set typing events disabled",
			instance: newTestInstance("me"),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					useParams: useParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(0x8000)),
										},
									},
								},
							},
						},
					},
				},
			},
			checkSession: func(t *testing.T, s *state.Session) {
				assert.True(t, s.UsesFeedbag())
				assert.False(t, s.TypingEventsEnabled())
			},
		},
		{
			name:     "enable user's feedbag and set typing events enabled",
			instance: newTestInstance("me"),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			mockParams: mockParams{
				feedbagManagerParams: feedbagManagerParams{
					useParams: useParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("me"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddyPrefs,
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesBuddyPrefs, uint32(wire.FeedbagBuddyPrefsWantsTypingEvents)),
										},
									},
								},
							},
						},
					},
				},
			},
			checkSession: func(t *testing.T, s *state.Session) {
				assert.True(t, s.UsesFeedbag())
				assert.True(t, s.TypingEventsEnabled())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tt.mockParams.useParams {
				feedbagManager.EXPECT().
					UseFeedbag(matchContext(), params.screenName).
					Return(nil)
			}
			for _, params := range tt.mockParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.results, nil)
			}

			svc := NewFeedbagService(slog.Default(), nil, feedbagManager, nil, nil, nil, nil, nil)

			haveErr := svc.Use(context.Background(), tt.instance)
			assert.ErrorIs(t, tt.wantErr, haveErr)
			tt.checkSession(t, tt.instance.Session())
		})
	}
}

func TestFeedbagService_RequestAuthorizeToHost(t *testing.T) {
	authReqSender := state.User{
		ICQBasicInfo: state.ICQBasicInfo{
			Nickname:     "CoolNickname",
			FirstName:    "Alice",
			LastName:     "Smith",
			EmailAddress: "alice@example.com",
		},
	}

	tests := []struct {
		// name is the unit test name
		name string
		// instance is the client session
		instance *state.SessionInstance
		// inSNAC is the SNAC message sent by the client
		inSNAC wire.SNACMessage
		// buddySess is the online session for the recipient, or nil if offline
		buddySess *state.Session
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
		// expectOutput is the expected SNAC passed to icbmSender
		expectOutput wire.SNACMessage
		// expectICBM is true when RequestAuthorizeToHost should route via icbmSender
		expectICBM bool
	}{
		{
			name:     "recipient is online with feedbag, relay authorization request",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			inSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRequestAuthorizeToHost,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
					ScreenName: "100002",
					Reason:     "please add me",
				},
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(state.NewIdentScreenName("100002"))
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: state.NewIdentScreenName("100002")},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100002"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagRequestAuthorizeToClient,
								},
								Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
									ScreenName: "100001",
									Reason:     "please add me",
								},
							},
						},
					},
				},
			},
			expectICBM: false,
		},
		{
			name:     "recipient is offline, send authorization request via ICBM",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			inSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRequestAuthorizeToHost,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
					ScreenName: "100002",
					Reason:     "please add me",
				},
			},
			buddySess: nil,
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: state.NewIdentScreenName("100002")},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("100001"), requester: state.NewIdentScreenName("100002"), result: false},
					},
				},
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{screenName: state.NewIdentScreenName("100001"), result: &authReqSender, err: nil},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMChannelMsgToHost,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelICQ,
					ScreenName: "100002",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
								UIN:         100001,
								MessageType: wire.ICBMMsgTypeAuthReq,
								Message: fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE%d\xFE%s",
									authReqSender.ICQBasicInfo.Nickname,
									authReqSender.ICQBasicInfo.FirstName,
									authReqSender.ICQBasicInfo.LastName,
									authReqSender.ICQBasicInfo.EmailAddress,
									1,
									utf8ToLatin1("please add me"),
								),
							}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
						},
					},
				},
			},
			expectICBM: true,
		},
		{
			name:     "recipient is online without feedbag, send authorization request via ICBM",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			inSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRequestAuthorizeToHost,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
					ScreenName: "100002",
					Reason:     "please add me",
				},
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(state.NewIdentScreenName("100002"))
				return s
			}(),
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: state.NewIdentScreenName("100002")},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("100001"), requester: state.NewIdentScreenName("100002"), result: false},
					},
				},
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{screenName: state.NewIdentScreenName("100001"), result: &authReqSender, err: nil},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMChannelMsgToHost,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelICQ,
					ScreenName: "100002",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
								UIN:         100001,
								MessageType: wire.ICBMMsgTypeAuthReq,
								Message: fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE%d\xFE%s",
									authReqSender.ICQBasicInfo.Nickname,
									authReqSender.ICQBasicInfo.FirstName,
									authReqSender.ICQBasicInfo.LastName,
									authReqSender.ICQBasicInfo.EmailAddress,
									1,
									utf8ToLatin1("please add me"),
								),
							}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
						},
					},
				},
			},
			expectICBM: true,
		},
		{
			name:     "recipient is offline, sender requires pre-authorization, send request with authorized=0",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			inSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRequestAuthorizeToHost,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
					ScreenName: "100002",
					Reason:     "please add me",
				},
			},
			buddySess: nil,
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: state.NewIdentScreenName("100002")},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("100001"), requester: state.NewIdentScreenName("100002"), result: true},
					},
				},
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{screenName: state.NewIdentScreenName("100001"), result: &authReqSender, err: nil},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMChannelMsgToHost,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelICQ,
					ScreenName: "100002",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
								UIN:         100001,
								MessageType: wire.ICBMMsgTypeAuthReq,
								Message: fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE%d\xFE%s",
									authReqSender.ICQBasicInfo.Nickname,
									authReqSender.ICQBasicInfo.FirstName,
									authReqSender.ICQBasicInfo.LastName,
									authReqSender.ICQBasicInfo.EmailAddress,
									0,
									utf8ToLatin1("please add me"),
								),
							}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
						},
					},
				},
			},
			expectICBM: true,
		},
		{
			name:     "icbmSender returns error",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			inSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRequestAuthorizeToHost,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost{
					ScreenName: "100002",
					Reason:     "please add me",
				},
			},
			buddySess: nil,
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: state.NewIdentScreenName("100002")},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					requiresAuthorizationParams: requiresAuthorizationParams{
						{owner: state.NewIdentScreenName("100001"), requester: state.NewIdentScreenName("100002"), result: false},
					},
				},
				userManagerParams: userManagerParams{
					getUserParams: getUserParams{
						{screenName: state.NewIdentScreenName("100001"), result: &authReqSender, err: nil},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMChannelMsgToHost,
				},
				Body: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					ChannelID:  wire.ICBMChannelICQ,
					ScreenName: "100002",
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
								UIN:         100001,
								MessageType: wire.ICBMMsgTypeAuthReq,
								Message: fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE%d\xFE%s",
									authReqSender.ICQBasicInfo.Nickname,
									authReqSender.ICQBasicInfo.FirstName,
									authReqSender.ICQBasicInfo.LastName,
									authReqSender.ICQBasicInfo.EmailAddress,
									1,
									utf8ToLatin1("please add me"),
								),
							}),
							wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
						},
					},
				},
			},
			wantErr:    assert.AnError,
			expectICBM: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().RetrieveSession(params.screenName).Return(tt.buddySess)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.messageRelayerParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(matchContext(), params.screenName, params.message)
			}

			icbmSender := func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
				if !tt.expectICBM {
					t.Fatalf("unexpected icbmSender call")
				}
				assert.Equal(t, tt.expectOutput.Frame, inFrame)
				assert.Equal(t, tt.instance, instance)
				wantBody := tt.expectOutput.Body.(wire.SNAC_0x04_0x06_ICBMChannelMsgToHost)
				assert.Equal(t, wantBody, inBody)
				return nil, tt.wantErr
			}

			contactPreAuth := newMockContactPreAuthorizer(t)
			for _, params := range tt.mockParams.requiresAuthorizationParams {
				contactPreAuth.EXPECT().
					RequiresAuthorization(matchContext(), params.owner, params.requester).
					Return(params.result, params.err)
			}

			userManager := newMockUserManager(t)
			for _, params := range tt.mockParams.userManagerParams.getUserParams {
				userManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}

			svc := NewFeedbagService(slog.Default(), messageRelayer, nil, nil, nil, sessionRetriever, contactPreAuth, userManager)
			svc.icbmSender = icbmSender

			haveErr := svc.RequestAuthorizeToHost(
				context.Background(),
				tt.instance,
				tt.inSNAC.Frame,
				tt.inSNAC.Body.(wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost),
			)
			assert.ErrorIs(t, haveErr, tt.wantErr)
		})
	}
}

func TestFeedbagService_RespondAuthorizeToHost(t *testing.T) {
	wantICBMFrame := wire.SNACFrame{
		FoodGroup: wire.ICBM,
		SubGroup:  wire.ICBMChannelMsgToHost,
	}
	tests := []struct {
		// name is the unit test name
		name string
		// instance is the client session
		instance *state.SessionInstance
		// bodyIn is the SNAC body sent by the client
		bodyIn wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost
		// buddySess is the online session for the recipient, or nil if offline
		buddySess *state.Session
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectICBM is true when RespondAuthorizeToHost should route via icbmSender
		expectICBM bool
		// wantHostSNAC is the expected ICBM body when expectICBM is true
		wantHostSNAC wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:     "authorization accepted - offline recipient receives legacy ICQ auth OK",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   1,
			},
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{owner: state.NewIdentScreenName("100001"), buddy: state.NewIdentScreenName("100003")},
					},
				},
			},
			expectICBM: true,
			wantHostSNAC: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: "100003",
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         100001,
							MessageType: wire.ICBMMsgTypeAuthOK,
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name:     "authorization denied - offline recipient receives legacy ICQ auth deny",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   0,
				Reason:     "I don't know you!",
			},
			expectICBM: true,
			wantHostSNAC: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: "100003",
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         100001,
							MessageType: wire.ICBMMsgTypeAuthDeny,
							Message:     "I don't know you!",
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name:     "authorization accepted - feedbag recipient receives FeedbagPreAuthorizedBuddy",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   1,
				Reason:     "welcome",
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(state.NewIdentScreenName("100003"))
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{owner: state.NewIdentScreenName("100001"), buddy: state.NewIdentScreenName("100003")},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{screenName: state.NewIdentScreenName("100003"), results: []wire.FeedbagItem{}},
					},
				},
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{me: state.NewIdentScreenName("100001"), them: state.NewIdentScreenName("100003"), result: state.Relationship{}},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagPreAuthorizedBuddy,
								},
								Body: wire.SNAC_0x13_0x15_FeedbagPreAuthorizedBuddy{
									ScreenName: "100001",
									Message:    "welcome",
									Flags:      0,
								},
							},
						},
					},
				},
			},
		},
		{
			name:     "authorization accepted - feedbag recipient with pending auth, sender has feedbag: clearPendingAuth feedbag path",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   1,
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(state.NewIdentScreenName("100003"))
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{owner: state.NewIdentScreenName("100001"), buddy: state.NewIdentScreenName("100003")},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "100001",
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}),
										},
									},
								},
							},
						},
					},
					feedbagUpsertParams: feedbagUpsertParams{
						// slices.DeleteFunc returns an empty non-nil slice after removing the pending tag
						{
							screenName: state.NewIdentScreenName("100003"),
							items: []wire.FeedbagItem{
								{ClassID: wire.FeedbagClassIdBuddy, Name: "100001", TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{}}},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("100001"),
							result: func() *state.Session {
								s := state.NewSession()
								s.SetIdentScreenName(state.NewIdentScreenName("100001"))
								s.SetUsesFeedbag()
								s.AddInstance()
								return s
							}(),
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100001"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagBuddyAdded,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: "100003",
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagUpdateItem,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{ClassID: wire.FeedbagClassIdBuddy, Name: "100001", TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{}}},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagRespondAuthorizeToClient,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: "100001",
									Accepted:   1,
								},
							},
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("100001"),
							filter:           []state.IdentScreenName{state.NewIdentScreenName("100003")},
							doSendDepartures: false,
						},
					},
				},
			},
		},
		{
			name:     "authorization accepted - feedbag recipient with pending auth, sender offline: clearPendingAuth legacy path",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   1,
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(state.NewIdentScreenName("100003"))
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{owner: state.NewIdentScreenName("100001"), buddy: state.NewIdentScreenName("100003")},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							results: []wire.FeedbagItem{
								{
									ClassID: wire.FeedbagClassIdBuddy,
									Name:    "100001",
									TLVLBlock: wire.TLVLBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.FeedbagAttributesPending, []byte{}),
										},
									},
								},
							},
						},
					},
					feedbagUpsertParams: feedbagUpsertParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							items: []wire.FeedbagItem{
								{ClassID: wire.FeedbagClassIdBuddy, Name: "100001", TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{}}},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: state.NewIdentScreenName("100001"), result: nil},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagUpdateItem,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
									Items: []wire.FeedbagItem{
										{ClassID: wire.FeedbagClassIdBuddy, Name: "100001", TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{}}},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagRespondAuthorizeToClient,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: "100001",
									Accepted:   1,
								},
							},
						},
					},
				},
			},
			expectICBM: true,
			wantHostSNAC: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: "100001",
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         0,
							MessageType: wire.ICBMMsgTypeAdded,
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name:     "authorization denied - feedbag recipient receives FeedbagRespondAuthorizeToClient",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   0,
				Reason:     "I don't know you!",
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(state.NewIdentScreenName("100003"))
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagRespondAuthorizeToClient,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: "100001",
									Accepted:   0,
									Reason:     "I don't know you!",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionRetriever := newMockSessionRetriever(t)
			sessionRetriever.EXPECT().
				RetrieveSession(state.NewIdentScreenName(tt.bodyIn.ScreenName)).
				Return(tt.buddySess)
			for _, params := range tt.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().RetrieveSession(params.screenName).Return(params.result)
			}

			contactPreAuth := newMockContactPreAuthorizer(t)
			for _, params := range tt.mockParams.recordPreAuthParams {
				contactPreAuth.EXPECT().RecordPreAuth(matchContext(), params.owner, params.buddy).Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.messageRelayerParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(matchContext(), params.screenName, params.message)
			}

			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tt.mockParams.feedbagManagerParams.feedbagParams {
				feedbagManager.EXPECT().Feedbag(matchContext(), params.screenName).Return(params.results, params.err)
			}
			for _, params := range tt.mockParams.feedbagManagerParams.feedbagUpsertParams {
				feedbagManager.EXPECT().FeedbagUpsert(matchContext(), params.screenName, params.items).Return(nil)
			}

			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, params := range tt.mockParams.relationshipFetcherParams.relationshipParams {
				relationshipFetcher.EXPECT().Relationship(matchContext(), params.me, params.them).Return(params.result, params.err)
			}

			buddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastVisibilityParams {
				buddyBroadcaster.EXPECT().
					BroadcastVisibility(mock.Anything, matchSession(params.from), params.filter, params.doSendDepartures).
					Return(params.err)
			}

			icbmSender := func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
				if !tt.expectICBM {
					t.Fatalf("unexpected icbmSender call")
				}
				assert.Equal(t, wantICBMFrame, inFrame)
				wantBody := tt.wantHostSNAC
				wantBody.Cookie = 0
				haveBody := inBody
				haveBody.Cookie = 0
				assert.Equal(t, wantBody, haveBody)
				return nil, tt.wantErr
			}

			svc := NewFeedbagService(slog.Default(), messageRelayer, feedbagManager, nil, relationshipFetcher, sessionRetriever, contactPreAuth, nil)
			svc.buddyBroadcaster = buddyBroadcaster
			svc.icbmSender = icbmSender

			haveErr := svc.RespondAuthorizeToHost(context.Background(), tt.instance.IdentScreenName(), wire.SNACFrame{}, tt.bodyIn)
			assert.ErrorIs(t, tt.wantErr, haveErr)
		})
	}
}

func TestFeedbagService_PreAuthorizeBuddy(t *testing.T) {
	alice := newTestInstance("100001", sessOptUIN(100001))
	buddySN := state.NewIdentScreenName("100002")
	wantICBMFrame := wire.SNACFrame{
		FoodGroup: wire.ICBM,
		SubGroup:  wire.ICBMChannelMsgToHost,
	}
	wantICBMBody := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelICQ,
		ScreenName: buddySN.String(),
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
					UIN:         100001,
					MessageType: wire.ICBMMsgTypeAuthOK,
				}),
				wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
			},
		},
	}

	tests := []struct {
		// name is the unit test name
		name string
		// inFrame is the SNAC frame sent by the client
		inFrame wire.SNACFrame
		// inBody is the SNAC body sent by the client
		inBody wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy
		// buddySess is the online session for the pre-authorized buddy, or nil
		// if the buddy is offline
		buddySess *state.Session
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantOut is the SNAC sent from the server to the client
		wantOut *wire.SNACMessage
		// wantErr is the expected error
		wantErr error
		// expectICBM is true when PreAuthorizeBuddy should send SNAC(0x04,0x06) auth OK
		expectICBM bool
	}{
		{
			name:    "rejects self with FeedbagErr",
			inFrame: wire.SNACFrame{RequestID: 0xabc},
			inBody:  wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{ScreenName: "100001"},
			wantOut: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagErr,
					RequestID: 0xabc,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotSupportedByHost,
				},
			},
			expectICBM: false,
		},
		{
			name:   "unknown buddy user",
			inBody: wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{ScreenName: buddySN.String()},
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: buddySN,
							result:     nil,
						},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{
							owner: alice.IdentScreenName(),
							buddy: buddySN,
							err:   state.ErrNoUser,
						},
					},
				},
			},
			expectICBM: false,
		},
		{
			name:   "RecordPreAuth error",
			inBody: wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{ScreenName: buddySN.String()},
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: buddySN,
							result:     nil,
						},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{
							owner: alice.IdentScreenName(),
							buddy: buddySN,
							err:   assert.AnError,
						},
					},
				},
			},
			wantErr:    assert.AnError,
			expectICBM: false,
		},
		{
			name: "offline buddy: records grant, sends ICBM auth OK",
			inBody: wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{
				ScreenName: buddySN.String(),
				Message:    "hi",
			},
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{
							owner: alice.IdentScreenName(),
							buddy: buddySN,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: buddySN,
							result:     nil,
						},
					},
				},
			},
			expectICBM: true,
		},
		{
			name:   "online no feedbag: sends ICBM auth OK",
			inBody: wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{ScreenName: buddySN.String()},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(buddySN)
				return s
			}(),
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{
							owner: alice.IdentScreenName(),
							buddy: buddySN,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: buddySN,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: buddySN,
							results:    []wire.FeedbagItem{},
						},
					},
				},
			},
			expectICBM: true,
		},
		{
			name: "online feedbag YouBlock: no relay",
			inBody: wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{
				ScreenName: buddySN.String(),
				Message:    "note",
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(buddySN)
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{
							owner: alice.IdentScreenName(),
							buddy: buddySN,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: buddySN,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: buddySN,
							results:    []wire.FeedbagItem{},
						},
					},
				},
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:     alice.IdentScreenName(),
							them:   buddySN,
							result: state.Relationship{BlocksYou: true},
						},
					},
				},
			},
			expectICBM: false,
		},
		{
			name: "online feedbag relays PreAuthorizedBuddy",
			inBody: wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy{
				ScreenName: buddySN.String(),
				Message:    "added you",
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(buddySN)
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{
							owner: alice.IdentScreenName(),
							buddy: buddySN,
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: buddySN,
						},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{
							screenName: buddySN,
							results:    []wire.FeedbagItem{},
						},
					},
				},
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:     alice.IdentScreenName(),
							them:   buddySN,
							result: state.Relationship{BlocksYou: false},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: buddySN,
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagPreAuthorizedBuddy,
								},
								Body: wire.SNAC_0x13_0x15_FeedbagPreAuthorizedBuddy{
									ScreenName: "100001",
									Message:    "added you",
									Flags:      0,
								},
							},
						},
					},
				},
			},
			expectICBM: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contactPreAuth := newMockContactPreAuthorizer(t)
			for _, params := range tt.mockParams.contactPreAuthorizerParams.recordPreAuthParams {
				contactPreAuth.EXPECT().RecordPreAuth(matchContext(), params.owner, params.buddy).Return(params.err)
			}
			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().RetrieveSession(params.screenName).Return(tt.buddySess)
			}
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tt.mockParams.feedbagManagerParams.feedbagParams {
				feedbagManager.EXPECT().
					Feedbag(matchContext(), params.screenName).
					Return(params.results, params.err)
			}
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, params := range tt.mockParams.relationshipFetcherParams.relationshipParams {
				relationshipFetcher.EXPECT().Relationship(matchContext(), params.me, params.them).Return(params.result, params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.messageRelayerParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(matchContext(), params.screenName, params.message)
			}

			icbmSender := func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
				if !tt.expectICBM {
					t.Fatalf("unexpected icbmSender call")
				}
				assert.Equal(t, wantICBMFrame, inFrame)
				assert.Equal(t, alice.IdentScreenName(), instance.IdentScreenName())
				assert.Equal(t, wantICBMBody.ChannelID, inBody.ChannelID)
				assert.Equal(t, wantICBMBody.ScreenName, inBody.ScreenName)
				assert.Equal(t, wantICBMBody.TLVRestBlock, inBody.TLVRestBlock)
				assert.NotZero(t, inBody.Cookie)
				return nil, nil
			}

			svc := NewFeedbagService(slog.Default(), messageRelayer, feedbagManager, nil, relationshipFetcher, sessionRetriever, contactPreAuth, nil)
			svc.icbmSender = icbmSender

			out, err := svc.PreAuthorizeBuddy(context.Background(), alice, tt.inFrame, tt.inBody)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.wantOut, out)
		})
	}
}

func TestUtf8ToLatin1(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "pure ASCII string returned unchanged",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "Latin-1 characters converted to single bytes",
			input: "caf\u00e9", // é = U+00E9
			want:  "caf\xe9",
		},
		{
			name:  "non-Latin-1 character replaced with question mark",
			input: "price: \u20ac", // € = U+20AC (> 0xFF)
			want:  "price: ?",
		},
		{
			name:  "mixed input: ASCII and Latin-1 kept, non-Latin-1 replaced",
			input: "r\u00e9sum\u00e9 \u20ac100", // résumé €100
			want:  "r\xe9sum\xe9 ?100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, utf8ToLatin1(tt.input))
		})
	}
}

func TestFeedbagBuddyPref(t *testing.T) {
	tests := []struct {
		name      string
		itemType  uint16
		list      wire.TLVList
		wantValid bool
		wantValue bool
	}{
		{
			name:     "offline messages disabled",
			itemType: wire.FeedbagBuddyPrefsAcceptOfflineIM,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 1}},
			},
			wantValid: true,
			wantValue: false,
		},
		{
			name:     "offline messages disabled",
			itemType: wire.FeedbagBuddyPrefsAcceptOfflineIM,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 1}},
			},
			wantValid: true,
			wantValue: false,
		},
		{
			name:     "offline messages disabled, extra padding",
			itemType: wire.FeedbagBuddyPrefsAcceptOfflineIM,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17, 0, 0}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 1, 0, 0}},
			},
			wantValid: true,
			wantValue: false,
		},
		{
			name:     "offline messages enabled",
			itemType: wire.FeedbagBuddyPrefsAcceptOfflineIM,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
			},
			wantValid: true,
			wantValue: true,
		},
		{
			name:     "offline messages enabled",
			itemType: wire.FeedbagBuddyPrefsAcceptOfflineIM,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17, 0, 0}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17, 0, 0}},
			},
			wantValid: true,
			wantValue: true,
		},
		{
			name:     "typing events enabled, with padding",
			itemType: wire.FeedbagBuddyPrefsAcceptOfflineIM,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 64, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 64, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
			},
			wantValid: true,
			wantValue: true,
		},
		{
			name:     "typing events enabled, without padding",
			itemType: 22,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{64, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{64, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{17}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{17}},
			},
			wantValid: true,
			wantValue: true,
		},
		{
			name:     "typing events disabled, with padding",
			itemType: 22,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 64, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 17}},
			},
			wantValid: true,
			wantValue: false,
		},
		{
			name:     "typing events disabled, without padding",
			itemType: 22,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{64, 24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{24, 64}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{17}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{17}},
			},
			wantValid: true,
			wantValue: false,
		},
		{
			name:     "show friendly IMs enabled (dupe of disclose radio)",
			itemType: 32,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0x00, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0x00, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0x80, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0x80, 0x00, 0x00, 0x00}},
			},
			wantValid: true,
			wantValue: true,
		},
		{
			name:     "disclose radio enabled (dupe of show friendly IMs)",
			itemType: 33,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0x00, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0x00, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0x80, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0x80, 0x00, 0x00, 0x00}},
			},
			wantValid: true,
			wantValue: true,
		},
		{
			name:     "show capabilities enabled",
			itemType: 34,
			list: wire.TLVList{
				{Tag: wire.FeedbagAttributesBuddyPrefsValid, Value: []byte{0x00, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs, Value: []byte{0x00, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0x40, 0x00, 0x00, 0x00}},
				{Tag: wire.FeedbagAttributesBuddyPrefs2, Value: []byte{0x40, 0x00, 0x00, 0x00}},
			},
			wantValid: true,
			wantValue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, value := feedbagBuddyPref(tt.itemType, tt.list)
			assert.Equal(t, tt.wantValid, valid)
			assert.Equal(t, tt.wantValue, value)
		})
	}
}

func TestFeedbagService_StartCluster(t *testing.T) {
	instance := newTestInstance("me")
	inFrame := wire.SNACFrame{
		FoodGroup: wire.Feedbag,
		SubGroup:  wire.FeedbagStartCluster,
		RequestID: 1234,
	}
	inBody := wire.SNAC_0x13_0x11_FeedbagStartCluster{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(0x01, uint16(100)),
			},
		},
	}

	messageRelayer := newMockMessageRelayer(t)
	messageRelayer.EXPECT().
		RelayToOtherInstances(matchContext(), instance, wire.SNACMessage{
			Frame: inFrame,
			Body:  inBody,
		})

	svc := NewFeedbagService(slog.Default(), messageRelayer, nil, nil, nil, nil, nil, nil)
	svc.StartCluster(context.Background(), instance, inFrame, inBody)
}

func TestFeedbagService_EndCluster(t *testing.T) {
	instance := newTestInstance("me")
	inFrame := wire.SNACFrame{
		FoodGroup: wire.Feedbag,
		SubGroup:  wire.FeedbagEndCluster,
		RequestID: 1234,
	}

	messageRelayer := newMockMessageRelayer(t)
	messageRelayer.EXPECT().
		RelayToOtherInstances(matchContext(), instance, wire.SNACMessage{
			Frame: inFrame,
			Body:  wire.SNAC_0x13_0x12_FeedbagEndCluster{},
		})

	svc := NewFeedbagService(slog.Default(), messageRelayer, nil, nil, nil, nil, nil, nil)
	svc.EndCluster(context.Background(), instance, inFrame)
}

func TestFeedbagService_ForwardICQAuthEvents(t *testing.T) {
	sender := newTestInstance("100001", sessOptUIN(100001))
	recipient := state.NewIdentScreenName("100002")

	tests := []struct {
		// name is the unit test name
		name string
		// authMsg is the ICQ channel-4 message to forward
		authMsg wire.ICBMCh4Message
		// buddySess is the online session for the recipient, or nil if offline
		buddySess *state.Session
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectICBM is true when ForwardICQAuthEvents should route via icbmSender
		expectICBM bool
		// wantICBMBody is the expected ICBM body sent via icbmSender (when expectICBM is true)
		wantICBMBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
		// wantErr is the expected error
		wantErr error
	}{
		{
			name: "auth OK - feedbag recipient receives PreAuthorizedBuddy SNAC",
			authMsg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAuthOK,
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(recipient)
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: recipient},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{owner: sender.IdentScreenName(), buddy: recipient},
					},
				},
				feedbagManagerParams: feedbagManagerParams{
					feedbagParams: feedbagParams{
						{screenName: recipient, results: []wire.FeedbagItem{}},
					},
				},
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{me: sender.IdentScreenName(), them: recipient, result: state.Relationship{}},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: recipient,
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagPreAuthorizedBuddy,
								},
								Body: wire.SNAC_0x13_0x15_FeedbagPreAuthorizedBuddy{
									ScreenName: sender.DisplayScreenName().String(),
									Flags:      0,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "auth OK - offline recipient receives legacy ICQ auth OK",
			authMsg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAuthOK,
			},
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: recipient},
					},
				},
				contactPreAuthorizerParams: contactPreAuthorizerParams{
					recordPreAuthParams: recordPreAuthParams{
						{owner: sender.IdentScreenName(), buddy: recipient},
					},
				},
			},
			expectICBM: true,
			wantICBMBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: recipient.String(),
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         sender.UIN(),
							MessageType: wire.ICBMMsgTypeAuthOK,
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name: "auth deny - feedbag recipient receives RespondAuthorizeToClient SNAC",
			authMsg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAuthDeny,
				Message:     "no thanks",
			},
			buddySess: func() *state.Session {
				s := state.NewSession()
				s.SetIdentScreenName(recipient)
				s.SetUsesFeedbag()
				return s
			}(),
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: recipient},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: recipient,
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagRespondAuthorizeToClient,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: sender.DisplayScreenName().String(),
									Accepted:   0,
									Reason:     "no thanks",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "auth deny - offline recipient receives legacy ICQ auth deny",
			authMsg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAuthDeny,
				Message:     "no thanks",
			},
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{screenName: recipient},
					},
				},
			},
			expectICBM: true,
			wantICBMBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ChannelID:  wire.ICBMChannelICQ,
				ScreenName: recipient.String(),
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
							UIN:         sender.UIN(),
							MessageType: wire.ICBMMsgTypeAuthDeny,
							Message:     "no thanks",
						}),
						wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
					},
				},
			},
		},
		{
			name: "added - relays FeedbagBuddyAdded SNAC to recipient",
			authMsg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAdded,
			},
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: recipient,
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagBuddyAdded,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x1C_FeedbagBuddyAdded{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: sender.IdentScreenName().String(),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "auth req - relays FeedbagRequestAuthorizeToClient SNAC to recipient",
			authMsg: wire.ICBMCh4Message{
				MessageType: wire.ICBMMsgTypeAuthReq,
				Message:     "11111111\xFE\xFE\xFE\xFE1\xFEplease add me",
			},
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: recipient,
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Feedbag,
									SubGroup:  wire.FeedbagRequestAuthorizeToClient,
									Flags:     0x8000,
								},
								Body: wire.SNAC_0x13_0x19_FeedbagRequestAuthorizeToClient{
									TLV:        wire.NewTLVBE(6, uint32(0x00020004)),
									ScreenName: sender.IdentScreenName().String(),
									Reason:     "please add me",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "unknown message type - logs warning and returns nil",
			authMsg: wire.ICBMCh4Message{
				MessageType: 0xFF,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.sessionRetrieverParams.retrieveSessionParams {
				sessionRetriever.EXPECT().RetrieveSession(params.screenName).Return(tt.buddySess)
			}
			contactPreAuth := newMockContactPreAuthorizer(t)
			for _, params := range tt.mockParams.contactPreAuthorizerParams.recordPreAuthParams {
				contactPreAuth.EXPECT().RecordPreAuth(matchContext(), params.owner, params.buddy).Return(params.err)
			}
			feedbagManager := newMockFeedbagManager(t)
			for _, params := range tt.mockParams.feedbagManagerParams.feedbagParams {
				feedbagManager.EXPECT().Feedbag(matchContext(), params.screenName).Return(params.results, params.err)
			}
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, params := range tt.mockParams.relationshipFetcherParams.relationshipParams {
				relationshipFetcher.EXPECT().Relationship(matchContext(), params.me, params.them).Return(params.result, params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.messageRelayerParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(matchContext(), params.screenName, params.message)
			}

			icbmSender := func(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
				if !tt.expectICBM {
					t.Fatalf("unexpected icbmSender call")
				}
				assert.Equal(t, wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}, inFrame)
				assert.Equal(t, sender.IdentScreenName(), instance.IdentScreenName())
				wantBody := tt.wantICBMBody
				wantBody.Cookie = 0
				haveBody := inBody
				haveBody.Cookie = 0
				assert.Equal(t, wantBody, haveBody)
				return nil, tt.wantErr
			}

			svc := NewFeedbagService(slog.Default(), messageRelayer, feedbagManager, nil, relationshipFetcher, sessionRetriever, contactPreAuth, nil)
			svc.icbmSender = icbmSender

			err := svc.ForwardICQAuthEvents(context.Background(), sender.IdentScreenName(), recipient, tt.authMsg)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
