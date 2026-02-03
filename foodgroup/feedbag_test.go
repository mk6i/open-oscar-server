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
	svc := NewFeedbagService(nil, nil, nil, nil, nil, nil)

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
			svc := NewFeedbagService(slog.Default(), messageRelayer, feedbagManager, bartItemManager, nil, nil)
			svc.buddyBroadcaster = buddyUpdateBroadcaster
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
		// wantTypingEventsEnabled indicates that the session should have
		// typing events enabled
		wantTypingEventsEnabled bool
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
			wantTypingEventsEnabled: false,
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
			wantTypingEventsEnabled: false,
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
			wantTypingEventsEnabled: true,
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

			svc := NewFeedbagService(slog.Default(), nil, feedbagManager, nil, nil, nil)

			haveErr := svc.Use(context.Background(), tt.instance)
			assert.ErrorIs(t, tt.wantErr, haveErr)

			assert.Equal(t, tt.wantTypingEventsEnabled, tt.instance.TypingEventsEnabled())
		})
	}
}

func TestFeedbagService_RespondAuthorizeToHost(t *testing.T) {
	tests := []struct {
		name       string
		instance   *state.SessionInstance
		bodyIn     wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost
		mockParams mockParams
		wantErr    error
	}{
		{
			name:     "authorization accepted",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   1,
			},
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelICQ,
									TLVUserInfo: newTestInstance("100001").Session().TLVUserInfo(),
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
						},
					},
				},
			},
		},
		{
			name:     "authorization denied (with reason)",
			instance: newTestInstance("100001", sessOptUIN(100001)),
			bodyIn: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
				ScreenName: "100003",
				Accepted:   0,
				Reason:     "I don't know you!",
			},
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICBM,
									SubGroup:  wire.ICBMChannelMsgToClient,
								},
								Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
									ChannelID:   wire.ICBMChannelICQ,
									TLVUserInfo: newTestInstance("100001").Session().TLVUserInfo(),
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
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(matchContext(), params.screenName, params.message)
			}

			svc := NewFeedbagService(slog.Default(), messageRelayer, nil, nil, nil, nil)
			haveErr := svc.RespondAuthorizeToHost(context.Background(), tt.instance, wire.SNACFrame{}, tt.bodyIn)
			assert.ErrorIs(t, tt.wantErr, haveErr)
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

	svc := NewFeedbagService(slog.Default(), messageRelayer, nil, nil, nil, nil)
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

	svc := NewFeedbagService(slog.Default(), messageRelayer, nil, nil, nil, nil)
	svc.EndCluster(context.Background(), instance, inFrame)
}
