package foodgroup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestBuddyService_RightsQuery(t *testing.T) {
	svc := NewBuddyService(nil, nil, nil, nil, nil)

	want := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyRightsReply,
			RequestID: 1234,
		},
		Body: wire.SNAC_0x03_0x03_BuddyRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxBuddies, uint16(100)),
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxWatchers, uint16(100)),
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxIcqBroad, uint16(100)),
					wire.NewTLVBE(wire.BuddyTLVTagsParmMaxTempBuddies, uint16(100)),
				},
			},
		},
	}
	have := svc.RightsQuery(nil, wire.SNACFrame{RequestID: 1234})

	assert.Equal(t, want, have)
}

func TestBuddyService_AddBuddies(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// instance is the client session
		instance *state.SessionInstance
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x03_0x04_BuddyAddBuddies
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:     "add 2 buddies, sign-on complete",
			instance: newTestInstance("user_screen_name", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x03_0x04_BuddyAddBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "buddy_1_online",
					},
					{
						ScreenName: "buddy_2_offline",
					},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					addBuddyParams: addBuddyParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_1_online"),
						},
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_2_offline"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("user_screen_name"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy_1_online"),
								state.NewIdentScreenName("buddy_2_offline"),
							},
						},
					},
				},
			},
		},
		{
			name:     "add 2 buddies, sign-on not complete",
			instance: newTestInstance("user_screen_name"),
			bodyIn: wire.SNAC_0x03_0x04_BuddyAddBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "buddy_1_online",
					},
					{
						ScreenName: "buddy_2_offline",
					},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					addBuddyParams: addBuddyParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_1_online"),
						},
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_2_offline"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, params := range tt.mockParams.addBuddyParams {
				clientSideBuddyListManager.EXPECT().
					AddBuddy(matchContext(), params.me, params.them).
					Return(params.err)
			}
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(matchContext(), matchSession(params.from), params.filter, true).
					Return(params.err)
			}

			svc := BuddyService{
				clientSideBuddyListManager: clientSideBuddyListManager,
				buddyBroadcaster:           mockBuddyBroadcaster,
			}

			haveErr := svc.AddBuddies(context.Background(), tt.instance, tt.bodyIn)
			assert.ErrorIs(t, tt.wantErr, haveErr)
		})
	}
}

func TestBuddyService_DelBuddies(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// instance is the client session
		instance *state.SessionInstance
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x03_0x05_BuddyDelBuddies
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:     "delete 2 buddies",
			instance: newTestInstance("user_screen_name", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x03_0x05_BuddyDelBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "buddy_1_online",
					},
					{
						ScreenName: "buddy_2_offline",
					},
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("user_screen_name"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy_1_online"),
								state.NewIdentScreenName("buddy_2_offline"),
							},
						},
					},
				},
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					deleteBuddyParams: deleteBuddyParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_1_online"),
						},
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_2_offline"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(matchContext(), matchSession(params.from), params.filter, true).
					Return(params.err)
			}
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, params := range tt.mockParams.deleteBuddyParams {
				clientSideBuddyListManager.EXPECT().
					RemoveBuddy(matchContext(), params.me, params.them).
					Return(params.err)
			}

			svc := BuddyService{
				buddyBroadcaster:           mockBuddyBroadcaster,
				clientSideBuddyListManager: clientSideBuddyListManager,
			}

			assert.ErrorIs(t, tt.wantErr, svc.DelBuddies(context.Background(), tt.instance, tt.bodyIn))
		})
	}
}

func TestBuddyService_AddTempBuddies(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// instance is the client session
		instance *state.SessionInstance
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x03_0x0F_BuddyAddTempBuddies
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:     "add 2 buddies, sign-on complete",
			instance: newTestInstance("user_screen_name", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x03_0x0F_BuddyAddTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "buddy_1_online",
					},
					{
						ScreenName: "buddy_2_offline",
					},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					addBuddyParams: addBuddyParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_1_online"),
						},
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_2_offline"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("user_screen_name"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy_1_online"),
								state.NewIdentScreenName("buddy_2_offline"),
							},
						},
					},
				},
			},
		},
		{
			name:     "add 2 buddies, sign-on not complete",
			instance: newTestInstance("user_screen_name"),
			bodyIn: wire.SNAC_0x03_0x0F_BuddyAddTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "buddy_1_online",
					},
					{
						ScreenName: "buddy_2_offline",
					},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					addBuddyParams: addBuddyParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_1_online"),
						},
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_2_offline"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, params := range tt.mockParams.addBuddyParams {
				clientSideBuddyListManager.EXPECT().
					AddBuddy(matchContext(), params.me, params.them).
					Return(params.err)
			}
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(matchContext(), matchSession(params.from), params.filter, true).
					Return(params.err)
			}

			svc := BuddyService{
				clientSideBuddyListManager: clientSideBuddyListManager,
				buddyBroadcaster:           mockBuddyBroadcaster,
			}

			haveErr := svc.AddTempBuddies(context.Background(), tt.instance, tt.bodyIn)
			assert.ErrorIs(t, tt.wantErr, haveErr)
		})
	}
}

func TestBuddyService_DelTempBuddies(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// instance is the client session
		instance *state.SessionInstance
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x03_0x10_BuddyDelTempBuddies
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:     "delete 2 buddies",
			instance: newTestInstance("user_screen_name", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x03_0x10_BuddyDelTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "buddy_1_online",
					},
					{
						ScreenName: "buddy_2_offline",
					},
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("user_screen_name"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("buddy_1_online"),
								state.NewIdentScreenName("buddy_2_offline"),
							},
						},
					},
				},
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					deleteBuddyParams: deleteBuddyParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_1_online"),
						},
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("buddy_2_offline"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(matchContext(), matchSession(params.from), params.filter, true).
					Return(params.err)
			}
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, params := range tt.mockParams.deleteBuddyParams {
				clientSideBuddyListManager.EXPECT().
					RemoveBuddy(matchContext(), params.me, params.them).
					Return(params.err)
			}

			svc := BuddyService{
				buddyBroadcaster:           mockBuddyBroadcaster,
				clientSideBuddyListManager: clientSideBuddyListManager,
			}

			assert.ErrorIs(t, tt.wantErr, svc.DelTempBuddies(context.Background(), tt.instance, tt.bodyIn))
		})
	}
}

func TestBuddyNotifier_BroadcastBuddyArrived(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// screenName is the user screen name
		screenName state.IdentScreenName
		// userInfo is the user info passed to BroadcastBuddyArrived
		userInfo wire.TLVUserInfo
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:       "happy path",
			screenName: state.NewIdentScreenName("me"),
			userInfo:   wire.TLVUserInfo{ScreenName: "me"},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					allRelationshipsParams: allRelationshipsParams{
						{
							screenName: state.NewIdentScreenName("me"),
							filter:     nil,
							result: []state.Relationship{
								{
									User:          state.NewIdentScreenName("friend1-visible"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend2-visible"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend3-you-block"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend4-blocks-you"),
									BlocksYou:     true,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend5-not-on-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: false,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNamesParams: relayToScreenNamesParams{
						{
							screenNames: []state.IdentScreenName{
								state.NewIdentScreenName("friend1-visible"),
								state.NewIdentScreenName("friend2-visible"),
							},
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Buddy,
									SubGroup:  wire.BuddyArrived,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x03_0x0B_BuddyArrived{
									TLVUserInfo: wire.TLVUserInfo{ScreenName: "me"},
								},
							},
						},
					},
				},
			},
		},
		{
			name:       "user invisible, don't send notification",
			screenName: state.NewIdentScreenName("me"),
			userInfo: wire.TLVUserInfo{
				ScreenName: "me",
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoStatus, wire.OServiceUserStatusInvisible),
					},
				},
			},
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					allRelationshipsParams: allRelationshipsParams{}, // don't look up relationships
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNamesParams: relayToScreenNamesParams{}, // don't send notification
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, params := range tc.mockParams.allRelationshipsParams {
				relationshipFetcher.EXPECT().
					AllRelationships(matchContext(), params.screenName, params.filter).
					Return(params.result, params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tc.mockParams.relayToScreenNamesParams {
				messageRelayer.EXPECT().
					RelayToScreenNames(matchContext(), params.screenNames, params.message)
			}

			svc := buddyNotifier{
				relationshipFetcher: relationshipFetcher,
				messageRelayer:      messageRelayer,
			}

			err := svc.BroadcastBuddyArrived(context.Background(), tc.screenName, tc.userInfo)
			assert.NoError(t, err)
		})
	}
}

func TestBuddyService_BroadcastDeparture(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user
		instance *state.SessionInstance
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "happy path",
			instance: newTestInstance("me"),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					allRelationshipsParams: allRelationshipsParams{
						{
							screenName: state.NewIdentScreenName("me"),
							filter:     nil,
							result: []state.Relationship{
								{
									User:          state.NewIdentScreenName("friend1-visible"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend2-visible"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend3-you-block"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend4-blocks-you"),
									BlocksYou:     true,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend5-not-on-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: false,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNamesParams: relayToScreenNamesParams{
						{
							screenNames: []state.IdentScreenName{
								state.NewIdentScreenName("friend1-visible"),
								state.NewIdentScreenName("friend2-visible"),
							},
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Buddy,
									SubGroup:  wire.BuddyDeparted,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
									TLVUserInfo: wire.TLVUserInfo{
										ScreenName:   "me",
										WarningLevel: 0,
										TLVBlock: wire.TLVBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0)),
											},
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
			for _, params := range tc.mockParams.allRelationshipsParams {
				relationshipFetcher.EXPECT().
					AllRelationships(matchContext(), params.screenName, params.filter).
					Return(params.result, params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tc.mockParams.relayToScreenNamesParams {
				messageRelayer.EXPECT().
					RelayToScreenNames(matchContext(), params.screenNames, params.message)
			}
			svc := buddyNotifier{
				relationshipFetcher: relationshipFetcher,
				messageRelayer:      messageRelayer,
			}

			err := svc.BroadcastBuddyDeparted(context.Background(), tc.instance)
			assert.NoError(t, err)
		})
	}
}

func Test_buddyNotifier_BroadcastVisibility(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user
		instance *state.SessionInstance
		// filter limits specific users that can be notified
		filter []state.IdentScreenName
		// doSendDepartures indicates whether departure messages should be sent
		doSendDepartures bool
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "happy path",
			instance: newTestInstance("me"),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					allRelationshipsParams: allRelationshipsParams{
						{
							screenName: state.NewIdentScreenName("me"),
							filter:     nil,
							result: []state.Relationship{
								{
									User:          state.NewIdentScreenName("friend1-blocks-you"),
									BlocksYou:     true,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend2-visible-on-their-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  false,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend3-visible-on-your-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: false,
								},
								{
									User:          state.NewIdentScreenName("friend4-visible-on-both-lists"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend5-blocked-on-their-list"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  false,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend6-blocked-on-your-list"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  true,
									IsOnTheirList: false,
								},
								{
									User:          state.NewIdentScreenName("friend7-blocked-on-both-lists"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend7-visible-offline"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("friend2-visible-on-their-list"),
							message:    newBuddyArrivedNotif("me"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyArrivedNotif("friend3-visible-on-your-list"),
						},
						{
							screenName: state.NewIdentScreenName("friend4-visible-on-both-lists"),
							message:    newBuddyArrivedNotif("me"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyArrivedNotif("friend4-visible-on-both-lists"),
						},
						{
							screenName: state.NewIdentScreenName("friend5-blocked-on-their-list"),
							message:    newBuddyDepartedNotif("me"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyDepartedNotif("friend6-blocked-on-your-list"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyDepartedNotif("friend7-blocked-on-both-lists"),
						},
						{
							screenName: state.NewIdentScreenName("friend7-blocked-on-both-lists"),
							message:    newBuddyDepartedNotif("me"),
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("friend2-visible-on-their-list"),
							result:     newTestInstance("friend2-visible-on-their-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend3-visible-on-your-list"),
							result:     newTestInstance("friend3-visible-on-your-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend4-visible-on-both-lists"),
							result:     newTestInstance("friend4-visible-on-both-lists").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend5-blocked-on-their-list"),
							result:     newTestInstance("friend5-blocked-on-their-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend6-blocked-on-your-list"),
							result:     newTestInstance("friend6-blocked-on-your-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend7-blocked-on-both-lists"),
							result:     newTestInstance("friend7-blocked-on-both-lists").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend7-visible-offline"),
							result:     nil,
						},
					},
				},
			},
			doSendDepartures: true,
		},
		{
			name:     "user invisible, don't send notification to buddies",
			instance: newTestInstance("me", sessOptInvisible),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					allRelationshipsParams: allRelationshipsParams{
						{
							screenName: state.NewIdentScreenName("me"),
							filter:     nil,
							result: []state.Relationship{
								{
									User:          state.NewIdentScreenName("friend1-blocks-you"),
									BlocksYou:     true,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend2-visible-on-their-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  false,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend3-visible-on-your-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: false,
								},
								{
									User:          state.NewIdentScreenName("friend4-visible-on-both-lists"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend5-blocked-on-their-list"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  false,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend6-blocked-on-your-list"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  true,
									IsOnTheirList: false,
								},
								{
									User:          state.NewIdentScreenName("friend7-blocked-on-both-lists"),
									BlocksYou:     false,
									YouBlock:      true,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend7-visible-offline"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyArrivedNotif("friend3-visible-on-your-list"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyArrivedNotif("friend4-visible-on-both-lists"),
						},
						{
							screenName: state.NewIdentScreenName("friend5-blocked-on-their-list"),
							message:    newBuddyDepartedNotif("me"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyDepartedNotif("friend6-blocked-on-your-list"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyDepartedNotif("friend7-blocked-on-both-lists"),
						},
						{
							screenName: state.NewIdentScreenName("friend7-blocked-on-both-lists"),
							message:    newBuddyDepartedNotif("me"),
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("friend2-visible-on-their-list"),
							result:     newTestInstance("friend2-visible-on-their-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend3-visible-on-your-list"),
							result:     newTestInstance("friend3-visible-on-your-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend4-visible-on-both-lists"),
							result:     newTestInstance("friend4-visible-on-both-lists").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend5-blocked-on-their-list"),
							result:     newTestInstance("friend5-blocked-on-their-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend6-blocked-on-your-list"),
							result:     newTestInstance("friend6-blocked-on-your-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend7-blocked-on-both-lists"),
							result:     newTestInstance("friend7-blocked-on-both-lists").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend7-visible-offline"),
							result:     nil,
						},
					},
				},
			},
			doSendDepartures: true,
		},
		{
			name:     "don't send departure notifications",
			instance: newTestInstance("me"),
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					allRelationshipsParams: allRelationshipsParams{
						{
							screenName: state.NewIdentScreenName("me"),
							filter:     nil,
							result: []state.Relationship{
								{
									User:          state.NewIdentScreenName("friend2-visible-on-their-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  false,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend3-visible-on-your-list"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: false,
								},
								{
									User:          state.NewIdentScreenName("friend4-visible-on-both-lists"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
								{
									User:          state.NewIdentScreenName("friend7-visible-offline"),
									BlocksYou:     false,
									YouBlock:      false,
									IsOnYourList:  true,
									IsOnTheirList: true,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("friend2-visible-on-their-list"),
							message:    newBuddyArrivedNotif("me"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyArrivedNotif("friend3-visible-on-your-list"),
						},
						{
							screenName: state.NewIdentScreenName("friend4-visible-on-both-lists"),
							message:    newBuddyArrivedNotif("me"),
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message:    newBuddyArrivedNotif("friend4-visible-on-both-lists"),
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("friend2-visible-on-their-list"),
							result:     newTestInstance("friend2-visible-on-their-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend3-visible-on-your-list"),
							result:     newTestInstance("friend3-visible-on-your-list").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend4-visible-on-both-lists"),
							result:     newTestInstance("friend4-visible-on-both-lists").Session(),
						},
						{
							screenName: state.NewIdentScreenName("friend7-visible-offline"),
							result:     nil,
						},
					},
				},
			},
			doSendDepartures: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, params := range tc.mockParams.allRelationshipsParams {
				relationshipFetcher.EXPECT().
					AllRelationships(matchContext(), params.screenName, params.filter).
					Return(params.result, params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tc.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(matchContext(), params.screenName, mock.MatchedBy(func(message wire.SNACMessage) bool {
						return params.message.Frame == message.Frame &&
							params.message.Body.(func(any) bool)(message.Body)
					}))
			}
			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tc.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName).
					Return(params.result)
			}

			svc := buddyNotifier{
				relationshipFetcher: relationshipFetcher,
				messageRelayer:      messageRelayer,
				sessionRetriever:    sessionRetriever,
			}

			err := svc.BroadcastVisibility(context.Background(), tc.instance, tc.filter, tc.doSendDepartures)
			assert.NoError(t, err)
		})
	}
}

func newBuddyDepartedNotif(screenName state.DisplayScreenName) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyDeparted,
			RequestID: wire.ReqIDFromServer,
		},
		Body: func(val any) bool {
			snac, ok := val.(wire.SNAC_0x03_0x0C_BuddyDeparted)
			if !ok {
				return false
			}
			return snac.ScreenName == screenName.String()
		},
	}
}

func newBuddyArrivedNotif(screenName state.DisplayScreenName) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Buddy,
			SubGroup:  wire.BuddyArrived,
			RequestID: wire.ReqIDFromServer,
		},
		Body: func(val any) bool {
			snac, ok := val.(wire.SNAC_0x03_0x0B_BuddyArrived)
			if !ok {
				return false
			}
			return snac.ScreenName == screenName.String() && len(snac.TLVUserInfo.TLVList) > 0
		},
	}
}
