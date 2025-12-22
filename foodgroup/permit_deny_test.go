package foodgroup

import (
	"context"
	"testing"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestPermitDenyService_RightsQuery(t *testing.T) {
	svc := NewPermitDenyService(nil, nil, nil, nil, nil)

	have := svc.RightsQuery(nil, wire.SNACFrame{RequestID: 1234})
	want := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.PermitDeny,
			SubGroup:  wire.PermitDenyRightsReply,
			RequestID: 1234,
		},
		Body: wire.SNAC_0x09_0x03_PermitDenyRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.PermitDenyTLVMaxDenies, uint16(100)),
					wire.NewTLVBE(wire.PermitDenyTLVMaxPermits, uint16(100)),
					wire.NewTLVBE(wire.PermitDenyTLVMaxTempPermits, uint16(100)),
				},
			},
		},
	}

	assert.Equal(t, want, have)
}

func TestPermitDenyService_AddDenyListEntries(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// sess is the client session
		sess *state.Session
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries
		// expectOutput is the expected return SNAC value
		expectOutput *wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name: "set FeedbagPDModePermitAll",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "me"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModePermitAll,
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
			},
		},
		{
			name:   "set FeedbagPDModeDenySome - 0 users",
			sess:   newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModeDenySome,
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
			},
		},
		{
			name: "set FeedbagPDModeDenySome - 1 user",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModeDenySome,
						},
					},
					denyBuddyParams: denyBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them"),
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
			},
		},
		{
			name: "set FeedbagPDModeDenySome sign on incomplete - 1 user",
			sess: newTestSession("me"),
			bodyIn: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModeDenySome,
						},
					},
					denyBuddyParams: denyBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{},
				},
			},
		},
		{
			name: "set FeedbagPDModeDenySome - 2 users",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them1"},
					{ScreenName: "them2"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModeDenySome,
						},
					},
					denyBuddyParams: denyBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them1"),
						},
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them2"),
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, item := range tt.mockParams.setPDModeParams {
				clientSideBuddyListManager.EXPECT().
					SetPDMode(matchContext(), item.userScreenName, item.pdMode).
					Return(item.err)
			}
			for _, item := range tt.mockParams.denyBuddyParams {
				clientSideBuddyListManager.EXPECT().
					DenyBuddy(matchContext(), item.me, item.them).
					Return(item.err)
			}
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, item := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(context.TODO(), matchSession(item.from), item.filter, true).
					Return(item.err)
			}

			svc := PermitDenyService{
				buddyBroadcaster:           mockBuddyBroadcaster,
				clientSideBuddyListManager: clientSideBuddyListManager,
			}
			err := svc.AddDenyListEntries(context.TODO(), tt.sess, tt.bodyIn)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func TestPermitDenyService_AddPermListEntries(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// sess is the client session
		sess *state.Session
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries
		// expectOutput is the expected return SNAC value
		expectOutput *wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name: "set FeedbagPDModeDenyAll",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "me"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModeDenyAll,
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
			},
		},
		{
			name:   "set FeedbagPDModePermitSome - 0 users",
			sess:   newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModePermitSome,
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
			},
		},
		{
			name: "set FeedbagPDModePermitSome - 1 user",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModePermitSome,
						},
					},
					permitBuddyParams: permitBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them"),
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
			},
		},
		{
			name: "set FeedbagPDModePermitSome sign on incomplete - 1 user",
			sess: newTestSession("me"),
			bodyIn: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModePermitSome,
						},
					},
					permitBuddyParams: permitBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{},
				},
			},
		},
		{
			name: "set FeedbagPDModePermitSome - 2 users",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them1"},
					{ScreenName: "them2"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					setPDModeParams: setPDModeParams{
						{
							userScreenName: state.NewIdentScreenName("me"),
							pdMode:         wire.FeedbagPDModePermitSome,
						},
					},
					permitBuddyParams: permitBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them1"),
						},
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them2"),
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, item := range tt.mockParams.setPDModeParams {
				clientSideBuddyListManager.EXPECT().
					SetPDMode(matchContext(), item.userScreenName, item.pdMode).
					Return(item.err)
			}
			for _, item := range tt.mockParams.permitBuddyParams {
				clientSideBuddyListManager.EXPECT().
					PermitBuddy(matchContext(), item.me, item.them).
					Return(item.err)
			}
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, item := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(context.TODO(), matchSession(item.from), item.filter, true).
					Return(item.err)
			}

			svc := PermitDenyService{
				buddyBroadcaster:           mockBuddyBroadcaster,
				clientSideBuddyListManager: clientSideBuddyListManager,
			}
			err := svc.AddPermListEntries(context.TODO(), tt.sess, tt.bodyIn)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func TestPermitDenyService_DelDenyListEntries(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// sess is the client session
		sess *state.Session
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries
		// expectOutput is the expected return SNAC value
		expectOutput *wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name: "remove 0 deny list entries",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{},
			},
		},
		{
			name: "sign on incomplete remove 1 deny list entries",
			sess: newTestSession("me"),
			bodyIn: wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them1"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					removeDenyBuddyParams: removeDenyBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them1"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{},
				},
			},
		},
		{
			name: "remove 2 deny list entries",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them1"},
					{ScreenName: "them2"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					removeDenyBuddyParams: removeDenyBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them1"),
						},
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them2"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("them1"),
								state.NewIdentScreenName("them2"),
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, item := range tt.mockParams.removeDenyBuddyParams {
				clientSideBuddyListManager.EXPECT().
					RemoveDenyBuddy(matchContext(), item.me, item.them).
					Return(item.err)
			}
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, item := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(context.TODO(), matchSession(item.from), item.filter, true).
					Return(item.err)
			}

			svc := PermitDenyService{
				buddyBroadcaster:           mockBuddyBroadcaster,
				clientSideBuddyListManager: clientSideBuddyListManager,
			}
			err := svc.DelDenyListEntries(context.TODO(), tt.sess, tt.bodyIn)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func TestPermitDenyService_DelPermListEntries(t *testing.T) {
	tests := []struct {
		// name is the name of the test
		name string
		// sess is the client session
		sess *state.Session
		// bodyIn is the input SNAC
		bodyIn wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries
		// expectOutput is the expected return SNAC value
		expectOutput *wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name: "remove 0 deny list entries",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{},
			},
		},
		{
			name: "sign on incomplete remove 1 deny list entries",
			sess: newTestSession("me"),
			bodyIn: wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them1"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					removePermitBuddyParams: removePermitBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them1"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{},
				},
			},
		},
		{
			name: "remove 2 deny list entries",
			sess: newTestSession("me", sessOptSignonComplete),
			bodyIn: wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "them1"},
					{ScreenName: "them2"},
				},
			},
			mockParams: mockParams{
				clientSideBuddyListManagerParams: clientSideBuddyListManagerParams{
					removePermitBuddyParams: removePermitBuddyParams{
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them1"),
						},
						{
							me:   state.NewIdentScreenName("me"),
							them: state.NewIdentScreenName("them2"),
						},
					},
				},
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from: state.NewIdentScreenName("me"),
							filter: []state.IdentScreenName{
								state.NewIdentScreenName("them1"),
								state.NewIdentScreenName("them2"),
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSideBuddyListManager := newMockClientSideBuddyListManager(t)
			for _, item := range tt.mockParams.removePermitBuddyParams {
				clientSideBuddyListManager.EXPECT().
					RemovePermitBuddy(matchContext(), item.me, item.them).
					Return(item.err)
			}
			mockBuddyBroadcaster := newMockbuddyBroadcaster(t)
			for _, item := range tt.mockParams.broadcastVisibilityParams {
				mockBuddyBroadcaster.EXPECT().
					BroadcastVisibility(context.TODO(), matchSession(item.from), item.filter, true).
					Return(item.err)
			}

			svc := PermitDenyService{
				buddyBroadcaster:           mockBuddyBroadcaster,
				clientSideBuddyListManager: clientSideBuddyListManager,
			}
			err := svc.DelPermListEntries(context.TODO(), tt.sess, tt.bodyIn)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}
