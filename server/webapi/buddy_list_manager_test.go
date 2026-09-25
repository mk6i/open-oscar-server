package webapi

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func offlineWebAPIBuddy(aimID, displayID string) BuddyInfo {
	return BuddyInfo{
		AimID:     aimID,
		DisplayID: displayID,
		State:     "offline",
		UserType:  "aim",
		Bot:       false,
	}
}

// withAlias sets the viewer's private name for a buddy. It travels in friendly, not
// displayId, which keeps carrying the buddy's own screen name.
func withAlias(b BuddyInfo, alias string) BuddyInfo {
	b.Friendly = alias
	return b
}

func TestBuddyListManager_GetBuddyListForUser(t *testing.T) {
	ctx := context.Background()
	owner := state.NewIdentScreenName("listowner")

	tests := []struct {
		name    string
		fb      []wire.FeedbagItem
		fbErr   error
		want    []BuddyGroup
		wantErr string
	}{
		{
			name:    "retrieve feedbag error",
			fbErr:   errors.New("db unavailable"),
			wantErr: "failed to retrieve feedbag",
		},
		{
			name: "root group missing order attribute yields no groups",
			fb: []wire.FeedbagItem{
				{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, TLVLBlock: wire.TLVLBlock{}},
			},
			want: nil,
		},
		{
			name: "empty buddylist yields no groups",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
			},
			want: nil,
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
			want: []BuddyGroup{
				{
					Name: "Buddies",
					ID:   100,
					Buddies: []BuddyInfo{
						offlineWebAPIBuddy("user1", "user1"),
						offlineWebAPIBuddy("user2", "user2"),
					},
				},
			},
		},
		{
			name: "deny permit and pdinfo items do not produce groups",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
				{ClassID: wire.FeedbagClassIDDeny, Name: "blockeduser"},
				{ClassID: wire.FeedbagClassIDPermit, Name: "allowuser"},
				{
					ClassID:   wire.FeedbagClassIdPdinfo,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(3))}},
				},
			},
			want: nil,
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
			want: []BuddyGroup{
				{
					Name: "Buddies",
					ID:   100,
					// The buddy is offline, so no locate reply supplies a display
					// name and displayId falls back to the normalized feedbag name.
					Buddies: []BuddyInfo{withAlias(offlineWebAPIBuddy("bob", "bob"), "Bob Smith")},
				},
			},
		},
		{
			name: "unnormalized feedbag buddy name still yields a normalized aimId",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "Mike Kelly"},
			},
			want: []BuddyGroup{
				{
					Name:    "Buddies",
					ID:      100,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("mikekelly", "Mike Kelly")},
				},
			},
		},
		{
			name: "uin buddy is tagged icq",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "100003"},
			},
			want: []BuddyGroup{
				{
					Name: "Buddies",
					ID:   100,
					Buddies: []BuddyInfo{{
						AimID:     "100003",
						DisplayID: "100003",
						State:     "offline",
						UserType:  "icq",
						Service:   "icq",
					}},
				},
			},
		},
		{
			name: "buddy with note still listed note not exposed in WebAPI",
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
			want: []BuddyGroup{
				{
					Name:    "Buddies",
					ID:      100,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("alice", "alice")},
				},
			},
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
			want: []BuddyGroup{
				{
					Name:    "Buddies",
					ID:      100,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("friend1", "friend1")},
				},
				{
					Name:    "Family",
					ID:      200,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("mom", "mom")},
				},
			},
		},
		{
			name: "buddy order follows group order TLV not feedbag slice order",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "firstInSlice", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "secondInSlice", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []BuddyGroup{
				{
					Name: "Buddies",
					ID:   100,
					Buddies: []BuddyInfo{
						offlineWebAPIBuddy("secondinslice", "secondInSlice"),
						offlineWebAPIBuddy("firstinslice", "firstInSlice"),
					},
				},
			},
		},
		{
			name: "group order follows root order TLV not feedbag slice order",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{200, 100})}},
				},
				{Name: "Family", GroupID: 200, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}}},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "inBuddies", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 200, Name: "inFamily", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []BuddyGroup{
				{
					Name:    "Family",
					ID:      200,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("infamily", "inFamily")},
				},
				{
					Name:    "Buddies",
					ID:      100,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("inbuddies", "inBuddies")},
				},
			},
		},
		{
			name: "unnamed group becomes Buddies",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "solo", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []BuddyGroup{
				{
					Name:    "Buddies",
					ID:      100,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("solo", "solo")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newMockFeedbagService(t)
			// No buddy arrives, so every buddy resolves to offline, keeping the
			// focus on feedbag -> group conversion.
			if tt.fbErr != nil {
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(wire.SNACMessage{}, tt.fbErr).Once()
			} else {
				fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
					wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: tt.fb}}, nil,
				).Once()
			}

			m := NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
			sess := &Session{
				ScreenName:   state.DisplayScreenName(owner.String()),
				OSCARSession: state.NewSession().AddInstance(),
			}
			got, err := m.GetBuddyListForUser(ctx, sess)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuddyListManager_GetBuddyListForUser_DisplayIDFromPresenceView(t *testing.T) {
	// Feedbag buddy names are stored normalized, so an online buddy's display
	// name can only come from the user info their arrival carried.
	ctx := context.Background()

	fb := []wire.FeedbagItem{
		{
			Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
		},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
		{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"},
	}

	fs := newMockFeedbagService(t)
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: fb}}, nil,
	).Once()

	m := NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
		logger:       slog.Default(),
	}
	buddyArrives(sess, onlineBuddy("Mike Kelly"))

	got, err := m.GetBuddyListForUser(ctx, sess)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Buddies, 1)

	assert.Equal(t, "mikekelly", got[0].Buddies[0].AimID)
	assert.Equal(t, "Mike Kelly", got[0].Buddies[0].DisplayID)
	assert.Equal(t, "online", got[0].Buddies[0].State)
}

// A departure keeps the display name the buddy last arrived with, rather than
// falling back to the normalized feedbag name.
func TestBuddyListManager_GetBuddyListForUser_DepartureKeepsDisplayID(t *testing.T) {
	ctx := context.Background()

	fb := []wire.FeedbagItem{
		{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
		{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"},
	}

	fs := newMockFeedbagService(t)
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: fb}}, nil,
	).Once()

	m := NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
		BaseURL:      "http://api.example.com",
		logger:       slog.Default(),
	}
	buddyArrives(sess, bartBuddy("Mike Kelly", testIconBART, testStatusBART))
	buddyDeparts(sess, "Mike Kelly")

	got, err := m.GetBuddyListForUser(ctx, sess)
	require.NoError(t, err)
	require.Len(t, got[0].Buddies, 1)

	buddy := got[0].Buddies[0]
	assert.Equal(t, "offline", buddy.State)
	assert.Equal(t, "Mike Kelly", buddy.DisplayID)
	// An offline buddy publishes neither their icon nor their status message.
	assert.Empty(t, buddy.BuddyIcon)
	assert.Empty(t, buddy.StatusMsg)
}

// Icons are published only for online buddies: one with an icon gets a
// content-addressed URL, one without gets the placeholder URL, and an offline
// buddy gets none, so neither their icon nor its hash leaks. The hash rides in on
// the arrival, so no metadata lookup happens.
func TestBuddyListManager_GetBuddyListForUser_PublishesBuddyIcons(t *testing.T) {
	ctx := context.Background()

	fb := []wire.FeedbagItem{
		{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2, 3})}}},
		{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "onlineicon"},
		{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "offlinebud"},
		{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "onlinenoicon"},
	}

	fs := newMockFeedbagService(t)
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: fb}}, nil,
	).Once()

	iconRetriever := newMockBuddyIconRetriever(t)

	m := NewBuddyListManager(fs, newMockLocateService(t), BuddyIconSource{
		IconRetriever: iconRetriever,
		Logger:        slog.Default(),
	}, slog.Default())

	sess := &Session{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
		BaseURL:      "http://api.example.com",
		logger:       slog.Default(),
	}
	buddyArrives(sess, bartBuddy("onlineicon", wire.BARTID{
		Type:     wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{Hash: []byte{0xab, 0xcd}},
	}))
	buddyArrives(sess, onlineBuddy("onlinenoicon"))

	got, err := m.GetBuddyListForUser(ctx, sess)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Buddies, 3)

	// onlineicon: content-addressed URL carrying the icon hash.
	assert.Equal(t, "online", got[0].Buddies[0].State)
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=onlineicon&type=buddyIcon&bartId=abcd",
		got[0].Buddies[0].BuddyIcon)

	// offlinebud: never arrived, so no icon.
	assert.Equal(t, "offline", got[0].Buddies[1].State)
	assert.Empty(t, got[0].Buddies[1].BuddyIcon)

	// onlinenoicon: hash-less placeholder URL so a cleared icon still propagates.
	assert.Equal(t, "online", got[0].Buddies[2].State)
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=onlinenoicon&type=buddyIcon",
		got[0].Buddies[2].BuddyIcon)

	// The arrivals carried every hash, so the roster costs no metadata lookups.
	iconRetriever.AssertNotCalled(t, "BuddyIconMetadata", mock.Anything, mock.Anything)
}

// The roster is where a client first reads a buddy's status message.
func TestBuddyListManager_GetBuddyListForUser_PublishesStatusMessages(t *testing.T) {
	ctx := context.Background()

	fb := []wire.FeedbagItem{
		{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}}},
		{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "hasstatus"},
		{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "nostatus"},
	}

	fs := newMockFeedbagService(t)
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: fb}}, nil,
	).Once()

	m := NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
		BaseURL:      "http://api.example.com",
		logger:       slog.Default(),
	}
	buddyArrives(sess, bartBuddy("hasstatus", testStatusBART))
	buddyArrives(sess, onlineBuddy("nostatus"))

	got, err := m.GetBuddyListForUser(ctx, sess)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Buddies, 2)

	assert.Equal(t, "brb", got[0].Buddies[0].StatusMsg)
	assert.Empty(t, got[0].Buddies[1].StatusMsg)
}

// The roster is rebuilt on every feedbag change, so only an unavailable buddy may
// cost a locate query. Mockery fails the test on any other call.
func TestBuddyListManager_GetBuddyListForUser_QueriesOnlyAwayBuddies(t *testing.T) {
	ctx := context.Background()

	fb := []wire.FeedbagItem{
		{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2, 3})}}},
		{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "onlinebud"},
		{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "awaybud"},
		{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "neverseen"},
	}

	fs := newMockFeedbagService(t)
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: fb}}, nil,
	).Once()

	ls := newMockLocateService(t)
	// Only the away buddy earns a query.
	ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything,
		mock.MatchedBy(func(q wire.SNAC_0x02_0x05_LocateUserInfoQuery) bool {
			return q.ScreenName == "awaybud"
		})).
		Return(wire.SNACMessage{Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "awaybud"},
			LocateInfo: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "out to lunch"),
			}},
		}}, nil).Once()

	m := NewBuddyListManager(fs, ls, newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
		logger:       slog.Default(),
	}

	away := wire.TLVUserInfo{ScreenName: "awaybud"}
	away.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))

	buddyArrives(sess, onlineBuddy("onlinebud"))
	buddyArrives(sess, away)

	got, err := m.GetBuddyListForUser(ctx, sess)
	require.NoError(t, err)
	require.Len(t, got[0].Buddies, 3)

	assert.Equal(t, "online", got[0].Buddies[0].State)
	assert.Equal(t, "away", got[0].Buddies[1].State)
	// The away message is the one field a presence broadcast cannot carry.
	assert.Equal(t, "out to lunch", got[0].Buddies[1].AwayMsg)
	// A buddy no arrival has been relayed for renders offline rather than
	// triggering a lookup.
	assert.Equal(t, "offline", got[0].Buddies[2].State)
}

// The feedbag service relays a session's own writes only to the owner's other
// instances, so renaming a buddy from the web client produces no SNAC for that
// session. Without an explicit invalidation, its cached aliases would keep serving
// the old name and the next presence or IM event would rename the buddy back.
func TestBuddyListManager_SetBuddyAttributeInFeedbag_InvalidatesAliasCache(t *testing.T) {
	ctx := context.Background()

	feedbag := func(alias string) []wire.FeedbagItem {
		buddy := wire.FeedbagItem{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"}
		buddy.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, alias)}}
		return []wire.FeedbagItem{
			{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
			{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
			buddy,
		}
	}

	fs := newMockFeedbagService(t)
	// Query 1: the alias cache loads. Query 2: SetBuddyAttributeInFeedbag reads the
	// feedbag it is about to rewrite. Query 3: the cache reloads post-invalidation,
	// now seeing the stored rename.
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: feedbag("MICHAELKELLY")}}, nil).Twice()
	fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&wire.SNACMessage{}, nil).Once()
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: feedbag("MIKE")}}, nil).Once()

	m := NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
	}
	sess.BuddyAliasLoader = func(ctx context.Context) (map[string]string, error) {
		return LookupBuddyAliases(ctx, fs, sess.OSCARSession)
	}

	require.Equal(t, "MICHAELKELLY", sess.Aliases(ctx)["mikekelly"])

	resultCode, err := m.SetBuddyAttributeInFeedbag(ctx, sess, "mikekelly", "MIKE")
	require.NoError(t, err)
	require.Equal(t, "success", resultCode)

	assert.Equal(t, "MIKE", sess.Aliases(ctx)["mikekelly"])
}

func TestFeedbagGroupMatchesRequested(t *testing.T) {
	assert.True(t, feedbagGroupMatchesRequested("Buddies", "Buddies"))
	assert.True(t, feedbagGroupMatchesRequested("", "Buddies"))
	assert.True(t, feedbagGroupMatchesRequested("  ", "Buddies"))
	assert.True(t, feedbagGroupMatchesRequested("Friends", "friends"))
	assert.False(t, feedbagGroupMatchesRequested("", "Friends"))
}

func TestStoredGroupNameForRequest(t *testing.T) {
	items := []wire.FeedbagItem{
		{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "", GroupID: 1},
		{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "jon", GroupID: 1},
	}
	st, ok := storedGroupNameForRequest(items, "Buddies")
	assert.True(t, ok)
	assert.Equal(t, "", st)

	items2 := []wire.FeedbagItem{
		{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 2},
	}
	st2, ok2 := storedGroupNameForRequest(items2, "Friends")
	assert.True(t, ok2)
	assert.Equal(t, "Friends", st2)
}

// Removing a buddy stops any further presence SNAC for them, so their cached
// presence is dropped. A buddy listed in more than one group is still watched
// after leaving one of them, and keeps their entry.
func TestBuddyListManager_RemoveBuddyFromFeedbag_ForgetsPresence(t *testing.T) {
	ctx := context.Background()

	// feedbag places mikekelly in every group named.
	feedbag := func(groups ...string) []wire.FeedbagItem {
		items := []wire.FeedbagItem{
			{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100, 200})}}},
		}
		for i, group := range groups {
			gid := uint16(100 * (i + 1))
			itemID := uint16(i + 1)
			items = append(items,
				wire.FeedbagItem{Name: group, GroupID: gid, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{itemID})}}},
				wire.FeedbagItem{ItemID: itemID, ClassID: wire.FeedbagClassIdBuddy, GroupID: gid, Name: "mikekelly"},
			)
		}
		return items
	}

	tests := []struct {
		name        string
		fb          []wire.FeedbagItem
		group       string
		allGroups   bool
		wantForgot  bool
		description string
	}{
		{
			name:       "sole listing forgets the buddy",
			fb:         feedbag("Buddies"),
			group:      "Buddies",
			wantForgot: true,
		},
		{
			name:       "removing from all groups forgets the buddy",
			fb:         feedbag("Buddies", "Work"),
			allGroups:  true,
			wantForgot: true,
		},
		{
			// Still on the list via the other group, so still watched.
			name:       "removal from one of two groups keeps the buddy",
			fb:         feedbag("Buddies", "Work"),
			group:      "Buddies",
			wantForgot: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newMockFeedbagService(t)
			fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
				wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: tt.fb}}, nil,
			).Maybe()
			fs.EXPECT().DeleteItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(&wire.SNACMessage{}, nil).Once()
			fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(&wire.SNACMessage{}, nil).Maybe()

			m := NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
			sess := &Session{
				ScreenName:   state.DisplayScreenName("listowner"),
				OSCARSession: state.NewSession().AddInstance(),
				logger:       slog.Default(),
			}
			buddyArrives(sess, onlineBuddy("Mike Kelly"))

			resultCode, err := m.RemoveBuddyFromFeedbag(ctx, sess, "mikekelly", tt.group, tt.allGroups)
			require.NoError(t, err)
			require.Equal(t, "success", resultCode)

			_, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
			assert.Equal(t, !tt.wantForgot, ok)
		})
	}
}

// Deleting a group deletes the buddies in it.
func TestBuddyListManager_RemoveGroupFromFeedbag_ForgetsPresence(t *testing.T) {
	ctx := context.Background()

	fb := []wire.FeedbagItem{
		{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
		{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"},
	}

	fs := newMockFeedbagService(t)
	fs.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: fb}}, nil,
	).Maybe()
	fs.EXPECT().DeleteItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&wire.SNACMessage{}, nil).Once()
	fs.EXPECT().UpsertItem(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&wire.SNACMessage{}, nil).Maybe()

	m := NewBuddyListManager(fs, newMockLocateService(t), newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
		logger:       slog.Default(),
	}
	buddyArrives(sess, onlineBuddy("Mike Kelly"))

	resultCode, err := m.RemoveGroupFromFeedbag(ctx, sess, "Buddies")
	require.NoError(t, err)
	require.Equal(t, "success", resultCode)

	_, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
	assert.False(t, ok)
}
