package webapi

import (
	"context"
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
		name string
		fb   []wire.FeedbagItem
		want []BuddyGroup
	}{
		{
			name: "root group only yields no groups",
			fb: []wire.FeedbagItem{
				{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, TLVLBlock: wire.TLVLBlock{}},
			},
			want: []BuddyGroup{},
		},
		{
			name: "empty buddylist yields no groups",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
			},
			want: []BuddyGroup{},
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
			want: []BuddyGroup{},
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
		{
			name: "group without order attribute lists buddies in feedbag order",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
				{ItemID: 9, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "user9"},
				{ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "user3"},
			},
			want: []BuddyGroup{
				{
					Name: "Buddies",
					ID:   100,
					Buddies: []BuddyInfo{
						offlineWebAPIBuddy("user9", "user9"),
						offlineWebAPIBuddy("user3", "user3"),
					},
				},
			},
		},
		{
			name: "buddy missing from group order follows listed buddies",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "unlisted"},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "listed"},
			},
			want: []BuddyGroup{
				{
					Name: "Buddies",
					ID:   100,
					Buddies: []BuddyInfo{
						offlineWebAPIBuddy("listed", "listed"),
						offlineWebAPIBuddy("unlisted", "unlisted"),
					},
				},
			},
		},
		{
			name: "group missing from root order follows listed groups",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{200})}},
				},
				{Name: "Unlisted", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
				{Name: "Listed", GroupID: 200, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
			},
			want: []BuddyGroup{
				{Name: "Listed", ID: 200, Buddies: []BuddyInfo{}},
				{Name: "Unlisted", ID: 100, Buddies: []BuddyInfo{}},
			},
		},
		{
			name: "groups follow feedbag position when root group has no order attribute",
			fb: []wire.FeedbagItem{
				{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
				{Name: "Family", GroupID: 200, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
				{Name: "Friends", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup},
			},
			want: []BuddyGroup{
				{Name: "Family", ID: 200, Buddies: []BuddyInfo{}},
				{Name: "Friends", ID: 100, Buddies: []BuddyInfo{}},
			},
		},
		{
			name: "orphan buddy with root order is left out",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "user1"},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 300, Name: "orphan"},
			},
			want: []BuddyGroup{
				{
					Name:    "Buddies",
					ID:      100,
					Buddies: []BuddyInfo{offlineWebAPIBuddy("user1", "user1")},
				},
			},
		},
		{
			name: "orphan buddy without root order is left out",
			fb: []wire.FeedbagItem{
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 300, Name: "orphan"},
			},
			want: []BuddyGroup{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No buddy arrives, so every buddy resolves to offline, keeping the
			// focus on feedbag -> group conversion.
			m := NewBuddyListManager(newTestIconSource(t), slog.Default())
			sess := &Session{
				ScreenName: state.DisplayScreenName(owner.String()),
				logger:     slog.Default(),
			}
			sess.feedbag.Reset(tt.fb)
			assert.Equal(t, tt.want, m.GetBuddyListForUser(ctx, sess))
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

	m := NewBuddyListManager(newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName: state.DisplayScreenName("listowner"),
		logger:     slog.Default(),
	}
	sess.feedbag.Reset(fb)
	buddyArrives(sess, onlineBuddy("Mike Kelly"))

	got := m.GetBuddyListForUser(ctx, sess)
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

	m := NewBuddyListManager(newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName: state.DisplayScreenName("listowner"),
		BaseURL:    "http://api.example.com",
		logger:     slog.Default(),
	}
	sess.feedbag.Reset(fb)
	buddyArrives(sess, bartBuddy("Mike Kelly", testIconBART, testStatusBART))
	buddyDeparts(sess, "Mike Kelly")

	got := m.GetBuddyListForUser(ctx, sess)
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

	iconRetriever := newMockBuddyIconRetriever(t)

	m := NewBuddyListManager(BuddyIconSource{
		IconRetriever: iconRetriever,
		Logger:        slog.Default(),
	}, slog.Default())

	sess := &Session{
		ScreenName: state.DisplayScreenName("listowner"),
		BaseURL:    "http://api.example.com",
		logger:     slog.Default(),
	}
	sess.feedbag.Reset(fb)
	buddyArrives(sess, bartBuddy("onlineicon", wire.BARTID{
		Type:     wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{Hash: []byte{0xab, 0xcd}},
	}))
	buddyArrives(sess, onlineBuddy("onlinenoicon"))

	got := m.GetBuddyListForUser(ctx, sess)
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

	m := NewBuddyListManager(newTestIconSource(t), slog.Default())
	sess := &Session{
		ScreenName: state.DisplayScreenName("listowner"),
		BaseURL:    "http://api.example.com",
		logger:     slog.Default(),
	}
	sess.feedbag.Reset(fb)
	buddyArrives(sess, bartBuddy("hasstatus", testStatusBART))
	buddyArrives(sess, onlineBuddy("nostatus"))

	got := m.GetBuddyListForUser(ctx, sess)
	require.Len(t, got, 1)
	require.Len(t, got[0].Buddies, 2)

	assert.Equal(t, "brb", got[0].Buddies[0].StatusMsg)
	assert.Empty(t, got[0].Buddies[1].StatusMsg)
}

// The roster is rebuilt on every feedbag change, so only an unavailable buddy may
// cost a locate query.
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

	conn := newFakeConn().answering(locateReplies(map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply{
		"awaybud": {
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "awaybud"},
			LocateInfo: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "out to lunch"),
			}},
		},
	}))

	m := NewBuddyListManager(newTestIconSource(t), slog.Default())
	sess := newTestSession(t, conn)
	sess.feedbag.Reset(fb)

	away := wire.TLVUserInfo{ScreenName: "awaybud"}
	away.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))

	buddyArrives(sess, onlineBuddy("onlinebud"))
	buddyArrives(sess, away)

	got := m.GetBuddyListForUser(ctx, sess)
	require.Len(t, got[0].Buddies, 3)

	assert.Equal(t, "online", got[0].Buddies[0].State)
	assert.Equal(t, "away", got[0].Buddies[1].State)
	// The away message is the one field a presence broadcast cannot carry.
	assert.Equal(t, "out to lunch", got[0].Buddies[1].AwayMsg)
	// A buddy no arrival has been relayed for renders offline rather than
	// triggering a lookup.
	assert.Equal(t, "offline", got[0].Buddies[2].State)
	// Only the away buddy earns a query.
	assert.Equal(t, []any{wire.SNAC_0x02_0x05_LocateUserInfoQuery{
		Type:       uint16(wire.LocateTypeUnavailable),
		ScreenName: "awaybud",
	}}, conn.sentOf(wire.Locate, wire.LocateUserInfoQuery))
}

// rosterFeedbag is a feedbag with a Buddies group holding mikekelly, aliased
// alias when alias isn't empty.
func rosterFeedbag(alias string) []wire.FeedbagItem {
	buddy := wire.FeedbagItem{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"}
	if alias != "" {
		buddy.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, alias)}}
	}
	return []wire.FeedbagItem{
		{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
		buddy,
	}
}

// The feedbag service relays a session's own writes only to the owner's other
// instances, so renaming a buddy from the web client produces no SNAC for that
// session. The confirmed change has to reach its aliases anyway, or the next
// presence or IM event would rename the buddy back.
func TestBuddyListManager_SetBuddyAttributeInFeedbag_UpdatesAliases(t *testing.T) {
	ctx := context.Background()

	server := newFeedbagServer(rosterFeedbag("MICHAELKELLY")...)
	sess, conn := newFeedbagSession(t, server)
	m := NewBuddyListManager(newTestIconSource(t), slog.Default())

	require.Equal(t, "MICHAELKELLY", sess.Aliases()["mikekelly"])

	resultCode, err := m.SetBuddyAttributeInFeedbag(ctx, sess, "mikekelly", "MIKE")
	require.NoError(t, err)
	require.Equal(t, "success", resultCode)

	assert.Equal(t, "MIKE", sess.Aliases()["mikekelly"])
	assert.Equal(t, server.stored(), sess.Feedbag())
	// The change is diffed against the mirror, not a fresh read.
	assert.Len(t, conn.sentOf(wire.Feedbag, wire.FeedbagQuery), 1, "only the load queries the feedbag")
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
		name       string
		fb         []wire.FeedbagItem
		group      string
		allGroups  bool
		wantForgot bool
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
			server := newFeedbagServer(tt.fb...)
			sess, conn := newFeedbagSession(t, server)
			m := NewBuddyListManager(newTestIconSource(t), slog.Default())
			buddyArrives(sess, onlineBuddy("Mike Kelly"))

			resultCode, err := m.RemoveBuddyFromFeedbag(ctx, sess, "mikekelly", tt.group, tt.allGroups)
			require.NoError(t, err)
			require.Equal(t, "success", resultCode)

			_, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
			assert.Equal(t, !tt.wantForgot, ok)
			assert.Len(t, conn.sentOf(wire.Feedbag, wire.FeedbagDeleteItem), 1)
			assert.Equal(t, server.stored(), sess.Feedbag())
		})
	}
}

// Deleting a group deletes the buddies in it.
func TestBuddyListManager_RemoveGroupFromFeedbag_ForgetsPresence(t *testing.T) {
	ctx := context.Background()

	server := newFeedbagServer(rosterFeedbag("")...)
	sess, _ := newFeedbagSession(t, server)
	m := NewBuddyListManager(newTestIconSource(t), slog.Default())
	buddyArrives(sess, onlineBuddy("Mike Kelly"))

	resultCode, err := m.RemoveGroupFromFeedbag(ctx, sess, "Buddies")
	require.NoError(t, err)
	require.Equal(t, "success", resultCode)

	_, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
	assert.False(t, ok)
	assert.Equal(t, server.stored(), sess.Feedbag())
}

// Each edit sends the exact changes it computes from the mirror, one at a time.
func TestBuddyListManager_EditsSendExactChanges(t *testing.T) {
	ctx := context.Background()
	buddiesGroup := func(order ...uint16) wire.FeedbagItem {
		return wire.FeedbagItem{Name: "Buddies", GroupID: 100, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, order)}}}
	}
	root := func(order ...uint16) wire.FeedbagItem {
		return wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, order)}}}
	}
	buddy := wire.FeedbagItem{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"}
	aliased := buddy
	aliased.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, "MIKE")}}
	renamed := buddiesGroup(1)
	renamed.Name = "Friends"

	tests := []struct {
		name string
		edit func(m *BuddyListManager, sess *Session) (string, error)
		want []feedbagChangeSent
	}{
		{
			name: "remove buddy",
			edit: func(m *BuddyListManager, sess *Session) (string, error) {
				return m.RemoveBuddyFromFeedbag(ctx, sess, "mikekelly", "Buddies", false)
			},
			want: []feedbagChangeSent{
				{wire.FeedbagDeleteItem, []wire.FeedbagItem{buddy}},
				{wire.FeedbagUpdateItem, []wire.FeedbagItem{buddiesGroup()}},
			},
		},
		{
			name: "remove group",
			edit: func(m *BuddyListManager, sess *Session) (string, error) {
				return m.RemoveGroupFromFeedbag(ctx, sess, "Buddies")
			},
			want: []feedbagChangeSent{
				{wire.FeedbagDeleteItem, []wire.FeedbagItem{buddiesGroup(1), buddy}},
				{wire.FeedbagUpdateItem, []wire.FeedbagItem{root()}},
			},
		},
		{
			name: "rename group",
			edit: func(m *BuddyListManager, sess *Session) (string, error) {
				return m.RenameGroupInFeedbag(ctx, sess, "Buddies", "Friends")
			},
			want: []feedbagChangeSent{
				{wire.FeedbagUpdateItem, []wire.FeedbagItem{renamed}},
			},
		},
		{
			name: "set alias",
			edit: func(m *BuddyListManager, sess *Session) (string, error) {
				return m.SetBuddyAttributeInFeedbag(ctx, sess, "mikekelly", "MIKE")
			},
			want: []feedbagChangeSent{
				{wire.FeedbagUpdateItem, []wire.FeedbagItem{aliased}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFeedbagServer(root(100), buddiesGroup(1), buddy)
			sess, conn := newFeedbagSession(t, server)
			m := NewBuddyListManager(newTestIconSource(t), slog.Default())

			resultCode, err := tt.edit(m, sess)
			require.NoError(t, err)
			require.Equal(t, "success", resultCode)

			assert.Equal(t, tt.want, sentFeedbagChanges(conn))
			assert.Equal(t, server.stored(), sess.Feedbag())
		})
	}
}
