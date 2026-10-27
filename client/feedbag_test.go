package client

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func groupItem(name string, groupID uint16, order ...uint16) wire.FeedbagItem {
	item := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, Name: name, GroupID: groupID}
	if len(order) > 0 {
		item.AppendOrderMembers(order...)
	}
	return item
}

func buddyItem(name string, groupID, itemID uint16) wire.FeedbagItem {
	return wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, Name: name, GroupID: groupID, ItemID: itemID}
}

func TestFeedbag_groups(t *testing.T) {
	tests := []struct {
		name  string
		items []wire.FeedbagItem
		want  []BuddyGroup
	}{
		{
			name: "empty feedbag",
			want: nil,
		},
		{
			name: "groups and buddies follow order attributes",
			items: []wire.FeedbagItem{
				groupItem("", 0, 20, 10),
				groupItem("Family", 10, 2),
				groupItem("Friends", 20, 4, 3),
				buddyItem("mom", 10, 2),
				buddyItem("alice", 20, 3),
				buddyItem("bob", 20, 4),
			},
			want: []BuddyGroup{
				{Name: "Friends", Buddies: []Buddy{{ScreenName: "bob"}, {ScreenName: "alice"}}},
				{Name: "Family", Buddies: []Buddy{{ScreenName: "mom"}}},
			},
		},
		{
			name: "items missing from order attributes go last",
			items: []wire.FeedbagItem{
				groupItem("Buddies", 10, 2),
				buddyItem("alice", 10, 3),
				buddyItem("bob", 10, 2),
				groupItem("Other", 20),
			},
			want: []BuddyGroup{
				{Name: "Buddies", Buddies: []Buddy{{ScreenName: "bob"}, {ScreenName: "alice"}}},
				{Name: "Other"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := feedbag{items: tt.items}
			assert.Equal(t, tt.want, fb.groups())
		})
	}
}

func TestFeedbag_planAddBuddy(t *testing.T) {
	tests := []struct {
		name       string
		items      []wire.FeedbagItem
		group      string
		screenName string
		want       []BuddyGroup
		wantEmpty  bool
	}{
		{
			name:       "first buddy creates root and group",
			group:      "Buddies",
			screenName: "alice",
			want:       []BuddyGroup{{Name: "Buddies", Buddies: []Buddy{{ScreenName: "alice"}}}},
		},
		{
			name: "buddy appended to existing group",
			items: []wire.FeedbagItem{
				groupItem("", 0, 10),
				groupItem("Buddies", 10, 2),
				buddyItem("bob", 10, 2),
			},
			group:      "buddies",
			screenName: "alice",
			want:       []BuddyGroup{{Name: "Buddies", Buddies: []Buddy{{ScreenName: "bob"}, {ScreenName: "alice"}}}},
		},
		{
			name: "new group appended to root order",
			items: []wire.FeedbagItem{
				groupItem("", 0, 10),
				groupItem("Buddies", 10, 2),
				buddyItem("bob", 10, 2),
			},
			group:      "Work",
			screenName: "alice",
			want: []BuddyGroup{
				{Name: "Buddies", Buddies: []Buddy{{ScreenName: "bob"}}},
				{Name: "Work", Buddies: []Buddy{{ScreenName: "alice"}}},
			},
		},
		{
			name: "buddy already in group",
			items: []wire.FeedbagItem{
				groupItem("", 0, 10),
				groupItem("Buddies", 10, 2),
				buddyItem("Bob", 10, 2),
			},
			group:      "Buddies",
			screenName: "bob",
			wantEmpty:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := feedbag{items: tt.items}
			change := fb.planAddBuddy(tt.group, tt.screenName)
			if tt.wantEmpty {
				assert.True(t, change.empty())
				return
			}
			fb.apply(false, change.inserts)
			fb.apply(false, change.updates)
			assert.Equal(t, tt.want, fb.groups())
		})
	}
}

func TestFeedbag_planRemoveBuddy(t *testing.T) {
	items := []wire.FeedbagItem{
		groupItem("", 0, 10, 20),
		groupItem("Buddies", 10, 2, 3),
		groupItem("Work", 20, 4),
		buddyItem("bob", 10, 2),
		buddyItem("alice", 10, 3),
		buddyItem("Bob", 20, 4),
	}

	tests := []struct {
		name       string
		screenName string
		want       []BuddyGroup
		wantErr    error
	}{
		{
			name:       "removed from every group",
			screenName: "B O B",
			want: []BuddyGroup{
				{Name: "Buddies", Buddies: []Buddy{{ScreenName: "alice"}}},
				{Name: "Work"},
			},
		},
		{
			name:       "not on list",
			screenName: "carol",
			wantErr:    ErrNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := feedbag{items: append([]wire.FeedbagItem(nil), items...)}
			change, err := fb.planRemoveBuddy(tt.screenName)
			assert.ErrorIs(t, err, tt.wantErr)
			if err != nil {
				return
			}
			fb.apply(true, change.deletes)
			fb.apply(false, change.updates)
			assert.Equal(t, tt.want, fb.groups())
			for _, g := range change.updates {
				order, _ := g.Uint16SliceBE(wire.FeedbagAttributesOrder)
				assert.NotContains(t, order, uint16(2))
				assert.NotContains(t, order, uint16(4))
			}
		})
	}
}

func TestFeedbag_planBlock(t *testing.T) {
	pdInfo := func(mode wire.FeedbagPDMode) wire.FeedbagItem {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIdPdinfo, ItemID: 50}
		item.Set(wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(mode)))
		return item
	}

	tests := []struct {
		name        string
		items       []wire.FeedbagItem
		wantInserts int
		wantUpdates int
	}{
		{
			name:        "no pd info item",
			wantInserts: 2,
		},
		{
			name:        "permit all mode switches to deny some",
			items:       []wire.FeedbagItem{pdInfo(wire.FeedbagPDModePermitAll)},
			wantInserts: 1,
			wantUpdates: 1,
		},
		{
			name:        "already deny some",
			items:       []wire.FeedbagItem{pdInfo(wire.FeedbagPDModeDenySome)},
			wantInserts: 1,
		},
		{
			name: "already blocked",
			items: []wire.FeedbagItem{
				pdInfo(wire.FeedbagPDModeDenySome),
				{ClassID: wire.FeedbagClassIDDeny, Name: "bob", ItemID: 51},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := feedbag{items: tt.items}
			change := fb.planBlock("Bob")
			assert.Len(t, change.inserts, tt.wantInserts)
			assert.Len(t, change.updates, tt.wantUpdates)

			fb.apply(false, change.inserts)
			fb.apply(false, change.updates)
			assert.True(t, fb.isDenied("bob"))
			assert.Equal(t, wire.FeedbagPDModeDenySome, fb.pdMode())

			unblock, err := fb.planUnblock("bob")
			assert.NoError(t, err)
			fb.apply(true, unblock.deletes)
			assert.False(t, fb.isDenied("bob"))
		})
	}
}
