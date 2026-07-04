package state

import (
	"math"
	"testing"

	"github.com/mk6i/open-oscar-server/wire"
	"github.com/stretchr/testify/assert"
)

func TestFeedbagList_upsertItem(t *testing.T) {
	t.Run("generates unique ItemID", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 42 })

		result, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "alice",
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: 1,
		})
		assert.True(t, inserted)
		assert.Equal(t, uint16(42), result.ItemID)
		assert.Equal(t, "alice", result.Name)
		assert.Equal(t, wire.FeedbagClassIdBuddy, result.ClassID)
		assert.Equal(t, uint16(1), result.GroupID)
	})

	t.Run("subsequent insert avoids collision", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 42 })

		fl.upsertItem(wire.FeedbagItem{
			Name:    "alice",
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: 1,
		})
		result, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "bob",
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: 1,
		})
		assert.True(t, inserted)
		assert.Equal(t, uint16(43), result.ItemID)
	})

	t.Run("non-buddy item does not update group order", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 5 })
		fl.upsertItem(wire.FeedbagItem{
			Name:    "alice",
			ClassID: wire.FeedbagClassIDPermit,
		})
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, wire.FeedbagClassIDPermit, upserts[0].ClassID)
	})

	t.Run("updates existing non-buddy item in place", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{
				Name:    "alice",
				ClassID: wire.FeedbagClassIDPermit,
				ItemID:  7,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(0x01, uint16(100)),
					},
				},
			},
		}, nil)

		_, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "alice",
			ClassID: wire.FeedbagClassIDPermit,
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(0x01, uint16(200)),
				},
			},
		})
		assert.False(t, inserted)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, uint16(7), upserts[0].ItemID)
		val, ok := upserts[0].Uint16BE(0x01)
		assert.True(t, ok)
		assert.Equal(t, uint16(200), val)
	})

	t.Run("updates existing buddy item matched by group", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Group1", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
			{Name: "Group2", ClassID: wire.FeedbagClassIdGroup, GroupID: 2},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 2, ItemID: 20},
		}, nil)

		_, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "alice",
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: 2,
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(0x01, uint16(999)),
				},
			},
		})
		assert.False(t, inserted)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, uint16(2), upserts[0].GroupID)
		assert.Equal(t, "alice", upserts[0].Name)
		assert.Equal(t, uint16(20), upserts[0].ItemID)
		val, ok := upserts[0].Uint16BE(0x01)
		assert.True(t, ok)
		assert.Equal(t, uint16(999), val)
	})

	t.Run("skips update when existing item is identical", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{
				Name:    "alice",
				ClassID: wire.FeedbagClassIDPermit,
				ItemID:  7,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(0x01, uint16(100)),
					},
				},
			},
		}, nil)

		_, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "alice",
			ClassID: wire.FeedbagClassIDPermit,
			ItemID:  7,
			TLVLBlock: wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(0x01, uint16(100)),
				},
			},
		})
		assert.False(t, inserted)

		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("normalized screen name: buddy stored with lowercase name", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 10 })

		result, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "Alice",
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: 1,
		})
		assert.True(t, inserted)
		assert.Equal(t, "alice", result.Name)
	})

	t.Run("normalized screen name: buddy upsert with different case matches existing", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 99},
		}, nil)

		result, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "ALICE",
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: 1,
		})
		assert.False(t, inserted)
		assert.Equal(t, uint16(99), result.ItemID)
		assert.Equal(t, "alice", result.Name)
	})

	t.Run("normalized screen name: permit stored with lowercase name and spaces stripped", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 1 })

		result, _ := fl.upsertItem(wire.FeedbagItem{
			Name:    " Bob Smith ",
			ClassID: wire.FeedbagClassIDPermit,
		})
		assert.Equal(t, "bobsmith", result.Name)
	})

	t.Run("normalized screen name: permit upsert with different case matches existing", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "bob", ClassID: wire.FeedbagClassIDPermit, ItemID: 5},
		}, nil)

		result, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "BOB",
			ClassID: wire.FeedbagClassIDPermit,
		})
		assert.False(t, inserted)
		assert.Equal(t, "bob", result.Name)
		assert.Equal(t, uint16(5), result.ItemID)
	})

	t.Run("normalized screen name: deny upsert with different case matches existing", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "charlie", ClassID: wire.FeedbagClassIDDeny, ItemID: 3},
		}, nil)

		result, inserted := fl.upsertItem(wire.FeedbagItem{
			Name:    "Charlie",
			ClassID: wire.FeedbagClassIDDeny,
		})
		assert.False(t, inserted)
		assert.Equal(t, "charlie", result.Name)
		assert.Equal(t, uint16(3), result.ItemID)
	})
}

func TestFeedbagList_deleteItem(t *testing.T) {
	t.Run("non-buddy item does not update group order", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "alice", ClassID: wire.FeedbagClassIDPermit, ItemID: 5},
		}, nil)

		fl.deleteItem(wire.FeedbagItem{Name: "alice", ClassID: wire.FeedbagClassIDPermit, ItemID: 5})

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("removes item from items list", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "alice", ClassID: wire.FeedbagClassIDPermit, ItemID: 1},
			{Name: "bob", ClassID: wire.FeedbagClassIDPermit, ItemID: 2},
			{Name: "charlie", ClassID: wire.FeedbagClassIDPermit, ItemID: 3},
		}, nil)

		fl.deleteItem(wire.FeedbagItem{Name: "bob", ClassID: wire.FeedbagClassIDPermit, ItemID: 2})

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, "bob", deletes[0].Name)
		assert.Equal(t, wire.FeedbagClassIDPermit, deletes[0].ClassID)
	})

	t.Run("multiple deletes accumulate", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "alice", ClassID: wire.FeedbagClassIDDeny, ItemID: 1},
			{Name: "bob", ClassID: wire.FeedbagClassIDDeny, ItemID: 2},
		}, nil)

		fl.deleteItem(wire.FeedbagItem{Name: "alice", ClassID: wire.FeedbagClassIDDeny, ItemID: 1})
		fl.deleteItem(wire.FeedbagItem{Name: "bob", ClassID: wire.FeedbagClassIDDeny, ItemID: 2})

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 2)
	})

	t.Run("normalized screen name: delete buddy by different case", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 50},
		}, nil)

		deleted, found := fl.deleteItem(wire.FeedbagItem{
			Name:    "ALICE",
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: 1,
		})
		assert.True(t, found)
		assert.Equal(t, "alice", deleted.Name)
		assert.Equal(t, uint16(50), deleted.ItemID)
	})

	t.Run("normalized screen name: delete permit by different case", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "bob", ClassID: wire.FeedbagClassIDPermit, ItemID: 7},
		}, nil)

		deleted, found := fl.deleteItem(wire.FeedbagItem{Name: "Bob", ClassID: wire.FeedbagClassIDPermit})
		assert.True(t, found)
		assert.Equal(t, "bob", deleted.Name)
	})

	t.Run("normalized screen name: delete deny by different case", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "charlie", ClassID: wire.FeedbagClassIDDeny, ItemID: 8},
		}, nil)

		deleted, found := fl.deleteItem(wire.FeedbagItem{Name: "CHARLIE", ClassID: wire.FeedbagClassIDDeny})
		assert.True(t, found)
		assert.Equal(t, "charlie", deleted.Name)
	})
}

func TestFeedbagList_genID(t *testing.T) {
	tt := []struct {
		name    string
		randInt func(n int) int
		items   []wire.FeedbagItem
		want    uint16
	}{
		{
			name:    "empty items list returns random ID",
			randInt: func(n int) int { return 1000 },
			items:   []wire.FeedbagItem{},
			want:    1000,
		},
		{
			name:    "finds next available ID when starting ID conflicts with ItemID",
			randInt: func(n int) int { return 100 },
			items: []wire.FeedbagItem{
				{ItemID: 100, GroupID: 1},
				{ItemID: 101, GroupID: 1},
			},
			want: 102,
		},
		{
			name:    "finds next available ID when starting ID conflicts with GroupID",
			randInt: func(n int) int { return 50 },
			items: []wire.FeedbagItem{
				{ItemID: 1, GroupID: 50},
				{ItemID: 2, GroupID: 51},
			},
			want: 52,
		},
		{
			name:    "wraps around and skips 0 to find next available ID",
			randInt: func(n int) int { return math.MaxUint16 - 2 },
			items: []wire.FeedbagItem{
				{ItemID: math.MaxUint16 - 2, GroupID: 1},
				{ItemID: math.MaxUint16 - 1, GroupID: 1},
				{ItemID: math.MaxUint16, GroupID: 1},
			},
			want: 2,
		},
		{
			name:    "skips 0 when starting from 0 and finds next available",
			randInt: func(n int) int { return 0 },
			items:   []wire.FeedbagItem{},
			want:    1,
		},
		{
			name:    "returns 0 when all IDs are taken",
			randInt: func(n int) int { return 100 },
			items: func() []wire.FeedbagItem {
				items := make([]wire.FeedbagItem, 0, math.MaxUint16+1)
				for i := 0; i <= math.MaxUint16; i++ {
					items = append(items, wire.FeedbagItem{
						ItemID:  uint16(i),
						GroupID: uint16(i),
					})
				}
				return items
			}(),
			want: 0,
		},
		{
			name:    "finds ID that conflicts with both ItemID and GroupID",
			randInt: func(n int) int { return 200 },
			items: []wire.FeedbagItem{
				{ItemID: 200, GroupID: 201},
				{ItemID: 201, GroupID: 200},
			},
			want: 202,
		},
		{
			name:    "finds available ID immediately when no conflicts",
			randInt: func(n int) int { return 500 },
			items: []wire.FeedbagItem{
				{ItemID: 100, GroupID: 1},
				{ItemID: 200, GroupID: 2},
				{ItemID: 300, GroupID: 3},
			},
			want: 500,
		},
		{
			name:    "handles single conflict and finds next",
			randInt: func(n int) int { return 42 },
			items: []wire.FeedbagItem{
				{ItemID: 42, GroupID: 1},
			},
			want: 43,
		},
		{
			name:    "finds ID before starting point when wrapping",
			randInt: func(n int) int { return 5 },
			items: []wire.FeedbagItem{
				{ItemID: 5, GroupID: 1},
				{ItemID: 6, GroupID: 1},
				{ItemID: 7, GroupID: 1},
			},
			want: 8,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fl := NewFeedbagList(tc.items, tc.randInt)
			got := fl.genID()
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFeedbagList_AddGroup(t *testing.T) {
	t.Run("creates group and root group when none exists", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 5 })

		group := fl.AddGroup("Buddies")

		assert.Equal(t, uint16(5), group.GroupID)
		assert.Equal(t, "Buddies", group.Name)
		assert.Equal(t, wire.FeedbagClassIdGroup, group.ClassID)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 2)
		root := upserts[0]
		assert.Equal(t, wire.FeedbagClassIdGroup, root.ClassID)
		assert.Equal(t, uint16(0), root.GroupID)
		order, ok := root.Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{5}, order)
	})

	t.Run("updates existing root group order", func(t *testing.T) {
		existing := []wire.FeedbagItem{
			{
				ClassID: wire.FeedbagClassIdGroup,
				GroupID: 0,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1}),
					},
				},
			},
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}
		callCount := 0
		fl := NewFeedbagList(existing, func(n int) int {
			callCount++
			return callCount + 1
		})

		group := fl.AddGroup("Coworkers")

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 2)
		order, ok := upserts[0].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{1, group.GroupID}, order)
	})

	t.Run("multiple AddGroup calls accumulate in root order", func(t *testing.T) {
		callCount := 0
		fl := NewFeedbagList(nil, func(n int) int {
			callCount++
			return callCount * 10
		})

		g1 := fl.AddGroup("Group1")
		g2 := fl.AddGroup("Group2")

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 3)
		order, ok := upserts[0].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{g1.GroupID, g2.GroupID}, order)
	})
}

func TestFeedbagList_SetMode(t *testing.T) {
	t.Run("upserts pdinfo item with mode TLV", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.SetMode(2)
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, wire.FeedbagClassIdPdinfo, upserts[0].ClassID)
		mode, ok := upserts[0].Uint8(wire.FeedbagAttributesPdMode)
		assert.True(t, ok)
		assert.Equal(t, uint8(2), mode)
	})

	t.Run("second SetMode updates existing item in place", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.SetMode(1)
		_ = fl.PendingUpdates()
		fl.SetMode(3)
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		mode, ok := upserts[0].Uint8(wire.FeedbagAttributesPdMode)
		assert.True(t, ok)
		assert.Equal(t, uint8(3), mode)
	})
}

func TestFeedbagList_DeleteGroup(t *testing.T) {
	t.Run("updates root group order", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{
				Name: "", ClassID: wire.FeedbagClassIdGroup, GroupID: 0,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2, 3}),
					},
				},
			},
			{
				Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1}),
					},
				},
			},
			{Name: "Jane", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 1},
			{
				Name: "Coworkers", ClassID: wire.FeedbagClassIdGroup, GroupID: 2,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 3}),
					},
				},
			},
			{Name: "Joe", ClassID: wire.FeedbagClassIdBuddy, GroupID: 2, ItemID: 2},
			{Name: "Fred", ClassID: wire.FeedbagClassIdBuddy, GroupID: 2, ItemID: 3},
			{Name: "Family", ClassID: wire.FeedbagClassIdGroup, GroupID: 3,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{4}),
					},
				},
			},
			{Name: "Alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 3, ItemID: 4},
		}, nil)

		fl.DeleteGroup("Coworkers")

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 3)
		assert.Equal(t, "Coworkers", deletes[0].Name)
		assert.Equal(t, uint16(2), deletes[0].GroupID)
		assert.Equal(t, "Joe", deletes[1].Name)
		assert.Equal(t, uint16(2), deletes[1].GroupID)
		assert.Equal(t, "Fred", deletes[2].Name)
		assert.Equal(t, uint16(2), deletes[2].GroupID)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, uint16(0), upserts[0].GroupID)
		order, ok := upserts[0].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{1, 3}, order)
	})

	t.Run("deleting non-existent group is a no-op", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		fl.DeleteGroup("Nonexistent")
		assert.Empty(t, fl.PendingDeletes())
		assert.Nil(t, fl.PendingUpdates())
	})
}

func TestFeedbagList_AddBuddy(t *testing.T) {
	t.Run("updates parent group order", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 50 })

		inserted, err := fl.AddBuddy("Buddies", "alice", "", "")
		assert.NoError(t, err)
		assert.True(t, inserted)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 2)
		assert.Equal(t, uint16(1), upserts[1].GroupID)
		order, ok := upserts[1].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{upserts[0].ItemID}, order)
	})

	t.Run("multiple buddies accumulate in parent group order", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{
				Name:    "Buddies",
				ClassID: wire.FeedbagClassIdGroup,
				GroupID: 1,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10}),
					},
				},
			},
		}, func(n int) int { return 50 })

		_, err := fl.AddBuddy("Buddies", "alice", "", "")
		assert.NoError(t, err)
		_, err = fl.AddBuddy("Buddies", "bob", "", "")
		assert.NoError(t, err)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 3)
		order, ok := upserts[1].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{10, upserts[0].ItemID, upserts[2].ItemID}, order)
	})

	t.Run("returns error when parent group does not exist", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 5 })
		_, err := fl.AddBuddy("Nonexistent", "alice", "", "")
		assert.ErrorContains(t, err, "group \"Nonexistent\" not found")
	})

	t.Run("normalized screen name: stores buddy with lowercase name", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 1 })

		inserted, err := fl.AddBuddy("Buddies", "Alice", "", "")
		assert.NoError(t, err)
		assert.True(t, inserted)

		upserts := fl.PendingUpdates()
		var buddy *wire.FeedbagItem
		for i := range upserts {
			if upserts[i].ClassID == wire.FeedbagClassIdBuddy {
				buddy = &upserts[i]
				break
			}
		}
		assert.NotNil(t, buddy)
		assert.Equal(t, "alice", buddy.Name)
	})

	t.Run("normalized screen name: second AddBuddy with different case does not insert duplicate", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 1 })

		inserted1, err := fl.AddBuddy("Buddies", "alice", "", "")
		assert.NoError(t, err)
		assert.True(t, inserted1)

		inserted2, err := fl.AddBuddy("Buddies", "ALICE", "", "")
		assert.NoError(t, err)
		assert.False(t, inserted2)
	})

	t.Run("normalized screen name: DeleteBuddy finds buddy by different case", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 1 })
		_, err := fl.AddBuddy("Buddies", "alice", "", "")
		assert.NoError(t, err)
		_ = fl.PendingUpdates()

		err = fl.DeleteBuddy("Buddies", "Alice")
		assert.NoError(t, err)
		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, "alice", deletes[0].Name)
	})

	t.Run("alias is stored as TLV attribute", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 1 })
		_, err := fl.AddBuddy("Buddies", "alice", "Al", "")
		assert.NoError(t, err)
		upserts := fl.PendingUpdates()
		var buddy *wire.FeedbagItem
		for i := range upserts {
			if upserts[i].ClassID == wire.FeedbagClassIdBuddy {
				buddy = &upserts[i]
				break
			}
		}
		assert.NotNil(t, buddy)
		alias, ok := buddy.Bytes(wire.FeedbagAttributesAlias)
		assert.True(t, ok)
		assert.Equal(t, []byte("Al"), alias)
	})

	t.Run("note is stored as TLV attribute", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 1 })
		_, err := fl.AddBuddy("Buddies", "alice", "", "call first")
		assert.NoError(t, err)
		upserts := fl.PendingUpdates()
		var buddy *wire.FeedbagItem
		for i := range upserts {
			if upserts[i].ClassID == wire.FeedbagClassIdBuddy {
				buddy = &upserts[i]
				break
			}
		}
		assert.NotNil(t, buddy)
		note, ok := buddy.Bytes(wire.FeedbagAttributesNote)
		assert.True(t, ok)
		assert.Equal(t, []byte("call first"), note)
	})
}

func TestFeedbagList_DeleteBuddy(t *testing.T) {
	t.Run("updates parent group order", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{
				Name:    "Buddies",
				ClassID: wire.FeedbagClassIdGroup,
				GroupID: 1,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10, 20, 30}),
					},
				},
			},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10},
			{Name: "bob", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 20},
			{Name: "charlie", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 30},
		}, nil)

		err := fl.DeleteBuddy("Buddies", "bob")
		assert.NoError(t, err)

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, "bob", deletes[0].Name)
		assert.Equal(t, uint16(20), deletes[0].ItemID)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		order, ok := upserts[0].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{10, 30}, order)
	})

	t.Run("wildcard removes buddy from all groups", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{
				Name:    "Buddies",
				ClassID: wire.FeedbagClassIdGroup,
				GroupID: 1,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10, 20}),
					},
				},
			},
			{
				Name:    "Coworkers",
				ClassID: wire.FeedbagClassIdGroup,
				GroupID: 2,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{30, 40}),
					},
				},
			},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10},
			{Name: "bob", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 20},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 2, ItemID: 30},
			{Name: "charlie", ClassID: wire.FeedbagClassIdBuddy, GroupID: 2, ItemID: 40},
		}, nil)

		err := fl.DeleteBuddy("*", "alice")
		assert.NoError(t, err)

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 2)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 2)
		order1, ok := upserts[0].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{20}, order1)
		order2, ok := upserts[1].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{40}, order2)
	})

	t.Run("removes only buddy in specified group when same screen name in two groups", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{
				Name:    "Buddies",
				ClassID: wire.FeedbagClassIdGroup,
				GroupID: 1,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10, 20}),
					},
				},
			},
			{
				Name:    "Coworkers",
				ClassID: wire.FeedbagClassIdGroup,
				GroupID: 2,
				TLVLBlock: wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{20}),
					},
				},
			},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 2, ItemID: 20},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10},
		}, nil)

		err := fl.DeleteBuddy("Buddies", "alice")
		assert.NoError(t, err)

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, "alice", deletes[0].Name)
		assert.Equal(t, uint16(1), deletes[0].GroupID, "should delete from Buddies (group 1), not Coworkers (group 2)")
		assert.Equal(t, uint16(10), deletes[0].ItemID)
	})
}

func TestFeedbagList_PendingUpdates(t *testing.T) {
	t.Run("empty when nothing inserted", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 1 })
		assert.Nil(t, fl.PendingUpdates())
	})
	t.Run("includes inserts and updates", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, func(n int) int { return 50 })
		_, err := fl.AddBuddy("Buddies", "alice", "", "")
		assert.NoError(t, err)
		_, err = fl.AddBuddy("Buddies", "bob", "", "")
		assert.NoError(t, err)
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 3)
		assert.Equal(t, wire.FeedbagClassIdBuddy, upserts[0].ClassID)
		assert.Equal(t, wire.FeedbagClassIdGroup, upserts[1].ClassID)
		assert.Equal(t, wire.FeedbagClassIdBuddy, upserts[2].ClassID)
	})
	t.Run("clears after retrieval", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 5 })
		fl.AddGroup("Buddies")
		assert.Len(t, fl.PendingUpdates(), 2)
		assert.Nil(t, fl.PendingUpdates())
	})
}

func TestFeedbagList_PendingDeletes(t *testing.T) {
	t.Run("empty when nothing deleted", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		assert.Nil(t, fl.PendingDeletes())
	})

	t.Run("clears after retrieval", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "alice", ClassID: wire.FeedbagClassIDPermit, ItemID: 1},
		}, nil)
		fl.deleteItem(wire.FeedbagItem{Name: "alice", ClassID: wire.FeedbagClassIDPermit, ItemID: 1})
		assert.Len(t, fl.PendingDeletes(), 1)
		assert.Nil(t, fl.PendingDeletes())
	})
}

func TestFeedbagList_PendingUpdates_upsertsOnly(t *testing.T) {
	t.Run("tracks upserted items", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 5 })
		result, inserted := fl.upsertItem(wire.FeedbagItem{ClassID: wire.FeedbagClassIDPermit, Name: "alice"})
		assert.True(t, inserted)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, "alice", upserts[0].Name)
		assert.Equal(t, uint16(5), result.ItemID)
	})

	t.Run("clears after retrieval", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 5 })
		fl.upsertItem(wire.FeedbagItem{ClassID: wire.FeedbagClassIDPermit})
		assert.Len(t, fl.PendingUpdates(), 1)
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("multiple inserts accumulate", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 10 })
		fl.upsertItem(wire.FeedbagItem{ClassID: wire.FeedbagClassIDPermit, Name: "alice"})
		fl.upsertItem(wire.FeedbagItem{ClassID: wire.FeedbagClassIDPermit, Name: "bob"})

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 2)
	})
}

func TestFeedbagList_PermitUser(t *testing.T) {
	t.Run("new permit entry is added", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.PermitUser("alice")
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, wire.FeedbagClassIDPermit, upserts[0].ClassID)
		assert.Equal(t, "alice", upserts[0].Name)
	})

	t.Run("duplicate permit is not re-added", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIDPermit, Name: "alice", ItemID: 1},
		}, nil)
		fl.PermitUser("alice")
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("name is normalized", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.PermitUser("Alice")
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, "alice", upserts[0].Name)
	})
}

func TestFeedbagList_DenyUser(t *testing.T) {
	t.Run("new deny entry is added", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.DenyUser("alice")
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, wire.FeedbagClassIDDeny, upserts[0].ClassID)
		assert.Equal(t, "alice", upserts[0].Name)
	})

	t.Run("duplicate deny is not re-added", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIDDeny, Name: "alice", ItemID: 1},
		}, nil)
		fl.DenyUser("alice")
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("name is normalized", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.DenyUser("Alice")
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, "alice", upserts[0].Name)
	})
}

func TestFeedbagList_DeletePermit(t *testing.T) {
	t.Run("existing permit is deleted", func(t *testing.T) {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIDPermit, Name: "alice", ItemID: 1}
		fl := NewFeedbagList([]wire.FeedbagItem{item}, nil)
		fl.DeletePermit("alice")
		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, item, deletes[0])
	})

	t.Run("deleting non-existent permit is a no-op", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		fl.DeletePermit("alice")
		assert.Empty(t, fl.PendingDeletes())
	})

	t.Run("name comparison is case-insensitive", func(t *testing.T) {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIDPermit, Name: "alice", ItemID: 1}
		fl := NewFeedbagList([]wire.FeedbagItem{item}, nil)
		fl.DeletePermit("Alice")
		assert.Len(t, fl.PendingDeletes(), 1)
	})
}

func TestFeedbagList_DeleteDeny(t *testing.T) {
	t.Run("existing deny is deleted", func(t *testing.T) {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIDDeny, Name: "alice", ItemID: 1}
		fl := NewFeedbagList([]wire.FeedbagItem{item}, nil)
		fl.DeleteDeny("alice")
		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, item, deletes[0])
	})

	t.Run("deleting non-existent deny is a no-op", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		fl.DeleteDeny("alice")
		assert.Empty(t, fl.PendingDeletes())
	})

	t.Run("name comparison is case-insensitive", func(t *testing.T) {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIDDeny, Name: "alice", ItemID: 1}
		fl := NewFeedbagList([]wire.FeedbagItem{item}, nil)
		fl.DeleteDeny("Alice")
		assert.Len(t, fl.PendingDeletes(), 1)
	})
}

func TestFeedbagList_AddLinkedScreenName(t *testing.T) {
	t.Run("new linked screen name is added", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.AddLinkedScreenName("alice")
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, wire.FeedbagClassIdAlInfo, upserts[0].ClassID)
		assert.Equal(t, "alice", upserts[0].Name)
	})

	t.Run("duplicate linked screen name is not re-added", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIdAlInfo, Name: "alice", ItemID: 1},
		}, nil)
		fl.AddLinkedScreenName("alice")
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("name is normalized", func(t *testing.T) {
		fl := NewFeedbagList(nil, func(n int) int { return 0 })
		fl.AddLinkedScreenName("Alice")
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, "alice", upserts[0].Name)
	})
}

func TestFeedbagList_DeleteLinkedScreenName(t *testing.T) {
	t.Run("existing linked screen name is deleted, root group created and pending", func(t *testing.T) {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIdAlInfo, Name: "alice", ItemID: 1}
		fl := NewFeedbagList([]wire.FeedbagItem{item}, nil)
		fl.DeleteLinkedScreenName("alice")
		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, item, deletes[0])
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, wire.FeedbagClassIdGroup, upserts[0].ClassID)
		assert.Equal(t, uint16(0), upserts[0].GroupID)
	})

	t.Run("existing root group is touched on delete", func(t *testing.T) {
		root := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: 0, ItemID: 1}
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIdAlInfo, Name: "alice", ItemID: 2}
		fl := NewFeedbagList([]wire.FeedbagItem{root, item}, nil)
		fl.DeleteLinkedScreenName("alice")
		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, wire.FeedbagClassIdGroup, upserts[0].ClassID)
		assert.Equal(t, uint16(0), upserts[0].GroupID)
	})

	t.Run("deleting non-existent linked screen name is a no-op", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		fl.DeleteLinkedScreenName("alice")
		assert.Empty(t, fl.PendingDeletes())
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("name comparison is case-insensitive", func(t *testing.T) {
		item := wire.FeedbagItem{ClassID: wire.FeedbagClassIdAlInfo, Name: "alice", ItemID: 1}
		fl := NewFeedbagList([]wire.FeedbagItem{item}, nil)
		fl.DeleteLinkedScreenName("Alice")
		assert.Len(t, fl.PendingDeletes(), 1)
	})
}

func TestFeedbagList_LinkedScreenNames(t *testing.T) {
	t.Run("returns all linked screen names", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIdAlInfo, Name: "alice", ItemID: 1},
			{ClassID: wire.FeedbagClassIdAlInfo, Name: "bob", ItemID: 2},
			{ClassID: wire.FeedbagClassIdBuddy, Name: "carol", ItemID: 3},
		}, nil)
		names := fl.LinkedScreenNames()
		assert.Equal(t, []IdentScreenName{
			NewIdentScreenName("alice"),
			NewIdentScreenName("bob"),
		}, names)
	})

	t.Run("returns nil when no linked screen names exist", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		assert.Nil(t, fl.LinkedScreenNames())
	})
}

func TestFeedbagList_HasLinkedScreenName(t *testing.T) {
	t.Run("returns true when linked screen name exists", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIdAlInfo, Name: "alice", ItemID: 1},
		}, nil)
		assert.True(t, fl.HasLinkedScreenName("alice"))
	})

	t.Run("returns false when linked screen name does not exist", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		assert.False(t, fl.HasLinkedScreenName("alice"))
	})

	t.Run("match is case-insensitive", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIdAlInfo, Name: "alice", ItemID: 1},
		}, nil)
		assert.True(t, fl.HasLinkedScreenName("Alice"))
	})
}

func TestFeedbagList_RenameGroup(t *testing.T) {
	t.Run("renames group in place preserving IDs", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Coworkers", ClassID: wire.FeedbagClassIdGroup, GroupID: 5, ItemID: 0},
		}, nil)

		err := fl.RenameGroup("Coworkers", "Colleagues")
		assert.NoError(t, err)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, "Colleagues", upserts[0].Name)
		assert.Equal(t, uint16(5), upserts[0].GroupID)
		assert.Equal(t, wire.FeedbagClassIdGroup, upserts[0].ClassID)
	})

	t.Run("returns ErrGroupNotFound for missing group", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		err := fl.RenameGroup("Nope", "New")
		assert.ErrorIs(t, err, ErrGroupNotFound)
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("returns ErrGroupExists when target name taken", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "A", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
			{Name: "B", ClassID: wire.FeedbagClassIdGroup, GroupID: 2},
		}, nil)
		err := fl.RenameGroup("A", "B")
		assert.ErrorIs(t, err, ErrGroupExists)
		assert.Nil(t, fl.PendingUpdates())
	})

	t.Run("renaming to same name is a no-op", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "A", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, nil)
		err := fl.RenameGroup("A", "A")
		assert.NoError(t, err)
		assert.Nil(t, fl.PendingUpdates())
	})
}

func TestFeedbagList_MoveBuddy(t *testing.T) {
	t.Run("moves buddy across groups carrying alias", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10}),
				}}},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagAttributesAlias, "Al"),
				}}},
			{Name: "Coworkers", ClassID: wire.FeedbagClassIdGroup, GroupID: 2},
		}, func(n int) int { return 99 })

		err := fl.MoveBuddy("Buddies", "Coworkers", "alice", "")
		assert.NoError(t, err)

		deletes := fl.PendingDeletes()
		assert.Len(t, deletes, 1)
		assert.Equal(t, "alice", deletes[0].Name)
		assert.Equal(t, uint16(1), deletes[0].GroupID)

		upserts := fl.PendingUpdates()
		var newBuddy *wire.FeedbagItem
		for i := range upserts {
			if upserts[i].ClassID == wire.FeedbagClassIdBuddy {
				newBuddy = &upserts[i]
			}
		}
		assert.NotNil(t, newBuddy)
		assert.Equal(t, uint16(2), newBuddy.GroupID)
		alias, ok := newBuddy.Bytes(wire.FeedbagAttributesAlias)
		assert.True(t, ok)
		assert.Equal(t, []byte("Al"), alias)
	})

	t.Run("reorders within a group before another buddy", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{10, 20, 30}),
				}}},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10},
			{Name: "bob", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 20},
			{Name: "carol", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 30},
		}, nil)

		// move carol (30) before alice (10)
		err := fl.MoveBuddy("Buddies", "", "carol", "alice")
		assert.NoError(t, err)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		order, ok := upserts[0].Uint16SliceBE(wire.FeedbagAttributesOrder)
		assert.True(t, ok)
		assert.Equal(t, []uint16{30, 10, 20}, order)
	})

	t.Run("returns ErrBuddyNotFound when buddy missing", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, nil)
		err := fl.MoveBuddy("Buddies", "", "ghost", "")
		assert.ErrorIs(t, err, ErrBuddyNotFound)
	})

	t.Run("returns ErrGroupNotFound when destination missing", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Buddies", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10},
		}, nil)
		err := fl.MoveBuddy("Buddies", "Nowhere", "alice", "")
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})
}

func TestFeedbagList_SetBuddyAlias(t *testing.T) {
	t.Run("sets alias on all matching buddies", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10},
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 2, ItemID: 20},
		}, nil)

		found, err := fl.SetBuddyAlias("alice", "Al")
		assert.NoError(t, err)
		assert.True(t, found)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 2)
		for _, item := range upserts {
			alias, ok := item.Bytes(wire.FeedbagAttributesAlias)
			assert.True(t, ok)
			assert.Equal(t, []byte("Al"), alias)
		}
	})

	t.Run("clears alias when empty", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "alice", ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 10,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagAttributesAlias, "Al"),
				}}},
		}, nil)

		found, err := fl.SetBuddyAlias("alice", "")
		assert.NoError(t, err)
		assert.True(t, found)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.False(t, upserts[0].HasTag(wire.FeedbagAttributesAlias))
	})

	t.Run("returns false when buddy not found", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		found, err := fl.SetBuddyAlias("ghost", "X")
		assert.NoError(t, err)
		assert.False(t, found)
		assert.Nil(t, fl.PendingUpdates())
	})
}

func TestFeedbagList_SetGroupCollapsed(t *testing.T) {
	t.Run("sets collapsed attribute", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Coworkers", ClassID: wire.FeedbagClassIdGroup, GroupID: 1},
		}, nil)

		err := fl.SetGroupCollapsed("Coworkers", true)
		assert.NoError(t, err)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.True(t, upserts[0].HasTag(wire.FeedbagAttributesCollapsed))
	})

	t.Run("clears collapsed attribute", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "Coworkers", ClassID: wire.FeedbagClassIdGroup, GroupID: 1,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.FeedbagAttributesCollapsed, []byte{}),
				}}},
		}, nil)

		err := fl.SetGroupCollapsed("Coworkers", false)
		assert.NoError(t, err)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.False(t, upserts[0].HasTag(wire.FeedbagAttributesCollapsed))
	})

	t.Run("targets unnamed default group, not the root group", func(t *testing.T) {
		fl := NewFeedbagList([]wire.FeedbagItem{
			{Name: "", ClassID: wire.FeedbagClassIdGroup, GroupID: 0},
			{Name: "", ClassID: wire.FeedbagClassIdGroup, GroupID: 3},
		}, nil)

		err := fl.SetGroupCollapsed("", true)
		assert.NoError(t, err)

		upserts := fl.PendingUpdates()
		assert.Len(t, upserts, 1)
		assert.Equal(t, uint16(3), upserts[0].GroupID)
		assert.True(t, upserts[0].HasTag(wire.FeedbagAttributesCollapsed))
	})

	t.Run("returns ErrGroupNotFound for missing group", func(t *testing.T) {
		fl := NewFeedbagList(nil, nil)
		err := fl.SetGroupCollapsed("Nope", true)
		assert.ErrorIs(t, err, ErrGroupNotFound)
	})
}
