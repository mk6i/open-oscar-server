package state

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestFeedbagMirror(t *testing.T) {
	root := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup}
	friends := wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: 1, Name: "Friends"}
	alice := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 2, Name: "alice"}
	aliceRenamed := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 2, Name: "Alice"}
	bob := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 3, Name: "bob"}
	carol := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, GroupID: 1, ItemID: 4, Name: "carol"}

	t.Run("pending changes show in the snapshot until confirmed", func(t *testing.T) {
		m := &FeedbagMirror{}
		m.Reset([]wire.FeedbagItem{root, friends, alice})

		m.Sent(1, false, []wire.FeedbagItem{aliceRenamed, bob})
		m.Sent(2, true, []wire.FeedbagItem{aliceRenamed})
		assert.True(t, m.HasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends, bob}, m.Snapshot())

		// only the accepted items are confirmed
		m.Confirm(1, []uint16{0, 0x0E})
		m.Confirm(2, []uint16{0})
		assert.False(t, m.HasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends}, m.Snapshot())
	})

	t.Run("a rejected change is discarded", func(t *testing.T) {
		m := &FeedbagMirror{}
		m.Reset([]wire.FeedbagItem{root, friends})

		m.Sent(1, false, []wire.FeedbagItem{bob})
		m.Discard(1)
		assert.False(t, m.HasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends}, m.Snapshot())
	})

	t.Run("a reload keeps changes sent after its query", func(t *testing.T) {
		m := &FeedbagMirror{}
		m.Reset([]wire.FeedbagItem{root, friends})

		m.Sent(1, false, []wire.FeedbagItem{bob}) // dropped by the server
		marker := m.Mark()
		m.Sent(2, false, []wire.FeedbagItem{carol})

		m.Reload(marker, []wire.FeedbagItem{root, friends, alice})
		assert.Equal(t, []wire.FeedbagItem{root, friends, alice, carol}, m.Snapshot())

		// the confirmation of the dropped change never comes; a late one for
		// a change the reload covered changes nothing
		m.Confirm(1, []uint16{0})
		m.Confirm(2, []uint16{0})
		assert.False(t, m.HasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends, alice, carol}, m.Snapshot())
	})

	t.Run("changes from other locations apply right away", func(t *testing.T) {
		m := &FeedbagMirror{}
		m.Reset([]wire.FeedbagItem{root, friends, alice})

		m.ApplyRemote(false, []wire.FeedbagItem{bob})
		m.ApplyRemote(true, []wire.FeedbagItem{alice})
		assert.False(t, m.HasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends, bob}, m.Snapshot())
		assert.Equal(t, map[uint16]string{0: "", 1: "Friends"}, m.GroupNames())
	})

	t.Run("a snapshot doesn't change with the mirror", func(t *testing.T) {
		m := &FeedbagMirror{}
		m.Reset([]wire.FeedbagItem{root, friends, alice})
		snapshot := m.Snapshot()
		m.ApplyRemote(true, []wire.FeedbagItem{alice})
		assert.Equal(t, []wire.FeedbagItem{root, friends, alice}, snapshot)
	})

	t.Run("the mirror shares no TLVs with items going in or out", func(t *testing.T) {
		order := func(ids ...uint16) wire.FeedbagItem {
			return wire.FeedbagItem{
				ClassID:   wire.FeedbagClassIdGroup,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, ids)}},
			}
		}
		edit := func(items []wire.FeedbagItem) {
			items[0].Set(wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{9}))
		}

		m := &FeedbagMirror{}
		items := []wire.FeedbagItem{order(1)}
		m.Reset(items)
		edit(items)
		edit(m.Snapshot())
		assert.Equal(t, []wire.FeedbagItem{order(1)}, m.Snapshot())

		items = []wire.FeedbagItem{order(1, 2)}
		m.Sent(1, false, items)
		edit(items)
		assert.Equal(t, []wire.FeedbagItem{order(1, 2)}, m.Snapshot())

		items = []wire.FeedbagItem{order(1, 2, 3)}
		m.Reload(m.Mark(), items)
		edit(items)
		assert.Equal(t, []wire.FeedbagItem{order(1, 2, 3)}, m.Snapshot())

		items = []wire.FeedbagItem{order(1, 2, 3, 4)}
		m.ApplyRemote(false, items)
		edit(items)
		assert.Equal(t, []wire.FeedbagItem{order(1, 2, 3, 4)}, m.Snapshot())
	})
}
