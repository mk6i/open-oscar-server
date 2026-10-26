package toc

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
		m := &feedbagMirror{}
		m.reset([]wire.FeedbagItem{root, friends, alice})

		m.sent(1, false, []wire.FeedbagItem{aliceRenamed, bob})
		m.sent(2, true, []wire.FeedbagItem{aliceRenamed})
		assert.True(t, m.hasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends, bob}, m.snapshot())

		// only the accepted items are confirmed
		m.confirm(1, []uint16{0, 0x0E})
		m.confirm(2, []uint16{0})
		assert.False(t, m.hasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends}, m.snapshot())
	})

	t.Run("a rejected change is discarded", func(t *testing.T) {
		m := &feedbagMirror{}
		m.reset([]wire.FeedbagItem{root, friends})

		m.sent(1, false, []wire.FeedbagItem{bob})
		m.discard(1)
		assert.False(t, m.hasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends}, m.snapshot())
	})

	t.Run("a reload keeps changes sent after its query", func(t *testing.T) {
		m := &feedbagMirror{}
		m.reset([]wire.FeedbagItem{root, friends})

		m.sent(1, false, []wire.FeedbagItem{bob}) // dropped by the server
		marker := m.mark()
		m.sent(2, false, []wire.FeedbagItem{carol})

		m.reload(marker, []wire.FeedbagItem{root, friends, alice})
		assert.Equal(t, []wire.FeedbagItem{root, friends, alice, carol}, m.snapshot())

		// the confirmation of the dropped change never comes; a late one for
		// a change the reload covered changes nothing
		m.confirm(1, []uint16{0})
		m.confirm(2, []uint16{0})
		assert.False(t, m.hasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends, alice, carol}, m.snapshot())
	})

	t.Run("changes from other locations apply right away", func(t *testing.T) {
		m := &feedbagMirror{}
		m.reset([]wire.FeedbagItem{root, friends, alice})

		m.applyRemote(false, []wire.FeedbagItem{bob})
		m.applyRemote(true, []wire.FeedbagItem{alice})
		assert.False(t, m.hasPending())
		assert.Equal(t, []wire.FeedbagItem{root, friends, bob}, m.snapshot())
		assert.Equal(t, map[uint16]string{0: "", 1: "Friends"}, m.groupNames())
	})

	t.Run("a snapshot doesn't change with the mirror", func(t *testing.T) {
		m := &feedbagMirror{}
		m.reset([]wire.FeedbagItem{root, friends, alice})
		snapshot := m.snapshot()
		m.applyRemote(true, []wire.FeedbagItem{alice})
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

		m := &feedbagMirror{}
		items := []wire.FeedbagItem{order(1)}
		m.reset(items)
		edit(items)
		edit(m.snapshot())
		assert.Equal(t, []wire.FeedbagItem{order(1)}, m.snapshot())

		items = []wire.FeedbagItem{order(1, 2)}
		m.sent(1, false, items)
		edit(items)
		assert.Equal(t, []wire.FeedbagItem{order(1, 2)}, m.snapshot())

		items = []wire.FeedbagItem{order(1, 2, 3)}
		m.reload(m.mark(), items)
		edit(items)
		assert.Equal(t, []wire.FeedbagItem{order(1, 2, 3)}, m.snapshot())

		items = []wire.FeedbagItem{order(1, 2, 3, 4)}
		m.applyRemote(false, items)
		edit(items)
		assert.Equal(t, []wire.FeedbagItem{order(1, 2, 3, 4)}, m.snapshot())
	})
}
