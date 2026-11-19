package state

import (
	"slices"
	"sync"

	"github.com/mk6i/open-oscar-server/wire"
)

// FeedbagMirror is a client's copy of a user's feedbag (server-side buddy
// list). It holds the feedbag as the server last confirmed it plus the changes
// the client sent that the server hasn't confirmed yet. Clients work from the
// feedbag as it will be once those changes land, and only confirmed changes
// become part of the confirmed feedbag.
type FeedbagMirror struct {
	mu        sync.Mutex
	confirmed []wire.FeedbagItem
	pending   []feedbagChange
	lastSeq   uint64
}

// feedbagChange is a feedbag change sent to the server and not yet
// confirmed.
type feedbagChange struct {
	seq       uint64
	requestID uint32
	del       bool
	items     []wire.FeedbagItem
}

// Snapshot returns the feedbag with all pending changes applied.
func (m *FeedbagMirror) Snapshot() []wire.FeedbagItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := append([]wire.FeedbagItem(nil), m.confirmed...)
	for _, change := range m.pending {
		items = applyFeedbagChange(items, change.del, change.items)
	}
	return CloneFeedbagItems(items)
}

// Reset replaces the confirmed feedbag with items and forgets pending
// changes.
func (m *FeedbagMirror) Reset(items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.confirmed = CloneFeedbagItems(items)
	m.pending = nil
}

// Sent records a change the client is sending as request requestID. del is
// true when the change deletes items.
func (m *FeedbagMirror) Sent(requestID uint32, del bool, items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSeq++
	m.pending = append(m.pending, feedbagChange{
		seq:       m.lastSeq,
		requestID: requestID,
		del:       del,
		items:     CloneFeedbagItems(items),
	})
}

// Confirm applies the items of change requestID that the server accepted,
// according to results, and forgets the change.
func (m *FeedbagMirror) Confirm(requestID uint32, results []uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.indexOf(requestID)
	if i < 0 {
		return
	}
	change := m.pending[i]
	var accepted []wire.FeedbagItem
	for j, item := range change.items {
		if j < len(results) && results[j] == 0 {
			accepted = append(accepted, item)
		}
	}
	m.confirmed = applyFeedbagChange(m.confirmed, change.del, accepted)
	m.pending = append(m.pending[:i], m.pending[i+1:]...)
}

// Discard forgets change requestID, which the server rejected.
func (m *FeedbagMirror) Discard(requestID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i := m.indexOf(requestID); i >= 0 {
		m.pending = append(m.pending[:i], m.pending[i+1:]...)
	}
}

// HasPending returns true if any change is awaiting confirmation.
func (m *FeedbagMirror) HasPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending) > 0
}

// Mark returns a marker for the changes sent so far, for Reload.
func (m *FeedbagMirror) Mark() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSeq
}

// Reload replaces the confirmed feedbag with items, the server's feedbag as of
// a query sent after the changes up to marker. Those changes are forgotten,
// since the server either applied them or dropped them. Changes sent after the
// query stay pending.
func (m *FeedbagMirror) Reload(marker uint64, items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.confirmed = CloneFeedbagItems(items)
	var pending []feedbagChange
	for _, change := range m.pending {
		if change.seq > marker {
			pending = append(pending, change)
		}
	}
	m.pending = pending
}

// ApplyRemote applies a change made at another of the user's locations. del
// is true when the change deletes items.
func (m *FeedbagMirror) ApplyRemote(del bool, items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.confirmed = applyFeedbagChange(m.confirmed, del, CloneFeedbagItems(items))
}

// GroupNames returns the name of each group by group ID, with all pending
// changes applied.
func (m *FeedbagMirror) GroupNames() map[uint16]string {
	names := make(map[uint16]string)
	for _, item := range m.Snapshot() {
		if item.ClassID == wire.FeedbagClassIdGroup {
			names[item.GroupID] = item.Name
		}
	}
	return names
}

func (m *FeedbagMirror) indexOf(requestID uint32) int {
	for i, change := range m.pending {
		if change.requestID == requestID {
			return i
		}
	}
	return -1
}

// CloneFeedbagItems returns a copy of items that shares no TLV lists with
// them, since FeedbagList edits TLV lists in place.
func CloneFeedbagItems(items []wire.FeedbagItem) []wire.FeedbagItem {
	items = slices.Clone(items)
	for i := range items {
		items[i].TLVList = slices.Clone(items[i].TLVList)
	}
	return items
}

// applyFeedbagChange returns items with changed upserted, or deleted when del
// is true. Items match by group and item ID.
func applyFeedbagChange(items []wire.FeedbagItem, del bool, changed []wire.FeedbagItem) []wire.FeedbagItem {
	for _, item := range changed {
		i := slices.IndexFunc(items, func(existing wire.FeedbagItem) bool {
			return existing.GroupID == item.GroupID && existing.ItemID == item.ItemID
		})
		switch {
		case del && i >= 0:
			items = slices.Delete(items, i, i+1)
		case !del && i >= 0:
			items[i] = item
		case !del:
			items = append(items, item)
		}
	}
	return items
}
