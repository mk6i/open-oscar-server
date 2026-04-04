package state

import (
	"fmt"
	"math"
	"slices"

	"github.com/mk6i/open-oscar-server/wire"
)

// FeedbagList provides operations for manipulating a collection of feedbag
// items. It supports lookups by class/name/group, item insertion with
// automatic ID generation, and transparent root group management.
type FeedbagList struct {
	items          []*wire.FeedbagItem
	randInt        func(int) int
	pendingUpdates []*wire.FeedbagItem
	pendingDeletes []*wire.FeedbagItem
}

// NewFeedbagList creates a FeedbagList from the given items. The randInt
// function is used for generating unique item/group IDs; inject a
// deterministic function in tests to assert exact feedbag item slices.
func NewFeedbagList(items []wire.FeedbagItem, randInt func(int) int) *FeedbagList {
	ptrs := make([]*wire.FeedbagItem, len(items))
	for i := range items {
		ptrs[i] = &items[i]
	}
	return &FeedbagList{
		items:   ptrs,
		randInt: randInt,
	}
}

// SetMode upserts the permit/deny mode item.
func (f *FeedbagList) SetMode(mode uint8) {
	f.upsertItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdPdinfo,
		TLVLBlock: wire.TLVLBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.FeedbagAttributesPdMode, mode),
			},
		},
	})
}

// AddGroup returns the existing group with the given name or creates a new
// one with an auto-generated GroupID. When a new group is created, the root
// group's order TLV is updated to include it. Call PendingUpdates to retrieve
// new or modified items for persistence. Returns the group item.
func (f *FeedbagList) AddGroup(name string) wire.FeedbagItem {
	if g := f.groupByName(name); g != nil {
		return *g
	}

	var root *wire.FeedbagItem
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID == 0 {
			root = item
			break
		}
	}
	if root == nil {
		root = &wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, GroupID: 0}
		f.items = append(f.items, root)
		f.trackUpdate(root)
	}

	group := &wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdGroup,
		Name:    name,
		GroupID: f.genID(),
	}
	f.items = append(f.items, group)

	root.AppendOrderMembers(group.GroupID)
	f.trackUpdate(root)
	f.trackUpdate(group)

	return *group
}

// DeleteGroup marks a group item for deletion by name. If the group exists
// and is not the root group, the root group's order TLV is updated.
func (f *FeedbagList) DeleteGroup(groupName string) {
	deleted, found := f.deleteItem(wire.FeedbagItem{
		Name:    groupName,
		ClassID: wire.FeedbagClassIdGroup,
	})
	if found && deleted.GroupID > 0 {
		for _, item := range f.items {
			if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID == 0 {
				item.RemoveOrderMembers(deleted.GroupID)
				f.trackUpdate(item)
			}
		}
	}
}

// AddBuddy upserts a buddy item in the given group (by name), optionally
// attaching alias and note attributes. Returns true if a new buddy was inserted.
func (f *FeedbagList) AddBuddy(groupName, screenName, alias, note string) (bool, error) {
	group := f.groupByName(groupName)
	if group == nil {
		return false, fmt.Errorf("group %q not found", groupName)
	}
	item := wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdBuddy,
		GroupID: group.GroupID,
		Name:    screenName,
	}
	if alias != "" {
		item.Append(wire.NewTLVBE(wire.FeedbagAttributesAlias, alias))
	}
	if note != "" {
		item.Append(wire.NewTLVBE(wire.FeedbagAttributesNote, note))
	}
	result, inserted := f.upsertItem(item)
	if inserted {
		group.AppendOrderMembers(result.ItemID)
		f.trackUpdate(group)
	}
	return inserted, nil
}

// DeleteBuddy marks a buddy item for deletion in the given group (by name).
// The parent group's order TLV is updated to remove the buddy.
func (f *FeedbagList) DeleteBuddy(groupName, buddyName string) error {
	group := f.groupByName(groupName)
	if group == nil {
		return fmt.Errorf("group %q not found", groupName)
	}
	deleted, found := f.deleteItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdBuddy,
		GroupID: group.GroupID,
		Name:    buddyName,
	})
	if found {
		group.RemoveOrderMembers(deleted.ItemID)
		f.trackUpdate(group)
	}
	return nil
}

// PermitUser upserts a permit-list entry for the given screen name.
func (f *FeedbagList) PermitUser(screenName string) {
	f.upsertItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIDPermit,
		Name:    screenName,
	})
}

// DenyUser upserts a deny-list entry for the given screen name.
func (f *FeedbagList) DenyUser(screenName string) {
	f.upsertItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIDDeny,
		Name:    screenName,
	})
}

// DeletePermit marks a permit-list entry for deletion.
func (f *FeedbagList) DeletePermit(screenName string) {
	f.deleteItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIDPermit,
		Name:    screenName,
	})
}

// DeleteDeny marks a deny-list entry for deletion.
func (f *FeedbagList) DeleteDeny(screenName string) {
	f.deleteItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIDDeny,
		Name:    screenName,
	})
}

// PendingUpdates returns items that were explicitly upserted via upsertItem
// and items that were implicitly created or modified as side effects of other
// operations (e.g., group order updates from upsertItem, root group updates
// from AddGroup). The pending list is cleared after each call.
func (f *FeedbagList) PendingUpdates() []wire.FeedbagItem {
	var result []wire.FeedbagItem
	for _, p := range f.pendingUpdates {
		result = append(result, *p)
	}
	f.pendingUpdates = nil
	if len(result) == 0 {
		return nil
	}
	return result
}

// PendingDeletes returns items marked for deletion via deleteItem.
// The pending list is cleared after each call.
func (f *FeedbagList) PendingDeletes() []wire.FeedbagItem {
	var result []wire.FeedbagItem
	for _, p := range f.pendingDeletes {
		result = append(result, *p)
	}
	f.pendingDeletes = nil
	return result
}

// groupByName returns the group item with the given name, or nil if not found.
func (f *FeedbagList) groupByName(name string) *wire.FeedbagItem {
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.Name == name {
			return item
		}
	}
	return nil
}

// trackUpdate adds item to the pending-updates list if not already present.
func (f *FeedbagList) trackUpdate(item *wire.FeedbagItem) {
	if slices.Contains(f.pendingUpdates, item) {
		return // already tracked
	}
	f.pendingUpdates = append(f.pendingUpdates, item)
}

// itemsMatch reports whether two feedbag items are considered the same for
// upsert/delete (buddy: ClassID, Name, GroupID; others: ClassID and Name).
// Stored items are assumed to have normalized names; the input (b) name is
// normalized for comparison when the class is buddy, permit, or deny.
func (f *FeedbagList) itemsMatch(a, b *wire.FeedbagItem) bool {
	if a.ClassID != b.ClassID {
		return false
	}
	var nameMatch bool
	if hasScreenName(a.ClassID) {
		nameMatch = a.Name == NewIdentScreenName(b.Name).String()
	} else {
		nameMatch = a.Name == b.Name
	}
	if !nameMatch {
		return false
	}
	if a.ClassID == wire.FeedbagClassIdBuddy {
		return a.GroupID == b.GroupID
	}
	return true
}

// deleteItem removes the first item matching the same criteria as upsertItem:
// buddy items by ClassID, Name, and GroupID; other items by ClassID and Name.
// Returns the deleted item and true if found, or a zero item and false otherwise.
func (f *FeedbagList) deleteItem(item wire.FeedbagItem) (wire.FeedbagItem, bool) {
	for i, existing := range f.items {
		if f.itemsMatch(existing, &item) {
			f.pendingDeletes = append(f.pendingDeletes, existing)
			f.items = append(f.items[:i], f.items[i+1:]...)
			return *existing, true
		}
	}
	return wire.FeedbagItem{}, false
}

// upsertItem updates an existing feedbag item or inserts a new one. Buddy
// items are matched by GroupID, ClassID, and Name; all other items are matched
// by ClassID and Name. When matched, the existing item is replaced in place
// (preserving its ItemID). When no match is found, a new item is inserted with
// an auto-generated ItemID. Names for buddy, permit, and deny items are
// normalized before storage. Returns the stored item and true if a new item
// was inserted, or the existing item and false if it was updated/unchanged.
func (f *FeedbagList) upsertItem(item wire.FeedbagItem) (wire.FeedbagItem, bool) {
	if hasScreenName(item.ClassID) {
		item.Name = NewIdentScreenName(item.Name).String() // normalize name
	}
	for _, existing := range f.items {
		if f.itemsMatch(existing, &item) {
			if !existing.IsEqual(item) {
				item.ItemID = existing.ItemID
				*existing = item
				f.trackUpdate(existing)
			}
			return *existing, false
		}
	}

	item.ItemID = f.genID()
	f.items = append(f.items, &item)
	f.pendingUpdates = append(f.pendingUpdates, &item)
	return item, true
}

// genID generates a unique ID that does not conflict with any existing ItemID
// or GroupID in the list.
func (f *FeedbagList) genID() uint16 {
	num := uint16(f.randInt(math.MaxUint16))
	for itemID := num; itemID != num-1; itemID++ {
		if itemID == 0 {
			continue
		}
		exists := false
		for _, item := range f.items {
			if item.GroupID == itemID || item.ItemID == itemID {
				exists = true
				break
			}
		}
		if !exists {
			return itemID
		}
	}
	return 0
}

// hasScreenName reports whether the feedbag class stores a screen name that
// should be normalized (buddy, permit, deny).
func hasScreenName(classID uint16) bool {
	return classID == wire.FeedbagClassIdBuddy ||
		classID == wire.FeedbagClassIDPermit ||
		classID == wire.FeedbagClassIDDeny
}
