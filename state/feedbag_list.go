package state

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/mk6i/open-oscar-server/wire"
)

// ErrGroupNotFound is returned when a feedbag group cannot be found.
var ErrGroupNotFound = errors.New("group not found")

// ErrGroupExists is returned when a feedbag group cannot be created or renamed
// because another group already has the target name.
var ErrGroupExists = errors.New("group already exists")

// ErrBuddyNotFound is returned when a feedbag buddy cannot be found.
var ErrBuddyNotFound = errors.New("buddy not found")

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

	group := &wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdGroup,
		Name:    name,
		GroupID: f.genID(),
	}
	f.items = append(f.items, group)

	root := f.rootGroup()
	root.AppendOrderMembers(group.GroupID)
	f.trackUpdate(root)
	f.trackUpdate(group)

	return *group
}

// DeleteGroup marks a group item for deletion by name. If the group exists
// and is not the root group, the root group's order TLV is updated.
func (f *FeedbagList) DeleteGroup(groupName string) {
	groupItem := f.groupByName(groupName)
	if groupItem == nil {
		return
	}

	var toDelete []*wire.FeedbagItem

	for _, item := range f.items {
		if item.GroupID == groupItem.GroupID {
			toDelete = append(toDelete, item)
		}
	}

	for _, item := range toDelete {
		f.deleteItem(*item)
	}

	if len(toDelete) > 0 && groupItem.GroupID != 0 {
		for _, item := range f.items {
			if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID == 0 {
				item.RemoveOrderMembers(groupItem.GroupID)
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
// Pass "*" as groupName to remove the buddy from all groups.
func (f *FeedbagList) DeleteBuddy(groupName, buddyName string) error {
	var groups []*wire.FeedbagItem

	if groupName == "*" {
		// delete from all groups
		for _, item := range f.items {
			if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID != 0 {
				groups = append(groups, item)
			}
		}
	} else {
		group := f.groupByName(groupName)
		if group == nil {
			return fmt.Errorf("%w: %q", ErrGroupNotFound, groupName)
		}
		groups = []*wire.FeedbagItem{group}
	}

	for _, group := range groups {
		deleted, found := f.deleteItem(wire.FeedbagItem{
			ClassID: wire.FeedbagClassIdBuddy,
			GroupID: group.GroupID,
			Name:    buddyName,
		})
		if found {
			group.RemoveOrderMembers(deleted.ItemID)
			f.trackUpdate(group)
		}
	}

	return nil
}

// RenameGroup changes a group's name in place, preserving its GroupID and
// ItemID. Returns ErrGroupNotFound if oldName does not exist, or ErrGroupExists
// if a different group already uses newName. The group is renamed in place
// rather than re-inserted because upsertItem keys groups on name and would
// otherwise create a duplicate.
func (f *FeedbagList) RenameGroup(oldName, newName string) error {
	group := f.groupByName(oldName)
	if group == nil {
		return fmt.Errorf("%w: %q", ErrGroupNotFound, oldName)
	}
	if newName != oldName && f.groupByName(newName) != nil {
		return fmt.Errorf("%w: %q", ErrGroupExists, newName)
	}
	if group.Name == newName {
		return nil
	}
	group.Name = newName
	f.trackUpdate(group)
	return nil
}

// MoveBuddy moves a buddy between groups and/or repositions it within a group's
// order. When toGroup names a different group than fromGroup, the buddy's
// feedbag item is deleted from the source group and re-inserted into the
// destination (a buddy's identity includes its GroupID at the protocol level),
// carrying over its alias and note attributes. When beforeBuddy is non-empty,
// the buddy is positioned immediately before that buddy in the destination
// group's order; otherwise it is appended. Returns ErrGroupNotFound or
// ErrBuddyNotFound if the source group/buddy or destination group is missing.
func (f *FeedbagList) MoveBuddy(fromGroup, toGroup, buddyName, beforeBuddy string) error {
	src := f.groupByName(fromGroup)
	if src == nil {
		return fmt.Errorf("%w: %q", ErrGroupNotFound, fromGroup)
	}
	srcBuddy := f.buddyItem(src, buddyName)
	if srcBuddy == nil {
		return fmt.Errorf("%w: %q", ErrBuddyNotFound, buddyName)
	}

	dst := src
	if toGroup != "" && toGroup != fromGroup {
		dst = f.groupByName(toGroup)
		if dst == nil {
			return fmt.Errorf("%w: %q", ErrGroupNotFound, toGroup)
		}

		alias, _ := srcBuddy.String(wire.FeedbagAttributesAlias)
		note, _ := srcBuddy.String(wire.FeedbagAttributesNote)

		if err := f.DeleteBuddy(fromGroup, buddyName); err != nil {
			return err
		}
		if _, err := f.AddBuddy(toGroup, buddyName, alias, note); err != nil {
			return err
		}
	}

	if beforeBuddy != "" {
		moved := f.buddyItem(dst, buddyName)
		before := f.buddyItem(dst, beforeBuddy)
		if moved != nil && before != nil {
			f.reorderInGroupOrder(dst, moved.ItemID, before.ItemID)
		}
	}

	return nil
}

// SetBuddyAlias sets (or, when alias is empty, clears) the alias attribute on
// every buddy item matching buddyName across all groups. Returns true if at
// least one buddy item was found.
func (f *FeedbagList) SetBuddyAlias(buddyName, alias string) (bool, error) {
	buddies := f.buddyItemsByName(buddyName)
	if len(buddies) == 0 {
		return false, nil
	}
	for _, buddy := range buddies {
		if alias != "" {
			setItemTLV(buddy, wire.FeedbagAttributesAlias, alias)
		} else {
			clearItemTLV(buddy, wire.FeedbagAttributesAlias)
		}
		f.trackUpdate(buddy)
	}
	return true, nil
}

// SetGroupCollapsed sets (or, when collapsed is false, clears) the collapsed
// attribute on a group. An empty groupName targets the unnamed default group.
// Returns ErrGroupNotFound if the group does not exist.
func (f *FeedbagList) SetGroupCollapsed(groupName string, collapsed bool) error {
	group := f.groupByName(groupName)
	if group == nil {
		return fmt.Errorf("%w: %q", ErrGroupNotFound, groupName)
	}
	if collapsed {
		setItemTLV(group, wire.FeedbagAttributesCollapsed, []byte{})
	} else {
		clearItemTLV(group, wire.FeedbagAttributesCollapsed)
	}
	f.trackUpdate(group)
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

// AddLinkedScreenName adds a linked screen name.
func (f *FeedbagList) AddLinkedScreenName(screenName string) {
	f.upsertItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdAlInfo,
		Name:    screenName,
	})
}

// DeleteLinkedScreenName deletes a linked screen name.
func (f *FeedbagList) DeleteLinkedScreenName(screenName string) {
	_, deleted := f.deleteItem(wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdAlInfo,
		Name:    screenName,
	})

	if deleted {
		// touch the root group so that the client purges its local
		// buddy list cache
		f.trackUpdate(f.rootGroup())
	}
}

// LinkedScreenNames returns all linked screen names in the feedbag.
func (f *FeedbagList) LinkedScreenNames() []IdentScreenName {
	var names []IdentScreenName
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdAlInfo {
			names = append(names, NewIdentScreenName(item.Name))
		}
	}
	return names
}

// HasLinkedScreenName returns whether the feedbag has a linked screen name.
func (f *FeedbagList) HasLinkedScreenName(screenName string) bool {
	return slices.ContainsFunc(f.items, func(item *wire.FeedbagItem) bool {
		return item.ClassID == wire.FeedbagClassIdAlInfo && item.Name == NewIdentScreenName(screenName).String()
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

func (f *FeedbagList) Items() []wire.FeedbagItem {
	var result []wire.FeedbagItem
	for _, p := range f.items {
		result = append(result, *p)
	}
	return result
}

// rootGroup retrieves the root group, creating one if non-existent.
func (f *FeedbagList) rootGroup() *wire.FeedbagItem {
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
	return root
}

// groupByName returns the group item with the given name, or nil if not found.
// The root group (GroupID 0) is never returned; it holds the master group order
// rather than buddies, and an empty name matches the unnamed default buddy group.
func (f *FeedbagList) groupByName(name string) *wire.FeedbagItem {
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID != 0 && item.Name == name {
			return item
		}
	}
	return nil
}

// buddyItem returns the buddy item with the given name in the given group, or
// nil if not found. Names are normalized before comparison.
func (f *FeedbagList) buddyItem(group *wire.FeedbagItem, buddyName string) *wire.FeedbagItem {
	want := NewIdentScreenName(buddyName).String()
	for _, item := range f.items {
		if item.ClassID != wire.FeedbagClassIdBuddy || item.GroupID != group.GroupID {
			continue
		}
		if NewIdentScreenName(item.Name).String() == want {
			return item
		}
	}
	return nil
}

// buddyItemsByName returns every buddy item matching buddyName across all
// groups. Names are normalized before comparison.
func (f *FeedbagList) buddyItemsByName(buddyName string) []*wire.FeedbagItem {
	want := NewIdentScreenName(buddyName).String()
	var out []*wire.FeedbagItem
	for _, item := range f.items {
		if item.ClassID != wire.FeedbagClassIdBuddy {
			continue
		}
		if NewIdentScreenName(item.Name).String() == want {
			out = append(out, item)
		}
	}
	return out
}

// reorderInGroupOrder moves itemID so that it sits immediately before
// beforeItemID in the group's order TLV. If beforeItemID is not present, itemID
// is appended. The group is tracked as updated.
func (f *FeedbagList) reorderInGroupOrder(group *wire.FeedbagItem, itemID, beforeItemID uint16) {
	order, ok := group.Uint16SliceBE(wire.FeedbagAttributesOrder)
	if !ok {
		return
	}
	filtered := make([]uint16, 0, len(order))
	for _, id := range order {
		if id != itemID {
			filtered = append(filtered, id)
		}
	}
	insertAt := len(filtered)
	for i, id := range filtered {
		if id == beforeItemID {
			insertAt = i
			break
		}
	}
	reordered := make([]uint16, 0, len(filtered)+1)
	reordered = append(reordered, filtered[:insertAt]...)
	reordered = append(reordered, itemID)
	reordered = append(reordered, filtered[insertAt:]...)

	if group.HasTag(wire.FeedbagAttributesOrder) {
		group.Replace(wire.NewTLVBE(wire.FeedbagAttributesOrder, reordered))
	} else {
		group.Append(wire.NewTLVBE(wire.FeedbagAttributesOrder, reordered))
	}
	f.trackUpdate(group)
}

// setItemTLV sets a single attribute TLV on item, replacing an existing TLV
// with the same tag or appending a new one. Mirrors AppendOrderMembers'
// replace-or-append pattern since TLVList.Replace no-ops when the tag is absent.
func setItemTLV(item *wire.FeedbagItem, tag uint16, value any) {
	if item.HasTag(tag) {
		item.Replace(wire.NewTLVBE(tag, value))
	} else {
		item.Append(wire.NewTLVBE(tag, value))
	}
}

// clearItemTLV removes every TLV with the given tag from item.
func clearItemTLV(item *wire.FeedbagItem, tag uint16) {
	filtered := item.TLVList[:0:0]
	for _, tlv := range item.TLVList {
		if tlv.Tag != tag {
			filtered = append(filtered, tlv)
		}
	}
	item.TLVList = filtered
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
		nameMatch = NewIdentScreenName(a.Name).String() == NewIdentScreenName(b.Name).String()
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
		classID == wire.FeedbagClassIdAlInfo ||
		classID == wire.FeedbagClassIDDeny
}
