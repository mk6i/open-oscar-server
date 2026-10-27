package client

import (
	"errors"
	"math/rand/v2"
	"strings"

	"github.com/mk6i/open-oscar-server/wire"
)

// DefaultBuddyGroup is the group buddies are added to when none is given.
const DefaultBuddyGroup = "Buddies"

// ErrNotFound indicates that a buddy or block list entry does not exist.
var ErrNotFound = errors.New("not found")

// NormalizeScreenName returns the canonical form of a screen name, which is
// lower case without spaces. Two screen names refer to the same user if their
// normalized forms are equal.
func NormalizeScreenName(screenName string) string {
	return strings.ToLower(strings.ReplaceAll(screenName, " ", ""))
}

// BuddyGroup is a group on the server-stored buddy list.
type BuddyGroup struct {
	Name    string
	Buddies []Buddy
}

// Buddy is an entry on the buddy list, along with the buddy's presence.
type Buddy struct {
	ScreenName string
	// Online indicates whether the buddy is signed on. Info is only set when
	// the buddy is online.
	Online bool
	Info   UserInfo
}

// feedbagChange is a set of item changes to send to the server.
type feedbagChange struct {
	deletes []wire.FeedbagItem
	inserts []wire.FeedbagItem
	updates []wire.FeedbagItem
}

func (c feedbagChange) empty() bool {
	return len(c.deletes) == 0 && len(c.inserts) == 0 && len(c.updates) == 0
}

// feedbag mirrors the user's server-stored buddy list (feedbag). Methods named
// plan* compute the changes for an operation without modifying the mirror;
// apply records changes once the server has accepted them.
type feedbag struct {
	items []wire.FeedbagItem
}

// key identifies a feedbag item.
type feedbagKey struct {
	groupID uint16
	itemID  uint16
}

func keyOf(item wire.FeedbagItem) feedbagKey {
	return feedbagKey{groupID: item.GroupID, itemID: item.ItemID}
}

// apply records items deleted, inserted or updated on the server.
func (f *feedbag) apply(del bool, items []wire.FeedbagItem) {
	for _, item := range items {
		idx := -1
		for i, existing := range f.items {
			if keyOf(existing) == keyOf(item) {
				idx = i
				break
			}
		}
		switch {
		case del && idx >= 0:
			f.items = append(f.items[:idx], f.items[idx+1:]...)
		case !del && idx >= 0:
			f.items[idx] = item
		case !del:
			f.items = append(f.items, item)
		}
	}
}

func (f *feedbag) root() (wire.FeedbagItem, bool) {
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID == 0 {
			return item, true
		}
	}
	return wire.FeedbagItem{}, false
}

func (f *feedbag) groupByID(id uint16) (wire.FeedbagItem, bool) {
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID == id {
			return item, true
		}
	}
	return wire.FeedbagItem{}, false
}

func (f *feedbag) groupByName(name string) (wire.FeedbagItem, bool) {
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID != 0 && strings.EqualFold(item.Name, name) {
			return item, true
		}
	}
	return wire.FeedbagItem{}, false
}

// genID returns a random ID unused by any item or group.
func (f *feedbag) genID(reserved ...uint16) uint16 {
	for {
		id := uint16(rand.IntN(0x7FFF) + 1)
		used := false
		for _, item := range f.items {
			if item.ItemID == id || item.GroupID == id {
				used = true
				break
			}
		}
		for _, r := range reserved {
			if r == id {
				used = true
			}
		}
		if !used {
			return id
		}
	}
}

// groups returns the buddy list groups in display order. Buddies carry no
// presence info.
func (f *feedbag) groups() []BuddyGroup {
	var groupIDs []uint16
	seen := map[uint16]bool{}
	if root, ok := f.root(); ok {
		order, _ := root.Uint16SliceBE(wire.FeedbagAttributesOrder)
		for _, id := range order {
			if _, ok := f.groupByID(id); ok && !seen[id] {
				groupIDs = append(groupIDs, id)
				seen[id] = true
			}
		}
	}
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdGroup && item.GroupID != 0 && !seen[item.GroupID] {
			groupIDs = append(groupIDs, item.GroupID)
			seen[item.GroupID] = true
		}
	}

	var groups []BuddyGroup
	for _, id := range groupIDs {
		group, _ := f.groupByID(id)
		bg := BuddyGroup{Name: group.Name}

		byItemID := map[uint16]wire.FeedbagItem{}
		for _, item := range f.items {
			if item.ClassID == wire.FeedbagClassIdBuddy && item.GroupID == id {
				byItemID[item.ItemID] = item
			}
		}
		order, _ := group.Uint16SliceBE(wire.FeedbagAttributesOrder)
		for _, itemID := range order {
			if item, ok := byItemID[itemID]; ok {
				bg.Buddies = append(bg.Buddies, Buddy{ScreenName: item.Name})
				delete(byItemID, itemID)
			}
		}
		// buddies missing from the group order go last, in feedbag order
		for _, item := range f.items {
			if _, ok := byItemID[item.ItemID]; ok && item.ClassID == wire.FeedbagClassIdBuddy && item.GroupID == id {
				bg.Buddies = append(bg.Buddies, Buddy{ScreenName: item.Name})
			}
		}
		groups = append(groups, bg)
	}
	return groups
}

// buddyItems returns the buddy items for screenName in any group.
func (f *feedbag) buddyItems(screenName string) []wire.FeedbagItem {
	var out []wire.FeedbagItem
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdBuddy && NormalizeScreenName(item.Name) == NormalizeScreenName(screenName) {
			out = append(out, item)
		}
	}
	return out
}

// planAddBuddy adds screenName to groupName, creating the group if needed.
func (f *feedbag) planAddBuddy(groupName, screenName string) feedbagChange {
	var c feedbagChange

	group, ok := f.groupByName(groupName)
	if !ok {
		root, hasRoot := f.root()
		if !hasRoot {
			root = wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup}
		}
		group = wire.FeedbagItem{
			ClassID: wire.FeedbagClassIdGroup,
			Name:    groupName,
			GroupID: f.genID(),
		}
		root.AppendOrderMembers(group.GroupID)
		if hasRoot {
			c.updates = append(c.updates, root)
		} else {
			c.inserts = append(c.inserts, root)
		}
	} else {
		for _, item := range f.buddyItems(screenName) {
			if item.GroupID == group.GroupID {
				return c // already in this group
			}
		}
	}

	buddy := wire.FeedbagItem{
		ClassID: wire.FeedbagClassIdBuddy,
		Name:    screenName,
		GroupID: group.GroupID,
		ItemID:  f.genID(group.GroupID),
	}
	group.AppendOrderMembers(buddy.ItemID)

	if ok {
		c.inserts = append(c.inserts, buddy)
		c.updates = append(c.updates, group)
	} else {
		// a new group goes in ahead of its first buddy
		c.inserts = append(c.inserts, group, buddy)
	}
	return c
}

// planRemoveBuddy removes screenName from every group.
func (f *feedbag) planRemoveBuddy(screenName string) (feedbagChange, error) {
	var c feedbagChange
	items := f.buddyItems(screenName)
	if len(items) == 0 {
		return c, ErrNotFound
	}
	changedGroups := map[uint16]wire.FeedbagItem{}
	for _, item := range items {
		c.deletes = append(c.deletes, item)
		group, ok := changedGroups[item.GroupID]
		if !ok {
			if group, ok = f.groupByID(item.GroupID); !ok {
				continue
			}
		}
		group.RemoveOrderMembers(item.ItemID)
		changedGroups[item.GroupID] = group
	}
	for _, group := range changedGroups {
		c.updates = append(c.updates, group)
	}
	return c, nil
}

// pdMode returns the permit/deny mode, defaulting to permit-all.
func (f *feedbag) pdMode() wire.FeedbagPDMode {
	if item, ok := f.pdInfo(); ok {
		if mode, ok := item.Uint8(wire.FeedbagAttributesPdMode); ok {
			return wire.FeedbagPDMode(mode)
		}
	}
	return wire.FeedbagPDModePermitAll
}

func (f *feedbag) pdInfo() (wire.FeedbagItem, bool) {
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIdPdinfo {
			return item, true
		}
	}
	return wire.FeedbagItem{}, false
}

// denied returns the screen names on the deny (block) list.
func (f *feedbag) denied() []string {
	var out []string
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIDDeny {
			out = append(out, item.Name)
		}
	}
	return out
}

func (f *feedbag) isDenied(screenName string) bool {
	_, ok := f.denyItem(screenName)
	return ok
}

func (f *feedbag) denyItem(screenName string) (wire.FeedbagItem, bool) {
	for _, item := range f.items {
		if item.ClassID == wire.FeedbagClassIDDeny && NormalizeScreenName(item.Name) == NormalizeScreenName(screenName) {
			return item, true
		}
	}
	return wire.FeedbagItem{}, false
}

// planBlock adds screenName to the deny list. The server only enforces the
// deny list in deny-some mode, so the mode is switched to it.
func (f *feedbag) planBlock(screenName string) feedbagChange {
	var c feedbagChange
	var denyID uint16
	if !f.isDenied(screenName) {
		denyID = f.genID()
		c.inserts = append(c.inserts, wire.FeedbagItem{
			ClassID: wire.FeedbagClassIDDeny,
			Name:    screenName,
			ItemID:  denyID,
		})
	}
	if f.pdMode() != wire.FeedbagPDModeDenySome {
		item, ok := f.pdInfo()
		if !ok {
			item = wire.FeedbagItem{
				ClassID: wire.FeedbagClassIdPdinfo,
				ItemID:  f.genID(denyID),
			}
		}
		item.Set(wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(wire.FeedbagPDModeDenySome)))
		if ok {
			c.updates = append(c.updates, item)
		} else {
			c.inserts = append(c.inserts, item)
		}
	}
	return c
}

// planUnblock removes screenName from the deny list.
func (f *feedbag) planUnblock(screenName string) (feedbagChange, error) {
	item, ok := f.denyItem(screenName)
	if !ok {
		return feedbagChange{}, ErrNotFound
	}
	return feedbagChange{deletes: []wire.FeedbagItem{item}}, nil
}
