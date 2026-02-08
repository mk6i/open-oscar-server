package wire

import (
	"bytes"
	"errors"
	"math"
)

// FeedbagPDMode represents a buddy list permit/deny mode setting that
// determines who can interact with a user.
type FeedbagPDMode uint8

const (
	// FeedbagPDModePermitAll allows all users to see and talk to user. This is
	// the session default.
	FeedbagPDModePermitAll FeedbagPDMode = 0x01
	// FeedbagPDModeDenyAll blocks all users from communicating with user.
	FeedbagPDModeDenyAll FeedbagPDMode = 0x02
	// FeedbagPDModePermitSome only allows a specified list of users to see and
	// talk to user and blocks all others from communicating.
	FeedbagPDModePermitSome FeedbagPDMode = 0x03
	// FeedbagPDModeDenySome blocks a list of users from seeing and talking to
	// user and allows all others to communicate.
	FeedbagPDModeDenySome FeedbagPDMode = 0x04
	// FeedbagPDModePermitOnList only allows communication with users on buddy
	// list and blocks all others from communicating.
	FeedbagPDModePermitOnList FeedbagPDMode = 0x05
)

var (
	// ErrNoAvailableItemID is returned when no available itemID can be found.
	ErrNoAvailableItemID = errors.New("no available itemID")
	// ErrGroupNotFound is returned when a group is not found.
	ErrGroupNotFound = errors.New("group not found")
	// ErrBuddyAlreadyExists is returned when a buddy with the same screen name already exists in the group.
	ErrBuddyAlreadyExists = errors.New("buddy already exists")
	// ErrTooManyBuddies is returned when there are too many buddies in the group (max 30).
	ErrTooManyBuddies = errors.New("too many buddies in group. max: 30")
)

type FeedbagItems []FeedbagItem

// FindGroup searches for a group by id.
// Returns the group item and true if found, or an empty FeedbagItem and false if not found.
func (items FeedbagItems) FindGroup(groupID uint16) (FeedbagItem, bool) {
	for _, item := range items {
		if item.ClassID == FeedbagClassIdGroup && item.GroupID == groupID {
			return item, true
		}
	}
	return FeedbagItem{}, false
}

// FindItems finds all items that belong to the given group.
// Returns a slice of items where GroupID matches the given groupID.
func (items FeedbagItems) FindItems(groupID uint16) []FeedbagItem {
	var result []FeedbagItem
	for _, item := range items {
		if item.GroupID == groupID {
			result = append(result, item)
		}
	}
	return result
}

// AddBuddy inserts a buddy into the list and updates its group.
// It creates a buddy item with the given screen name, finds the group,
// generates an available itemID, and updates the group's order TLV to include the new buddy.
// The FeedbagItems slice is updated in place.
// Returns the created buddy item, the updated group item, and an error if the group is not found, no itemID is available, or buddy already exists.
func (items *FeedbagItems) AddBuddy(groupID uint16, buddyScreenName string, randInt func(n int) int) (FeedbagItem, FeedbagItem, error) {
	group, found := items.FindGroup(groupID)
	if !found {
		return FeedbagItem{}, FeedbagItem{}, ErrGroupNotFound
	}

	// Check if buddy already exists and count buddies in group
	groupItems := items.FindItems(groupID)
	buddyCount := 0
	for _, item := range groupItems {
		if item.ClassID == FeedbagClassIdBuddy {
			buddyCount++
			if item.Name == buddyScreenName {
				return item, FeedbagItem{}, ErrBuddyAlreadyExists
			}
		}
	}

	if buddyCount >= 30 {
		return FeedbagItem{}, FeedbagItem{}, ErrTooManyBuddies
	}

	// Find an available itemID using random starting point
	itemID := items.randItemID(randInt)
	if itemID == 0 {
		return FeedbagItem{}, FeedbagItem{}, ErrNoAvailableItemID
	}

	buddyItem := FeedbagItem{
		Name:    buddyScreenName,
		GroupID: groupID,
		ItemID:  itemID,
		ClassID: FeedbagClassIdBuddy,
	}

	// Update the group's order TLV
	if order, hasOrder := group.Bytes(FeedbagAttributesOrder); hasOrder {
		var memberIDs []uint16
		if err := UnmarshalBE(&memberIDs, bytes.NewReader(order)); err != nil {
			return FeedbagItem{}, FeedbagItem{}, err
		}
		group.Replace(NewTLVBE(FeedbagAttributesOrder, append(memberIDs, buddyItem.ItemID)))
	} else {
		group.Append(NewTLVBE(FeedbagAttributesOrder, []uint16{buddyItem.ItemID}))
	}

	// Update the items slice in place
	*items = append(*items, buddyItem)

	// Find and replace the group item in the slice
	for i := range *items {
		if (*items)[i].ClassID == FeedbagClassIdGroup && (*items)[i].GroupID == groupID {
			(*items)[i] = group
			break
		}
	}

	return buddyItem, group, nil
}

// randItemID finds an available itemID by starting from a random number and searching forward.
// It checks both ItemID and GroupID to avoid conflicts.
// Returns 0 if no ID is available.
func (items FeedbagItems) randItemID(randInt func(n int) int) uint16 {
	num := uint16(randInt(math.MaxUint16))
	for itemID := num; itemID != num-1; itemID++ {
		if itemID == 0 {
			continue
		}
		exists := false
		for _, item := range items {
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

type FeedbagItem struct {
	Name    string `oscar:"len_prefix=uint16"`
	GroupID uint16
	ItemID  uint16
	ClassID uint16
	TLVLBlock
}
