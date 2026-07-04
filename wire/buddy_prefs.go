package wire

import "slices"

// Buddy preferences are boolean values stored in a single feedbag item of class
// FeedbagClassIdBuddyPrefs. Each preference is a bit position in a logical
// bitmask spanning two physical bitmasks, each paired with a "valid" bitmask
// that records which positions carry a meaningful value.
//
// The first bitmask (BuddyPrefs, 0x00C9) is fixed at 32 bits (4 bytes) and is
// 0-offset with the most significant bit on the right side. The second bitmask
// (BuddyPrefs2, 0x00D7) is unbounded, positional, with the most significant bit
// on the left side.
//
// Preferences 0-31 live in BuddyPrefs:
//
//	Pref #1:
//	00000000 00000000 00000000 00000010 (BuddyPrefs)
//	                                 ^ offset 1, bit 2
//
//	Pref #31:
//	10000000 00000000 00000000 00000000 (BuddyPrefs)
//	^ offset 31, bit 32
//
// Preferences 32+ live in BuddyPrefs2. The bit offset is (prefNum-33), except
// for the edge case of prefs 32 and 33, which both fall at offset 0 (an
// artifact of the transition from offset- to position-based indexing):
//
//	Pref #52:
//	00000000 00000000 00010000 00000000 (BuddyPrefs2)
//	                     ^ offset 19, bit 52
//
// For each logical bitmask there are two physical bitmasks: the value bitmask
// and the valid bitmask. The valid bitmask disambiguates an unset position:
// i.e. whether an unset value means false or "not present".
//
// The bitmasks are carried in four TLVs:
//
//   - 0x00C9: FeedbagAttributesBuddyPrefs        (value, prefs 0-31)
//   - 0x00D6: FeedbagAttributesBuddyPrefsValid   (valid, prefs 0-31)
//   - 0x00D7: FeedbagAttributesBuddyPrefs2       (value, prefs 32+)
//   - 0x00D8: FeedbagAttributesBuddyPrefs2Valid  (valid, prefs 32+)

// Buddy preference bit numbers. OSCAR defines preferences through
// FeedbagBuddyPrefsImblastInviteNotify (0x4B).
const (
	FeedbagBuddyPrefsDisplayLogin             uint16 = 0x00
	FeedbagBuddyPrefsDisplayEBuddy            uint16 = 0x01
	FeedbagBuddyPrefsPlayEnter                uint16 = 0x02
	FeedbagBuddyPrefsPlayExit                 uint16 = 0x03
	FeedbagBuddyPrefsViewIMStamp              uint16 = 0x04
	FeedbagBuddyPrefsViewSmileys              uint16 = 0x05
	FeedbagBuddyPrefsAcceptIcons              uint16 = 0x06
	FeedbagBuddyPrefsKnockNonAOLIMs           uint16 = 0x08
	FeedbagBuddyPrefsKnockNonListIMs          uint16 = 0x09
	FeedbagBuddyPrefsDiscloseIdle             uint16 = 0x0A
	FeedbagBuddyPrefsAcceptCustomBart         uint16 = 0x0B
	FeedbagBuddyPrefsAcceptNonListBart        uint16 = 0x0C
	FeedbagBuddyPrefsAcceptBgs                uint16 = 0x0D
	FeedbagBuddyPrefsAcceptChromes            uint16 = 0x0E
	FeedbagBuddyPrefsAcceptBLSounds           uint16 = 0x0F
	FeedbagBuddyPrefsAcceptIMSounds           uint16 = 0x10
	FeedbagBuddyPrefsNoSeeRecentBuddies       uint16 = 0x11
	FeedbagBuddyPrefsAcceptSMSLegal           uint16 = 0x12
	FeedbagBuddyPrefsEnterDoesCRLF            uint16 = 0x14
	FeedbagBuddyPrefsPlayIMSound              uint16 = 0x15
	FeedbagBuddyPrefsDiscloseTyping           uint16 = 0x16
	FeedbagBuddyPrefsAcceptSuperIcons         uint16 = 0x18
	FeedbagBuddyPrefsAcceptBLRichText         uint16 = 0x19
	FeedbagBuddyPrefsReduceIMSound            uint16 = 0x1A
	FeedbagBuddyPrefsConfirmDirectIM          uint16 = 0x1B
	FeedbagBuddyPrefsOneTabbedIMWindow        uint16 = 0x1C
	FeedbagBuddyPrefsBuddyInfoOnMouseover     uint16 = 0x1D
	FeedbagBuddyPrefsDiscloseBuddyMatches     uint16 = 0x1E
	FeedbagBuddyPrefsCatchIMs                 uint16 = 0x1F
	FeedbagBuddyPrefsShowFriendlyName         uint16 = 0x20
	FeedbagBuddyPrefsDiscloseRadio            uint16 = 0x21
	FeedbagBuddyPrefsShowCapabilities         uint16 = 0x22
	FeedbagBuddyPrefsShowBuddyListFilter      uint16 = 0x23
	FeedbagBuddyPrefsShowAwayIdle             uint16 = 0x24
	FeedbagBuddyPrefsShowMobile               uint16 = 0x25
	FeedbagBuddyPrefsSortBuddyList            uint16 = 0x26
	FeedbagBuddyPrefsCatchIMsForClient        uint16 = 0x27
	FeedbagBuddyPrefsNewMessageSmallNotify    uint16 = 0x28
	FeedbagBuddyPrefsNoFrequentBuddies        uint16 = 0x29
	FeedbagBuddyPrefsBlogAwayMessages         uint16 = 0x2A
	FeedbagBuddyPrefsBlogAIMSigMessages       uint16 = 0x2B
	FeedbagBuddyPrefsBlogNoComments           uint16 = 0x2C
	FeedbagBuddyPrefsFriendOfFriend           uint16 = 0x2D
	FeedbagBuddyPrefsFriendGetContactList     uint16 = 0x2E
	FeedbagBuddyPrefsCompadInit               uint16 = 0x2F
	FeedbagBuddyPrefsSendBuddyFeed            uint16 = 0x30
	FeedbagBuddyPrefsBlkSendIMWhileAway       uint16 = 0x31
	FeedbagBuddyPrefsShowBuddyFeed            uint16 = 0x32
	FeedbagBuddyPrefsNoSaveVanityInfo         uint16 = 0x33
	FeedbagBuddyPrefsAcceptOfflineIM          uint16 = 0x34
	FeedbagBuddyPrefsShowGroups               uint16 = 0x35
	FeedbagBuddyPrefsSortGroup                uint16 = 0x36
	FeedbagBuddyPrefsShowOfflineBuddies       uint16 = 0x37
	FeedbagBuddyPrefsExpandBuddies            uint16 = 0x38
	FeedbagBuddyPrefsThirdPartyFeeds          uint16 = 0x39
	FeedbagBuddyPrefsNotifyReceivedInvite     uint16 = 0x3A
	FeedbagBuddyPrefsApfAutoAccept            uint16 = 0x3B
	FeedbagBuddyPrefsApfAutoAcceptBuddy       uint16 = 0x3C
	FeedbagBuddyPrefsBlockAwayMsgFeed         uint16 = 0x3D
	FeedbagBuddyPrefsBlockAIMProfileFeed      uint16 = 0x3E
	FeedbagBuddyPrefsBlockAIMPagesFeed        uint16 = 0x3F
	FeedbagBuddyPrefsBlockJournalsFeed        uint16 = 0x40
	FeedbagBuddyPrefsBlockLocationFeed        uint16 = 0x41
	FeedbagBuddyPrefsBlockStickiesFeed        uint16 = 0x42
	FeedbagBuddyPrefsBlockUncutFeed           uint16 = 0x43
	FeedbagBuddyPrefsBlockLinksFeed           uint16 = 0x44
	FeedbagBuddyPrefsBlockAIMBulletinFeed     uint16 = 0x45
	FeedbagBuddyPrefsSaveStatusMsg            uint16 = 0x46
	FeedbagBuddyPrefsApfNotifyReceivedByEmail uint16 = 0x47
	FeedbagBuddyPrefsShowOfflineGrp           uint16 = 0x48
	FeedbagBuddyPrefsOfflineGrpCollapsed      uint16 = 0x49
	FeedbagBuddyPrefsFirstIMSoundOnly         uint16 = 0x4A
	FeedbagBuddyPrefsImblastInviteNotify      uint16 = 0x4B
)

// Web-client-only preferences with no OSCAR equivalent. They are persisted in
// the buddy-prefs bitmask at positions above OSCAR's range (0x4B); no real
// OSCAR client reads or writes these bits.
const (
	FeedbagBuddyPrefsViewIMsInBubbles           uint16 = 0x4C
	FeedbagBuddyPrefsViewIMTimestampsRelative   uint16 = 0x4D
	FeedbagBuddyPrefsGlobalOTR                  uint16 = 0x4E
	FeedbagBuddyPrefsImblastInviteFromBuddyOnly uint16 = 0x4F
)

// buddyPrefTags returns the (valid, value) TLV tags that hold prefNum.
func buddyPrefTags(prefNum uint16) (validTag, valueTag uint16) {
	if prefNum < 32 {
		return FeedbagAttributesBuddyPrefsValid, FeedbagAttributesBuddyPrefs
	}
	return FeedbagAttributesBuddyPrefs2Valid, FeedbagAttributesBuddyPrefs2
}

// buddyPrefBit returns the byte index and bit mask for prefNum within a bitmask
// of the given byte length.
func buddyPrefBit(prefNum uint16, length int) (index int, mask byte) {
	if prefNum < 32 {
		// most significant bit on the right side
		index = (length - 1) - int(prefNum)/8
		return index, byte(1) << (prefNum % 8)
	}
	// most significant bit on the left side
	offset := 0
	if prefNum != 32 {
		offset = int(prefNum) - 33
	}
	index = offset / 8
	return index, byte(0x80) >> (offset % 8)
}

// BuddyPref reads preference prefNum from a feedbag buddy-prefs TLV list. valid
// reports whether the preference is present in the bitmask; value is its boolean
// value, meaningful only when valid is true.
func BuddyPref(list TLVList, prefNum uint16) (valid, value bool) {
	validTag, valueTag := buddyPrefTags(prefNum)

	validBytes, ok := list.Bytes(validTag)
	if !ok {
		return false, false
	}
	valueBytes, ok := list.Bytes(valueTag)
	if !ok {
		return false, false
	}

	index, mask := buddyPrefBit(prefNum, len(validBytes))
	if index < 0 || index >= len(validBytes) || index >= len(valueBytes) {
		return false, false
	}

	valid = validBytes[index]&mask != 0
	value = valueBytes[index]&mask != 0
	return valid, value
}

// SetBuddyPref returns list with preference prefNum set to value and marked
// valid, growing the underlying bitmask byte slices as needed. The value and
// valid TLVs are created if absent and other preference bits are preserved.
func SetBuddyPref(list TLVList, prefNum uint16, value bool) TLVList {
	validTag, valueTag := buddyPrefTags(prefNum)

	// Clone so we never mutate a caller's backing array in place.
	rawValid, _ := list.Bytes(validTag)
	validBytes := slices.Clone(rawValid)
	rawValue, _ := list.Bytes(valueTag)
	valueBytes := slices.Clone(rawValue)

	// Normalize both bitmasks to a common length large enough to hold prefNum.
	var length int
	if prefNum < 32 {
		length = max(4, len(validBytes), len(valueBytes))
		validBytes = leftPad(validBytes, length)
		valueBytes = leftPad(valueBytes, length)
	} else {
		offset := 0
		if prefNum != 32 {
			offset = int(prefNum) - 33
		}
		length = max(offset/8+1, len(validBytes), len(valueBytes))
		validBytes = rightPad(validBytes, length)
		valueBytes = rightPad(valueBytes, length)
	}

	index, mask := buddyPrefBit(prefNum, length)
	validBytes[index] |= mask // a preference we set is always valid
	if value {
		valueBytes[index] |= mask
	} else {
		valueBytes[index] &^= mask
	}

	list = setTLVBytes(list, validTag, validBytes)
	list = setTLVBytes(list, valueTag, valueBytes)
	return list
}

// setTLVBytes replaces the value of tag in list, or appends it when absent.
func setTLVBytes(list TLVList, tag uint16, b []byte) TLVList {
	if list.HasTag(tag) {
		list.Replace(NewTLVBE(tag, b))
		return list
	}
	list.Append(NewTLVBE(tag, b))
	return list
}

// leftPad grows b to length n by prepending zero bytes (bit indexing is
// right-aligned for the fixed BuddyPrefs bitmask).
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(make([]byte, n-len(b)), b...)
}

// rightPad grows b to length n by appending zero bytes (bit indexing is
// left-aligned for the positional BuddyPrefs2 bitmask).
func rightPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(b, make([]byte, n-len(b))...)
}
