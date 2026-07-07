package wire

import (
	"bytes"
	"testing"
)

func TestBuddyPref(t *testing.T) {
	tests := []struct {
		name    string
		prefNum uint16
		list    TLVList
		want    bool
	}{
		{
			// PlayIMSound (0x15) defaults to true when the bitmask is absent.
			name:    "absent bitmask => default true",
			prefNum: FeedbagBuddyPrefsPlayIMSound,
			list:    TLVList{},
			want:    true,
		},
		{
			// AcceptCustomBart (0x0B) defaults to false when the bitmask is absent.
			name:    "absent bitmask => default false",
			prefNum: FeedbagBuddyPrefsAcceptCustomBart,
			list:    TLVList{},
			want:    false,
		},
		{
			// pref 0x34 (=52) lives in BuddyPrefs2 at offset 19 (index 2, mask 0x10).
			// Explicitly set to false, overriding the true default.
			name:    "offline messages disabled",
			prefNum: FeedbagBuddyPrefsAcceptOfflineIM,
			list: TLVList{
				{Tag: FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0, 24, 64}},
				{Tag: FeedbagAttributesBuddyPrefs, Value: []byte{0, 0, 24, 64}},
				{Tag: FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0, 0, 17}},
				{Tag: FeedbagAttributesBuddyPrefs2, Value: []byte{0, 0, 1}},
			},
			want: false,
		},
		{
			// pref 22 lives in BuddyPrefs at index 1, mask 0x40.
			name:    "typing events enabled (pref 22 in BuddyPrefs)",
			prefNum: 22,
			list: TLVList{
				{Tag: FeedbagAttributesBuddyPrefsValid, Value: []byte{0, 0x40, 0, 0}},
				{Tag: FeedbagAttributesBuddyPrefs, Value: []byte{0, 0x40, 0, 0}},
			},
			want: true,
		},
		{
			// prefs 32 and 33 both fall at offset 0 in BuddyPrefs2.
			name:    "pref 33 at shared offset 0",
			prefNum: 33,
			list: TLVList{
				{Tag: FeedbagAttributesBuddyPrefs2Valid, Value: []byte{0x80, 0, 0, 0}},
				{Tag: FeedbagAttributesBuddyPrefs2, Value: []byte{0x80, 0, 0, 0}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuddyPref(tt.list, tt.prefNum); got != tt.want {
				t.Fatalf("BuddyPref(%d) = %v, want %v", tt.prefNum, got, tt.want)
			}
		})
	}
}

func TestSetBuddyPref_RoundTrip(t *testing.T) {
	// Cover both bitmasks (0-31 and 32+), the 32==33 edge, and true/false.
	prefs := []uint16{0x00, 0x16, 0x20, 0x34, 0x49}
	for _, want := range []bool{true, false} {
		for _, prefNum := range prefs {
			list := SetBuddyPref(TLVList{}, prefNum, want)
			if value := BuddyPref(list, prefNum); value != want {
				t.Errorf("pref 0x%02x round-trip: got %v, want %v", prefNum, value, want)
			}
		}
	}
}

func TestSetBuddyPref_PreservesOtherBits(t *testing.T) {
	// Two prefs in the same BuddyPrefs byte, plus one in BuddyPrefs2.
	list := TLVList{}
	list = SetBuddyPref(list, 0x15, false) // playIMSound off
	list = SetBuddyPref(list, 0x16, true)  // discloseTyping on
	list = SetBuddyPref(list, 0x34, true)  // acceptOffLineIM on

	for _, tc := range []struct {
		prefNum   uint16
		wantValue bool
	}{
		{0x15, false},
		{0x16, true},
		{0x34, true},
	} {
		if value := BuddyPref(list, tc.prefNum); value != tc.wantValue {
			t.Errorf("pref 0x%02x = %v, want %v", tc.prefNum, value, tc.wantValue)
		}
	}
}

func TestSetBuddyPref_Encoding(t *testing.T) {
	// pref 0x34 (=52) enabled from empty: BuddyPrefs2 index 2, mask 0x10.
	list := SetBuddyPref(TLVList{}, 0x34, true)

	valid, _ := list.Bytes(FeedbagAttributesBuddyPrefs2Valid)
	value, _ := list.Bytes(FeedbagAttributesBuddyPrefs2)
	if !bytes.Equal(valid, []byte{0, 0, 0x10}) {
		t.Errorf("BuddyPrefs2Valid = %v, want [0 0 16]", valid)
	}
	if !bytes.Equal(value, []byte{0, 0, 0x10}) {
		t.Errorf("BuddyPrefs2 = %v, want [0 0 16]", value)
	}

	// A pref in the fixed bitmask allocates the full 4 bytes.
	list = SetBuddyPref(TLVList{}, 0x15, true) // index 1, mask 0x20
	valid, _ = list.Bytes(FeedbagAttributesBuddyPrefsValid)
	value, _ = list.Bytes(FeedbagAttributesBuddyPrefs)
	if !bytes.Equal(valid, []byte{0, 0x20, 0, 0}) {
		t.Errorf("BuddyPrefsValid = %v, want [0 32 0 0]", valid)
	}
	if !bytes.Equal(value, []byte{0, 0x20, 0, 0}) {
		t.Errorf("BuddyPrefs = %v, want [0 32 0 0]", value)
	}
}
