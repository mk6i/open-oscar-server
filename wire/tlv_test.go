package wire

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLVList_Append(t *testing.T) {
	want := TLVList{
		{
			Tag:   0,
			Value: []byte(`0`),
		},
		{
			Tag:   1,
			Value: []byte(`1`),
		},
		{
			Tag:   2,
			Value: []byte(`2`),
		},
	}

	have := TLVList{}
	have.Append(NewTLVBE(0, []byte(`0`)))
	have.Append(NewTLVBE(1, []byte(`1`)))
	have.Append(NewTLVBE(2, []byte(`2`)))

	assert.Equal(t, want, have)
}

func TestTLVList_HasTag(t *testing.T) {
	list := TLVList{
		{
			Tag:   0,
			Value: []byte(`0`),
		},
		{
			Tag:   1,
			Value: []byte(`1`),
		},
		{
			Tag:   2,
			Value: []byte(`2`),
		},
	}

	assert.True(t, list.HasTag(0))
	assert.False(t, list.HasTag(3))
}

func TestTLVList_AppendList(t *testing.T) {
	want := TLVList{
		{
			Tag:   0,
			Value: []byte(`0`),
		},
		{
			Tag:   1,
			Value: []byte(`1`),
		},
		{
			Tag:   2,
			Value: []byte(`2`),
		},
	}

	have := TLVList{}
	have.AppendList([]TLV{
		NewTLVBE(0, []byte(`0`)),
		NewTLVBE(1, []byte(`1`)),
		NewTLVBE(2, []byte(`2`)),
	})

	assert.Equal(t, want, have)
}

func TestTLVList_Getters(t *testing.T) {
	tests := []struct {
		name   string
		given  []TLV
		ttype  any
		lookup func(TLVList) (any, bool)
		expect any
		found  bool
		panic  bool
	}{
		{
			name: "given a TLV of big-endian uint32, expect found value",
			given: []TLV{
				NewTLVBE(0, uint32(12)),
				NewTLVBE(1, uint32(34)),
				NewTLVBE(2, uint32(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint32BE(1)
			},
			expect: uint32(34),
			found:  true,
		},
		{
			name: "given a TLV of big-endian uint32, expect not found value",
			given: []TLV{
				NewTLVBE(0, uint32(12)),
				NewTLVBE(1, uint32(34)),
				NewTLVBE(2, uint32(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint32BE(3)
			},
			expect: uint32(0),
			found:  false,
		},
		{
			name: "given a TLV of big-endian uint16, expect found value",
			given: []TLV{
				NewTLVBE(0, uint16(12)),
				NewTLVBE(1, uint16(34)),
				NewTLVBE(2, uint16(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint16BE(1)
			},
			expect: uint16(34),
			found:  true,
		},
		{
			name: "given a TLV of big-endian uint16, expect not found value",
			given: []TLV{
				NewTLVBE(0, uint16(12)),
				NewTLVBE(1, uint16(34)),
				NewTLVBE(2, uint16(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint16BE(3)
			},
			expect: uint16(0),
			found:  false,
		},
		{
			name: "given a TLV of little-endian uint32, expect found value",
			given: []TLV{
				NewTLVLE(0, uint32(12)),
				NewTLVLE(1, uint32(34)),
				NewTLVLE(2, uint32(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint32LE(1)
			},
			expect: uint32(34),
			found:  true,
		},
		{
			name: "given a TLV of little-endian uint32, expect not found value",
			given: []TLV{
				NewTLVLE(0, uint32(12)),
				NewTLVLE(1, uint32(34)),
				NewTLVLE(2, uint32(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint32LE(3)
			},
			expect: uint32(0),
			found:  false,
		},
		{
			name: "given a TLV of little-endian uint16, expect found value",
			given: []TLV{
				NewTLVLE(0, uint16(12)),
				NewTLVLE(1, uint16(34)),
				NewTLVLE(2, uint16(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint16LE(1)
			},
			expect: uint16(34),
			found:  true,
		},
		{
			name: "given a TLV of little-endian uint16, expect not found value",
			given: []TLV{
				NewTLVLE(0, uint16(12)),
				NewTLVLE(1, uint16(34)),
				NewTLVLE(2, uint16(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint16LE(3)
			},
			expect: uint16(0),
			found:  false,
		},
		{
			name: "given a TLV of uint8, expect found value",
			given: []TLV{
				NewTLVLE(0, uint8(12)),
				NewTLVLE(1, uint8(34)),
				NewTLVLE(2, uint8(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint8(1)
			},
			expect: uint8(34),
			found:  true,
		},
		{
			name: "given a TLV of uint8, expect not found value",
			given: []TLV{
				NewTLVLE(0, uint8(12)),
				NewTLVLE(1, uint8(34)),
				NewTLVLE(2, uint8(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint8(3)
			},
			expect: uint8(0),
			found:  false,
		},
		{
			name: "given a TLV of string, expect found value",
			given: []TLV{
				NewTLVBE(0, "12"),
				NewTLVBE(1, "34"),
				NewTLVBE(2, "56"),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.String(1)
			},
			expect: "34",
			found:  true,
		},
		{
			name: "given a TLV of string, expect not found value",
			given: []TLV{
				NewTLVBE(0, "12"),
				NewTLVBE(1, "34"),
				NewTLVBE(2, "56"),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.String(3)
			},
			expect: "",
			found:  false,
		},
		{
			name: "given a TLV of slice, expect found value",
			given: []TLV{
				NewTLVBE(0, []byte(`12`)),
				NewTLVBE(1, []byte(`34`)),
				NewTLVBE(2, []byte(`56`)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Bytes(1)
			},
			expect: []byte(`34`),
			found:  true,
		},
		{
			name: "given a TLV of string, expect not found value",
			given: []TLV{
				NewTLVBE(0, []byte(`12`)),
				NewTLVBE(1, []byte(`34`)),
				NewTLVBE(2, []byte(`56`)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Bytes(3)
			},
			expect: []byte(nil),
			found:  false,
		},
		{
			name: "expect a panic when there's a type mismatch between big-endian uint16 and uint32",
			given: []TLV{
				NewTLVBE(0, uint16(12)),
				NewTLVBE(1, uint16(34)),
				NewTLVBE(2, uint16(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint32BE(1)
			},
			panic: true,
		},
		{
			name: "expect a panic when there's a type mismatch between little-endian uint16 and uint32",
			given: []TLV{
				NewTLVLE(0, uint16(12)),
				NewTLVLE(1, uint16(34)),
				NewTLVLE(2, uint16(56)),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint32LE(1)
			},
			panic: true,
		},
		{
			name: "given a TLV of big-endian uint16 slice, expect found value",
			given: []TLV{
				NewTLVBE(200, []uint16{12, 34, 56}),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint16SliceBE(200)
			},
			expect: []uint16{12, 34, 56},
			found:  true,
		},
		{
			name: "given a TLV of big-endian uint16 slice, expect not found value",
			given: []TLV{
				NewTLVBE(200, []uint16{12, 34, 56}),
			},
			lookup: func(l TLVList) (any, bool) {
				return l.Uint16SliceBE(50)
			},
			expect: []uint16{},
			found:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panic {
				assert.Panics(t, func() { tt.lookup(tt.given) })
				return
			}
			have, found := tt.lookup(tt.given)
			assert.Equal(t, tt.expect, have)
			assert.Equal(t, tt.found, found)
		})
	}
}

func TestTLVList_NewTLVBEPanic(t *testing.T) {
	// make sure NewTLVBE panics when it encounters an unsupported type, in this
	// case it's int.
	assert.Panics(t, func() {
		NewTLVBE(1, 30)
	})
}

func TestTLVList_NewTLVLEPanic(t *testing.T) {
	// make sure NewTLVLE panics when it encounters an unsupported type, in this
	// case it's int.
	assert.Panics(t, func() {
		NewTLVLE(1, 30)
	})
}

func TestTLVList_ICQString(t *testing.T) {
	// Create a new TLV list
	tlv := TLVList{}

	// Add a valid ICQ string TLV entry to the list
	tlv.Append(NewTLVLE(0x01, []byte{0x09, 0x00, 'k', 'n', 'i', 't', 't', 'i', 'n', 'g', '\x00'}))

	t.Run("Valid ICQString", func(t *testing.T) {
		// Test retrieving a valid ICQ string
		str, ok := tlv.ICQString(0x01)
		assert.True(t, ok)
		assert.Equal(t, "knitting", str)
	})

	t.Run("Non-existent Tag", func(t *testing.T) {
		// Test retrieving an ICQ string for a non-existent tag
		str, ok := tlv.ICQString(0x02)
		assert.False(t, ok)
		assert.Empty(t, str)
	})

	t.Run("Malformed ICQString", func(t *testing.T) {
		// Add a malformed TLV entry (length prefix too short)
		tlvMalformed := TLVList{}
		tlvMalformed.Append(NewTLVLE(0x03, []byte{0x02, 0x00, 'a'})) // Length 2 but only 1 character and no null terminator

		str, ok := tlvMalformed.ICQString(0x03)
		assert.False(t, ok)
		assert.Empty(t, str)
	})

	t.Run("Incorrect Length Prefix", func(t *testing.T) {
		// Add an incorrect length prefix (does not match actual string length)
		tlvIncorrectLength := TLVList{}
		tlvIncorrectLength.Append(NewTLVLE(0x04, []byte{0x0A, 0x00, 'k', 'n', 'i', 't', 't', 'i', 'n', 'g', '\x00'})) // Length prefix is 9 but actual length is 7 + 1 (null terminator)

		str, ok := tlvIncorrectLength.ICQString(0x04)
		assert.False(t, ok)
		assert.Empty(t, str)
	})

	t.Run("Short Length Prefix", func(t *testing.T) {
		// Add a TLV with a length prefix, but the data is too short to contain a valid ICQ string
		tlvShortLength := TLVList{}
		tlvShortLength.Append(NewTLVLE(0x05, []byte{0x05, 0x00})) // Length prefix is 5 but no data

		str, ok := tlvShortLength.ICQString(0x05)
		assert.False(t, ok)
		assert.Empty(t, str)
	})

	t.Run("Empty String", func(t *testing.T) {
		// Add a TLV with an empty ICQ string (just the length prefix and null terminator)
		tlvEmptyString := TLVList{}
		tlvEmptyString.Append(NewTLVLE(0x06, []byte{0x01, 0x00, '\x00'})) // Length prefix is 1 with just null terminator

		str, ok := tlvEmptyString.ICQString(0x06)
		assert.True(t, ok)
		assert.Empty(t, str)
	})
}

func TestTLVList_Replace(t *testing.T) {
	tests := []struct {
		name        string
		given       TLVList
		want        TLVList
		replacement TLV
	}{
		{
			name: "replace multiple TLVs",
			given: TLVList{
				NewTLVLE(0x01, []byte{0x01}),
				NewTLVLE(0x02, []byte{0x02}),
				NewTLVLE(0x01, []byte{0x03}),
				NewTLVLE(0x03, []byte{0x04}),
			},
			replacement: NewTLVLE(0x01, []byte{0xAA}),
			want: TLVList{
				NewTLVLE(0x01, []byte{0xAA}),
				NewTLVLE(0x02, []byte{0x02}),
				NewTLVLE(0x01, []byte{0xAA}),
				NewTLVLE(0x03, []byte{0x04}),
			},
		},
		{
			name: "no matching tags",
			given: TLVList{
				NewTLVLE(0x01, []byte{0x01}),
				NewTLVLE(0x02, []byte{0x02}),
				NewTLVLE(0x01, []byte{0x03}),
				NewTLVLE(0x03, []byte{0x04}),
			},
			replacement: NewTLVLE(0x07, []byte{0xAA}),
			want: TLVList{
				NewTLVLE(0x01, []byte{0x01}),
				NewTLVLE(0x02, []byte{0x02}),
				NewTLVLE(0x01, []byte{0x03}),
				NewTLVLE(0x03, []byte{0x04}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.given.Replace(tt.replacement)
			assert.Equal(t, tt.want, tt.given)
		})
	}
}
