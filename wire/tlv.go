package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// TLV represents dynamically typed data in the OSCAR protocol. Each message
// consists of a tag (or key) and a blob value. TLVs are typically grouped
// together in arrays.
type TLV struct {
	Tag   uint16
	Value []byte `oscar:"len_prefix=uint16"`
}

func (t TLV) ICQString() string {
	// Ensure the value is long enough to contain a valid length prefix and value
	if len(t.Value) < 3 {
		return ""
	}

	// Extract the length prefix (first 2 bytes) as a uint16
	expectedLength := binary.LittleEndian.Uint16(t.Value[0:2])

	// Extract the actual string value, excluding the length prefix
	value := t.Value[2:]

	// Check if the length matches the value length (including the null terminator)
	if int(expectedLength) != len(value) {
		return ""
	}

	// Remove the null terminator
	return string(value[:len(value)-1])
}

// Uint8 returns a uint8 representation of the TLV.
func (t TLV) Uint8() uint8 {
	if len(t.Value) > 0 {
		return t.Value[0]
	}
	return 0
}

// Uint16LE returns a uint16 little-endian representation of the TLV.
func (t TLV) Uint16LE() uint16 {
	return binary.LittleEndian.Uint16(t.Value)
}

// Uint16BE returns a uint16 big-endian representation of the TLV.
func (t TLV) Uint16BE() uint16 {
	return binary.BigEndian.Uint16(t.Value)
}

// Uint32LE returns a uint32 little-endian representation of the TLV.
func (t TLV) Uint32LE() uint32 {
	return binary.LittleEndian.Uint32(t.Value)
}

// Uint32BE returns a uint32 big-endian representation of the TLV.
func (t TLV) Uint32BE() uint32 {
	return binary.BigEndian.Uint32(t.Value)
}

// NewTLVBE creates a new TLV. Values are marshalled in big-endian order.
func NewTLVBE(tag uint16, val any) TLV {
	return newTLV(tag, val, binary.BigEndian)
}

// NewTLVLE creates a new TLV. Values are marshalled in little-endian order.
func NewTLVLE(tag uint16, val any) TLV {
	return newTLV(tag, val, binary.LittleEndian)
}

func newTLV(tag uint16, val any, order binary.ByteOrder) TLV {
	t := TLV{
		Tag: tag,
	}
	if _, ok := val.([]byte); ok {
		t.Value = val.([]byte)
	} else {
		buf := &bytes.Buffer{}
		switch order {
		case binary.BigEndian:
			if err := MarshalBE(val, buf); err != nil {
				panic(fmt.Sprintf("unable to create TLV: %s", err.Error()))
			}
		case binary.LittleEndian:
			if err := MarshalLE(val, buf); err != nil {
				panic(fmt.Sprintf("unable to create TLV: %s", err.Error()))
			}
		}
		t.Value = buf.Bytes()
	}
	return t
}

// TLVRestBlock is a type of TLV array that does not have any length
// information encoded in the blob. This typically means that a given offset in
// the SNAC payload, the TLV occupies the "rest" of the payload.
type TLVRestBlock struct {
	TLVList
}

// TLVBlock is a type of TLV array that has the TLV element count encoded as a
// 2-byte value at the beginning of the encoded blob.
type TLVBlock struct {
	TLVList `oscar:"count_prefix=uint16"`
}

// TLVLBlock is a type of TLV array that has the TLV blob byte-length encoded
// as a 2-byte value at the beginning of the encoded blob.
type TLVLBlock struct {
	TLVList `oscar:"len_prefix=uint16"`
}

// TLVList is a list of TLV elements. It provides methods to append and access
// TLVs in the array. It provides methods that decode the data blob into the
// appropriate type at runtime. The caller assumes the TLV data type at runtime
// based on the protocol specification. These methods are not safe for
// read-write access by  multiple goroutines.
type TLVList []TLV

// Append adds a TLV to the end of the TLV list.
func (s *TLVList) Append(tlv TLV) {
	*s = append(*s, tlv)
}

// AppendList adds a TLV list to the end of the TLV list.
func (s *TLVList) AppendList(tlvs []TLV) {
	*s = append(*s, tlvs...)
}

// HasTag indicates if a TLV list has a tag.
func (s *TLVList) HasTag(tag uint16) bool {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return true
		}
	}
	return false
}

// Replace updates the values of TLVs in the list with the same tag as new. If
// no matching tag is found, the list remains unchanged.
func (s *TLVList) Replace(new TLV) {
	for i, old := range *s {
		if old.Tag == new.Tag {
			(*s)[i].Value = new.Value
		}
	}
}

// String retrieves the string value associated with the specified tag from the
// TLVList.
//
// If the specified tag is found, the function returns the associated string
// value and true. If the tag is not found, the function returns an empty
// string and false.
func (s *TLVList) String(tag uint16) (string, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return string(tlv.Value), true
		}
	}
	return "", false
}

// ICQString retrieves the ICQ string value associated with the specified tag
// from the TLVList.
//
// An ICQ string is a string that is prefixed with its length and ends with a
// null terminator.
//
// If the specified tag is found, the function returns the extracted string
// value and true. If the tag is not found or the string is malformed, the
// function returns an empty string and false.
func (s *TLVList) ICQString(tag uint16) (string, bool) {
	// Find the TLV entry with the specified tag
	for _, tlv := range *s {
		if tag != tlv.Tag {
			continue
		}
		return tlv.ICQString(), true
	}

	// Tag not found
	return "", false
}

// Bytes retrieves the byte payload associated with the specified tag from the
// TLVList.
//
// If the specified tag is found, the function returns the associated byte
// slice and true. If the tag is not found, the function returns nil and false.
func (s *TLVList) Bytes(tag uint16) ([]byte, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return tlv.Value, true
		}
	}
	return nil, false
}

// Uint8 retrieves a byte value from the TLVList associated with the specified
// tag.
//
// If the specified tag is found, the function returns the associated value
// as a uint8 and true. If the tag is not found, the function returns 0 and
// false.
func (s *TLVList) Uint8(tag uint16) (uint8, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return tlv.Uint8(), true
		}
	}
	return 0, false
}

// Uint16BE retrieves a 16-bit unsigned integer value from the TLVList
// associated with the specified tag, interpreting the bytes in big-endian
// format.
//
// If the specified tag is found, the function returns the associated value
// as a uint16 and true. If the tag is not found, the function returns 0 and
// false.
func (s *TLVList) Uint16BE(tag uint16) (uint16, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return tlv.Uint16BE(), true
		}
	}
	return 0, false
}

// Uint16LE retrieves a 16-bit unsigned integer value from the TLVList
// associated with the specified tag, interpreting the bytes in little-endian
// format.
//
// If the specified tag is found, the function returns the associated value
// as a uint16 and true. If the tag is not found, the function returns 0 and
// false.
func (s *TLVList) Uint16LE(tag uint16) (uint16, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return tlv.Uint16LE(), true
		}
	}
	return 0, false
}

// Uint32BE retrieves a 32-bit unsigned integer value from the TLVList
// associated with the specified tag, interpreting the bytes in big-endian format.
//
// If the specified tag is found, the function returns the associated value
// as a uint32 and true. If the tag is not found, the function returns 0 and false.
func (s *TLVList) Uint32BE(tag uint16) (uint32, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return tlv.Uint32BE(), true
		}
	}
	return 0, false
}

// Uint32LE retrieves a 32-bit unsigned integer value from the TLVList
// associated with the specified tag, interpreting the bytes in little-endian format.
//
// If the specified tag is found, the function returns the associated value
// as a uint32 and true. If the tag is not found, the function returns 0 and false.
func (s *TLVList) Uint32LE(tag uint16) (uint32, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			return tlv.Uint32LE(), true
		}
	}
	return 0, false
}

// Uint16SliceBE retrieves a slice of 16-bit unsigned integer values from the TLVList
// associated with the specified tag, interpreting the bytes in big-endian format.
//
// If the specificed tag is found, the function returns the associated value as a
// uint16 slice and true. If the tag is not found, the function returns an empty
// slice and false.
func (s *TLVList) Uint16SliceBE(tag uint16) ([]uint16, bool) {
	for _, tlv := range *s {
		if tag == tlv.Tag {
			outputLen := len(tlv.Value) / 2
			outputSlice := make([]uint16, outputLen)
			for i := range outputLen {
				chunk := tlv.Value[i*2 : (i*2)+2]
				outputSlice[i] = binary.BigEndian.Uint16(chunk)
			}
			return outputSlice, true
		}
	}
	return []uint16{}, false
}
