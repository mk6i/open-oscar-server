package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

var (
	ErrUnmarshalFailure  = errors.New("failed to unmarshal")
	errNotNullTerminated = errors.New("nullterm tag is set, but string is not null-terminated")
)

// UnmarshalBE unmarshalls OSCAR protocol messages in big-endian format.
func UnmarshalBE(v any, r io.Reader) error {
	if err := unmarshal(reflect.TypeOf(v).Elem(), reflect.ValueOf(v).Elem(), "", r, binary.BigEndian, ""); err != nil {
		return fmt.Errorf("%w: %w", ErrUnmarshalFailure, err)
	}
	return nil
}

// UnmarshalLE unmarshalls OSCAR protocol messages in little-endian format.
func UnmarshalLE(v any, r io.Reader) error {
	if err := unmarshal(reflect.TypeOf(v).Elem(), reflect.ValueOf(v).Elem(), "", r, binary.LittleEndian, ""); err != nil {
		return fmt.Errorf("%w: %w", ErrUnmarshalFailure, err)
	}
	return nil
}

func unmarshal(t reflect.Type, v reflect.Value, tag reflect.StructTag, r io.Reader, order binary.ByteOrder, activeQuirk string) error {
	oscTag, err := parseOSCARTag(tag)
	if err != nil {
		return fmt.Errorf("error parsing tag: %w", err)
	}
	effectiveQuirk := strings.TrimSpace(oscTag.quirk)
	if effectiveQuirk == "" {
		effectiveQuirk = activeQuirk
	}

	if oscTag.optional {
		v.Set(reflect.New(t.Elem()))
		err := unmarshalStruct(t.Elem(), v.Elem(), oscTag, r, order, effectiveQuirk)
		if errors.Is(err, io.EOF) {
			// no values to read, but that's ok since this struct is optional
			v.Set(reflect.Zero(t))
			err = nil
		}
		return err
	} else if v.Kind() == reflect.Ptr {
		return errNonOptionalPointer
	}

	switch v.Kind() {
	case reflect.Array:
		return unmarshalArray(v, r, order, effectiveQuirk)
	case reflect.Slice:
		return unmarshalSlice(v, oscTag, r, order, effectiveQuirk)
	case reflect.String:
		return unmarshalString(v, oscTag, r, order)
	case reflect.Struct:
		return unmarshalStruct(t, v, oscTag, r, order, effectiveQuirk)
	case reflect.Uint8:
		var l uint8
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	case reflect.Uint16:
		var l uint16
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	case reflect.Uint32:
		var l uint32
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	case reflect.Uint64:
		var l uint64
		if err := binary.Read(r, order, &l); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(l))
		return nil
	default:
		return fmt.Errorf("unsupported type %v", t.Kind())
	}
}

func unmarshalArray(v reflect.Value, r io.Reader, order binary.ByteOrder, activeQuirk string) error {
	arrLen := v.Len()
	arrType := v.Type().Elem()

	for i := 0; i < arrLen; i++ {
		elem := reflect.New(arrType).Elem()
		if err := unmarshal(arrType, elem, "", r, order, activeQuirk); err != nil {
			return err
		}
		v.Index(i).Set(elem)
	}

	return nil
}

func unmarshalSlice(v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder, activeQuirk string) error {
	slice := reflect.New(v.Type()).Elem()
	elemType := v.Type().Elem()

	if oscTag.hasLenPrefix {
		bufLen, err := unmarshalUnsignedInt(oscTag.lenPrefix, r, order)
		if err != nil {
			return err
		}
		b := make([]byte, bufLen)
		if bufLen > 0 {
			if _, err := io.ReadFull(r, b); err != nil {
				return err
			}
		}
		buf := bytes.NewBuffer(b)
		for buf.Len() > 0 {
			elem := reflect.New(elemType).Elem()
			if err := unmarshalSliceElement(elemType, elem, buf, order, activeQuirk); err != nil {
				return err
			}
			slice = reflect.Append(slice, elem)
		}
	} else if oscTag.hasCountPrefix {
		count, err := unmarshalUnsignedInt(oscTag.countPrefix, r, order)
		if err != nil {
			return err
		}

		for i := 0; i < count; i++ {
			elem := reflect.New(elemType).Elem()
			if err := unmarshalSliceElement(elemType, elem, r, order, activeQuirk); err != nil {
				return err
			}
			slice = reflect.Append(slice, elem)
		}
	} else {
		for {
			elem := reflect.New(elemType).Elem()
			if err := unmarshalSliceElement(elemType, elem, r, order, activeQuirk); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			slice = reflect.Append(slice, elem)
		}
	}
	v.Set(slice)
	return nil
}

// unmarshalSliceElement reads one element of a slice; for TLV under LE with decode quirks,
// applies client-specific length workarounds (see unmarshalTLV* helpers).
func unmarshalSliceElement(elemType reflect.Type, elem reflect.Value, r io.Reader, order binary.ByteOrder, activeQuirk string) error {
	if activeQuirk != "" {
		switch {
		case activeQuirk == "icq2003b_set_fullinfo" && order == binary.LittleEndian && elemType == reflect.TypeOf(TLV{}):
			return unmarshalTLVICQ2003bSetFullInfo(elem, r, order)
		case activeQuirk == "qip_2005_search_by_uin2" && order == binary.LittleEndian && elemType == reflect.TypeOf(TLV{}):
			return unmarshalTLVQIP2005SearchByUIN2(elem, r, order)
		}
	}
	return unmarshal(elemType, elem, "", r, order, activeQuirk)
}

// unmarshalTLVICQ2003bSetFullInfo decodes one TLV with ICQ 2003b save-info workaround for ICQTLVTagsEmail.
func unmarshalTLVICQ2003bSetFullInfo(elem reflect.Value, r io.Reader, order binary.ByteOrder) error {
	var tag uint16
	if err := binary.Read(r, order, &tag); err != nil {
		return err
	}
	var n uint16
	if err := binary.Read(r, order, &n); err != nil {
		return err
	}
	if tag == ICQTLVTagsEmail && n == 3 {
		n = 4
	}
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
	}
	elem.Field(0).Set(reflect.ValueOf(tag))
	elem.Field(1).SetBytes(buf)
	return nil
}

// unmarshalTLVQIP2005SearchByUIN2 decodes one TLV for META SearchByUIN2 (0x0569): QIP 2005 sends
// ICQTLVTagsUIN (0x0136) with an incorrect length (e.g. 6) for a 4-byte UIN, causing EOF on a strict read.
func unmarshalTLVQIP2005SearchByUIN2(elem reflect.Value, r io.Reader, order binary.ByteOrder) error {
	var tag uint16
	if err := binary.Read(r, order, &tag); err != nil {
		return err
	}
	var n uint16
	if err := binary.Read(r, order, &n); err != nil {
		return err
	}
	if tag == ICQTLVTagsUIN && n != 4 {
		n = 4
	}
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
	}
	elem.Field(0).Set(reflect.ValueOf(tag))
	elem.Field(1).SetBytes(buf)
	return nil
}

func unmarshalString(v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder) error {
	if !oscTag.hasLenPrefix {
		return fmt.Errorf("missing len_prefix tag")
	}
	bufLen, err := unmarshalUnsignedInt(oscTag.lenPrefix, r, order)
	if err != nil {
		return err
	}
	buf := make([]byte, bufLen)
	if bufLen > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		if oscTag.nullTerminated {
			// search for null within string and truncate there if found
			// needed for icq 6 login to be working
			if nullPos := bytes.IndexByte(buf, 0x00); nullPos != -1 {
				buf = buf[0:nullPos]
			}
		}
	}

	// todo is there a more efficient way?
	v.SetString(string(buf))
	return nil
}

func unmarshalStruct(t reflect.Type, v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder, activeQuirk string) error {
	if oscTag.hasLenPrefix {
		bufLen, err := unmarshalUnsignedInt(oscTag.lenPrefix, r, order)
		if err != nil {
			return err
		}
		b := make([]byte, bufLen)
		if bufLen > 0 {
			if _, err := io.ReadFull(r, b); err != nil {
				return err
			}
		}
		r = bytes.NewBuffer(b)
	}
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)
		if field.Type.Kind() == reflect.Ptr {
			if i != v.NumField()-1 {
				return fmt.Errorf("pointer type found at non-final field %s", field.Name)
			}
			if field.Type.Elem().Kind() != reflect.Struct {
				return fmt.Errorf("%w: field %s must point to a struct, got %v instead",
					errNonOptionalPointer, field.Name, field.Type.Elem().Kind())
			}
		}
		if err := unmarshal(field.Type, value, field.Tag, r, order, activeQuirk); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalUnsignedInt(intType reflect.Kind, r io.Reader, order binary.ByteOrder) (int, error) {
	var bufLen int
	switch intType {
	case reflect.Uint8:
		var l uint8
		if err := binary.Read(r, order, &l); err != nil {
			return 0, err
		}
		bufLen = int(l)
	case reflect.Uint16:
		var l uint16
		if err := binary.Read(r, order, &l); err != nil {
			return 0, err
		}
		bufLen = int(l)
	default:
		panic(fmt.Sprintf("unsupported type %s. allowed types: uint8, uint16", intType))
	}
	return bufLen, nil
}
