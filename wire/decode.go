package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

var (
	ErrUnmarshalFailure  = errors.New("failed to unmarshal")
	errNotNullTerminated = errors.New("nullterm tag is set, but string is not null-terminated")
)

// UnmarshalBE unmarshalls OSCAR protocol messages in big-endian format.
func UnmarshalBE(v any, r io.Reader) error {
	if err := unmarshal(reflect.TypeOf(v).Elem(), reflect.ValueOf(v).Elem(), "", r, binary.BigEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrUnmarshalFailure, err)
	}
	return nil
}

// UnmarshalLE unmarshalls OSCAR protocol messages in little-endian format.
func UnmarshalLE(v any, r io.Reader) error {
	if err := unmarshal(reflect.TypeOf(v).Elem(), reflect.ValueOf(v).Elem(), "", r, binary.LittleEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrUnmarshalFailure, err)
	}
	return nil
}

// MarshalLE marshals ICQ protocol messages in little-endian format.
func unmarshal(t reflect.Type, v reflect.Value, tag reflect.StructTag, r io.Reader, order binary.ByteOrder) error {
	oscTag, err := parseOSCARTag(tag)
	if err != nil {
		return fmt.Errorf("error parsing tag: %w", err)
	}

	if oscTag.optional {
		v.Set(reflect.New(t.Elem()))
		err := unmarshalStruct(t.Elem(), v.Elem(), oscTag, r, order)
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
		return unmarshalArray(v, r, order)
	case reflect.Slice:
		return unmarshalSlice(v, oscTag, r, order)
	case reflect.String:
		return unmarshalString(v, oscTag, r, order)
	case reflect.Struct:
		return unmarshalStruct(t, v, oscTag, r, order)
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

func unmarshalArray(v reflect.Value, r io.Reader, order binary.ByteOrder) error {
	arrLen := v.Len()
	arrType := v.Type().Elem()

	for i := 0; i < arrLen; i++ {
		elem := reflect.New(arrType).Elem()
		if err := unmarshal(arrType, elem, "", r, order); err != nil {
			return err
		}
		v.Index(i).Set(elem)
	}

	return nil
}

func unmarshalSlice(v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder) error {
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
			if err := unmarshal(elemType, elem, "", buf, order); err != nil {
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
			if err := unmarshal(elemType, elem, "", r, order); err != nil {
				return err
			}
			slice = reflect.Append(slice, elem)
		}
	} else {
		for {
			elem := reflect.New(elemType).Elem()
			if err := unmarshal(elemType, elem, "", r, order); err != nil {
				// Tolerate partial or malformed TLV. It fixes compatibility with vanilla
				// Jimm, which sends an incorrect TLV value length and then leaving orphaned bytes that fail to parse as a TLV.
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
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

func unmarshalStruct(t reflect.Type, v reflect.Value, oscTag oscarTag, r io.Reader, order binary.ByteOrder) error {
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
		if err := unmarshal(field.Type, value, field.Tag, r, order); err != nil {
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
