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
	ErrMarshalFailure        = errors.New("failed to marshal")
	errMarshalFailureNilSNAC = errors.New("attempting to marshal a nil SNAC")
	errNonOptionalPointer    = errors.New("pointer fields must reference structs and have an `optional` struct tag")
	errOptionalNonPointer    = errors.New("optional fields must be pointers")
	errInvalidStructTag      = errors.New("invalid struct tag")
)

// MarshalBE marshals OSCAR protocol messages in big-endian format.
func MarshalBE(v any, w io.Writer) error {
	if err := marshal(reflect.TypeOf(v), reflect.ValueOf(v), "", w, binary.BigEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrMarshalFailure, err)
	}
	return nil
}

// MarshalLE marshals ICQ protocol messages in little-endian format.
func MarshalLE(v any, w io.Writer) error {
	if err := marshal(reflect.TypeOf(v), reflect.ValueOf(v), "", w, binary.LittleEndian); err != nil {
		return fmt.Errorf("%w: %w", ErrMarshalFailure, err)
	}
	return nil
}

func marshal(t reflect.Type, v reflect.Value, tag reflect.StructTag, w io.Writer, order binary.ByteOrder) error {
	if t == nil {
		return errMarshalFailureNilSNAC
	}

	oscTag, err := parseOSCARTag(tag)
	if err != nil {
		return err
	}

	if oscTag.optional {
		if t.Kind() != reflect.Ptr {
			return fmt.Errorf("%w: got %v", errOptionalNonPointer, t.Kind())
		}
		if v.IsNil() {
			return nil // nil value
		}
		// dereference pointer
		return marshalStruct(t.Elem(), v.Elem(), oscTag, w, order)
	} else if t.Kind() == reflect.Ptr {
		return errNonOptionalPointer
	}

	switch t.Kind() {
	case reflect.Array:
		return marshalArray(t, v, w, order)
	case reflect.Slice:
		return marshalSlice(t, v, oscTag, w, order)
	case reflect.String:
		return marshalString(oscTag, v, w, order)
	case reflect.Struct:
		return marshalStruct(t, v, oscTag, w, order)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return binary.Write(w, order, v.Interface())
	case reflect.Interface:
		return marshalInterface(v, w, oscTag, order)
	default:
		return fmt.Errorf("unsupported type %v", t.Kind())
	}
}

func marshalInterface(v reflect.Value, w io.Writer, tag oscarTag, order binary.ByteOrder) error {
	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("interface underlying type must be a struct, got %v instead", elem.Kind())
	}

	return marshalStruct(elem.Type(), elem, tag, w, order)
}

func marshalArray(t reflect.Type, v reflect.Value, w io.Writer, order binary.ByteOrder) error {
	if t.Elem().Kind() == reflect.Struct {
		for j := 0; j < v.Len(); j++ {
			if err := marshalStruct(t.Elem(), v.Index(j), oscarTag{}, w, order); err != nil {
				return fmt.Errorf("error marshalling %s: %w", t.Elem().Kind(), err)
			}
		}
	} else {
		if err := binary.Write(w, order, v.Interface()); err != nil {
			return fmt.Errorf("error marshalling %s: %w", t.Elem().Kind(), err)
		}
	}
	return nil
}

func marshalSlice(t reflect.Type, v reflect.Value, oscTag oscarTag, w io.Writer, order binary.ByteOrder) error {
	// todo: only write to temporary buffer if len_prefix is set
	buf := &bytes.Buffer{}
	if t.Elem().Kind() == reflect.Struct {
		for j := 0; j < v.Len(); j++ {
			if err := marshalStruct(t.Elem(), v.Index(j), oscarTag{}, buf, order); err != nil {
				return err
			}
		}
	} else {
		if err := binary.Write(buf, order, v.Interface()); err != nil {
			return fmt.Errorf("error marshalling %s", t.Elem().Kind())
		}
	}

	if oscTag.hasLenPrefix {
		if err := marshalUnsignedInt(oscTag.lenPrefix, buf.Len(), w, order); err != nil {
			return err
		}
	} else if oscTag.hasCountPrefix {
		if err := marshalUnsignedInt(oscTag.countPrefix, v.Len(), w, order); err != nil {
			return err
		}
	}
	if buf.Len() > 0 {
		_, err := w.Write(buf.Bytes())
		return err
	}
	return nil
}

func marshalString(oscTag oscarTag, v reflect.Value, w io.Writer, order binary.ByteOrder) error {
	str := v.String()
	if oscTag.nullTerminated && str != "" {
		str = str + "\x00"
	}
	if oscTag.hasLenPrefix {
		if err := marshalUnsignedInt(oscTag.lenPrefix, len(str), w, order); err != nil {
			return err
		}
	}
	if str == "" {
		return nil
	}
	return binary.Write(w, order, []byte(str))
}

func marshalStruct(t reflect.Type, v reflect.Value, oscTag oscarTag, w io.Writer, order binary.ByteOrder) error {
	// marshal ICQ messages in little endian order
	if t.Name() == "ICQMessageReplyEnvelope" {
		order = binary.LittleEndian
	}

	marshalEachField := func(w io.Writer) error {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			value := v.Field(i)
			if field.Type.Kind() == reflect.Ptr {
				if i != t.NumField()-1 {
					return fmt.Errorf("pointer type found at non-final field %s", field.Name)
				}
				if field.Type.Elem().Kind() != reflect.Struct {
					return fmt.Errorf("field %s must point to a struct, got %v instead", field.Name,
						field.Type.Elem().Kind())
				}
			}
			if err := marshal(field.Type, value, field.Tag, w, order); err != nil {
				return err
			}
		}
		return nil
	}
	if oscTag.hasLenPrefix {
		buf := &bytes.Buffer{}
		if err := marshalEachField(buf); err != nil {
			return err
		}
		// write struct length
		if err := marshalUnsignedInt(oscTag.lenPrefix, buf.Len(), w, order); err != nil {
			return err
		}
		// write struct bytes
		if buf.Len() > 0 {
			_, err := w.Write(buf.Bytes())
			return err
		}
		return nil
	}
	return marshalEachField(w)
}

func marshalUnsignedInt(intType reflect.Kind, intVal int, w io.Writer, order binary.ByteOrder) error {
	switch intType {
	case reflect.Uint8:
		if err := binary.Write(w, order, uint8(intVal)); err != nil {
			return err
		}
	case reflect.Uint16:
		if err := binary.Write(w, order, uint16(intVal)); err != nil {
			return err
		}
	default:
		panic(fmt.Sprintf("unsupported type %s. allowed types: uint8, uint16", intType))
	}
	return nil
}

type oscarTag struct {
	hasCountPrefix bool
	countPrefix    reflect.Kind
	hasLenPrefix   bool
	lenPrefix      reflect.Kind
	optional       bool
	nullTerminated bool
	// quirk names an unmarshal-only decode exception
	quirk string
}

func parseOSCARTag(tag reflect.StructTag) (oscarTag, error) {
	var oscTag oscarTag

	val, ok := tag.Lookup("oscar")
	if !ok {
		return oscTag, nil
	}

	for _, kv := range strings.Split(val, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		kvSplit := strings.SplitN(kv, "=", 2)
		key := strings.TrimSpace(kvSplit[0])
		if len(kvSplit) == 2 {
			valPart := strings.TrimSpace(kvSplit[1])
			switch key {
			case "len_prefix":
				oscTag.hasLenPrefix = true
				switch valPart {
				case "uint8":
					oscTag.lenPrefix = reflect.Uint8
				case "uint16":
					oscTag.lenPrefix = reflect.Uint16
				default:
					return oscTag, fmt.Errorf("%w: unsupported type %s. allowed types: uint8, uint16",
						errInvalidStructTag, valPart)
				}
			case "count_prefix":
				oscTag.hasCountPrefix = true
				switch valPart {
				case "uint8":
					oscTag.countPrefix = reflect.Uint8
				case "uint16":
					oscTag.countPrefix = reflect.Uint16
				default:
					return oscTag, fmt.Errorf("%w: unsupported type %s. allowed types: uint8, uint16",
						errInvalidStructTag, valPart)
				}
			case "quirk":
				if valPart == "" {
					return oscTag, fmt.Errorf("%w: empty quirk value", errInvalidStructTag)
				}
				if oscTag.quirk != "" {
					return oscTag, fmt.Errorf("%w: duplicate quirk key", errInvalidStructTag)
				}
				oscTag.quirk = valPart
			default:
				return oscTag, fmt.Errorf("%w: unsupported struct tag %s",
					errInvalidStructTag, key)
			}
		} else {
			switch key {
			case "optional":
				oscTag.optional = true
			case "nullterm":
				oscTag.nullTerminated = true
			default:
				return oscTag, fmt.Errorf("%w: unsupported struct tag %s",
					errInvalidStructTag, key)
			}
		}
	}

	var err error
	if oscTag.hasCountPrefix && oscTag.hasLenPrefix {
		err = fmt.Errorf("%w: struct elem has both len_prefix and count_prefix", errInvalidStructTag)
	}
	return oscTag, err
}
