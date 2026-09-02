package wire

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	goAMF3 "github.com/breign/goAMF3"
)

// AMF3 stores whole numbers in a signed 29-bit integer. A value outside this
// range is written as a double instead, which is how a Unix timestamp survives
// the trip.
const (
	minInt29 = -(1 << 28)
	maxInt29 = 1<<28 - 1
)

var (
	timeType = reflect.TypeFor[time.Time]()
	byteType = reflect.TypeFor[byte]()
)

// MarshalAMF3 returns the AMF3 encoding of v, the format the Flash-based Web AIM
// client reads its fetchEvents payloads in.
//
// Struct fields are named by their amf3 tag, falling back to the json tag, so a
// field carries an amf3 tag only where the two formats disagree. Both spellings
// honor "-" and ",omitempty".
func MarshalAMF3(v any) ([]byte, error) {
	norm, err := amf3Value(reflect.ValueOf(v))
	if err != nil {
		return nil, err
	}
	if norm == nil {
		// A response body is an object even when it carries nothing, because the
		// client dereferences it unconditionally.
		norm = map[string]any{}
	}
	return goAMF3.EncodeAMF3(norm), nil
}

// amf3Value reduces v to the values the AMF3 writer encodes correctly: bool,
// string, int32, float64, []byte, time.Time, []any and map[string]any. It is
// given anything else only as an error, because the writer silently emits
// nothing for a value it cannot handle, truncating the enclosing object.
func amf3Value(v reflect.Value) (any, error) {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil, nil
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return nil, nil
	}

	switch v.Kind() {
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.String:
		return v.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return amf3Int(v.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return amf3Uint(v.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return v.Float(), nil
	case reflect.Slice, reflect.Array:
		return amf3Slice(v)
	case reflect.Map:
		return amf3Map(v)
	case reflect.Struct:
		if v.Type() == timeType {
			return v.Interface(), nil
		}
		return amf3Struct(v)
	default:
		return nil, fmt.Errorf("amf3: cannot encode %s", v.Type())
	}
}

// amf3Int returns the narrowest AMF3 number holding n.
func amf3Int(n int64) any {
	if n >= minInt29 && n <= maxInt29 {
		return int32(n)
	}
	return float64(n)
}

// amf3Uint returns the narrowest AMF3 number holding n.
func amf3Uint(n uint64) any {
	if n <= maxInt29 {
		return int32(n)
	}
	return float64(n)
}

// amf3Slice returns v's elements as []any, passing a byte slice through so it is
// written as an AMF3 byte array. A nil slice becomes an empty one because the
// client iterates lists such as capabilities unconditionally.
func amf3Slice(v reflect.Value) (any, error) {
	if v.Kind() == reflect.Slice && v.Type().Elem() == byteType {
		return v.Bytes(), nil
	}
	out := make([]any, v.Len())
	for i := range out {
		elem, err := amf3Value(v.Index(i))
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out[i] = elem
	}
	return out, nil
}

// amf3Map returns v's entries keyed by the string form of each key, which is the
// only key type an AMF3 object has. A nil value is dropped rather than written as
// null: the client merges each object it receives onto the one it already holds,
// so an absent key leaves the current value alone.
func amf3Map(v reflect.Value) (any, error) {
	out := make(map[string]any, v.Len())
	for iter := v.MapRange(); iter.Next(); {
		val, err := amf3Value(iter.Value())
		if err != nil {
			return nil, err
		}
		if val == nil {
			continue
		}
		out[amf3Key(iter.Key())] = val
	}
	return out, nil
}

// amf3Key renders a map key as an AMF3 object key.
func amf3Key(k reflect.Value) string {
	if k.Kind() == reflect.String {
		return k.String()
	}
	return fmt.Sprint(k.Interface())
}

// amf3Struct returns v's exported fields keyed by their tag names.
func amf3Struct(v reflect.Value) (any, error) {
	out := map[string]any{}
	if err := amf3Fields(v, out); err != nil {
		return nil, err
	}
	return out, nil
}

// amf3Fields writes v's fields into out. An untagged embedded struct contributes
// its own fields to the enclosing object, as it does in JSON, including when its
// type is unexported: reflect still reads the exported fields inside it.
func amf3Fields(v reflect.Value, out map[string]any) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, omitEmpty, omitZero, ok := amf3FieldKey(f)
		if !ok {
			continue
		}
		fv := v.Field(i)

		if f.Anonymous && name == "" {
			embedded := reflect.Indirect(fv)
			if embedded.Kind() == reflect.Struct && embedded.Type() != timeType {
				if err := amf3Fields(embedded, out); err != nil {
					return err
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if omitEmpty && isEmptyValue(fv) {
			continue
		}
		if omitZero && isZeroValue(fv) {
			continue
		}

		val, err := amf3Value(fv)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", t.Name(), f.Name, err)
		}
		if val == nil {
			if omitEmpty || omitZero {
				continue
			}
			// A field the client dereferences unconditionally, such as a
			// response's data or an event's eventData, is an empty object rather
			// than an absent key.
			val = map[string]any{}
		}
		out[name] = val
	}
	return nil
}

// amf3FieldKey returns the AMF3 name for f and whether it is written at all. An
// amf3 tag replaces the json tag outright, so a field that must always be present
// in AMF but is omitempty in JSON just names itself in amf3.
func amf3FieldKey(f reflect.StructField) (name string, omitEmpty, omitZero, ok bool) {
	tag, tagged := f.Tag.Lookup("amf3")
	if !tagged {
		tag = f.Tag.Get("json")
	}
	if tag == "-" {
		return "", false, false, false
	}
	name, opts, _ := strings.Cut(tag, ",")
	return name, hasTagOption(opts, "omitempty"), hasTagOption(opts, "omitzero"), true
}

// hasTagOption reports whether the comma-separated tag options contain want.
func hasTagOption(opts, want string) bool {
	for opts != "" {
		var opt string
		opt, opts, _ = strings.Cut(opts, ",")
		if opt == want {
			return true
		}
	}
	return false
}

var zeroerType = reflect.TypeOf((*interface{ IsZero() bool })(nil)).Elem()

// isZeroValue reports whether v is the zero value omitzero suppresses, mirroring
// encoding/json including the IsZero override. Unlike omitempty, an empty-but-non-nil
// slice or map is not zero.
func isZeroValue(v reflect.Value) bool {
	if v.Type().Implements(zeroerType) {
		if v.Kind() == reflect.Pointer && v.IsNil() {
			return true
		}
		return v.Interface().(interface{ IsZero() bool }).IsZero()
	}
	if v.CanAddr() && reflect.PointerTo(v.Type()).Implements(zeroerType) {
		return v.Addr().Interface().(interface{ IsZero() bool }).IsZero()
	}
	return v.IsZero()
}

// isEmptyValue reports whether v is the zero value that omitempty suppresses.
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	case reflect.Struct:
		return v.Type() == timeType && v.Interface().(time.Time).IsZero()
	}
	return false
}
