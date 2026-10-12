package foodgroup

import (
	"reflect"
	"unicode/utf8"

	"golang.org/x/text/encoding"

	"github.com/mk6i/open-oscar-server/wire"
)

// ICQ meta-info requests and replies carry no charset marker. Vintage clients
// write and read them in their ANSI code page, while the user store, the WebAPI
// and the management API all speak UTF-8. The helpers below convert at that
// boundary so the store only ever holds UTF-8.

// legacyToUTF8 returns a copy of v, a decoded meta-info request, with every
// string in it as UTF-8.
func legacyToUTF8[T any](enc encoding.Encoding, v T) T {
	return mapStrings(v, func(s string) string { return legacyTextToUTF8(enc, s) })
}

// utf8ToLegacy returns a copy of v, data bound for a meta-info reply, with
// every string in it in the fallback charset.
func utf8ToLegacy[T any](enc encoding.Encoding, v T) T {
	return mapStrings(v, func(s string) string { return utf8TextToLegacy(enc, s) })
}

// legacyTextToUTF8 decodes s from the fallback charset. Text that is already
// valid UTF-8 is kept, which is what clients that write UTF-8 send.
func legacyTextToUTF8(enc encoding.Encoding, s string) string {
	if enc == nil || utf8.ValidString(s) {
		return s
	}
	decoded, err := enc.NewDecoder().String(s)
	if err != nil {
		return s
	}
	return decoded
}

// utf8TextToLegacy encodes s into the fallback charset. Text the charset cannot
// fully represent is returned as is: a vintage client garbles it either way,
// while a client that also reads UTF-8 still shows it correctly.
func utf8TextToLegacy(enc encoding.Encoding, s string) string {
	if enc == nil || wire.AllASCII(s) || !utf8.ValidString(s) {
		return s
	}
	encoded, err := enc.NewEncoder().String(s)
	if err != nil {
		return s
	}
	return encoded
}

// mapStrings returns a copy of v with fn applied to every string reachable
// through its exported fields. v itself is left untouched.
func mapStrings[T any](v T, fn func(string) string) T {
	out := reflect.New(reflect.TypeOf(v)).Elem()
	out.Set(reflect.ValueOf(v))
	mapStringValues(out, fn)
	return out.Interface().(T)
}

func mapStringValues(v reflect.Value, fn func(string) string) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(fn(v.String()))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			mapStringValues(v.Field(i), fn)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			mapStringValues(v.Index(i), fn)
		}
	case reflect.Slice:
		// Raw bytes are not text, and a slice shares its backing array with
		// the original, so it is copied before its elements change.
		if v.IsNil() || !v.CanSet() || v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		elems := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(elems, v)
		v.Set(elems)
		for i := 0; i < v.Len(); i++ {
			mapStringValues(v.Index(i), fn)
		}
	case reflect.Pointer:
		if v.IsNil() || !v.CanSet() {
			return
		}
		elem := reflect.New(v.Type().Elem())
		elem.Elem().Set(v.Elem())
		v.Set(elem)
		mapStringValues(elem.Elem(), fn)
	}
}
