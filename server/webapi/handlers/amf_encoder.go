package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"time"

	goAMF3 "github.com/breign/goAMF3"
)

// AMFVersion represents the AMF encoding version
type AMFVersion int

const (
	AMF3 AMFVersion = 3
)

// AMFEncoder handles AMF encoding operations for WebAPI responses
type AMFEncoder struct {
	logger *slog.Logger
}

// NewAMFEncoder creates a new AMF encoder instance
func NewAMFEncoder(logger *slog.Logger) *AMFEncoder {
	return &AMFEncoder{logger: logger}
}

// EncodeAMF encodes data to AMF3 format (only supported version)
func (e *AMFEncoder) EncodeAMF(data interface{}, version AMFVersion) ([]byte, error) {
	// For AMF3, use goAMF3 which properly supports it
	// Convert to a regular map structure (no ECMAArray needed)
	amfData := e.toAMF3Compatible(data)
	// goAMF3 panics on nil values, ensure we sanitize
	sanitized := e.sanitizeForAMF3(amfData)
	encoded := goAMF3.EncodeAMF3(sanitized)
	return encoded, nil
}

// toAMF3Compatible converts Go types to AMF3-compatible format for goAMF3
func (e *AMFEncoder) toAMF3Compatible(data interface{}) interface{} {
	if data == nil {
		return map[string]interface{}{}
	}

	// goAMF3 handles regular Go types well, just need to ensure maps are used
	// Don't use ECMAArray for AMF3 - just regular maps
	// Every response is a struct whose json tags name its fields, and
	// structToMap reflects over exactly those tags, so no response needs a case
	// of its own here. sanitizeForAMF3 handles the types goAMF3 cannot take —
	// notably the uint64 sequence numbers — on the way out.
	switch d := data.(type) {
	case BaseResponse:
		return e.baseResponseToMap(d)
	case ResponseBody:
		return e.responseBodyToMap(d)
	case ErrorResponse:
		return e.errorResponseToMap(d)
	default:
		// For other types, convert structs to maps
		return e.convertToMap(data)
	}
}

// sanitizeForAMF3 recursively removes nil values from the data structure
// because goAMF3 panics when encountering nil values in maps.
//
// It runs on the output of toAMF3Compatible, so every struct and slice has
// already been reduced to maps and []interface{}; only the leaf types goAMF3
// cannot take are left to convert.
func (e *AMFEncoder) sanitizeForAMF3(data interface{}) interface{} {
	if data == nil {
		return map[string]interface{}{}
	}

	switch v := data.(type) {
	case uint64:
		// goAMF3 can't handle uint64, convert to int
		return int(v)
	case uint32:
		// Convert all unsigned to signed for safety
		return int(v)
	case uint16:
		return int(v)
	case uint8:
		return int(v)
	case uint:
		return int(v)
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			if val == nil {
				// For fields like 'data', replace with empty map
				// For other fields, skip them
				if key == "data" {
					result[key] = map[string]interface{}{}
				}
				continue
			}
			result[key] = e.sanitizeForAMF3(val)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = e.sanitizeForAMF3(item)
		}
		return result
	default:
		// goAMF3 writes nothing for a value it cannot encode, which truncates the
		// object mid-key, so pointers and structs are reduced to maps first.
		rv := reflect.ValueOf(data)
		if rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return map[string]interface{}{}
			}
			rv = rv.Elem()
		}
		if rv.Kind() == reflect.Struct {
			return e.sanitizeForAMF3(e.structToMap(rv))
		}
		return rv.Interface()
	}
}

// baseResponseToMap converts BaseResponse to AMF3-compatible map
func (e *AMFEncoder) baseResponseToMap(resp BaseResponse) map[string]interface{} {
	return map[string]interface{}{
		"response": e.responseBodyToMap(resp.Response),
	}
}

// responseBodyToMap converts ResponseBody to AMF3-compatible map
func (e *AMFEncoder) responseBodyToMap(body ResponseBody) map[string]interface{} {
	m := map[string]interface{}{
		"statusCode": body.StatusCode,
		"statusText": body.StatusText,
	}
	if body.RequestID != "" {
		m["requestId"] = body.RequestID
	}
	if body.Data != nil {
		m["data"] = e.toAMF3Compatible(body.Data)
	} else {
		// For AMF3, always include data field even if empty to prevent truncation
		m["data"] = map[string]interface{}{}
	}
	return m
}

// errorResponseToMap converts ErrorResponse to AMF3-compatible map
func (e *AMFEncoder) errorResponseToMap(err ErrorResponse) map[string]interface{} {
	m := map[string]interface{}{
		"statusCode": err.Response.StatusCode,
		"statusText": err.Response.StatusText,
	}
	// The client dereferences response.data on a failure too, so the error
	// envelope carries one in AMF as it does in every other format.
	if err.Response.Data != nil {
		m["data"] = e.toAMF3Compatible(err.Response.Data)
	} else {
		m["data"] = map[string]interface{}{}
	}
	return map[string]interface{}{"response": m}
}

// structToMap converts a struct to a map using JSON tags for AMF3
func (e *AMFEncoder) structToMap(v reflect.Value) map[string]interface{} {
	result := make(map[string]interface{})
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip unexported fields
		if !fieldValue.CanInterface() {
			continue
		}

		// Get JSON tag
		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		// Parse JSON tag
		tagParts := strings.Split(jsonTag, ",")
		fieldName := tagParts[0]
		if fieldName == "" {
			fieldName = field.Name
		}

		// Check for omitempty
		omitEmpty := false
		for _, part := range tagParts[1:] {
			if part == "omitempty" {
				omitEmpty = true
				break
			}
		}

		// Skip if omitempty and value is zero
		if omitEmpty && e.isZeroValue(fieldValue) {
			continue
		}

		// Get field value and convert recursively
		fieldData := fieldValue.Interface()
		result[fieldName] = e.toAMF3Compatible(fieldData)
	}

	return result
}

// mapToAMFMap converts a Go map to an AMF3-compatible map
func (e *AMFEncoder) mapToAMFMap(v reflect.Value) map[string]interface{} {
	result := make(map[string]interface{})

	for _, key := range v.MapKeys() {
		// Convert key to string (AMF only supports string keys)
		keyStr := fmt.Sprintf("%v", key.Interface())
		value := v.MapIndex(key)

		if value.CanInterface() {
			result[keyStr] = e.toAMF3Compatible(value.Interface())
		}
	}

	return result
}

// convertToMap converts any data to a map structure for AMF3
func (e *AMFEncoder) convertToMap(data interface{}) interface{} {
	if data == nil {
		// For AMF3, return empty map instead of nil to avoid truncation
		return map[string]interface{}{}
	}

	// If already a map, return as-is (even if empty)
	if m, ok := data.(map[string]interface{}); ok {
		if m == nil {
			return map[string]interface{}{}
		}
		return m
	}

	v := reflect.ValueOf(data)

	// Handle pointers
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
		data = v.Interface()
	}

	// Handle different types
	switch v.Kind() {
	case reflect.Struct:
		return e.structToMap(v)
	case reflect.Map:
		return e.mapToAMFMap(v)
	case reflect.Slice, reflect.Array:
		result := make([]interface{}, v.Len())
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			if elem.CanInterface() {
				result[i] = e.convertToMap(elem.Interface())
			}
		}
		return result
	default:
		// For basic types, return as-is
		return data
	}
}

// isZeroValue checks if a reflect.Value is a zero value
func (e *AMFEncoder) isZeroValue(v reflect.Value) bool {
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
		// For time.Time, check if it's zero
		if t, ok := v.Interface().(time.Time); ok {
			return t.IsZero()
		}
		// For other structs, we can't easily determine zero value
		return false
	}
	return false
}

// DetectAMFVersion determines which AMF version to use based on the request
func DetectAMFVersion(r *http.Request) AMFVersion {
	if r == nil {
		return AMF3
	}

	// Check query parameter first (highest priority)
	format := strings.ToLower(r.URL.Query().Get("f"))
	switch format {
	case "amf3":
		return AMF3
	case "amf":
		// Default to AMF3 for modern clients (Gromit expects AMF3)
		return AMF3
	}

	// Check Accept header for version hint
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "amf3") || strings.Contains(accept, "AMF3") {
		return AMF3
	}
	if strings.Contains(accept, "amf") || strings.Contains(accept, "AMF") {
		return AMF3 // Default to AMF3 for AMF requests
	}

	// Check Content-Type header (for POST requests)
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "amf3") || strings.Contains(contentType, "AMF3") {
		return AMF3
	}
	if strings.Contains(contentType, "amf") || strings.Contains(contentType, "AMF") {
		return AMF3 // Default to AMF3 for AMF requests
	}

	// Default to AMF3 for modern clients
	return AMF3
}
