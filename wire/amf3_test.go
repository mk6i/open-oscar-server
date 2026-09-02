package wire

import (
	"testing"
	"time"

	goAMF3 "github.com/breign/goAMF3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// marshalAMF3Map encodes v and decodes it back as an AMF3 object.
func marshalAMF3Map(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := MarshalAMF3(v)
	require.NoError(t, err)

	decoded := goAMF3.DecodeAMF3(b)
	m, ok := decoded.(map[string]any)
	require.True(t, ok, "decoded as %T, want an object", decoded)
	return m
}

// amf3EventType stands in for the named string types that carry an event's type
// constant.
type amf3EventType string

type amf3Tagged struct {
	Sender   string `json:"sender" amf3:"source"`
	AutoResp bool   `json:"autoResponse,omitempty" amf3:"autoresponse"`
	Message  string `json:"message"`
	State    string `json:"state,omitempty" amf3:"state"`
	Secret   string `json:"-"`
	Hidden   string `amf3:"-" json:"hidden"`
	MsgID    string `json:"msgId,omitempty"`
	unseen   string
}

// An amf3 tag replaces the json tag, which is how the same struct spells a field
// one way for the Web AIM client and another for the documented JSON API.
func TestMarshalAMF3TagOverridesJSON(t *testing.T) {
	m := marshalAMF3Map(t, amf3Tagged{
		Sender: "chattingchuck", Message: "hi", Secret: "s", Hidden: "h", unseen: "u",
	})

	assert.Equal(t, "chattingchuck", m["source"])
	assert.NotContains(t, m, "sender")
	assert.Equal(t, "hi", m["message"])

	// An amf3 tag carrying no omitempty keeps a field the JSON encoding drops.
	assert.Contains(t, m, "autoresponse")
	assert.Equal(t, false, m["autoresponse"])
	assert.Contains(t, m, "state")
	assert.Equal(t, "", m["state"])

	// "-" suppresses the field whichever tag spells it, and unexported fields
	// never appear.
	assert.NotContains(t, m, "secret")
	assert.NotContains(t, m, "hidden")
	assert.NotContains(t, m, "unseen")

	// A json omitempty still applies when no amf3 tag overrides it.
	assert.NotContains(t, m, "msgId")
}

// AMF3 stores whole numbers in 29 bits, so anything wider has to arrive as a
// double or it is silently truncated on the wire.
func TestMarshalAMF3IntegerRange(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  any
	}{
		{"zero", 0, int32(0)},
		{"negative", -5, int32(-5)},
		{"max int29", maxInt29, int32(maxInt29)},
		{"min int29", minInt29, int32(minInt29)},
		{"one past max int29", int64(maxInt29 + 1), float64(maxInt29 + 1)},
		{"one past min int29", int64(minInt29 - 1), float64(minInt29 - 1)},
		{"unix timestamp", int64(1700000000), float64(1700000000)},
		{"uint64 in range", uint64(42), int32(42)},
		{"uint64 out of range", uint64(1) << 40, float64(uint64(1) << 40)},
		{"uint64 max", uint64(1<<64 - 1), float64(uint64(1<<64 - 1))},
		{"uint32 out of range", uint32(4000000000), float64(4000000000)},
		{"float stays a double", 1.5, 1.5},
		{"seqNum", uint64(7), int32(7)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := marshalAMF3Map(t, map[string]any{"n": tt.value})
			assert.Equal(t, tt.want, m["n"])
		})
	}
}

type amf3Embedded struct {
	AimID string `json:"aimId"`
}

type amf3WithEmbedded struct {
	amf3Embedded
	State string `json:"state"`
}

type amf3Nested struct {
	Source   amf3Embedded   `json:"source"`
	Ptr      *amf3Embedded  `json:"ptr,omitempty"`
	Absent   *amf3Embedded  `json:"absent,omitempty"`
	Required *amf3Embedded  `json:"required"`
	Boxed    any            `json:"boxed"`
	List     []amf3Embedded `json:"list"`
	NilList  []string       `json:"capabilities"`
	Counts   map[string]int `json:"counts"`
	Any      any            `json:"any"`
	When     time.Time      `json:"when"`
}

func TestMarshalAMF3NestedValues(t *testing.T) {
	when := time.Unix(1700000000, 0).UTC()
	m := marshalAMF3Map(t, amf3Nested{
		Source: amf3Embedded{AimID: "chuck"},
		Ptr:    &amf3Embedded{AimID: "fred"},
		List:   []amf3Embedded{{AimID: "one"}},
		Counts: map[string]int{"unread": 3},
		Any:    amf3Embedded{AimID: "boxed"},
		When:   when,
	})

	assert.Equal(t, map[string]any{"aimId": "chuck"}, m["source"])
	assert.Equal(t, map[string]any{"aimId": "fred"}, m["ptr"])
	assert.Equal(t, []any{map[string]any{"aimId": "one"}}, m["list"])
	// A map of a concrete value type reaches the wire; the writer takes only
	// map[string]any on its own.
	assert.Equal(t, map[string]any{"unread": int32(3)}, m["counts"])
	assert.Equal(t, map[string]any{"aimId": "boxed"}, m["any"])

	// An AMF3 date is a bare UTC epoch, so the instant survives but the zone
	// does not.
	decodedWhen, ok := m["when"].(time.Time)
	require.True(t, ok, "when decoded as %T", m["when"])
	assert.True(t, when.Equal(decodedWhen), "got %s, want %s", decodedWhen, when)

	// A nil list is sent as an empty one because the client iterates lists such
	// as capabilities unconditionally.
	assert.Equal(t, []any{}, m["capabilities"])

	// omitempty is what drops a nil, so the client's merge leaves whatever it
	// already holds alone.
	assert.NotContains(t, m, "absent")

	// Without omitempty the field is one the client dereferences on sight, so it
	// arrives as an empty object rather than an absent key.
	assert.Equal(t, map[string]any{}, m["required"])
	assert.Equal(t, map[string]any{}, m["boxed"])
}

// An untagged embedded struct contributes its fields to the enclosing object.
func TestMarshalAMF3PromotesEmbeddedFields(t *testing.T) {
	m := marshalAMF3Map(t, amf3WithEmbedded{amf3Embedded: amf3Embedded{AimID: "chuck"}, State: "online"})

	assert.Equal(t, map[string]any{"aimId": "chuck", "state": "online"}, m)
}

// A named string encodes as its underlying string, which is what carries an
// event's type constant.
func TestMarshalAMF3NamedString(t *testing.T) {
	m := marshalAMF3Map(t, map[string]any{"type": amf3EventType("presence")})

	assert.Equal(t, "presence", m["type"])
}

// The AMF3 writer emits nothing for a value it cannot handle, truncating the
// enclosing object mid-key, so an unsupported type has to be an error instead.
func TestMarshalAMF3RejectsUnsupportedTypes(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{"channel", make(chan int)},
		{"func", func() {}},
		{"complex", complex(1, 2)},
		{"struct carrying a channel", struct {
			Ch chan int `json:"ch"`
		}{Ch: make(chan int)}},
		{"slice of channels", []chan int{make(chan int)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MarshalAMF3(tt.value)
			assert.Error(t, err)
		})
	}
}

// Every response is an object, so a nil payload is an empty one rather than a
// null the client would dereference.
func TestMarshalAMF3NilIsAnEmptyObject(t *testing.T) {
	assert.Equal(t, map[string]any{}, marshalAMF3Map(t, nil))
	assert.Equal(t, map[string]any{}, marshalAMF3Map(t, (*amf3Nested)(nil)))
	assert.Equal(t, map[string]any{}, marshalAMF3Map(t, struct{}{}))
}

// Byte slices are the one slice written as an AMF3 byte array.
func TestMarshalAMF3ByteSlice(t *testing.T) {
	b, err := MarshalAMF3(map[string]any{"raw": []byte{1, 2, 3}})
	require.NoError(t, err)

	m, ok := goAMF3.DecodeAMF3(b).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []byte{1, 2, 3}, m["raw"])
}

// TestMarshalAMF3_OmitZero pins the omitzero option: unlike omitempty it suppresses
// only the zero value, so an empty-but-non-nil slice still encodes.
func TestMarshalAMF3_OmitZero(t *testing.T) {
	type payload struct {
		Users []string `json:"users,omitzero"`
	}

	tests := []struct {
		name  string
		value payload
		want  string
	}{
		{name: "nil is omitted", value: payload{}, want: ""},
		{name: "empty is kept", value: payload{Users: []string{}}, want: "users"},
		{name: "populated is kept", value: payload{Users: []string{"bob"}}, want: "users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := MarshalAMF3(tt.value)
			assert.NoError(t, err)
			if tt.want == "" {
				assert.NotContains(t, string(b), "users")
			} else {
				assert.Contains(t, string(b), "users")
			}
		})
	}
}
