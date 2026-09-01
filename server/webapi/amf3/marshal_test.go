package amf3

import (
	"testing"
	"time"

	goAMF3 "github.com/breign/goAMF3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// marshalMap encodes v and decodes it back as an AMF3 object.
func marshalMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := Marshal(v)
	require.NoError(t, err)
	decoded := goAMF3.DecodeAMF3(b)
	m, ok := decoded.(map[string]any)
	require.True(t, ok, "decoded as %T, want an object", decoded)
	return m
}

type tagged struct {
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
func TestMarshalTagOverridesJSON(t *testing.T) {
	m := marshalMap(t, tagged{Sender: "chattingchuck", Message: "hi", Secret: "s", Hidden: "h"})

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
func TestMarshalIntegerRange(t *testing.T) {
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
			m := marshalMap(t, map[string]any{"n": tt.value})
			assert.Equal(t, tt.want, m["n"])
		})
	}
}

type embeddedBase struct {
	AimID string `json:"aimId"`
}

type withEmbedded struct {
	embeddedBase
	State string `json:"state"`
}

type nested struct {
	Source   embeddedBase   `json:"source"`
	Ptr      *embeddedBase  `json:"ptr,omitempty"`
	Absent   *embeddedBase  `json:"absent,omitempty"`
	Required *embeddedBase  `json:"required"`
	Boxed    any            `json:"boxed"`
	List     []embeddedBase `json:"list"`
	NilList  []string       `json:"capabilities"`
	Counts   map[string]int `json:"counts"`
	Any      any            `json:"any"`
	When     time.Time      `json:"when"`
}

func TestMarshalNestedValues(t *testing.T) {
	when := time.Unix(1700000000, 0).UTC()
	m := marshalMap(t, nested{
		Source: embeddedBase{AimID: "chuck"},
		Ptr:    &embeddedBase{AimID: "fred"},
		List:   []embeddedBase{{AimID: "one"}},
		Counts: map[string]int{"unread": 3},
		Any:    embeddedBase{AimID: "boxed"},
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

	// Without omitempty the field is one the client dereferences on sight, so
	// it arrives as an empty object rather than an absent key.
	assert.Equal(t, map[string]any{}, m["required"])
	assert.Equal(t, map[string]any{}, m["boxed"])
}

// An untagged embedded struct contributes its fields to the enclosing object.
func TestMarshalPromotesEmbeddedFields(t *testing.T) {
	m := marshalMap(t, withEmbedded{embeddedBase: embeddedBase{AimID: "chuck"}, State: "online"})

	assert.Equal(t, map[string]any{"aimId": "chuck", "state": "online"}, m)
}

type eventType string

// A named string encodes as its underlying string, which is what carries an
// event's type constant.
func TestMarshalNamedString(t *testing.T) {
	m := marshalMap(t, map[string]any{"type": eventType("presence")})

	assert.Equal(t, "presence", m["type"])
}

// The AMF3 writer emits nothing for a value it cannot handle, truncating the
// enclosing object mid-key, so an unsupported type has to be an error instead.
func TestMarshalRejectsUnsupportedTypes(t *testing.T) {
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
			_, err := Marshal(tt.value)
			assert.Error(t, err)
		})
	}
}

// Every response is an object, so a nil payload is an empty one rather than a
// null the client would dereference.
func TestMarshalNilIsAnEmptyObject(t *testing.T) {
	assert.Equal(t, map[string]any{}, marshalMap(t, nil))
	assert.Equal(t, map[string]any{}, marshalMap(t, (*nested)(nil)))
	assert.Equal(t, map[string]any{}, marshalMap(t, struct{}{}))
}

// Byte slices are the one slice written as an AMF3 byte array.
func TestMarshalByteSlice(t *testing.T) {
	b, err := Marshal(map[string]any{"raw": []byte{1, 2, 3}})
	require.NoError(t, err)

	m, ok := goAMF3.DecodeAMF3(b).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []byte{1, 2, 3}, m["raw"])
}
