package wire

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestUnmangleXtrazXML(t *testing.T) {
	tests := []struct {
		name    string
		mangled string
		want    string
	}{
		{
			name:    "unmangle basic entities",
			mangled: "&lt;N&gt;&lt;QUERY&gt;&lt;/QUERY&gt;&lt;/N&gt;",
			want:    "<N><QUERY></QUERY></N>",
		},
		{
			name:    "unmangle all entities",
			mangled: "&lt;tag attr=&quot;value&quot;&gt;text &amp; more&lt;/tag&gt;",
			want:    `<tag attr="value">text & more</tag>`,
		},
		{
			name:    "plain text unchanged",
			mangled: "plain text",
			want:    "plain text",
		},
		{
			name:    "empty string",
			mangled: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnmangleXtrazXML(tt.mangled)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMangleXtrazXML(t *testing.T) {
	tests := []struct {
		name  string
		plain string
		want  string
	}{
		{
			name:  "mangle basic XML",
			plain: "<N><QUERY></QUERY></N>",
			want:  "&lt;N&gt;&lt;QUERY&gt;&lt;/QUERY&gt;&lt;/N&gt;",
		},
		{
			name:  "mangle special chars",
			plain: `<tag attr="value">text & more</tag>`,
			want:  "&lt;tag attr=&#34;value&#34;&gt;text &amp; more&lt;/tag&gt;",
		},
		{
			name:  "plain text unchanged",
			plain: "plain text",
			want:  "plain text",
		},
		{
			name:  "empty string",
			plain: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MangleXtrazXML(tt.plain)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseXtrazNotifyRequest(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		want    *XtrazNotifyRequest
		wantErr bool
	}{
		{
			name: "parse valid XStatus request",
			xml: `<N><QUERY><PluginID>srvMng</PluginID></QUERY>` +
				`<NOTIFY><srv><id>cAwaySrv</id>` +
				`<req><id>AwayStat</id><trans>1</trans><senderId>123456</senderId></req>` +
				`</srv></NOTIFY></N>`,
			want: &XtrazNotifyRequest{
				PluginID:  "srvMng",
				ServiceID: "cAwaySrv",
				RequestID: "AwayStat",
				TransID:   "1",
				SenderID:  "123456",
			},
			wantErr: false,
		},
		{
			name:    "parse invalid XML",
			xml:     "<invalid>",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "parse empty XML",
			xml:     "",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseXtrazNotifyRequest([]byte(tt.xml))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseXtrazNotifyResponse(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		want    *XtrazNotifyResponse
		wantErr bool
	}{
		{
			name: "parse valid XStatus response",
			xml: `<NR><RES><ret event="OnRemoteNotification"><srv><id></id>` +
				`<val srv_id="cAwaySrv"><Root><CASXtraSetAwayMessage></CASXtraSetAwayMessage>` +
				`<uin>123456</uin><index>5</index><title>Having a beer</title>` +
				`<desc>Cheers!</desc></Root></val></srv></ret></RES></NR>`,
			want: &XtrazNotifyResponse{
				UIN:     "123456",
				Index:   5,
				Title:   "Having a beer",
				Message: "Cheers!",
			},
			wantErr: false,
		},
		{
			name:    "parse XML without Root element",
			xml:     "<NR><RES></RES></NR>",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "parse empty XML",
			xml:     "",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseXtrazNotifyResponse([]byte(tt.xml))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildXtrazNotifyRequest(t *testing.T) {
	senderUIN := "123456"
	result := BuildXtrazNotifyRequest(senderUIN)

	// Unmangle and verify the structure
	unmangled := UnmangleXtrazXML(result)
	assert.Contains(t, unmangled, "<N>")
	assert.Contains(t, unmangled, "<PluginID>srvMng</PluginID>")
	assert.Contains(t, unmangled, "<senderId>123456</senderId>")
	assert.Contains(t, unmangled, "<id>AwayStat</id>")
	assert.Contains(t, unmangled, "<id>cAwaySrv</id>")

	// Verify it can be parsed back
	parsed, err := ParseXtrazNotifyRequest([]byte(unmangled))
	assert.NoError(t, err)
	assert.Equal(t, "srvMng", parsed.PluginID)
	assert.Equal(t, "cAwaySrv", parsed.ServiceID)
	assert.Equal(t, "AwayStat", parsed.RequestID)
	assert.Equal(t, senderUIN, parsed.SenderID)
}

func TestBuildXtrazNotifyResponse(t *testing.T) {
	uin := "123456"
	index := uint8(5)
	title := "Having a beer"
	message := "Cheers!"

	result := BuildXtrazNotifyResponse(uin, index, title, message)

	// Unmangle and verify the structure
	unmangled := UnmangleXtrazXML(result)
	assert.Contains(t, unmangled, "<NR>")
	assert.Contains(t, unmangled, "<uin>123456</uin>")
	assert.Contains(t, unmangled, "<index>5</index>")

	// Verify it can be parsed back
	parsed, err := ParseXtrazNotifyResponse([]byte(unmangled))
	assert.NoError(t, err)
	assert.Equal(t, uin, parsed.UIN)
	assert.Equal(t, index, parsed.Index)
}

func TestXtrazCapabilityGUID(t *testing.T) {
	// Verify the GUID matches the expected GUID
	expected := "3b60b3ef-d82a-6c45-a4e0-9c5a5e67e865"
	assert.Equal(t, expected, CapXtrazScript.String())
}

func TestXStatusConstants(t *testing.T) {
	assert.Equal(t, uint8(1), XStatusAngry)
	assert.Equal(t, uint8(32), XStatusCoffee2)
}

func TestMoodByID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want Mood
		ok   bool
	}{
		{
			name: "mood with a real ICQ capability",
			id:   "0icqmood6",
			want: Mood{ID: "0icqmood6", Cap: CapXStatusPlate},
			ok:   true,
		},
		{
			name: "mood with a placeholder capability",
			id:   "0icqmood13",
			want: Mood{ID: "0icqmood13", Cap: CapMoodHavingFun},
			ok:   true,
		},
		{
			name: "unknown token",
			id:   "0icqmood999",
		},
		{
			name: "token missing the leading zero",
			id:   "icqmood6",
		},
		{
			name: "empty token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := MoodByID(tt.id)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMoodByCap(t *testing.T) {
	tests := []struct {
		name   string
		cap    uuid.UUID
		wantID string
		ok     bool
	}{
		{
			name:   "capability used by one mood",
			cap:    CapXStatusBeer,
			wantID: "0icqmood4",
			ok:     true,
		},
		{
			name:   "capability shared by two moods returns the canonical one",
			cap:    CapXStatusConsole,
			wantID: "0icqmood81",
			ok:     true,
		},
		{
			name:   "other shared capability returns the canonical one",
			cap:    CapXStatusSleeping,
			wantID: "0icqmood70",
			ok:     true,
		},
		{
			name:   "placeholder capability",
			cap:    CapMoodOnTheWay,
			wantID: "0icqmood83",
			ok:     true,
		},
		{
			name: "capability that is not a mood",
			cap:  CapChat,
		},
		{
			name: "nil capability",
			cap:  uuid.Nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := MoodByCap(tt.cap)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.wantID, got.ID)
			assert.Equal(t, tt.ok, IsMoodCap(tt.cap))
		})
	}
}

// TestMoodsRoundTrip verifies every token resolves to itself and every
// capability to a token that carries it.
func TestMoodsRoundTrip(t *testing.T) {
	canonical := make(map[uuid.UUID]string)

	for _, m := range Moods {
		t.Run(m.ID, func(t *testing.T) {
			byID, ok := MoodByID(m.ID)
			assert.True(t, ok)
			assert.Equal(t, m, byID)

			// A mood with no capability is invisible to other users.
			assert.NotEqual(t, uuid.Nil, m.Cap)

			byCap, ok := MoodByCap(m.Cap)
			assert.True(t, ok)
			assert.Equal(t, m.Cap, byCap.Cap)
		})

		if first, seen := canonical[m.Cap]; seen {
			// A shared capability resolves to whichever mood is listed first.
			byCap, _ := MoodByCap(m.Cap)
			assert.Equal(t, first, byCap.ID)
			continue
		}
		canonical[m.Cap] = m.ID
	}
}

func TestMoodIconID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "encodes length prefix and token bytes",
			id:   "0icqmood6",
			want: "0009306963716d6f6f6436",
		},
		{
			name: "encodes a two digit mood",
			id:   "0icqmood23",
			want: "000a306963716d6f6f643233",
		},
		{
			name: "empty token encodes to nothing",
			id:   "",
			want: "",
		},
		{
			name: "oversized token encodes to nothing",
			id:   strings.Repeat("a", math.MaxUint16+1),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MoodIconID(tt.id))
		})
	}
}

// TestMoodIconIDDecodes verifies every token encodes to something ICQ clients can
// decode: even-length hex whose length prefix matches the token that follows.
func TestMoodIconIDDecodes(t *testing.T) {
	for _, m := range Moods {
		t.Run(m.ID, func(t *testing.T) {
			encoded := MoodIconID(m.ID)
			assert.Zero(t, len(encoded)%2)

			raw, err := hex.DecodeString(encoded)
			assert.NoError(t, err)

			assert.Equal(t, len(m.ID), int(binary.BigEndian.Uint16(raw[:2])))
			assert.Equal(t, m.ID, string(raw[2:]))
		})
	}
}
