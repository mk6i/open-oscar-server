package wire

import (
	"testing"

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
