package wire

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBARTInfo_HasClearIconHash(t *testing.T) {
	tests := []struct {
		name     string
		bartInfo BARTInfo
		want     bool
	}{
		{
			bartInfo: BARTInfo{
				Hash: GetClearIconHash(),
			},
			want: true,
		},
		{
			bartInfo: BARTInfo{
				Hash: []byte{'s', 'o', 'm', 'e', 'd', 'a', 't', 'a'},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.bartInfo.HasClearIconHash())
		})
	}
}

func TestSNAC_0x01_0x14_OServiceSetPrivacyFlags_IdleFlag(t *testing.T) {
	type fields struct {
		PrivacyFlags uint32
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "flag is set",
			fields: fields{
				PrivacyFlags: OServicePrivacyFlagIdle | OServicePrivacyFlagMember,
			},
			want: true,
		},
		{
			name: "flag is not set",
			fields: fields{
				PrivacyFlags: OServicePrivacyFlagMember,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SNAC_0x01_0x14_OServiceSetPrivacyFlags{
				PrivacyFlags: tt.fields.PrivacyFlags,
			}
			assert.Equal(t, tt.want, s.IdleFlag())
		})
	}
}

func TestSNAC_0x01_0x14_OServiceSetPrivacyFlags_MemberFlag(t *testing.T) {
	type fields struct {
		PrivacyFlags uint32
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "flag is set",
			fields: fields{
				PrivacyFlags: OServicePrivacyFlagIdle | OServicePrivacyFlagMember,
			},
			want: true,
		},
		{
			name: "flag is not set",
			fields: fields{
				PrivacyFlags: OServicePrivacyFlagIdle,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SNAC_0x01_0x14_OServiceSetPrivacyFlags{
				PrivacyFlags: tt.fields.PrivacyFlags,
			}
			assert.Equal(t, tt.want, s.MemberFlag())
		})
	}
}

func TestUnmarshalChatMessageText(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			b: func() []byte {
				tlv := TLVRestBlock{
					TLVList: TLVList{
						NewTLVBE(ChatTLVMessageInfoText, "<p>hello world!</p>"),
					},
				}
				b := &bytes.Buffer{}
				err := MarshalBE(tlv, b)
				assert.NoError(t, err)
				return b.Bytes()
			}(),
			want: "<p>hello world!</p>",
		},
		{
			name: "missing ChatTLVMessageInfoText",
			b: func() []byte {
				tlv := TLVRestBlock{TLVList: TLVList{}}
				b := &bytes.Buffer{}
				err := MarshalBE(tlv, b)
				assert.NoError(t, err)
				return b.Bytes()
			}(),
			wantErr: "has no chat msg text TLV",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalChatMessageText(tt.b)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTLVPaddedRestBlock_Marshal(t *testing.T) {
	block := TLVPaddedRestBlock{
		Reserved: 0,
		TLVList: TLVList{
			NewTLVBE(0x03, uint8(10)),
		},
	}

	buf := &bytes.Buffer{}
	err := MarshalBE(block, buf)
	assert.NoError(t, err)

	expected := []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x0A}
	assert.Equal(t, expected, buf.Bytes())
}

func TestSNAC_0x0D_0x09_TLVExchangeInfo_Marshal(t *testing.T) {
	info := SNAC_0x0D_0x09_TLVExchangeInfo{
		Identifier: 4,
		TLVPaddedRestBlock: TLVPaddedRestBlock{
			Reserved: 0,
			TLVList: TLVList{
				NewTLVBE(0x03, uint8(10)),
			},
		},
	}

	buf := &bytes.Buffer{}
	err := MarshalBE(info, buf)
	assert.NoError(t, err)

	expected := []byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x0A}
	assert.Equal(t, expected, buf.Bytes())
}
