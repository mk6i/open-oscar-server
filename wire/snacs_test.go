package wire

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
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

func TestTLVUserInfo_IsAway(t *testing.T) {
	tests := []struct {
		name     string
		userInfo TLVUserInfo
		want     bool
	}{
		{
			name: "flag is set",
			userInfo: TLVUserInfo{
				TLVBlock: TLVBlock{
					TLVList: TLVList{
						NewTLVBE(OServiceUserInfoUserFlags, OServiceUserFlagUnavailable),
					},
				},
			},
			want: true,
		},
		{
			name: "flag is not set",
			userInfo: TLVUserInfo{
				TLVBlock: TLVBlock{
					TLVList: TLVList{
						NewTLVBE(OServiceUserInfoUserFlags, OServiceUserFlagOSCARFree),
					},
				},
			},
			want: false,
		},
		{
			name: "TLV is missing",
			userInfo: TLVUserInfo{
				TLVBlock: TLVBlock{
					TLVList: TLVList{},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.userInfo.IsAway())
		})
	}
}

func TestTLVUserInfo_IsInvisible(t *testing.T) {
	tests := []struct {
		name     string
		userInfo TLVUserInfo
		want     bool
	}{
		{
			name: "status mask has invisible bit set",
			userInfo: TLVUserInfo{
				TLVBlock: TLVBlock{
					TLVList: TLVList{
						NewTLVBE(OServiceUserInfoStatus, OServiceUserStatusInvisible),
					},
				},
			},
			want: true,
		},
		{
			name: "status mask does not have invisible bit set",
			userInfo: TLVUserInfo{
				TLVBlock: TLVBlock{
					TLVList: TLVList{
						NewTLVBE(OServiceUserInfoStatus, OServiceUserStatusAvailable),
					},
				},
			},
			want: false,
		},
		{
			name: "TLV is missing",
			userInfo: TLVUserInfo{
				TLVBlock: TLVBlock{
					TLVList: TLVList{},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.userInfo.IsInvisible())
		})
	}
}

func TestCapabilityUUIDs(t *testing.T) {
	tests := []struct {
		name     string
		cap      uuid.UUID
		expected string
	}{
		// Original capabilities
		{"CapChat", CapChat, "748f2420-6287-11d1-8222-444553540000"},
		{"CapFileTransfer", CapFileTransfer, "09461343-4c7f-11d1-8222-444553540000"},

		// Short caps
		{"CapShortCaps", CapShortCaps, "09460000-4c7f-11d1-8222-444553540000"},
		{"CapSecureIM", CapSecureIM, "09460001-4c7f-11d1-8222-444553540000"},
		{"CapXHTMLIM", CapXHTMLIM, "09460002-4c7f-11d1-8222-444553540000"},
		{"CapRTCVideo", CapRTCVideo, "09460101-4c7f-11d1-8222-444553540000"},
		{"CapHasCamera", CapHasCamera, "09460102-4c7f-11d1-8222-444553540000"},
		{"CapHasMicrophone", CapHasMicrophone, "09460103-4c7f-11d1-8222-444553540000"},
		{"CapRTCAudio", CapRTCAudio, "09460104-4c7f-11d1-8222-444553540000"},
		{"CapHostStatusTextAware", CapHostStatusTextAware, "0946010a-4c7f-11d1-8222-444553540000"},
		{"CapRTIM", CapRTIM, "0946010b-4c7f-11d1-8222-444553540000"},
		{"CapSmartCaps", CapSmartCaps, "094601ff-4c7f-11d1-8222-444553540000"},
		{"CapVoiceChat", CapVoiceChat, "09461341-4c7f-11d1-8222-444553540000"},
		{"CapDirectPlay", CapDirectPlay, "09461342-4c7f-11d1-8222-444553540000"},
		{"CapRouteFinder", CapRouteFinder, "09461344-4c7f-11d1-8222-444553540000"},
		{"CapDirectICBM", CapDirectICBM, "09461345-4c7f-11d1-8222-444553540000"},
		{"CapAvatarService", CapAvatarService, "09461346-4c7f-11d1-8222-444553540000"},
		{"CapStocksAddins", CapStocksAddins, "09461347-4c7f-11d1-8222-444553540000"},
		{"CapFileSharing", CapFileSharing, "09461348-4c7f-11d1-8222-444553540000"},
		{"CapICQCh2Extended", CapICQCh2Extended, "09461349-4c7f-11d1-8222-444553540000"},
		{"CapGames", CapGames, "0946134a-4c7f-11d1-8222-444553540000"},
		{"CapBuddyListTransfer", CapBuddyListTransfer, "0946134b-4c7f-11d1-8222-444553540000"},
		{"CapSupportICQ", CapSupportICQ, "0946134d-4c7f-11d1-8222-444553540000"},
		{"CapUTF8Messages", CapUTF8Messages, "0946134e-4c7f-11d1-8222-444553540000"},

		// Full UUIDs
		{"CapRTFMessages", CapRTFMessages, "97b12751-243c-4334-ad22-d6abf73f1492"},
		{"CapTrillianSecureIM", CapTrillianSecureIM, "f2e7c7f4-fead-4dfb-b235-36798bdf0000"},
		{"CapXtrazScript", CapXtrazScript, "3b60b3ef-d82a-6c45-a4e0-9c5a5e67e865"},

		// Unknown/Legacy
		{"CapUnknownICQ2001_2002", CapUnknownICQ2001_2002, "a0e93f37-4c7f-11d1-8222-444553540000"},
		{"CapUnknownICQ2002", CapUnknownICQ2002, "10cf40d1-4c7f-11d1-8222-444553540000"},
		{"CapUnknownICQ2001", CapUnknownICQ2001, "2e7a6475-fadf-4dc8-886f-ea3595fdb6df"},
		{"CapUnknownICQLite", CapUnknownICQLite, "563fc809-0b6f-41bd-9f79-422609dfa2f3"},
		{"CapGamesAlt", CapGamesAlt, "0946134a-4c7f-11d1-2282-444553540000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.cap.String())
		})
	}
}
