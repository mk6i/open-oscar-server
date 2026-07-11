package handlers

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func offlineWebAPIBuddy(aimID, displayID string) WebAPIBuddyInfo {
	return WebAPIBuddyInfo{
		AimID:     aimID,
		DisplayID: displayID,
		State:     "offline",
		UserType:  "aim",
		Bot:       false,
		Service:   "AIM",
	}
}

// withAlias sets the viewer's private name for a buddy. It travels in friendly, not
// displayId, which keeps carrying the buddy's own screen name.
func withAlias(b WebAPIBuddyInfo, alias string) WebAPIBuddyInfo {
	b.Friendly = alias
	return b
}

func TestBuddyListManager_GetBuddyListForUser(t *testing.T) {
	ctx := context.Background()
	owner := state.NewIdentScreenName("listowner")

	tests := []struct {
		name    string
		fb      []wire.FeedbagItem
		fbErr   error
		want    []WebAPIBuddyGroup
		wantErr string
	}{
		{
			name:    "retrieve feedbag error",
			fbErr:   errors.New("db unavailable"),
			wantErr: "failed to retrieve feedbag",
		},
		{
			name: "root group missing order attribute yields no groups",
			fb: []wire.FeedbagItem{
				{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup, TLVLBlock: wire.TLVLBlock{}},
			},
			want: nil,
		},
		{
			name: "empty buddylist yields no groups",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
			},
			want: nil,
		},
		{
			name: "single group with buddies",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1, 2})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "user1", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "user2", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []WebAPIBuddyGroup{
				{
					Name: "Buddies",
					Buddies: []WebAPIBuddyInfo{
						offlineWebAPIBuddy("user1", "user1"),
						offlineWebAPIBuddy("user2", "user2"),
					},
				},
			},
		},
		{
			name: "deny permit and pdinfo items do not produce groups",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{})}},
				},
				{ClassID: wire.FeedbagClassIDDeny, Name: "blockeduser"},
				{ClassID: wire.FeedbagClassIDPermit, Name: "allowuser"},
				{
					ClassID:   wire.FeedbagClassIdPdinfo,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesPdMode, uint8(3))}},
				},
			},
			want: nil,
		},
		{
			name: "buddy with alias",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{
					ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "bob",
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, "Bob Smith")}},
				},
			},
			want: []WebAPIBuddyGroup{
				{
					Name: "Buddies",
					// The buddy is offline, so no locate reply supplies a display
					// name and displayId falls back to the normalized feedbag name.
					Buddies: []WebAPIBuddyInfo{withAlias(offlineWebAPIBuddy("bob", "bob"), "Bob Smith")},
				},
			},
		},
		{
			name: "unnormalized feedbag buddy name still yields a normalized aimId",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "Mike Kelly"},
			},
			want: []WebAPIBuddyGroup{
				{
					Name:    "Buddies",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("mikekelly", "Mike Kelly")},
				},
			},
		},
		{
			name: "buddy with note still listed note not exposed in WebAPI",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{
					ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "alice",
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesNote, "Friend from work")}},
				},
			},
			want: []WebAPIBuddyGroup{
				{
					Name:    "Buddies",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("alice", "alice")},
				},
			},
		},
		{
			name: "multiple groups in root order",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100, 200})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{Name: "Family", GroupID: 200, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "friend1", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 200, Name: "mom", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []WebAPIBuddyGroup{
				{
					Name:    "Buddies",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("friend1", "friend1")},
				},
				{
					Name:    "Family",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("mom", "mom")},
				},
			},
		},
		{
			name: "buddy order follows group order TLV not feedbag slice order",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2, 1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "firstInSlice", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "secondInSlice", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []WebAPIBuddyGroup{
				{
					Name: "Buddies",
					Buddies: []WebAPIBuddyInfo{
						offlineWebAPIBuddy("secondinslice", "secondInSlice"),
						offlineWebAPIBuddy("firstinslice", "firstInSlice"),
					},
				},
			},
		},
		{
			name: "group order follows root order TLV not feedbag slice order",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{200, 100})}},
				},
				{Name: "Family", GroupID: 200, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{2})}}},
				{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "inBuddies", TLVLBlock: wire.TLVLBlock{}},
				{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, GroupID: 200, Name: "inFamily", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []WebAPIBuddyGroup{
				{
					Name:    "Family",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("infamily", "inFamily")},
				},
				{
					Name:    "Buddies",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("inbuddies", "inBuddies")},
				},
			},
		},
		{
			name: "unnamed group becomes Buddies",
			fb: []wire.FeedbagItem{
				{
					Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
				},
				{Name: "", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
					TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
				{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "solo", TLVLBlock: wire.TLVLBlock{}},
			},
			want: []WebAPIBuddyGroup{
				{
					Name:    "Buddies",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("solo", "solo")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &MockFeedbagService{}
			// The locate query returns an error, so every buddy resolves to
			// offline. This keeps the focus on feedbag -> group conversion.
			ls := &MockLocateService{}
			ls.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(wire.SNACMessage{}, errors.New("offline")).Maybe()
			if tt.fbErr != nil {
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(wire.SNACMessage{}, tt.fbErr).Once()
			} else {
				fs.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(
					wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: tt.fb}}, nil,
				).Once()
			}

			m := NewBuddyListManager(fs, ls, slog.Default())
			sess := &state.WebAPISession{
				ScreenName:   state.DisplayScreenName(owner.String()),
				OSCARSession: state.NewSession().AddInstance(),
			}
			got, err := m.GetBuddyListForUser(ctx, sess)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				fs.AssertExpectations(t)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
			fs.AssertExpectations(t)
			ls.AssertExpectations(t)
		})
	}
}

func TestBuddyListManager_GetBuddyListForUser_DisplayIDFromLocateReply(t *testing.T) {
	// Feedbag buddy names are stored normalized, so an online buddy's display
	// name can only come from the locate reply's user info.
	ctx := context.Background()

	fb := []wire.FeedbagItem{
		{
			Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}},
		},
		{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
			TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
		{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"},
	}

	fs := &MockFeedbagService{}
	fs.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: fb}}, nil,
	).Once()

	ls := &MockLocateService{}
	ls.On("UserInfoQuery", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		wire.SNACMessage{Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}}, nil,
	).Once()

	m := NewBuddyListManager(fs, ls, slog.Default())
	sess := &state.WebAPISession{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
	}
	got, err := m.GetBuddyListForUser(ctx, sess)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Buddies, 1)

	assert.Equal(t, "mikekelly", got[0].Buddies[0].AimID)
	assert.Equal(t, "Mike Kelly", got[0].Buddies[0].DisplayID)
	assert.Equal(t, "online", got[0].Buddies[0].State)

	fs.AssertExpectations(t)
	ls.AssertExpectations(t)
}

// The feedbag service relays a session's own writes only to the owner's other
// instances, so renaming a buddy from the web client produces no SNAC for that
// session. Without an explicit invalidation, its cached aliases would keep serving
// the old name and the next presence or IM event would rename the buddy back.
func TestBuddyListManager_SetBuddyAttributeInFeedbag_InvalidatesAliasCache(t *testing.T) {
	ctx := context.Background()

	feedbag := func(alias string) []wire.FeedbagItem {
		buddy := wire.FeedbagItem{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: "mikekelly"}
		buddy.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, alias)}}
		return []wire.FeedbagItem{
			{Name: "", GroupID: 0, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{100})}}},
			{Name: "Buddies", GroupID: 100, ItemID: 0, ClassID: wire.FeedbagClassIdGroup,
				TLVLBlock: wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{1})}}},
			buddy,
		}
	}

	fs := &MockFeedbagService{}
	// Query 1: the alias cache loads. Query 2: SetBuddyAttributeInFeedbag reads the
	// feedbag it is about to rewrite. Query 3: the cache reloads post-invalidation,
	// now seeing the stored rename.
	fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: feedbag("MICHAELKELLY")}}, nil).Twice()
	fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&wire.SNACMessage{}, nil).Once()
	fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: feedbag("MIKE")}}, nil).Once()

	m := NewBuddyListManager(fs, &MockLocateService{}, slog.Default())
	sess := &state.WebAPISession{
		ScreenName:   state.DisplayScreenName("listowner"),
		OSCARSession: state.NewSession().AddInstance(),
	}
	sess.BuddyAliasLoader = func(ctx context.Context) (map[string]string, error) {
		return LookupBuddyAliases(ctx, fs, sess.OSCARSession)
	}

	require.Equal(t, "MICHAELKELLY", sess.Aliases(ctx)["mikekelly"])

	resultCode, err := m.SetBuddyAttributeInFeedbag(ctx, sess, "mikekelly", "MIKE")
	require.NoError(t, err)
	require.Equal(t, "success", resultCode)

	assert.Equal(t, "MIKE", sess.Aliases(ctx)["mikekelly"])
	fs.AssertExpectations(t)
}
