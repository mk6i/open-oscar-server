package handlers

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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
		Service:   "aim",
	}
}

func buddyCountInGroups(groups []WebAPIBuddyGroup) int {
	n := 0
	for _, g := range groups {
		n += len(g.Buddies)
	}
	return n
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
					Name:    "Buddies",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("bob", "Bob Smith")},
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
						offlineWebAPIBuddy("secondInSlice", "secondInSlice"),
						offlineWebAPIBuddy("firstInSlice", "firstInSlice"),
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
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("inFamily", "inFamily")},
				},
				{
					Name:    "Buddies",
					Buddies: []WebAPIBuddyInfo{offlineWebAPIBuddy("inBuddies", "inBuddies")},
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
			fr := &MockFeedbagRetriever{}
			sr := &MockSessionRetriever{}
			if tt.fbErr != nil {
				fr.On("RetrieveFeedbag", mock.Anything, owner).Return(nil, tt.fbErr).Once()
			} else {
				fr.On("RetrieveFeedbag", mock.Anything, owner).Return(tt.fb, nil).Once()
				if bc := buddyCountInGroups(tt.want); bc > 0 {
					sr.On("RetrieveSession", mock.Anything).Return((*state.Session)(nil)).Times(bc)
				}
			}

			m := NewBuddyListManager(fr, sr, slog.Default())
			got, err := m.GetBuddyListForUser(ctx, owner)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				fr.AssertExpectations(t)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
			fr.AssertExpectations(t)
			if tt.fbErr == nil && buddyCountInGroups(tt.want) > 0 {
				sr.AssertExpectations(t)
			}
		})
	}
}
