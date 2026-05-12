package handlers

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestBuddyListManager_GetBuddyListForUser_MergesLegacyContacts(t *testing.T) {
	feedbagRetriever := &MockFeedbagRetriever{}
	sessionRetriever := &MockSessionRetriever{}
	manager := NewBuddyListManager(feedbagRetriever, sessionRetriever, slog.Default())

	me := state.NewIdentScreenName("testuser")
	feedbagRetriever.On("RetrieveFeedbag", mock.Anything, me).Return([]wire.FeedbagItem{
		{ItemID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 0},
		{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "feedbagbuddy", GroupID: 1},
	}, nil)
	feedbagRetriever.On("RelationshipsByUser", mock.Anything, me).Return([]state.IdentScreenName{
		state.NewIdentScreenName("legacybuddy"),
		state.NewIdentScreenName("feedbagbuddy"),
		me,
	}, nil)
	sessionRetriever.On("RetrieveSession", state.NewIdentScreenName("feedbagbuddy")).Return(nil)
	sessionRetriever.On("RetrieveSession", state.NewIdentScreenName("legacybuddy")).Return(nil)

	groups, err := manager.GetBuddyListForUser(context.Background(), me)

	assert.NoError(t, err)
	assertBuddyInGroup(t, groups, "Friends", "feedbagbuddy")
	assertBuddyInGroup(t, groups, "Buddies", "legacybuddy")
	assertBuddyMissing(t, groups, "testuser")
	feedbagRetriever.AssertExpectations(t)
	sessionRetriever.AssertExpectations(t)
}

func assertBuddyInGroup(t *testing.T, groups []WebAPIBuddyGroup, groupName string, buddyName string) {
	t.Helper()
	for _, group := range groups {
		if group.Name != groupName {
			continue
		}
		for _, buddy := range group.Buddies {
			if buddy.AimID == buddyName {
				return
			}
		}
	}
	assert.Failf(t, "buddy missing from group", "expected %q in %q", buddyName, groupName)
}

func assertBuddyMissing(t *testing.T, groups []WebAPIBuddyGroup, buddyName string) {
	t.Helper()
	for _, group := range groups {
		for _, buddy := range group.Buddies {
			if buddy.AimID == buddyName {
				assert.Failf(t, "buddy unexpectedly present", "did not expect %q", buddyName)
			}
		}
	}
}
