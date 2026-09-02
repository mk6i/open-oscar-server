package webapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Some clients read these response keys strictly, throwing on an absent key rather
// than treating it as empty, and nothing surfaces that failure: an event parse is
// dropped and a queued request retried forever. Each key below must therefore be
// present even when its value is empty, zero or false — presence is the contract, not
// the value. These tests keep a future `omitempty` from reintroducing the failure.

// renderJSON sends payload through the default JSON path and returns the body.
func renderJSON(t *testing.T, data any) string {
	t.Helper()
	rr := httptest.NewRecorder()
	SendOK(rr, httptest.NewRequest(http.MethodGet, "/x?f=json", nil), data, nil)
	return rr.Body.String()
}

func TestStrictKeys_IMEvents(t *testing.T) {
	t.Run("im carries imf and autoresponse when false", func(t *testing.T) {
		body := renderJSON(t, IMEvent{
			Source:  UserInfo{AimID: "chattingchuck"},
			Message: "hi",
			Imf:     imfPlainText,
		})

		assert.Contains(t, body, `"imf":"plain"`)
		assert.Contains(t, body, `"autoresponse":false`)
	})

	t.Run("offlineIM carries imf and autoresponse when false", func(t *testing.T) {
		body := renderJSON(t, OfflineIMEvent{
			AimID:   "chattingchuck",
			Message: "hi",
			Imf:     imfPlainText,
		})

		assert.Contains(t, body, `"imf":"plain"`)
		assert.Contains(t, body, `"autoresponse":false`)
	})
}

func TestStrictKeys_BuddyGroupID(t *testing.T) {
	// The zero id is the interesting case: omitempty here would drop the key for
	// the group the client is most likely to have, and cost it the whole roster.
	body := renderJSON(t, BuddyListData{Groups: []BuddyGroup{{
		Name: "Buddies", ID: 0, Buddies: []BuddyInfo{},
	}}})

	assert.Contains(t, body, `"id":0`)
}

func TestStrictKeys_PresenceUsers(t *testing.T) {
	// Each query fills in one field, and a match of none must still render that
	// field as an empty array rather than drop it: a client reading data.users or
	// data.groups strictly cannot tell an absent key from a failed request.
	populatedGroups := []BuddyGroupInfo{{Name: "Buddies", Buddies: []BuddyPresenceInfo{}}}

	t.Run("empty user result still renders the array", func(t *testing.T) {
		body := renderJSON(t, PresenceData{Users: []BuddyPresenceInfo{}})

		assert.Contains(t, body, `"users":[]`)
	})

	t.Run("empty group result still renders the array", func(t *testing.T) {
		body := renderJSON(t, PresenceData{Groups: []BuddyGroupInfo{}})

		assert.Contains(t, body, `"groups":[]`)
	})

	t.Run("buddy list query omits users", func(t *testing.T) {
		body := renderJSON(t, PresenceData{Groups: populatedGroups})

		assert.NotContains(t, body, `"users"`)
	})

	t.Run("presence query omits groups", func(t *testing.T) {
		body := renderJSON(t, PresenceData{Users: []BuddyPresenceInfo{}})

		assert.NotContains(t, body, `"groups"`)
	})
}

func TestStrictKeys_FetchEventsArray(t *testing.T) {
	// A nil slice renders as null, which throws exactly as an absent key does — and
	// a poll that throws is retried every 5s forever.
	body := renderJSON(t, &FetchEventsData{Events: []Event{}})

	assert.Contains(t, body, `"events":[]`)
	assert.NotContains(t, body, `"events":null`)
}

func TestStrictKeys_GetInfoUserData(t *testing.T) {
	// The web client reads loginId and displayName off userData unconditionally, so
	// both keys must survive a blank name.
	body := renderJSON(t, GetInfoData{})

	assert.Contains(t, body, `"loginId":""`)
	assert.Contains(t, body, `"displayName":""`)
}
