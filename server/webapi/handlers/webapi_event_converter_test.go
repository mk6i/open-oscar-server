package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
)

// The AMF3 converter re-flattens PresenceEvent through an explicit allowlist, so a
// field absent from that allowlist never reaches an AMF3 client. buddyIcon must be
// on it.
func TestConvertEventForAMF3_PresenceCarriesBuddyIcon(t *testing.T) {
	t.Run("buddyIcon is included when set", func(t *testing.T) {
		out := ConvertEventForAMF3(types.Event{
			Type: types.EventTypePresence,
			Data: types.PresenceEvent{
				AimID:     "mikekelly",
				State:     "online",
				UserType:  "aim",
				BuddyIcon: "http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead",
			},
		})

		eventData := out["eventData"].(map[string]interface{})
		assert.Equal(t,
			"http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead",
			eventData["buddyIcon"])
	})

	t.Run("buddyIcon is omitted when empty", func(t *testing.T) {
		out := ConvertEventForAMF3(types.Event{
			Type: types.EventTypePresence,
			Data: types.PresenceEvent{AimID: "mikekelly", State: "offline", UserType: "aim"},
		})

		eventData := out["eventData"].(map[string]interface{})
		_, ok := eventData["buddyIcon"]
		assert.False(t, ok)
	})
}
