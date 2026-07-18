package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
)

func TestBuildMyInfo_UserTypeAndService(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		wantType   string
		wantSvc    string
	}{
		{"aim screen name", "mikekelly", "aim", "AIM"},
		{"icq uin", "123456789", "icq", "ICQ"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := buildMyInfo(state.DisplayScreenName(tt.screenName), "online", "")
			assert.Equal(t, tt.wantType, mi["userType"])
			assert.Equal(t, tt.wantSvc, mi["service"])
		})
	}
}

func TestBuildMyInfo_BuddyIcon(t *testing.T) {
	t.Run("included when set", func(t *testing.T) {
		mi := buildMyInfo(state.DisplayScreenName("mikekelly"), "away", "http://x/icon")
		assert.Equal(t, "http://x/icon", mi["buddyIcon"])
	})
	t.Run("omitted when empty so the client merge preserves the current icon", func(t *testing.T) {
		mi := buildMyInfo(state.DisplayScreenName("mikekelly"), "away", "")
		_, ok := mi["buddyIcon"]
		assert.False(t, ok)
	})
}
