package webapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
)

func TestUserTypeFor(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		want       string
	}{
		{"uin", "123456789", userTypeICQ},
		{"single digit", "5", userTypeICQ},
		{"aim handle", "cooluser", userTypeAIM},
		{"aim handle with digits", "cool123", userTypeAIM},
		{"digits around letters", "12abc34", userTypeAIM},
		{"empty", "", userTypeAIM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, userTypeFor(state.NewIdentScreenName(tt.screenName)))
		})
	}
}

func TestServiceFor(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		want       string
	}{
		{"uin names icq", "123400", serviceICQ},
		{"aim handle is unnamed", "mike", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, serviceFor(state.NewIdentScreenName(tt.screenName)))
		})
	}
}

func TestNewServiceData_MatchesUserServiceTag(t *testing.T) {
	cfgs := newServiceData().ServiceConfigs
	require.Len(t, cfgs, 1)

	// The client joins a user's tag to this list by name, so the two must agree.
	assert.Equal(t, serviceFor(state.NewIdentScreenName("123400")), cfgs[0].Name)
	assert.Equal(t, "ICQ", cfgs[0].FriendlyName)
	assert.True(t, cfgs[0].Associated)
	assert.Equal(t, "connected", cfgs[0].ConnectionState)
}
