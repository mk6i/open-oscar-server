package state

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInMemorySessionManager_MultiSession(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	ctx := context.Background()

	// Add first session (single-session mode)
	sess1, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess1.SetSignonComplete()

	// Add second session (multi-session mode) - should add to existing SessionGroup
	sess2, err := sm.AddSession(ctx, "user-screen-name", true)
	assert.NoError(t, err)
	sess2.SetSignonComplete()

	// Both sessions should belong to the same SessionGroup
	assert.Equal(t, sess1.SessionGroup, sess2.SessionGroup)

	// Both sessions should be retrievable
	retrieved1 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), 0)
	assert.NotNil(t, retrieved1)
	assert.Equal(t, sess1.SessionGroup, retrieved1.SessionGroup)

	// AllSessions should return both sessions
	allSessions := sm.AllSessions()
	assert.Len(t, allSessions, 2)

	// Remove first session - SessionGroup should still exist
	sm.RemoveSession(sess1)

	// SessionGroup should still exist with one active instance
	retrieved2 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), 0)
	assert.NotNil(t, retrieved2)
	assert.Equal(t, sess2.SessionGroup, retrieved2.SessionGroup)

	// AllSessions should return one session
	allSessions = sm.AllSessions()
	assert.Len(t, allSessions, 1)

	// Remove second session - SessionGroup should be removed
	sm.RemoveSession(sess2)

	// SessionGroup should no longer exist
	retrieved3 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), 0)
	assert.Nil(t, retrieved3)

	// AllSessions should return no sessions
	allSessions = sm.AllSessions()
	assert.Len(t, allSessions, 0)

	// SessionManager should be empty
	assert.True(t, sm.Empty())
}

func TestInMemorySessionManager_MultiSession_ReplaceMode(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	ctx := context.Background()

	// Add first session (single-session mode)
	sess1, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess1.SetSignonComplete()

	// Set up automatic removal when the first session is closed
	go func() {
		<-sess1.Closed()
		sm.RemoveSession(sess1)
	}()

	// Add second session (single-session mode) - should replace the first
	sess2, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess2.SetSignonComplete()

	// Sessions should belong to different SessionGroups (replacement)
	assert.NotEqual(t, sess1.SessionGroup, sess2.SessionGroup)

	// Only the second session should be retrievable
	retrieved := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), 0)
	assert.NotNil(t, retrieved)
	assert.Equal(t, sess2.SessionGroup, retrieved.SessionGroup)

	// AllSessions should return only one session
	allSessions := sm.AllSessions()
	assert.Len(t, allSessions, 1)
}

func TestInMemorySessionManager_RetrieveSession_WithSessionNum(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	ctx := context.Background()

	// Add first session (single-session mode)
	sess1, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess1.SetSignonComplete()

	// Add second session (multi-session mode) - should add to existing SessionGroup
	sess2, err := sm.AddSession(ctx, "user-screen-name", true)
	assert.NoError(t, err)
	sess2.SetSignonComplete()

	// Both sessions should belong to the same SessionGroup
	assert.Equal(t, sess1.SessionGroup, sess2.SessionGroup)

	// Test retrieving with sessionNum = 0 (should return first active instance)
	retrieved0 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), 0)
	assert.NotNil(t, retrieved0)
	assert.Equal(t, sess1.SessionGroup, retrieved0.SessionGroup)

	// Test retrieving with specific session numbers
	retrieved1 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), sess1.InstanceNum())
	assert.NotNil(t, retrieved1)
	assert.Equal(t, sess1.InstanceNum(), retrieved1.InstanceNum())
	assert.Equal(t, sess1.SessionGroup, retrieved1.SessionGroup)

	retrieved2 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), sess2.InstanceNum())
	assert.NotNil(t, retrieved2)
	assert.Equal(t, sess2.InstanceNum(), retrieved2.InstanceNum())
	assert.Equal(t, sess2.SessionGroup, retrieved2.SessionGroup)

	// Test retrieving with non-existent session number
	retrieved3 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), 99)
	assert.Nil(t, retrieved3)

	// Test retrieving with non-existent user
	retrieved4 := sm.RetrieveSession(NewIdentScreenName("non-existent-user"), 1)
	assert.Nil(t, retrieved4)
}

func TestInMemorySessionManager_RetrieveSession_WithSessionNum_IncompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	ctx := context.Background()

	// Add first session (single-session mode)
	sess1, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess1.SetSignonComplete()

	// Add second session (multi-session mode) - should add to existing SessionGroup
	sess2, err := sm.AddSession(ctx, "user-screen-name", true)
	assert.NoError(t, err)
	// sess2 has not completed signon

	// Test retrieving with sessionNum = 0 (should return first active instance with complete signon)
	retrieved0 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), 0)
	assert.NotNil(t, retrieved0)
	assert.Equal(t, sess1.InstanceNum(), retrieved0.InstanceNum())

	// Test retrieving with specific session number for incomplete signon
	retrieved2 := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), sess2.InstanceNum())
	assert.Nil(t, retrieved2, "should return nil for session with incomplete signon")

	// Complete signon for sess2
	sess2.SetSignonComplete()

	// Now should be able to retrieve sess2
	retrieved2Complete := sm.RetrieveSession(NewIdentScreenName("user-screen-name"), sess2.InstanceNum())
	assert.NotNil(t, retrieved2Complete)
	assert.Equal(t, sess2.InstanceNum(), retrieved2Complete.InstanceNum())
}
