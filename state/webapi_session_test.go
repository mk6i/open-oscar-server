package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
)

func TestWebAPISession_TempBuddies(t *testing.T) {
	tests := []struct {
		name           string
		setupSession   func() *WebAPISession
		operations     func(*WebAPISession)
		expectedChecks func(*testing.T, *WebAPISession)
	}{
		{
			name: "Initialize_NilTempBuddies",
			setupSession: func() *WebAPISession {
				return &WebAPISession{
					AimSID:       "test-session",
					ScreenName:   DisplayScreenName("testuser"),
					EventQueue:   types.NewEventQueue(100),
					CreatedAt:    time.Now(),
					LastAccessed: time.Now(),
					ExpiresAt:    time.Now().Add(time.Hour),
				}
			},
			operations: func(s *WebAPISession) {
				// Initialize TempBuddies if nil
				if s.TempBuddies == nil {
					s.TempBuddies = make(map[string]bool)
				}
				s.TempBuddies["buddy1"] = true
			},
			expectedChecks: func(t *testing.T, s *WebAPISession) {
				assert.NotNil(t, s.TempBuddies)
				assert.True(t, s.TempBuddies["buddy1"])
				assert.Equal(t, 1, len(s.TempBuddies))
			},
		},
		{
			name: "Add_MultipleTempBuddies",
			setupSession: func() *WebAPISession {
				return &WebAPISession{
					AimSID:       "test-session",
					ScreenName:   DisplayScreenName("testuser"),
					TempBuddies:  make(map[string]bool),
					EventQueue:   types.NewEventQueue(100),
					CreatedAt:    time.Now(),
					LastAccessed: time.Now(),
					ExpiresAt:    time.Now().Add(time.Hour),
				}
			},
			operations: func(s *WebAPISession) {
				s.TempBuddies["buddy1"] = true
				s.TempBuddies["buddy2"] = true
				s.TempBuddies["buddy3"] = true
			},
			expectedChecks: func(t *testing.T, s *WebAPISession) {
				assert.Equal(t, 3, len(s.TempBuddies))
				assert.True(t, s.TempBuddies["buddy1"])
				assert.True(t, s.TempBuddies["buddy2"])
				assert.True(t, s.TempBuddies["buddy3"])
			},
		},
		{
			name: "Add_DuplicateTempBuddy",
			setupSession: func() *WebAPISession {
				return &WebAPISession{
					AimSID:       "test-session",
					ScreenName:   DisplayScreenName("testuser"),
					TempBuddies:  map[string]bool{"buddy1": true},
					EventQueue:   types.NewEventQueue(100),
					CreatedAt:    time.Now(),
					LastAccessed: time.Now(),
					ExpiresAt:    time.Now().Add(time.Hour),
				}
			},
			operations: func(s *WebAPISession) {
				// Add the same buddy again
				s.TempBuddies["buddy1"] = true
			},
			expectedChecks: func(t *testing.T, s *WebAPISession) {
				// Should still only have one entry
				assert.Equal(t, 1, len(s.TempBuddies))
				assert.True(t, s.TempBuddies["buddy1"])
			},
		},
		{
			name: "Remove_TempBuddy",
			setupSession: func() *WebAPISession {
				return &WebAPISession{
					AimSID:     "test-session",
					ScreenName: DisplayScreenName("testuser"),
					TempBuddies: map[string]bool{
						"buddy1": true,
						"buddy2": true,
					},
					EventQueue:   types.NewEventQueue(100),
					CreatedAt:    time.Now(),
					LastAccessed: time.Now(),
					ExpiresAt:    time.Now().Add(time.Hour),
				}
			},
			operations: func(s *WebAPISession) {
				delete(s.TempBuddies, "buddy1")
			},
			expectedChecks: func(t *testing.T, s *WebAPISession) {
				assert.Equal(t, 1, len(s.TempBuddies))
				assert.False(t, s.TempBuddies["buddy1"])
				assert.True(t, s.TempBuddies["buddy2"])
			},
		},
		{
			name: "Check_NonExistentBuddy",
			setupSession: func() *WebAPISession {
				return &WebAPISession{
					AimSID:       "test-session",
					ScreenName:   DisplayScreenName("testuser"),
					TempBuddies:  map[string]bool{"buddy1": true},
					EventQueue:   types.NewEventQueue(100),
					CreatedAt:    time.Now(),
					LastAccessed: time.Now(),
					ExpiresAt:    time.Now().Add(time.Hour),
				}
			},
			operations: func(s *WebAPISession) {
				// No operations, just checking
			},
			expectedChecks: func(t *testing.T, s *WebAPISession) {
				assert.False(t, s.TempBuddies["nonexistent"])
				assert.True(t, s.TempBuddies["buddy1"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			session := tt.setupSession()

			// Perform operations
			tt.operations(session)

			// Verify
			tt.expectedChecks(t, session)
		})
	}
}

func TestWebAPISession_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		isExpired bool
	}{
		{
			name:      "Not_Expired",
			expiresAt: time.Now().Add(time.Hour),
			isExpired: false,
		},
		{
			name:      "Already_Expired",
			expiresAt: time.Now().Add(-time.Hour),
			isExpired: true,
		},
		{
			name:      "Just_Expired",
			expiresAt: time.Now().Add(-time.Second),
			isExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &WebAPISession{
				AimSID:     "test-session",
				ScreenName: DisplayScreenName("testuser"),
				ExpiresAt:  tt.expiresAt,
			}

			assert.Equal(t, tt.isExpired, session.IsExpired())
		})
	}
}

func TestWebAPISession_WithTempBuddiesIntegration(t *testing.T) {
	// Test that temp buddies work correctly with a full session
	session := &WebAPISession{
		AimSID:       "integration-test",
		ScreenName:   DisplayScreenName("testuser"),
		EventQueue:   types.NewEventQueue(100),
		TempBuddies:  nil,
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
		FetchTimeout: 30000,
	}

	// Initialize TempBuddies
	session.TempBuddies = make(map[string]bool)

	// Simulate adding temp buddies
	buddies := []string{"alice", "bob", "charlie"}
	for _, buddy := range buddies {
		session.TempBuddies[buddy] = true
	}

	// Verify all buddies are present
	assert.Equal(t, 3, len(session.TempBuddies))
	for _, buddy := range buddies {
		assert.True(t, session.TempBuddies[buddy], "Buddy %s should be in TempBuddies", buddy)
	}

	// Test that temp buddies persist with the session
	assert.False(t, session.IsExpired())
	assert.Equal(t, "testuser", string(session.ScreenName))
	assert.NotNil(t, session.TempBuddies)

	// Simulate buddy removal
	delete(session.TempBuddies, "bob")
	assert.Equal(t, 2, len(session.TempBuddies))
	assert.False(t, session.TempBuddies["bob"])
	assert.True(t, session.TempBuddies["alice"])
	assert.True(t, session.TempBuddies["charlie"])
}

func TestWebAPISession_TempBuddiesIndependence(t *testing.T) {
	// Test that temp buddies are independent across sessions
	session1 := &WebAPISession{
		AimSID:      "session1",
		ScreenName:  DisplayScreenName("user1"),
		TempBuddies: map[string]bool{"buddy1": true},
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	session2 := &WebAPISession{
		AimSID:      "session2",
		ScreenName:  DisplayScreenName("user2"),
		TempBuddies: map[string]bool{"buddy2": true},
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	// Verify sessions have independent temp buddies
	assert.True(t, session1.TempBuddies["buddy1"])
	assert.False(t, session1.TempBuddies["buddy2"])

	assert.False(t, session2.TempBuddies["buddy1"])
	assert.True(t, session2.TempBuddies["buddy2"])

	// Modify one session's temp buddies
	session1.TempBuddies["buddy3"] = true

	// Verify it doesn't affect the other session
	assert.True(t, session1.TempBuddies["buddy3"])
	assert.False(t, session2.TempBuddies["buddy3"])
}
