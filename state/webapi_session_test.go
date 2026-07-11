package state

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/wire"
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

// TestWebAPISessionManager_ShutdownIdempotent verifies Shutdown is safe to call
// more than once (e.g. from overlapping shutdown paths): the closed flag makes
// the second call a no-op instead of re-draining.
func TestWebAPISessionManager_ShutdownIdempotent(t *testing.T) {
	mgr := NewWebAPISessionManager()

	mgr.Shutdown()

	assert.NotPanics(t, func() {
		mgr.Shutdown()
	})
}

// TestWebAPISessionManager_CreateAfterShutdown verifies that a session cannot be
// created once the manager is shut down. Otherwise the reaper is stopped and the
// session would never be closed or reaped, leaking its OSCAR session.
func TestWebAPISessionManager_CreateAfterShutdown(t *testing.T) {
	mgr := NewWebAPISessionManager()

	ctx := context.Background()
	mgr.Shutdown()

	sess, err := mgr.CreateSession(ctx, DisplayScreenName("testuser"), "dev", []string{"presence"}, nil, nil)
	assert.Nil(t, sess)
	assert.ErrorIs(t, err, ErrWebAPISessionManagerClosed)
}

// TestWebAPISessionManager_ShutdownDrainsAndClosesSessions verifies that Shutdown
// collects every live session and tears it down: it drains the maps and closes
// each session's event queue and OSCAR instance.
func TestWebAPISessionManager_ShutdownDrainsAndClosesSessions(t *testing.T) {
	mgr := NewWebAPISessionManager()
	ctx := context.Background()

	inst1 := NewSession().AddInstance()
	inst2 := NewSession().AddInstance()

	s1, err := mgr.CreateSession(ctx, DisplayScreenName("alice"), "dev", []string{"presence"}, inst1, slog.Default())
	assert.NoError(t, err)
	s2, err := mgr.CreateSession(ctx, DisplayScreenName("bob"), "dev", []string{"presence"}, inst2, slog.Default())
	assert.NoError(t, err)

	mgr.Shutdown()

	// Maps drained: the collect loop ran over both sessions.
	assert.Empty(t, mgr.sessions)

	// Each session's event queue and OSCAR instance were closed: the teardown
	// loop ran for every collected session.
	for _, s := range []*WebAPISession{s1, s2} {
		_, err := s.EventQueue.Fetch(ctx, 0, 10*time.Millisecond)
		assert.Error(t, err, "event queue should be closed")
	}
	for _, inst := range []*SessionInstance{inst1, inst2} {
		select {
		case <-inst.Closed():
		default:
			t.Error("OSCAR instance should be closed")
		}
	}
}

// TestWebAPISessionManager_ReapExpired verifies reapExpired removes and tears
// down only expired sessions, leaving live ones untouched.
func TestWebAPISessionManager_ReapExpired(t *testing.T) {
	mgr := NewWebAPISessionManager()
	ctx := context.Background()

	expiredInst := NewSession().AddInstance()
	liveInst := NewSession().AddInstance()

	expired, err := mgr.CreateSession(ctx, "alice", "dev", []string{"presence"}, expiredInst, slog.Default())
	assert.NoError(t, err)
	live, err := mgr.CreateSession(ctx, "bob", "dev", []string{"presence"}, liveInst, slog.Default())
	assert.NoError(t, err)

	// Force alice's session into the past; bob keeps its default future expiry.
	expired.ExpiresAt = time.Now().Add(-time.Minute)

	mgr.reapExpired()

	// Expired session removed; live session retained.
	assert.NotContains(t, mgr.sessions, expired.AimSID)
	assert.Contains(t, mgr.sessions, live.AimSID)

	// Expired session torn down: event queue and OSCAR instance closed.
	_, err = expired.EventQueue.Fetch(ctx, 0, 10*time.Millisecond)
	assert.Error(t, err, "expired session's event queue should be closed")
	select {
	case <-expiredInst.Closed():
	default:
		t.Error("expired session's OSCAR instance should be closed")
	}

	// Live session left running.
	select {
	case <-liveInst.Closed():
		t.Error("live session's OSCAR instance should not be closed")
	default:
	}
}

// The client deletes the alias it holds each time it merges a user map, so every
// event naming a buddy has to repeat it. An incoming IM and a presence change both
// carry a user map, and both would otherwise rename an aliased buddy.
func TestWebAPISession_RepeatsBuddyAliasOnOSCAREvents(t *testing.T) {
	newSession := func() *WebAPISession {
		return &WebAPISession{
			ScreenName: DisplayScreenName("me"),
			Events:     []string{"im", "conversation", "presence"},
			EventQueue: types.NewEventQueue(10),
			logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			BuddyAliasLoader: func(_ context.Context) (map[string]string, error) {
				return map[string]string{"mikekelly": "MICHAELKELLY"}, nil
			},
		}
	}

	t.Run("incoming IM", func(t *testing.T) {
		sess := newSession()
		frags, err := wire.ICBMFragmentList("hello")
		require.NoError(t, err)
		body := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			ChannelID:   wire.ICBMChannelIM,
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}
		body.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))

		sess.handleIncomingIM(wire.SNACMessage{Body: body})

		events := sess.EventQueue.GetAllEvents()
		require.NotEmpty(t, events)
		imEvent := events[0].Data.(types.IMEvent)
		assert.Equal(t, "mikekelly", imEvent.Source.AimID)
		assert.Equal(t, "Mike Kelly", imEvent.Source.DisplayID)
		assert.Equal(t, "MICHAELKELLY", imEvent.Source.Friendly)
	})

	t.Run("buddy arrived", func(t *testing.T) {
		sess := newSession()
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}})

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		presence := events[0].Data.(types.PresenceEvent)
		assert.Equal(t, "mikekelly", presence.AimID)
		assert.Equal(t, "MICHAELKELLY", presence.Friendly)
	})

	t.Run("buddy departed", func(t *testing.T) {
		sess := newSession()
		sess.handleBuddyDeparted(wire.SNACMessage{Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}})

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		presence := events[0].Data.(types.PresenceEvent)
		assert.Equal(t, "mikekelly", presence.AimID)
		assert.Equal(t, "MICHAELKELLY", presence.Friendly)
	})

	t.Run("unaliased buddy omits friendly", func(t *testing.T) {
		sess := newSession()
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Someone Else"},
		}})

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		assert.Empty(t, events[0].Data.(types.PresenceEvent).Friendly)
	})
}

// Aliases all come from one feedbag query, so a signon that brings a whole buddy
// list online must not re-query the feedbag per buddy.
func TestWebAPISession_CachesBuddyAliases(t *testing.T) {
	var loads int
	sess := &WebAPISession{
		ScreenName: DisplayScreenName("me"),
		Events:     []string{"presence"},
		EventQueue: types.NewEventQueue(10),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		BuddyAliasLoader: func(_ context.Context) (map[string]string, error) {
			loads++
			return map[string]string{"mikekelly": "MICHAELKELLY"}, nil
		},
	}

	for range 5 {
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}})
	}

	events := sess.EventQueue.GetAllEvents()
	require.Len(t, events, 5)
	for _, event := range events {
		assert.Equal(t, "MICHAELKELLY", event.Data.(types.PresenceEvent).Friendly)
	}
	assert.Equal(t, 1, loads, "aliases should be loaded once, not once per event")
}

// A feedbag change from another of the owner's clients arrives as a SNAC, which is
// the session's only signal that its cached aliases are stale.
func TestWebAPISession_FeedbagSNACInvalidatesAliasCache(t *testing.T) {
	alias := "MICHAELKELLY"
	sess := &WebAPISession{
		ScreenName: DisplayScreenName("me"),
		Events:     []string{"presence"},
		EventQueue: types.NewEventQueue(10),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		BuddyAliasLoader: func(_ context.Context) (map[string]string, error) {
			return map[string]string{"mikekelly": alias}, nil
		},
	}

	arrive := func() types.PresenceEvent {
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}})
		events := sess.EventQueue.GetAllEvents()
		require.NotEmpty(t, events)
		return events[len(events)-1].Data.(types.PresenceEvent)
	}

	assert.Equal(t, "MICHAELKELLY", arrive().Friendly)

	// The buddy is renamed elsewhere: the feedbag SNAC must drop the cached map.
	alias = "MIKE"
	sess.handleFeedbagMessage(wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
		Body:  wire.SNAC_0x13_0x09_FeedbagUpdateItem{},
	})

	assert.Equal(t, "MIKE", arrive().Friendly)
}

// A session sees no SNAC for feedbag writes it makes itself, so the handlers that
// perform those writes invalidate the cache directly.
func TestWebAPISession_InvalidateAliases(t *testing.T) {
	alias := "MICHAELKELLY"
	sess := &WebAPISession{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		BuddyAliasLoader: func(_ context.Context) (map[string]string, error) {
			return map[string]string{"mikekelly": alias}, nil
		},
	}

	assert.Equal(t, "MICHAELKELLY", sess.Aliases(context.Background())["mikekelly"])

	alias = "MIKE"
	assert.Equal(t, "MICHAELKELLY", sess.Aliases(context.Background())["mikekelly"], "cached until invalidated")

	sess.InvalidateAliases()
	assert.Equal(t, "MIKE", sess.Aliases(context.Background())["mikekelly"])
}

// A failed load must not be cached as an empty map: aliases would stay missing for
// the life of the session.
func TestWebAPISession_AliasLoadErrorIsNotCached(t *testing.T) {
	var loads int
	sess := &WebAPISession{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		BuddyAliasLoader: func(_ context.Context) (map[string]string, error) {
			loads++
			if loads == 1 {
				return nil, io.EOF
			}
			return map[string]string{"mikekelly": "MICHAELKELLY"}, nil
		},
	}

	assert.Empty(t, sess.Aliases(context.Background()))
	assert.Equal(t, "MICHAELKELLY", sess.Aliases(context.Background())["mikekelly"])
}

func TestWebAPISession_HandleIncomingIM_NormalizesAimID(t *testing.T) {
	sess := &WebAPISession{
		ScreenName: DisplayScreenName("me"),
		Events:     []string{"im", "conversation"},
		EventQueue: types.NewEventQueue(10),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	frags, err := wire.ICBMFragmentList("hello")
	assert.NoError(t, err)

	body := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
		ChannelID:   wire.ICBMChannelIM,
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
	}
	body.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))

	sess.handleIncomingIM(wire.SNACMessage{Body: body})

	events := sess.EventQueue.GetAllEvents()
	require.Len(t, events, 2)

	imEvent := events[0].Data.(types.IMEvent)
	assert.Equal(t, "mikekelly", imEvent.Source.AimID)
	assert.Equal(t, "Mike Kelly", imEvent.Source.DisplayID)

	convData := events[1].Data.(map[string]interface{})
	entries := convData["conversations"].([]map[string]interface{})
	require.Len(t, entries, 1)
	assert.Equal(t, "mikekelly", entries[0]["aimId"])
	assert.Equal(t, "Mike Kelly", entries[0]["displayId"])
	assert.Equal(t, "mikekelly", entries[0]["lastIM"].(map[string]interface{})["sender"])

	// The IM log is keyed by aimId, so the conversation the client opens from
	// this event finds its own history.
	msgs := sess.GetStoredIMs(StoredIMQuery{PartnerAimID: "mikekelly", NToGet: 10})
	require.Len(t, msgs, 1)
	assert.Equal(t, "hello", msgs[0]["message"])
}

func TestWebAPISession_HandleTypingNotification_NormalizesAimID(t *testing.T) {
	sess := &WebAPISession{
		Events:     []string{"typing"},
		EventQueue: types.NewEventQueue(10),
	}

	sess.handleTypingNotification(wire.SNACMessage{
		Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
			ScreenName: "Mike Kelly",
			Event:      0x0002,
		},
	})

	events := sess.EventQueue.GetAllEvents()
	require.Len(t, events, 1)
	typing := events[0].Data.(types.TypingEvent)
	assert.Equal(t, "mikekelly", typing.AimID)
	assert.Equal(t, "typing", typing.TypingStatus)
}

func TestWebAPISession_HandleBuddyArrivedDeparted_NormalizesAimID(t *testing.T) {
	sess := &WebAPISession{
		Events:     []string{"presence"},
		EventQueue: types.NewEventQueue(10),
	}

	sess.handleBuddyArrived(wire.SNACMessage{
		Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		},
	})
	sess.handleBuddyDeparted(wire.SNACMessage{
		Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		},
	})

	events := sess.EventQueue.GetAllEvents()
	require.Len(t, events, 2)

	arrived := events[0].Data.(types.PresenceEvent)
	assert.Equal(t, "mikekelly", arrived.AimID)
	assert.Equal(t, "online", arrived.State)

	departed := events[1].Data.(types.PresenceEvent)
	assert.Equal(t, "mikekelly", departed.AimID)
	assert.Equal(t, "offline", departed.State)
}
