package webapi

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestSession_IsExpired(t *testing.T) {
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
			session := &Session{
				AimSID:     "test-session",
				ScreenName: state.DisplayScreenName("testuser"),
				ExpiresAt:  tt.expiresAt,
			}

			assert.Equal(t, tt.isExpired, session.IsExpired())
		})
	}
}

func TestSessionManager_ShutdownIdempotent(t *testing.T) {
	mgr := NewSessionManager()

	_ = mgr.Shutdown(context.Background())

	assert.NotPanics(t, func() {
		_ = mgr.Shutdown(context.Background())
	})
}

// TestSessionManager_CreateAfterShutdown verifies that a session cannot be
// created once the manager is shut down. Otherwise the reaper is stopped and the
// session would never be closed or reaped, leaking its OSCAR session.
func TestSessionManager_CreateAfterShutdown(t *testing.T) {
	mgr := NewSessionManager()

	_ = mgr.Shutdown(context.Background())

	sess, err := mgr.CreateSession(state.DisplayScreenName("testuser"), []string{"presence"}, nil, "", nil)
	assert.Nil(t, sess)
	assert.ErrorIs(t, err, ErrWebAPISessionManagerClosed)
}

// A broadcast rate limit SNAC surfaces to the client only for the IM class: the
// web client renders any rateLimit event as the conversation-window alert. Code 1
// (a class-params change) is not a status transition and is dropped.
func TestSession_handleRateLimitUpdate(t *testing.T) {
	const imClass = wire.RateLimitClassID(3)

	newSession := func() *Session {
		return &Session{
			IMRateClassID: imClass,
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	rateSNAC := func(classID uint16, code uint16) wire.SNACMessage {
		return wire.SNACMessage{
			Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamChange},
			Body:  wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: code, Rate: wire.RateParamsSNAC{ID: classID}},
		}
	}

	t.Run("IM-class transitions become rateLimit events", func(t *testing.T) {
		sess := newSession()
		sess.handleSNACMessage(rateSNAC(uint16(imClass), 3)) // limited
		sess.handleSNACMessage(rateSNAC(uint16(imClass), 4)) // clear

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 2)
		assert.Equal(t, "limit", events[0].Data.(RateLimitEvent).Classes[0].Status)
		assert.Equal(t, "clear", events[1].Data.(RateLimitEvent).Classes[0].Status)
	})

	t.Run("other classes and non-status codes are ignored", func(t *testing.T) {
		sess := newSession()
		sess.handleSNACMessage(rateSNAC(1, 3))               // class 1 limited: not the IM class
		sess.handleSNACMessage(rateSNAC(uint16(imClass), 1)) // IM class param change, not a status

		assert.Empty(t, sess.EventQueue.GetAllEvents())
	})

	t.Run("a session with no IM class disables the alert", func(t *testing.T) {
		sess := newSession()
		sess.IMRateClassID = 0
		sess.handleSNACMessage(rateSNAC(uint16(imClass), 3))

		assert.Empty(t, sess.EventQueue.GetAllEvents())
	})
}

// A rate-limit disconnect closes the account's OSCAR session; the web session's
// aimsid must then stop resolving. Before this fix GetSession only checked
// time-based expiry, so a client told to disconnect could keep issuing charged
// requests against a dead session (and, downstream, spam clear events on every
// one of them). Once the aimsid is turned away at RequireSession, neither is
// possible.
func TestSessionManager_GetSession_rejectsAfterRateLimitDisconnect(t *testing.T) {
	mgr := NewSessionManager()

	// A rate class that escalates to disconnect after a short back-to-back burst.
	var classes [5]wire.RateClass
	for i := range classes {
		classes[i] = wire.RateClass{
			ID:              wire.RateLimitClassID(i + 1),
			WindowSize:      2,
			ClearLevel:      100,
			AlertLevel:      80,
			LimitLevel:      70,
			DisconnectLevel: 2,
			MaxLevel:        200,
		}
	}
	inst := state.NewSession().AddInstance()
	inst.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

	sess, err := mgr.CreateSession(state.DisplayScreenName("advbot"), []string{"presence"}, inst, "", slog.Default())
	require.NoError(t, err)
	sess.FeedbagLoader = emptyFeedbagLoader

	// Healthy session resolves.
	got, err := mgr.GetSession(context.Background(), sess.AimSID)
	require.NoError(t, err)
	assert.Same(t, sess, got)

	// Burst until EvaluateRateLimit escalates to disconnect, which closes the
	// account's OSCAR session.
	var status wire.RateLimitStatus
	now := time.Now()
	for range 10 {
		if status = inst.Session().EvaluateRateLimit(now, 1); status == wire.RateLimitStatusDisconnect {
			break
		}
	}
	require.Equal(t, wire.RateLimitStatusDisconnect, status)
	require.True(t, inst.IsClosed(), "disconnect must close the OSCAR instance")

	// The aimsid no longer resolves, even though ExpiresAt is far in the future.
	_, err = mgr.GetSession(context.Background(), sess.AimSID)
	assert.ErrorIs(t, err, ErrWebAPISessionExpired)
	assert.False(t, sess.IsExpired(), "the guard must fire on OSCAR close, not on time expiry")

	// The reaper frees the dead entry on its next sweep.
	mgr.reapExpired()
	assert.NotContains(t, mgr.sessions, sess.AimSID)
}

// TestSessionManager_ShutdownDrainsAndClosesSessions verifies that Shutdown
// collects every live session and tears it down: it drains the maps and closes
// each session's event queue and OSCAR instance.
func TestSessionManager_ShutdownDrainsAndClosesSessions(t *testing.T) {
	mgr := NewSessionManager()
	ctx := context.Background()

	inst1 := state.NewSession().AddInstance()
	inst2 := state.NewSession().AddInstance()

	s1, err := mgr.CreateSession(state.DisplayScreenName("alice"), []string{"presence"}, inst1, "", slog.Default())
	assert.NoError(t, err)
	s1.FeedbagLoader = emptyFeedbagLoader
	s2, err := mgr.CreateSession(state.DisplayScreenName("bob"), []string{"presence"}, inst2, "", slog.Default())
	assert.NoError(t, err)
	s2.FeedbagLoader = emptyFeedbagLoader

	assert.NoError(t, mgr.Shutdown(context.Background()))

	// Maps drained: the collect loop ran over both sessions.
	assert.Empty(t, mgr.sessions)

	// Each session's event queue and OSCAR instance were closed: the teardown
	// loop ran for every collected session.
	for _, s := range []*Session{s1, s2} {
		assertQueueClosed(t, ctx, s)
	}
	for _, inst := range []*state.SessionInstance{inst1, inst2} {
		select {
		case <-inst.Closed():
		default:
			t.Error("OSCAR instance should be closed")
		}
	}
}

// TestSessionManager_ReapExpired verifies reapExpired removes and tears
// down only expired sessions, leaving live ones untouched.
func TestSessionManager_ReapExpired(t *testing.T) {
	mgr := NewSessionManager()
	ctx := context.Background()

	expiredInst := state.NewSession().AddInstance()
	liveInst := state.NewSession().AddInstance()

	expired, err := mgr.CreateSession("alice", []string{"presence"}, expiredInst, "", slog.Default())
	assert.NoError(t, err)
	expired.FeedbagLoader = emptyFeedbagLoader
	live, err := mgr.CreateSession("bob", []string{"presence"}, liveInst, "", slog.Default())
	assert.NoError(t, err)
	live.FeedbagLoader = emptyFeedbagLoader

	// Force alice's session into the past; bob keeps its default future expiry.
	expired.ExpiresAt = time.Now().Add(-time.Minute)

	mgr.reapExpired()

	// Expired session removed; live session retained.
	assert.NotContains(t, mgr.sessions, expired.AimSID)
	assert.Contains(t, mgr.sessions, live.AimSID)

	// Expired session torn down: event queue and OSCAR instance closed.
	assertQueueClosed(t, ctx, expired)
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

// assertQueueClosed asserts the session's event queue is closed: a fetch returns
// straight away with no events and no error, rather than parking for the timeout.
func assertQueueClosed(t *testing.T, ctx context.Context, sess *Session) {
	t.Helper()

	const timeout = 5 * time.Second
	start := time.Now()

	events, err := sess.EventQueue.Fetch(ctx, 0, timeout)
	assert.NoError(t, err)
	assert.Empty(t, events)
	assert.Less(t, time.Since(start), timeout/2, "fetch parked instead of returning on a closed queue")
}

// TestSessionManager_ShutdownWithoutReaper verifies Shutdown returns when no
// reaper was ever started. Shutdown must not depend on the caller cancelling the
// context passed to Run.
func TestSessionManager_ShutdownWithoutReaper(t *testing.T) {
	mgr := NewSessionManager()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// This test is about Shutdown returning at all, not what it returns.
		_ = mgr.Shutdown(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown hung waiting for a reaper that was never started")
	}
}

// TestSessionManager_ShutdownJoinsReaper verifies Shutdown stops a running
// reaper on its own and does not return until that reaper has exited.
func TestSessionManager_ShutdownJoinsReaper(t *testing.T) {
	mgr := NewSessionManager()

	reaperExited := make(chan struct{})
	go func() {
		defer close(reaperExited)
		mgr.Run(context.Background()) // context is never cancelled: Shutdown must stop it
	}()

	// Give Run a chance to register itself before shutting down.
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// This test is about Shutdown returning at all, not what it returns.
		_ = mgr.Shutdown(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown hung instead of stopping the reaper")
	}

	// Shutdown joins the reaper, so it has already exited by the time it returns.
	select {
	case <-reaperExited:
	default:
		t.Error("Shutdown returned before the reaper exited")
	}
}

// TestSessionManager_RunAfterShutdown verifies a reaper that loses the race
// with Shutdown never starts, so it cannot reap an already-drained manager.
func TestSessionManager_RunAfterShutdown(t *testing.T) {
	mgr := NewSessionManager()
	assert.NoError(t, mgr.Shutdown(context.Background()))

	done := make(chan struct{})
	go func() {
		defer close(done)
		mgr.Run(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run should be a no-op on a closed manager")
	}
}

// The client deletes the alias it holds each time it merges a user map, so every
// event naming a buddy has to repeat it. An incoming IM and a presence change both
// carry a user map, and both would otherwise rename an aliased buddy.
func TestSession_UINBuddyReportsICQOnArrivalAndDeparture(t *testing.T) {
	sess := &Session{
		ScreenName:    state.DisplayScreenName("me"),
		Events:        []string{"presence"},
		EventQueue:    NewEventQueue(10),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: emptyFeedbagLoader,
	}

	sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "100003"},
	}})
	sess.handleBuddyDeparted(wire.SNACMessage{Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
		TLVUserInfo: wire.TLVUserInfo{ScreenName: "100003"},
	}})

	events := sess.EventQueue.GetAllEvents()
	require.Len(t, events, 2)
	assert.Equal(t, "icq", events[0].Data.(PresenceEvent).UserType)
	assert.Equal(t, "icq", events[1].Data.(PresenceEvent).UserType)
}

func TestSession_RepeatsBuddyAliasOnOSCAREvents(t *testing.T) {
	newSession := func() *Session {
		return &Session{
			ScreenName:    state.DisplayScreenName("me"),
			Events:        []string{"im", "conversation", "presence"},
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: aliasFeedbagLoader(map[string]string{"mikekelly": "MICHAELKELLY"}),
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
		imEvent := events[0].Data.(IMEvent)
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
		presence := events[0].Data.(PresenceEvent)
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
		presence := events[0].Data.(PresenceEvent)
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
		assert.Empty(t, events[0].Data.(PresenceEvent).Friendly)
	})
}

// Aliases all come from one feedbag query, so a signon that brings a whole buddy
// list online must not re-query the feedbag per buddy.
func TestSession_CachesBuddyAliases(t *testing.T) {
	var loads int
	sess := &Session{
		ScreenName: state.DisplayScreenName("me"),
		Events:     []string{"presence"},
		EventQueue: NewEventQueue(10),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: func(context.Context) ([]wire.FeedbagItem, error) {
			loads++
			return aliasFeedbagItems(map[string]string{"mikekelly": "MICHAELKELLY"}), nil
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
		assert.Equal(t, "MICHAELKELLY", event.Data.(PresenceEvent).Friendly)
	}
	assert.Equal(t, 1, loads, "aliases should be loaded once, not once per event")
}

// A feedbag change from another of the owner's clients arrives as a SNAC, which is
// the session's only signal that its cached aliases are stale.
func TestSession_FeedbagSNACInvalidatesAliasCache(t *testing.T) {
	alias := "MICHAELKELLY"
	sess := &Session{
		ScreenName: state.DisplayScreenName("me"),
		Events:     []string{"presence"},
		EventQueue: NewEventQueue(10),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: func(context.Context) ([]wire.FeedbagItem, error) {
			return aliasFeedbagItems(map[string]string{"mikekelly": alias}), nil
		},
	}

	arrive := func() PresenceEvent {
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}})
		events := sess.EventQueue.GetAllEvents()
		require.NotEmpty(t, events)
		return events[len(events)-1].Data.(PresenceEvent)
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

// Permit/deny changes from another of the owner's clients arrive as an insert,
// an update, or a delete, and all three have to refresh the client's privacy
// state.
func TestSession_FeedbagSNACRefreshesPermitDeny(t *testing.T) {
	denyItem := wire.FeedbagItem{ClassID: wire.FeedbagClassIDDeny, Name: "blockeduser"}
	buddyItem := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, Name: "friend"}

	tests := []struct {
		name      string
		subGroup  uint16
		body      any
		wantEvent bool
	}{
		{
			name:      "insert relays an update body",
			subGroup:  wire.FeedbagInsertItem,
			body:      wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{denyItem}},
			wantEvent: true,
		},
		{
			name:      "update",
			subGroup:  wire.FeedbagUpdateItem,
			body:      wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{denyItem}},
			wantEvent: true,
		},
		{
			name:      "delete",
			subGroup:  wire.FeedbagDeleteItem,
			body:      wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{denyItem}},
			wantEvent: true,
		},
		{
			name:      "buddy item only",
			subGroup:  wire.FeedbagInsertItem,
			body:      wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{buddyItem}},
			wantEvent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &Session{
				ScreenName: state.DisplayScreenName("me"),
				EventQueue: NewEventQueue(10),
				logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
				PermitDenyRefresher: func(_ context.Context) (any, error) {
					return map[string]any{"pdMode": "denySome"}, nil
				},
				FeedbagLoader: emptyFeedbagLoader,
			}

			sess.handleFeedbagMessage(wire.SNACMessage{
				Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: tt.subGroup},
				Body:  tt.body,
			})

			var got int
			for _, event := range sess.EventQueue.GetAllEvents() {
				if event.Type == EventTypePermitDeny {
					got++
				}
			}
			if tt.wantEvent {
				assert.Equal(t, 1, got)
			} else {
				assert.Zero(t, got)
			}
		})
	}
}

// A session sees no SNAC for feedbag writes it makes itself, so the handlers that
// perform those writes invalidate the cache directly.
func TestSession_InvalidateFeedbag(t *testing.T) {
	alias := "MICHAELKELLY"
	sess := &Session{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: func(context.Context) ([]wire.FeedbagItem, error) {
			return aliasFeedbagItems(map[string]string{"mikekelly": alias}), nil
		},
	}

	assert.Equal(t, "MICHAELKELLY", sess.Aliases(context.Background())["mikekelly"])

	alias = "MIKE"
	assert.Equal(t, "MICHAELKELLY", sess.Aliases(context.Background())["mikekelly"], "cached until invalidated")

	sess.InvalidateFeedbag()
	assert.Equal(t, "MIKE", sess.Aliases(context.Background())["mikekelly"])
}

// A failed load must not be cached as an empty map: aliases would stay missing for
// the life of the session.
func TestSession_FeedbagLoadErrorIsNotCached(t *testing.T) {
	var loads int
	sess := &Session{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: func(context.Context) ([]wire.FeedbagItem, error) {
			loads++
			if loads == 1 {
				return nil, io.EOF
			}
			return aliasFeedbagItems(map[string]string{"mikekelly": "MICHAELKELLY"}), nil
		},
	}

	assert.Empty(t, sess.Aliases(context.Background()))
	assert.Equal(t, "MICHAELKELLY", sess.Aliases(context.Background())["mikekelly"])
}

func TestSession_HandleIncomingIM_NormalizesAimID(t *testing.T) {
	sess := &Session{
		ScreenName:    state.DisplayScreenName("me"),
		Events:        []string{"im", "conversation"},
		EventQueue:    NewEventQueue(10),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: emptyFeedbagLoader,
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

	imEvent := events[0].Data.(IMEvent)
	assert.Equal(t, "mikekelly", imEvent.Source.AimID)
	assert.Equal(t, "Mike Kelly", imEvent.Source.DisplayID)

	convData := events[1].Data.(*ConversationData)
	require.Len(t, convData.Conversations, 1)
	entry := convData.Conversations[0]
	assert.Equal(t, "mikekelly", entry.AimID)
	assert.Equal(t, "Mike Kelly", entry.DisplayID)
	require.NotNil(t, entry.LastIM)
	assert.Equal(t, "mikekelly", entry.LastIM.Sender)

	// The IM log is keyed by aimId, so the conversation the client opens from
	// this event finds its own history.
	msgs := sess.GetStoredIMs(StoredIMQuery{PartnerAimID: "mikekelly", NToGet: 10})
	require.Len(t, msgs, 1)
	assert.Equal(t, "hello", msgs[0].Message)
}

func TestSession_HandleTypingNotification_NormalizesAimID(t *testing.T) {
	sess := &Session{
		Events:        []string{"typing"},
		EventQueue:    NewEventQueue(10),
		FeedbagLoader: emptyFeedbagLoader,
	}

	sess.handleTypingNotification(wire.SNACMessage{
		Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
			ScreenName: "Mike Kelly",
			Event:      0x0002,
		},
	})

	events := sess.EventQueue.GetAllEvents()
	require.Len(t, events, 1)
	typing := events[0].Data.(TypingEvent)
	assert.Equal(t, "mikekelly", typing.AimID)
	assert.Equal(t, "typing", typing.TypingStatus)
}

func TestSession_HandleBuddyArrivedDeparted_NormalizesAimID(t *testing.T) {
	sess := &Session{
		Events:        []string{"presence"},
		EventQueue:    NewEventQueue(10),
		FeedbagLoader: emptyFeedbagLoader,
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

	arrived := events[0].Data.(PresenceEvent)
	assert.Equal(t, "mikekelly", arrived.AimID)
	assert.Equal(t, "online", arrived.State)

	departed := events[1].Data.(PresenceEvent)
	assert.Equal(t, "mikekelly", departed.AimID)
	assert.Equal(t, "offline", departed.State)
}

// A BuddyArrived carries the buddy's current icon as TLV 0x1D, so an icon change
// rides along on the presence broadcast and must reach the presence event. The
// stub BuddyIconURL stands in for the handlers-side URL formatter, which state
// cannot import.
var testIconBART = wire.BARTID{
	Type:     wire.BARTTypesBuddyIcon,
	BARTInfo: wire.BARTInfo{Hash: []byte{0xde, 0xad, 0xbe, 0xef}},
}

var testStatusBART = statusBARTID("brb")

// statusBARTID builds the BART item that advertises statusMsg as a user's status
// message. It panics only on a message too long to fit the item.
func statusBARTID(statusMsg string) wire.BARTID {
	var id wire.BARTID
	if err := id.SetStatusText(statusMsg); err != nil {
		panic(err)
	}
	return id
}

func TestSession_PublishesBuddyIconOnPresence(t *testing.T) {
	newSession := func() *Session {
		return &Session{
			ScreenName: state.DisplayScreenName("me"),
			Events:     []string{"presence"},
			EventQueue: NewEventQueue(10),
			logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			BuddyIconURL: func(sn state.IdentScreenName, hash []byte) string {
				if len(hash) == 0 {
					return "placeholder:" + sn.String()
				}
				return "icon:" + hex.EncodeToString(hash)
			},
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	arrived := func(sess *Session, screenName string, hash []byte) {
		info := wire.TLVUserInfo{ScreenName: screenName}
		if hash != nil {
			info.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, wire.BARTID{
				Type:     wire.BARTTypesBuddyIcon,
				BARTInfo: wire.BARTInfo{Hash: hash},
			}))
		}
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: info}})
	}

	lastPresence := func(sess *Session) PresenceEvent {
		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		return events[0].Data.(PresenceEvent)
	}

	t.Run("icon hash yields the content-addressed URL", func(t *testing.T) {
		sess := newSession()
		arrived(sess, "Mike Kelly", []byte{0xde, 0xad, 0xbe, 0xef})
		assert.Equal(t, "icon:deadbeef", lastPresence(sess).BuddyIcon)
	})

	t.Run("no icon TLV yields the placeholder URL", func(t *testing.T) {
		sess := newSession()
		arrived(sess, "Mike Kelly", nil)
		assert.Equal(t, "placeholder:mikekelly", lastPresence(sess).BuddyIcon)
	})

	// The BART TLV is a list, so a status message rides in it next to the icon.
	arrivedBART := func(sess *Session, screenName string, ids []wire.BARTID) {
		info := wire.TLVUserInfo{ScreenName: screenName}
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, ids))
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: info}})
	}

	t.Run("a buddy's status message reaches the presence event", func(t *testing.T) {
		sess := newSession()
		arrivedBART(sess, "Mike Kelly", []wire.BARTID{testIconBART, testStatusBART})
		assert.Equal(t, "brb", lastPresence(sess).StatusMsg)
	})

	t.Run("no status message leaves the field empty", func(t *testing.T) {
		sess := newSession()
		arrivedBART(sess, "Mike Kelly", []wire.BARTID{testIconBART})
		assert.Empty(t, lastPresence(sess).StatusMsg)
	})

	t.Run("a status message next to the icon does not displace it", func(t *testing.T) {
		sess := newSession()
		arrivedBART(sess, "Mike Kelly", []wire.BARTID{testIconBART, testStatusBART})
		assert.Equal(t, "icon:deadbeef", lastPresence(sess).BuddyIcon)
	})

	t.Run("a status message without an icon yields the placeholder URL", func(t *testing.T) {
		sess := newSession()
		arrivedBART(sess, "Mike Kelly", []wire.BARTID{testStatusBART})
		assert.Equal(t, "placeholder:mikekelly", lastPresence(sess).BuddyIcon)
	})

	t.Run("cleared icon yields a URL naming the sentinel hash", func(t *testing.T) {
		sess := newSession()
		arrived(sess, "Mike Kelly", wire.GetClearIconHash())
		assert.Equal(t, "icon:"+hex.EncodeToString(wire.GetClearIconHash()), lastPresence(sess).BuddyIcon)
	})

	t.Run("departed omits the icon so the client preserves it", func(t *testing.T) {
		sess := newSession()
		sess.handleBuddyDeparted(wire.SNACMessage{Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}})
		assert.Empty(t, lastPresence(sess).BuddyIcon)
	})

	t.Run("no callback wired omits the icon", func(t *testing.T) {
		sess := newSession()
		sess.BuddyIconURL = nil
		arrived(sess, "Mike Kelly", []byte{0x01})
		assert.Empty(t, lastPresence(sess).BuddyIcon)
	})
}

// A change to a user's own info is relayed to their session as
// OServiceUserInfoUpdate, which the pump turns into a myInfo event so the
// identity badge re-renders.
func TestSession_PushesMyInfoOnUserInfoUpdate(t *testing.T) {
	newSession := func(events ...string) *Session {
		return &Session{
			ScreenName:   state.DisplayScreenName("me"),
			OSCARSession: state.NewSession().AddInstance(),
			BaseURL:      "http://api.example.com",
			Events:       events,
			EventQueue:   NewEventQueue(10),
			logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
			BuddyIconURL: func(sn state.IdentScreenName, hash []byte) string {
				if len(hash) == 0 {
					return "placeholder:" + sn.String()
				}
				return "icon:" + hex.EncodeToString(hash)
			},
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	update := func(info wire.TLVUserInfo) wire.SNACMessage {
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceUserInfoUpdate,
			},
			Body: wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{
				UserInfo: []wire.TLVUserInfo{info},
			},
		}
	}

	lastMyInfo := func(t *testing.T, sess *Session) *MyInfo {
		t.Helper()
		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		require.Equal(t, EventTypeMyInfo, events[0].Type)
		return events[0].Data.(*MyInfo)
	}

	t.Run("subscribed session gets one myInfo built from the SNAC", func(t *testing.T) {
		sess := newSession("myInfo")
		sess.handleSNACMessage(update(wire.TLVUserInfo{ScreenName: "Mike Kelly"}))

		myInfo := lastMyInfo(t, sess)
		assert.Equal(t, "mikekelly", myInfo.AimID)
		assert.Equal(t, "Mike Kelly", myInfo.DisplayID)
		assert.Equal(t, "Mike Kelly", myInfo.Friendly)
		assert.Equal(t, "online", myInfo.State)
	})

	t.Run("a presence subscription also delivers myInfo", func(t *testing.T) {
		sess := newSession("presence")
		sess.handleSNACMessage(update(wire.TLVUserInfo{ScreenName: "me"}))
		assert.Len(t, sess.EventQueue.GetAllEvents(), 1)
	})

	t.Run("unsubscribed session gets nothing", func(t *testing.T) {
		sess := newSession("im")
		sess.handleSNACMessage(update(wire.TLVUserInfo{ScreenName: "me"}))
		assert.Empty(t, sess.EventQueue.GetAllEvents())
	})

	t.Run("other OService subgroups are ignored", func(t *testing.T) {
		sess := newSession("myInfo")
		sess.handleSNACMessage(wire.SNACMessage{Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceRateParamsQuery,
		}})
		assert.Empty(t, sess.EventQueue.GetAllEvents())
	})

	t.Run("an update carrying no user info block pushes nothing", func(t *testing.T) {
		sess := newSession("myInfo")
		sess.handleSNACMessage(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceUserInfoUpdate,
			},
			Body: wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{},
		})
		assert.Empty(t, sess.EventQueue.GetAllEvents())
	})

	t.Run("the away message comes from the session", func(t *testing.T) {
		sess := newSession("myInfo")
		// Session.AwayMessage reads only instances that are actually away.
		sess.OSCARSession.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
		sess.OSCARSession.SetAwayMessage("brb")

		info := wire.TLVUserInfo{ScreenName: "me"}
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))
		sess.handleSNACMessage(update(info))

		myInfo := lastMyInfo(t, sess)
		assert.Equal(t, "away", myInfo.State)
		assert.Equal(t, "brb", myInfo.AwayMsg)
	})

	t.Run("a mood capability publishes its icon", func(t *testing.T) {
		sess := newSession("myInfo")

		info := wire.TLVUserInfo{ScreenName: "me"}
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, wire.CapXStatusPlate[:]))
		sess.handleSNACMessage(update(info))

		assert.Equal(t, "http://api.example.com/mood?id="+wire.MoodIconID("0icqmood6"), lastMyInfo(t, sess).MoodIcon)
	})

	t.Run("the icon hash yields the content-addressed URL", func(t *testing.T) {
		sess := newSession("myInfo")

		info := wire.TLVUserInfo{ScreenName: "me"}
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, wire.BARTID{
			Type:     wire.BARTTypesBuddyIcon,
			BARTInfo: wire.BARTInfo{Hash: []byte{0xde, 0xad, 0xbe, 0xef}},
		}))
		sess.handleSNACMessage(update(info))

		assert.Equal(t, "icon:deadbeef", lastMyInfo(t, sess).BuddyIcon)
	})

	t.Run("a status message without an icon yields the placeholder URL", func(t *testing.T) {
		sess := newSession("myInfo")

		info := wire.TLVUserInfo{ScreenName: "me"}
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, []wire.BARTID{testStatusBART}))
		sess.handleSNACMessage(update(info))

		assert.Equal(t, "placeholder:me", lastMyInfo(t, sess).BuddyIcon)
	})

	// The user info update is the only myInfo raised after a status message is set,
	// so dropping the text here erases it from the user's own badge.
	t.Run("the user's own status message survives the update", func(t *testing.T) {
		sess := newSession("myInfo")

		info := wire.TLVUserInfo{ScreenName: "me"}
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, []wire.BARTID{testStatusBART}))
		sess.handleSNACMessage(update(info))

		assert.Equal(t, "brb", lastMyInfo(t, sess).StatusMsg)
	})

	t.Run("no status message leaves the field empty", func(t *testing.T) {
		sess := newSession("myInfo")
		sess.handleSNACMessage(update(wire.TLVUserInfo{ScreenName: "me"}))
		assert.Empty(t, lastMyInfo(t, sess).StatusMsg)
	})

	t.Run("no icon TLV yields the placeholder URL, which clears a removed icon", func(t *testing.T) {
		sess := newSession("myInfo")
		sess.handleSNACMessage(update(wire.TLVUserInfo{ScreenName: "me"}))
		assert.Equal(t, "placeholder:me", lastMyInfo(t, sess).BuddyIcon)
	})

	t.Run("the state is read off the user info block", func(t *testing.T) {
		tests := []struct {
			name       string
			screenName string
			flags      uint16
			status     uint32
			idle       uint16
			want       string
		}{
			{name: "invisible", screenName: "me", status: wire.OServiceUserStatusInvisible, want: "invisible"},
			{name: "icq busy", screenName: "100003", status: wire.OServiceUserStatusBusy, want: "occupied"},
			{name: "aim busy reports away", screenName: "me", status: wire.OServiceUserStatusBusy, want: "away"},
			{name: "icq dnd", screenName: "100003", status: wire.OServiceUserStatusDND, want: "dnd"},
			{name: "away flag", screenName: "me", flags: wire.OServiceUserFlagUnavailable, want: "away"},
			{name: "away status bit", screenName: "me", status: wire.OServiceUserStatusAway, want: "away"},
			{name: "idle", screenName: "me", idle: 5, want: "idle"},
			{name: "nothing set", screenName: "me", want: "online"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				sess := newSession("myInfo")

				info := wire.TLVUserInfo{ScreenName: tt.screenName}
				info.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, tt.flags))
				info.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, tt.status))
				if tt.idle > 0 {
					info.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, tt.idle))
				}
				sess.handleSNACMessage(update(info))

				assert.Equal(t, tt.want, lastMyInfo(t, sess).State)
			})
		}
	})
}

// TestSessionManager_ShutdownBoundedByContext verifies that Shutdown
// honors its context instead of blocking indefinitely. A listener goroutine that
// ignores cancellation must not be able to hold the whole server open: main
// budgets a few seconds for every server's shutdown combined, so an unbounded
// wait here means the process never exits.
func TestSessionManager_ShutdownBoundedByContext(t *testing.T) {
	mgr := NewSessionManager()

	inst := state.NewSession().AddInstance()
	sess, err := mgr.CreateSession("alice", []string{"presence"}, inst, "", slog.Default())
	assert.NoError(t, err)
	sess.FeedbagLoader = emptyFeedbagLoader

	// Stand in for a listener wedged somewhere that never observes cancellation.
	release := make(chan struct{})
	defer close(release)
	sess.listeners.Go(func() {
		<-release
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = mgr.Shutdown(ctx)
	elapsed := time.Since(start)

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 2*time.Second, "Shutdown must give up at its deadline, not wait on the stuck listener")
}

// TestSession_CloseCancelsSessionContext verifies that Close cancels the
// context handed to the refresher callbacks. The listener runs feedbag queries
// through it, and without cancellation Close's wait lasts as long as the query.
func TestSession_CloseCancelsSessionContext(t *testing.T) {
	mgr := NewSessionManager()

	inst := state.NewSession().AddInstance()
	sess, err := mgr.CreateSession("alice", []string{"presence"}, inst, "", slog.Default())
	assert.NoError(t, err)
	sess.FeedbagLoader = emptyFeedbagLoader

	assert.NoError(t, sess.ctx.Err(), "session context should be live before Close")

	sess.Close()

	assert.ErrorIs(t, sess.ctx.Err(), context.Canceled)
}

// A message replayed out of the offline store arrives as an ordinary
// ICBMChannelMsgToClient stamped with a send time. The client models that as its
// own offlineIM event, keyed by a bare aimId and timestamped when the sender sent
// it rather than when it was delivered.
func TestSession_OfflineIM(t *testing.T) {
	sentAt := time.Now().Add(-2 * time.Hour).Unix()

	newSession := func(events ...string) *Session {
		return &Session{
			ScreenName:    state.DisplayScreenName("me"),
			Events:        events,
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	storedMsg := func(t *testing.T, withSendTime bool) wire.SNACMessage {
		t.Helper()
		frags, err := wire.ICBMFragmentList("sent while you were out")
		require.NoError(t, err)
		body := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			ChannelID:   wire.ICBMChannelIM,
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}
		body.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))
		if withSendTime {
			body.Append(wire.NewTLVBE(wire.ICBMTLVSendTime, uint32(sentAt)))
		}
		return wire.SNACMessage{Body: body}
	}

	t.Run("send time yields an offlineIM event", func(t *testing.T) {
		sess := newSession("im", "offlineIM")
		sess.handleIncomingIM(storedMsg(t, true))

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		assert.Equal(t, EventTypeOfflineIM, events[0].Type)
		offline := events[0].Data.(OfflineIMEvent)
		assert.Equal(t, "mikekelly", offline.AimID)
		assert.Equal(t, "sent while you were out", offline.Message)
		assert.NotEmpty(t, offline.MsgID)
		assert.Equal(t, int64(sentAt), offline.Timestamp)
	})

	t.Run("no send time yields an im event", func(t *testing.T) {
		sess := newSession("im", "offlineIM")
		sess.handleIncomingIM(storedMsg(t, false))

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		assert.Equal(t, EventTypeIM, events[0].Type)
	})

	t.Run("offlineIM subscriber gets a conversation update", func(t *testing.T) {
		sess := newSession("offlineIM", "conversation")
		sess.handleIncomingIM(storedMsg(t, true))

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 2)
		assert.Equal(t, EventTypeOfflineIM, events[0].Type)
		assert.Equal(t, EventTypeConversation, events[1].Type)
	})

	// The history the client pulls with fetchStoredIMs has to order the message by
	// when it was sent, not when the session that drained the store started.
	t.Run("logs the message under its send time", func(t *testing.T) {
		sess := newSession("offlineIM")
		sess.handleIncomingIM(storedMsg(t, true))

		stored := sess.GetStoredIMs(StoredIMQuery{PartnerAimID: "mikekelly", NToGet: 10})
		require.Len(t, stored, 1)
		assert.Equal(t, int64(sentAt), stored[0].Date)
	})

	// Only a live IM is filtered on subscription here. Retrieval answers the
	// instance that asked and StartSession asks only for an offlineIM subscriber,
	// so a stamped message reaching a session that did not subscribe is not a state
	// this handler can be put in.
	t.Run("no subscription drops a live message", func(t *testing.T) {
		sess := newSession("presence")
		sess.handleIncomingIM(storedMsg(t, false))

		assert.Empty(t, sess.EventQueue.GetAllEvents())
	})
}

// A boot closes the account's OSCAR session out from under its web session. The
// client is parked on a long poll at that moment, so it must be released with a
// sessionEnded event rather than left to hang until the reaper's next sweep —
// which measured 26-28s against a running server.
func TestSession_BootReleasesParkedFetcherWithSessionEnded(t *testing.T) {
	mgr := NewSessionManager()
	inst := state.NewSession().AddInstance()

	sess, err := mgr.CreateSession(state.DisplayScreenName("mike"), []string{"presence"}, inst, "", slog.Default())
	require.NoError(t, err)
	sess.FeedbagLoader = emptyFeedbagLoader
	sess.StartListeningToOSCARSession()

	// Park a fetcher the way fetchEvents does, with nothing pending.
	type result struct {
		events []Event
		err    error
	}
	done := make(chan result, 1)
	go func() {
		events, err := sess.EventQueue.Fetch(context.Background(), 0, 60*time.Second)
		done <- result{events, err}
	}()

	// Let the fetcher block before the session is taken away.
	time.Sleep(50 * time.Millisecond)

	inst.Session().CloseSession()

	select {
	case got := <-done:
		require.NoError(t, got.err)
		require.Len(t, got.events, 1)
		assert.Equal(t, EventTypeSessionEnded, got.events[0].Type)
	case <-time.After(5 * time.Second):
		t.Fatal("parked fetcher was not released by the boot")
	}
}

// A session tearing itself down — endSession, or the idle reaper — needs no
// sessionEnded event: the client already knows it is leaving. Close closes the
// queue before the instance, so the listener's push lands on a closed queue.
func TestSession_SelfCloseEmitsNoSessionEndedEvent(t *testing.T) {
	mgr := NewSessionManager()
	inst := state.NewSession().AddInstance()

	sess, err := mgr.CreateSession(state.DisplayScreenName("mike"), []string{"presence"}, inst, "", slog.Default())
	require.NoError(t, err)
	sess.FeedbagLoader = emptyFeedbagLoader
	sess.StartListeningToOSCARSession()

	require.NoError(t, mgr.RemoveSession(context.Background(), sess.AimSID))

	events, err := sess.EventQueue.Fetch(context.Background(), 0, time.Second)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestSession_GetStoredIMs(t *testing.T) {
	sess := &Session{}
	sess.AddStoredIM("buddy1", "me", "hello", "msg-1", 100)
	sess.AddStoredIM("buddy1", "buddy1", "hi back", "msg-2", 200)
	sess.AddStoredIM("buddy2", "buddy2", "other chat", "msg-3", 150)

	msgs := sess.GetStoredIMs(StoredIMQuery{
		PartnerAimID: "buddy1",
		SortOrder:    "descendingDate",
		NToGet:       10,
	})
	assert.Len(t, msgs, 2)
	assert.Equal(t, "msg-2", msgs[0].MsgID)
	assert.Equal(t, int64(200), msgs[0].Date)
	assert.Equal(t, "hello", msgs[1].Message)

	msgs = sess.GetStoredIMs(StoredIMQuery{
		PartnerAimID: "buddy1",
		SortOrder:    "ascendingDate",
		StartTime:    150,
		EndTime:      250,
	})
	assert.Len(t, msgs, 1)
	assert.Equal(t, "msg-2", msgs[0].MsgID)
}

func TestSession_GetStoredIMs_NormalizesPartner(t *testing.T) {
	sess := &Session{}
	sess.AddStoredIM("Mike Kelly", "mikekelly", "hello", "msg-1", 100)

	// The web client queries history by the normalized aimId, never by the
	// display screen name it was stored under.
	msgs := sess.GetStoredIMs(StoredIMQuery{
		PartnerAimID: "mikekelly",
		NToGet:       10,
	})
	require.Len(t, msgs, 1)
	assert.Equal(t, "msg-1", msgs[0].MsgID)
}

// A session gets no insert/update/delete SNAC for a feedbag change it made itself —
// those reach only a user's *other* instances. FeedbagStatus is the one notification
// it does receive, so it drives the roster event for the client's own edits.
func TestSession_FeedbagStatusRefreshesBuddyList(t *testing.T) {
	tests := []struct {
		name      string
		events    []string
		results   []uint16
		body      any
		wantEvent bool
	}{
		{
			name:      "stored item refreshes the roster",
			events:    []string{"buddylist"},
			results:   []uint16{0x0000},
			wantEvent: true,
		},
		{
			// The declined item is still worth a refresh: the roster is how the
			// client discovers the buddy was not stored, since it is absent from it.
			name:      "declined item still refreshes the roster",
			events:    []string{"buddylist"},
			results:   []uint16{feedbagResultAuthRequired},
			wantEvent: true,
		},
		{
			name:      "no event when not subscribed",
			events:    []string{"presence"},
			results:   []uint16{0x0000},
			wantEvent: false,
		},
		{
			name:      "a body of the wrong type still refreshes",
			events:    []string{"buddylist"},
			body:      wire.SNAC_0x13_0x06_FeedbagReply{},
			wantEvent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refreshed := 0
			sess := &Session{
				ScreenName: state.DisplayScreenName("me"),
				Events:     tt.events,
				EventQueue: NewEventQueue(10),
				logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
				BuddyListRefresher: func(_ context.Context) (any, error) {
					refreshed++
					return &BuddyListData{Groups: []BuddyGroup{}}, nil
				},
				FeedbagLoader: emptyFeedbagLoader,
			}

			body := tt.body
			if body == nil {
				body = wire.SNAC_0x13_0x0E_FeedbagStatus{Results: tt.results}
			}
			sess.handleFeedbagMessage(wire.SNACMessage{
				Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagStatus},
				Body:  body,
			})

			var got int
			for _, event := range sess.EventQueue.GetAllEvents() {
				if event.Type == EventTypeBuddyList {
					got++
				}
			}
			if tt.wantEvent {
				assert.Equal(t, 1, got)
				assert.Equal(t, 1, refreshed)
			} else {
				assert.Zero(t, got)
				assert.Zero(t, refreshed, "an unsubscribed session should not even query the roster")
			}
		})
	}
}

func TestSession_HandleClientError(t *testing.T) {
	const (
		cookie = uint64(0xDEADBEEFCAFEF00D)
		msgID  = "11112222-3333-4444-8000-555566667777"
	)

	tests := []struct {
		name string
		// events is what the session subscribed to at startSession.
		events []string
		// record seeds the cookie->msgId map the way a prior im/sendIM would.
		record    bool
		channelID uint16
		wantEvent bool
		wantCooki string
		wantChan  string
	}{
		{
			name:      "im channel names the message this session sent",
			events:    []string{"im"},
			record:    true,
			channelID: wire.ICBMChannelIM,
			wantEvent: true,
			wantCooki: msgID,
			wantChan:  "im",
		},
		{
			name:      "rendezvous channel is reported as data",
			events:    []string{"im"},
			record:    true,
			channelID: wire.ICBMChannelRendezvous,
			wantEvent: true,
			wantCooki: msgID,
			wantChan:  "data",
		},
		{
			// Another instance of the account sent the message, so this session
			// has no msgId for it and must not invent one.
			name:      "unknown cookie yields an empty msgId",
			events:    []string{"im"},
			record:    false,
			channelID: wire.ICBMChannelIM,
			wantEvent: true,
			wantCooki: "",
			wantChan:  "im",
		},
		{
			name:      "not subscribed to im",
			events:    []string{"presence"},
			record:    true,
			channelID: wire.ICBMChannelIM,
			wantEvent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &Session{
				Events:        tt.events,
				EventQueue:    NewEventQueue(10),
				FeedbagLoader: emptyFeedbagLoader,
			}
			if tt.record {
				sess.RecordSentIM(cookie, msgID)
			}

			sess.handleSNACMessage(wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMClientErr,
				},
				Body: wire.SNAC_0x04_0x0B_ICBMClientErr{
					Cookie:     cookie,
					ChannelID:  tt.channelID,
					ScreenName: "Mike Kelly",
					Code:       0x0004,
				},
			})

			events := sess.EventQueue.GetAllEvents()
			if !tt.wantEvent {
				assert.Empty(t, events)
				return
			}

			require.Len(t, events, 1)
			assert.Equal(t, EventTypeClientError, events[0].Type)
			got := events[0].Data.(ClientErrorEvent)
			assert.Equal(t, tt.wantCooki, got.Cookie)
			assert.Equal(t, tt.wantChan, got.Channel)
			// The client keys users by the normalized id and renders the sender's
			// own formatting, so both forms have to survive the translation.
			assert.Equal(t, "mikekelly", got.Source.AimID)
			assert.Equal(t, "Mike Kelly", got.Source.DisplayID)
		})
	}
}

func TestSession_RecordSentIMEvictsOldestCookie(t *testing.T) {
	sess := &Session{}

	for i := 0; i <= sentIMCookieLimit; i++ {
		sess.RecordSentIM(uint64(i), fmt.Sprintf("msg-%d", i))
	}

	// The map is capped, so the oldest send is forgotten while the newest and the
	// one that pushed the map over its limit are both still resolvable.
	assert.Equal(t, "", sess.msgIDForCookie(0))
	assert.Equal(t, "msg-1", sess.msgIDForCookie(1))
	assert.Equal(t, fmt.Sprintf("msg-%d", sentIMCookieLimit), sess.msgIDForCookie(uint64(sentIMCookieLimit)))
	assert.Len(t, sess.sentIMs, sentIMCookieLimit)

	// A repeat cookie updates in place rather than consuming another slot.
	sess.RecordSentIM(1, "msg-1-again")
	assert.Equal(t, "msg-1-again", sess.msgIDForCookie(1))
	assert.Len(t, sess.sentIMs, sentIMCookieLimit)
}

// A buddy's mood rides along in the capability list of a BuddyArrived, so the
// presence event has to carry it as a mood icon URL.
func TestSession_PublishesMoodOnPresence(t *testing.T) {
	newSession := func() *Session {
		return &Session{
			ScreenName:    state.DisplayScreenName("me"),
			BaseURL:       "http://host",
			Events:        []string{"presence"},
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	// arrived delivers a BuddyArrived carrying a raw capabilities TLV value.
	arrived := func(sess *Session, caps []byte, invisible bool) PresenceEvent {
		info := wire.TLVUserInfo{ScreenName: "Mike Kelly"}
		if caps != nil {
			info.Append(wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, caps))
		}
		if invisible {
			info.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, wire.OServiceUserStatusInvisible))
		}
		sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: info}})

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		return events[0].Data.(PresenceEvent)
	}

	capBytes := func(caps ...[16]byte) []byte {
		var b []byte
		for _, c := range caps {
			b = append(b, c[:]...)
		}
		return b
	}

	t.Run("a mood capability yields the mood icon URL", func(t *testing.T) {
		got := arrived(newSession(), capBytes(wire.CapXStatusBeer), false)
		assert.Equal(t, "http://host/mood?id="+wire.MoodIconID("0icqmood4"), got.MoodIcon)
	})

	t.Run("a placeholder capability resolves too", func(t *testing.T) {
		got := arrived(newSession(), capBytes(wire.CapMoodOnTheWay), false)
		assert.Equal(t, "http://host/mood?id="+wire.MoodIconID("0icqmood83"), got.MoodIcon)
	})

	t.Run("a shared capability resolves to the canonical mood", func(t *testing.T) {
		// Console is reachable from 0icqmood15 and 0icqmood81; the table's first
		// entry wins, so the client is told the one it labels "gamepad".
		got := arrived(newSession(), capBytes(wire.CapXStatusConsole), false)
		assert.Equal(t, "http://host/mood?id="+wire.MoodIconID("0icqmood81"), got.MoodIcon)
	})

	t.Run("a mood is found after other capabilities", func(t *testing.T) {
		got := arrived(newSession(), capBytes(wire.CapChat, wire.CapXStatusBeer), false)
		assert.Equal(t, "http://host/mood?id="+wire.MoodIconID("0icqmood4"), got.MoodIcon)
	})

	t.Run("capabilities carrying no mood yield no icon", func(t *testing.T) {
		assert.Empty(t, arrived(newSession(), capBytes(wire.CapChat), false).MoodIcon)
	})

	t.Run("no capabilities TLV yields no icon", func(t *testing.T) {
		assert.Empty(t, arrived(newSession(), nil, false).MoodIcon)
	})

	t.Run("a trailing partial capability is ignored", func(t *testing.T) {
		// A truncated final chunk must not be read as a capability, nor panic.
		truncated := append(capBytes(wire.CapXStatusBeer), 0x01, 0x02, 0x03)
		got := arrived(newSession(), truncated, false)
		assert.Equal(t, "http://host/mood?id="+wire.MoodIconID("0icqmood4"), got.MoodIcon)
	})

	t.Run("a partial capability alone yields no icon", func(t *testing.T) {
		assert.Empty(t, arrived(newSession(), []byte{0x01, 0x02, 0x03}, false).MoodIcon)
	})

	t.Run("an invisible buddy shows no mood", func(t *testing.T) {
		// A mood supersedes state on the client, so one here would render the
		// buddy as present instead of offline.
		got := arrived(newSession(), capBytes(wire.CapXStatusBeer), true)
		assert.Equal(t, "offline", got.State)
		assert.Empty(t, got.MoodIcon)
	})
}

func TestSession_SetMood(t *testing.T) {
	t.Run("advertises the mood alongside the existing capabilities", func(t *testing.T) {
		sess := &Session{capabilities: [][16]byte{wire.CapChat}}

		sess.SetMood(wire.CapXStatusBeer)

		assert.Equal(t, [][16]byte{wire.CapChat, wire.CapXStatusBeer}, sess.Caps())
	})

	t.Run("a second mood replaces the first", func(t *testing.T) {
		// A client shows one mood at a time, so the moods must not accumulate.
		sess := &Session{capabilities: [][16]byte{wire.CapChat}}

		sess.SetMood(wire.CapXStatusBeer)
		sess.SetMood(wire.CapXStatusMusic)

		assert.Equal(t, [][16]byte{wire.CapChat, wire.CapXStatusMusic}, sess.Caps())
	})

	t.Run("panics on a capability that is not a mood", func(t *testing.T) {
		sess := &Session{}
		assert.Panics(t, func() {
			sess.SetMood(wire.CapChat)
		})
	})
}

func TestSession_ClearMood(t *testing.T) {
	t.Run("removes the mood and keeps every other capability", func(t *testing.T) {
		sess := &Session{capabilities: [][16]byte{wire.CapChat, wire.CapFileTransfer}}
		sess.SetMood(wire.CapXStatusBeer)

		sess.ClearMood()

		assert.Equal(t, [][16]byte{wire.CapChat, wire.CapFileTransfer}, sess.Caps())
	})

	t.Run("is a no-op when no mood is set", func(t *testing.T) {
		sess := &Session{capabilities: [][16]byte{wire.CapChat}}

		sess.ClearMood()

		assert.Equal(t, [][16]byte{wire.CapChat}, sess.Caps())
	})
}

func TestSession_Caps(t *testing.T) {
	t.Run("returns a copy the caller cannot write through", func(t *testing.T) {
		sess := &Session{capabilities: [][16]byte{wire.CapChat}}

		caps := sess.Caps()
		caps[0] = wire.CapFileTransfer

		assert.Equal(t, [][16]byte{wire.CapChat}, sess.Caps())
	})

	t.Run("a session advertising no capabilities returns an empty list", func(t *testing.T) {
		assert.Empty(t, (&Session{}).Caps())
	})
}

func TestSessionManager_CreateSession_SeedsCapabilities(t *testing.T) {
	// setStatus rewrites the capability list wholesale from the session's own
	// list, so the sign-on capabilities have to start out in it.
	mgr := NewSessionManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sess, err := mgr.CreateSession("testuser", nil, state.NewSession().AddInstance(), "", logger)
	require.NoError(t, err)
	sess.FeedbagLoader = emptyFeedbagLoader
	assert.Equal(t, webAPICaps, sess.Caps())

	sess.SetMood(wire.CapXStatusBeer)

	other, err := mgr.CreateSession("otheruser", nil, state.NewSession().AddInstance(), "", logger)
	require.NoError(t, err)
	other.FeedbagLoader = emptyFeedbagLoader
	assert.Equal(t, webAPICaps, other.Caps(), "one session's mood must not reach the next session's seed")
}

// An IM does not change its sender's presence, and the client shallow-merges the
// source user map onto the user object the buddy list rendered.
func TestSession_IncomingIMReportsSenderPresenceFromTheView(t *testing.T) {
	newSession := func() *Session {
		return &Session{
			ScreenName:    state.DisplayScreenName("me"),
			Events:        []string{"im", "presence"},
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	incomingIM := func(t *testing.T, sess *Session, from string) IMEvent {
		t.Helper()
		frags, err := wire.ICBMFragmentList("hello")
		require.NoError(t, err)
		body := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			ChannelID:   wire.ICBMChannelIM,
			TLVUserInfo: wire.TLVUserInfo{ScreenName: from},
		}
		body.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))
		sess.handleIncomingIM(wire.SNACMessage{Body: body})

		for _, event := range sess.EventQueue.GetAllEvents() {
			if im, ok := event.Data.(IMEvent); ok {
				return im
			}
		}
		t.Fatal("no im event was pushed")
		return IMEvent{}
	}

	t.Run("an away sender stays away", func(t *testing.T) {
		sess := newSession()
		away := wire.TLVUserInfo{ScreenName: "Mike Kelly"}
		away.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))
		buddyArrives(sess, away)

		assert.Equal(t, "away", incomingIM(t, sess, "Mike Kelly").Source.State)
	})

	t.Run("a busy ICQ sender stays occupied", func(t *testing.T) {
		sess := newSession()
		sess.ScreenName = state.DisplayScreenName("100001")
		busy := wire.TLVUserInfo{ScreenName: "100003"}
		busy.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, wire.OServiceUserStatusBusy))
		buddyArrives(sess, busy)

		assert.Equal(t, "occupied", incomingIM(t, sess, "100003").Source.State)
	})

	t.Run("an online sender is online", func(t *testing.T) {
		sess := newSession()
		buddyArrives(sess, onlineBuddy("Mike Kelly"))

		assert.Equal(t, "online", incomingIM(t, sess, "Mike Kelly").Source.State)
	})

	// A non-buddy raises no arrival, so there is no state to report.
	t.Run("a sender with no presence carries no state", func(t *testing.T) {
		sess := newSession()
		assert.Empty(t, incomingIM(t, sess, "stranger").Source.State)
	})
}

// userInfoWith builds the user info a buddy arrives with.
func userInfoWith(screenName string, tlvs ...wire.TLV) wire.TLVUserInfo {
	info := wire.TLVUserInfo{ScreenName: screenName}
	for _, tlv := range tlvs {
		info.Append(tlv)
	}
	return info
}

func awayFlagTLV() wire.TLV {
	return wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable)
}

func statusTLV(mask uint32) wire.TLV {
	return wire.NewTLVBE(wire.OServiceUserInfoStatus, mask)
}

func idleTLV(minutes uint16) wire.TLV {
	return wire.NewTLVBE(wire.OServiceUserInfoIdleTime, minutes)
}

func TestBuddyWebState(t *testing.T) {
	tests := []struct {
		name        string
		info        wire.TLVUserInfo
		isAIMViewer bool
		wantState   string
		wantIdle    int
	}{
		{
			name:        "a plain arrival is online",
			info:        userInfoWith("buddy"),
			isAIMViewer: true,
			wantState:   "online",
		},
		{
			// A buddy cannot tell an invisible user from a signed-off one.
			name:        "invisible reads as offline",
			info:        userInfoWith("buddy", statusTLV(wire.OServiceUserStatusInvisible)),
			isAIMViewer: true,
			wantState:   "offline",
		},
		{
			name:        "the unavailable flag is away",
			info:        userInfoWith("buddy", awayFlagTLV()),
			isAIMViewer: true,
			wantState:   "away",
		},
		{
			name:        "the away status bit is away",
			info:        userInfoWith("buddy", statusTLV(wire.OServiceUserStatusAway)),
			isAIMViewer: true,
			wantState:   "away",
		},
		{
			// Busy and DND also raise the unavailable flag, so the status bits
			// have to be read first or every busy user reports as away.
			name:        "busy reaches an ICQ viewer as occupied",
			info:        userInfoWith("buddy", statusTLV(wire.OServiceUserStatusBusy), awayFlagTLV()),
			isAIMViewer: false,
			wantState:   "occupied",
		},
		{
			name:        "dnd reaches an ICQ viewer as dnd",
			info:        userInfoWith("buddy", statusTLV(wire.OServiceUserStatusDND), awayFlagTLV()),
			isAIMViewer: false,
			wantState:   "dnd",
		},
		{
			// AIM accounts have no vocabulary for busy or dnd.
			name:        "busy collapses to away for an AIM viewer",
			info:        userInfoWith("buddy", statusTLV(wire.OServiceUserStatusBusy), awayFlagTLV()),
			isAIMViewer: true,
			wantState:   "away",
		},
		{
			name:        "dnd collapses to away for an AIM viewer",
			info:        userInfoWith("buddy", statusTLV(wire.OServiceUserStatusDND), awayFlagTLV()),
			isAIMViewer: true,
			wantState:   "away",
		},
		{
			name:        "idle alone is idle",
			info:        userInfoWith("buddy", idleTLV(7)),
			isAIMViewer: true,
			wantState:   "idle",
			wantIdle:    7,
		},
		{
			// Idle rides along in idleTime without taking over the state.
			name:        "idle does not displace away",
			info:        userInfoWith("buddy", awayFlagTLV(), idleTLV(12)),
			isAIMViewer: true,
			wantState:   "away",
			wantIdle:    12,
		},
		{
			name:        "idle does not displace occupied",
			info:        userInfoWith("buddy", statusTLV(wire.OServiceUserStatusBusy), awayFlagTLV(), idleTLV(3)),
			isAIMViewer: false,
			wantState:   "occupied",
			wantIdle:    3,
		},
		{
			name:        "zero idle minutes leave the buddy online",
			info:        userInfoWith("buddy", idleTLV(0)),
			isAIMViewer: true,
			wantState:   "online",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotState, gotIdle := buddyWebState(tt.info, tt.isAIMViewer)
			assert.Equal(t, tt.wantState, gotState)
			assert.Equal(t, tt.wantIdle, gotIdle)
		})
	}
}

// No locate query follows a presence record, so everything a roster payload
// needs has to survive the trip from the SNAC.
func TestBuddyPresenceFrom(t *testing.T) {
	info := userInfoWith("Mike Kelly", idleTLV(4),
		wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1700000000)),
		wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, wire.CapICQCh2Extended[:]),
		wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, []wire.BARTID{testIconBART, testStatusBART}),
	)

	got := buddyPresenceFrom(info, true)

	assert.Equal(t, "Mike Kelly", got.DisplayID)
	assert.Equal(t, "idle", got.State)
	assert.Equal(t, 4, got.IdleTime)
	assert.Equal(t, int64(1700000000), got.OnlineTime)
	assert.Equal(t, "brb", got.StatusMsg)
	assert.Equal(t, [][16]byte{wire.CapICQCh2Extended}, got.Caps)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, got.IconHash)
	assert.True(t, got.Online())
}

func TestSession_PresenceView(t *testing.T) {
	newSession := func(events ...string) *Session {
		return &Session{
			ScreenName:    state.DisplayScreenName("me"),
			Events:        events,
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	t.Run("an arrival records the buddy under their normalized aimId", func(t *testing.T) {
		sess := newSession("presence")
		buddyArrives(sess, onlineBuddy("Mike Kelly"))

		got, ok := sess.BuddyPresence(state.NewIdentScreenName("MIKE KELLY"))
		require.True(t, ok)
		assert.Equal(t, "online", got.State)
		assert.Equal(t, "Mike Kelly", got.DisplayID)
	})

	t.Run("a buddy never seen has no entry", func(t *testing.T) {
		sess := newSession("presence")
		_, ok := sess.BuddyPresence(state.NewIdentScreenName("stranger"))
		assert.False(t, ok)
	})

	// A departure carries no TLV block, so everything but the display name goes.
	t.Run("a departure marks the buddy offline and keeps their display name", func(t *testing.T) {
		sess := newSession("presence")
		buddyArrives(sess, bartBuddy("Mike Kelly", testIconBART, testStatusBART))
		buddyDeparts(sess, "mikekelly")

		got, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		require.True(t, ok)
		assert.Equal(t, "offline", got.State)
		assert.Equal(t, "Mike Kelly", got.DisplayID)
		assert.Empty(t, got.StatusMsg)
		assert.Empty(t, got.IconHash)
		assert.False(t, got.Online())
	})

	t.Run("a later arrival replaces the earlier state", func(t *testing.T) {
		sess := newSession("presence")
		buddyArrives(sess, onlineBuddy("mikekelly"))
		buddyArrives(sess, userInfoWith("mikekelly", awayFlagTLV()))

		got, _ := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		assert.Equal(t, "away", got.State)
	})

	// The roster reads this view, so a buddylist-only client still needs it.
	t.Run("the view is recorded without a presence subscription", func(t *testing.T) {
		sess := newSession("buddylist")
		buddyArrives(sess, onlineBuddy("mikekelly"))

		got, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		require.True(t, ok)
		assert.Equal(t, "online", got.State)
		assert.Empty(t, sess.EventQueue.GetAllEvents())

		buddyDeparts(sess, "mikekelly")
		got, _ = sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		assert.Equal(t, "offline", got.State)
		assert.Empty(t, sess.EventQueue.GetAllEvents())
	})

	// A UIN viewer keeps ICQ's own vocabulary; an AIM viewer does not.
	t.Run("the viewer's account type decides how busy is reported", func(t *testing.T) {
		busy := userInfoWith("100003", statusTLV(wire.OServiceUserStatusBusy), awayFlagTLV())

		aimViewer := newSession("presence")
		buddyArrives(aimViewer, busy)
		got, _ := aimViewer.BuddyPresence(state.NewIdentScreenName("100003"))
		assert.Equal(t, "away", got.State)

		icqViewer := newSession("presence")
		icqViewer.ScreenName = state.DisplayScreenName("100001")
		buddyArrives(icqViewer, busy)
		got, _ = icqViewer.BuddyPresence(state.NewIdentScreenName("100003"))
		assert.Equal(t, "occupied", got.State)
	})
}

// Idle time and signon time have fields on the presence event and come from the
// same record the roster reads.
func TestSession_PresenceEventCarriesIdleAndOnlineTime(t *testing.T) {
	sess := &Session{
		ScreenName:    state.DisplayScreenName("me"),
		Events:        []string{"presence"},
		EventQueue:    NewEventQueue(10),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: emptyFeedbagLoader,
	}

	buddyArrives(sess, userInfoWith("mikekelly", idleTLV(9),
		wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1700000000))))

	events := sess.EventQueue.GetAllEvents()
	require.Len(t, events, 1)
	got := events[0].Data.(PresenceEvent)
	assert.Equal(t, "idle", got.State)
	assert.Equal(t, 9, got.IdleTime)
	assert.Equal(t, int64(1700000000), got.OnlineTime)
}

// After un-watching a buddy, no arrival or departure for them reaches this
// session again, so a retained entry would serve its last-seen state forever.
func TestSession_ForgetBuddyPresence(t *testing.T) {
	newSession := func() *Session {
		return &Session{
			ScreenName:    state.DisplayScreenName("me"),
			Events:        []string{"presence", "im"},
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: emptyFeedbagLoader,
		}
	}

	t.Run("forgetting drops the entry rather than marking it offline", func(t *testing.T) {
		sess := newSession()
		buddyArrives(sess, onlineBuddy("Mike Kelly"))
		sess.forgetBuddyPresence(state.NewIdentScreenName("mikekelly"))

		// A miss, not an offline record: callers that can fall back to a live
		// lookup have to tell the two apart.
		_, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		assert.False(t, ok)
	})

	t.Run("forgetting an unknown buddy is a no-op", func(t *testing.T) {
		sess := newSession()
		sess.forgetBuddyPresence(state.NewIdentScreenName("stranger"))
		_, ok := sess.BuddyPresence(state.NewIdentScreenName("stranger"))
		assert.False(t, ok)
	})

	t.Run("a later arrival re-establishes the entry", func(t *testing.T) {
		sess := newSession()
		buddyArrives(sess, onlineBuddy("mikekelly"))
		sess.forgetBuddyPresence(state.NewIdentScreenName("mikekelly"))
		buddyArrives(sess, onlineBuddy("mikekelly"))

		got, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		require.True(t, ok)
		assert.Equal(t, "online", got.State)
	})

	// While watched a departure would have arrived; after un-watching none does.
	t.Run("an IM from a forgotten buddy carries no state", func(t *testing.T) {
		sess := newSession()
		buddyArrives(sess, onlineBuddy("Mike Kelly"))
		sess.forgetBuddyPresence(state.NewIdentScreenName("mikekelly"))

		frags, err := wire.ICBMFragmentList("hello")
		require.NoError(t, err)
		body := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			ChannelID:   wire.ICBMChannelIM,
			TLVUserInfo: wire.TLVUserInfo{ScreenName: "Mike Kelly"},
		}
		body.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))
		sess.handleIncomingIM(wire.SNACMessage{Body: body})

		for _, event := range sess.EventQueue.GetAllEvents() {
			if im, ok := event.Data.(IMEvent); ok {
				assert.Empty(t, im.Source.State)
				return
			}
		}
		t.Fatal("no im event was pushed")
	})
}

// A relayed delete names the items that went away, not whether the buddy left the
// roster, so only a buddy absent from the refreshed roster is forgotten.
func TestSession_RelayedFeedbagDeleteForgetsUnlistedBuddies(t *testing.T) {
	newSession := func(roster ...string) *Session {
		sess := &Session{
			ScreenName:    state.DisplayScreenName("me"),
			Events:        []string{"presence", "buddylist"},
			EventQueue:    NewEventQueue(10),
			logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
			FeedbagLoader: emptyFeedbagLoader,
		}
		sess.ctx = context.Background()
		sess.FeedbagLoader = func(context.Context) ([]wire.FeedbagItem, error) {
			items := make([]wire.FeedbagItem, 0, len(roster))
			for i, name := range roster {
				items = append(items, wire.FeedbagItem{
					ItemID: uint16(i + 1), ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: name,
				})
			}
			return items, nil
		}
		return sess
	}

	relayDelete := func(sess *Session, items ...wire.FeedbagItem) {
		sess.handleFeedbagMessage(wire.SNACMessage{
			Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
			Body:  wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: items},
		})
	}

	buddyItem := wire.FeedbagItem{ClassID: wire.FeedbagClassIdBuddy, Name: "mikekelly"}

	t.Run("a buddy gone from the roster is forgotten", func(t *testing.T) {
		sess := newSession()
		buddyArrives(sess, onlineBuddy("Mike Kelly"))

		relayDelete(sess, buddyItem)

		_, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		assert.False(t, ok)
	})

	// The move case: a delete for the old group's item, then an insert.
	t.Run("a buddy still on the roster keeps their entry", func(t *testing.T) {
		sess := newSession("mikekelly")
		buddyArrives(sess, onlineBuddy("Mike Kelly"))

		relayDelete(sess, buddyItem)

		got, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		require.True(t, ok)
		assert.Equal(t, "online", got.State)
	})

	t.Run("a group row does not evict a like-named buddy", func(t *testing.T) {
		sess := newSession()
		buddyArrives(sess, onlineBuddy("keeper"))

		relayDelete(sess, wire.FeedbagItem{ClassID: wire.FeedbagClassIdGroup, Name: "keeper"})

		_, ok := sess.BuddyPresence(state.NewIdentScreenName("keeper"))
		assert.True(t, ok)
	})

	// Without a roster the two cases are indistinguishable, so nothing is dropped.
	t.Run("a roster lookup failure keeps the entry", func(t *testing.T) {
		sess := newSession()
		sess.FeedbagLoader = func(context.Context) ([]wire.FeedbagItem, error) {
			return nil, io.ErrUnexpectedEOF
		}
		buddyArrives(sess, onlineBuddy("Mike Kelly"))

		relayDelete(sess, buddyItem)

		_, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
		assert.True(t, ok)
	})
}

// An insert or update leaves the roster membership intact, so it must not evict.
func TestSession_RelayedFeedbagUpdateKeepsPresence(t *testing.T) {
	sess := &Session{
		ScreenName:    state.DisplayScreenName("me"),
		Events:        []string{"presence", "buddylist"},
		EventQueue:    NewEventQueue(10),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: emptyFeedbagLoader,
	}
	buddyArrives(sess, onlineBuddy("Mike Kelly"))

	sess.handleFeedbagMessage(wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
		Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIdBuddy, Name: "mikekelly"},
		}},
	})

	got, ok := sess.BuddyPresence(state.NewIdentScreenName("mikekelly"))
	require.True(t, ok)
	assert.Equal(t, "online", got.State)
}

// The roster, its aliases and the membership check a relayed delete makes are three
// views of the same rows, so one feedbag change must cost one read.
func TestSession_FeedbagCacheServesEveryReadFromOneLoad(t *testing.T) {
	var loads int
	sess := &Session{
		ScreenName:    state.DisplayScreenName("me"),
		Events:        []string{"presence", "buddylist"},
		EventQueue:    NewEventQueue(10),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		FeedbagLoader: emptyFeedbagLoader,
	}
	sess.ctx = context.Background()
	sess.FeedbagLoader = func(context.Context) ([]wire.FeedbagItem, error) {
		loads++
		return aliasFeedbagItems(map[string]string{"keeper": "KEEPER"}), nil
	}

	buddyArrives(sess, onlineBuddy("keeper"))
	buddyArrives(sess, onlineBuddy("gone"))
	require.Equal(t, 1, loads, "arrivals resolve aliases off one load")

	sess.handleFeedbagMessage(wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
		Body: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{
			{ClassID: wire.FeedbagClassIdBuddy, Name: "gone"},
			{ClassID: wire.FeedbagClassIdBuddy, Name: "keeper"},
		}},
	})
	assert.Equal(t, 2, loads, "one reload serves the whole handler")

	_, ok := sess.BuddyPresence(state.NewIdentScreenName("gone"))
	assert.False(t, ok)
	_, ok = sess.BuddyPresence(state.NewIdentScreenName("keeper"))
	assert.True(t, ok)

	assert.Equal(t, "KEEPER", sess.Aliases(context.Background())["keeper"])
	_, err := sess.Feedbag(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, loads)
}
