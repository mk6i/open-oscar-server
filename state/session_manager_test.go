package state

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/mk6i/retro-aim-server/wire"

	"github.com/stretchr/testify/assert"
)

func TestInMemorySessionManager_AddSession(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	ctx := context.Background()
	sess1, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess1.SetSignonComplete()

	go func() {
		<-sess1.Closed()
		sm.RemoveSession(sess1)
	}()

	sess2, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess2.SetSignonComplete()

	assert.NotSame(t, sess1, sess2)
	assert.Contains(t, sm.AllSessions(), sess2)
}

func TestInMemorySessionManager_AddSession_Timeout(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	sess1, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess1.SetSignonComplete()

	go func() {
		<-sess1.Closed()
		cancel()
	}()

	sess2, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.Nil(t, sess2)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestInMemorySessionManager_AddSession_SessionConflict(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	ctx := context.Background()
	sess1, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.NoError(t, err)
	sess1.SetSignonComplete()

	go func() {
		<-sess1.Closed()
		rec, ok := sm.store[NewIdentScreenName("user-screen-name")]
		if assert.True(t, ok) {
			close(rec.removed)
		}
	}()

	sess2, err := sm.AddSession(ctx, "user-screen-name", false)
	assert.Nil(t, sess2)
	assert.ErrorIs(t, err, errSessConflict)
}

func TestInMemorySessionManager_Remove_Existing(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1Old, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	sm.RemoveSession(user1Old)

	user1New, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1New.SetSignonComplete()

	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()

	sm.RemoveSession(user1New)

	if assert.Len(t, sm.AllSessions(), 1) {
		assert.NotContains(t, sm.AllSessions(), user1Old)
		assert.NotContains(t, sm.AllSessions(), user1New)
		assert.Contains(t, sm.AllSessions(), user2)
	}
}

func TestInMemorySessionManager_Remove_MissingSameScreenName(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1Old, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	sm.RemoveSession(user1Old)

	user1New, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1New.SetSignonComplete()

	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()

	sm.RemoveSession(user1Old)

	if assert.Len(t, sm.AllSessions(), 2) {
		assert.NotContains(t, sm.AllSessions(), user1Old)
		assert.Contains(t, sm.AllSessions(), user1New)
		assert.Contains(t, sm.AllSessions(), user2)
	}
}

func TestInMemorySessionManager_Empty(t *testing.T) {
	tests := []struct {
		name  string
		given []DisplayScreenName
		want  bool
	}{
		{
			name: "session manager is not empty",
			given: []DisplayScreenName{
				"user-screen-name-1",
			},
			want: false,
		},
		{
			name:  "session manager is empty",
			given: []DisplayScreenName{},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewInMemorySessionManager(slog.Default())

			for _, screenName := range tt.given {
				sess, err := sm.AddSession(context.Background(), screenName, false)
				assert.NoError(t, err)
				sess.SetSignonComplete()
			}

			have := sm.Empty()
			assert.Equal(t, tt.want, have)
		})
	}
}

func TestInMemorySessionManager_Retrieve(t *testing.T) {
	tests := []struct {
		name             string
		given            []DisplayScreenName
		lookupScreenName IdentScreenName
		wantScreenName   IdentScreenName
	}{
		{
			name: "lookup finds match",
			given: []DisplayScreenName{
				"user-screen-name-1",
				"user-screen-name-2",
			},
			lookupScreenName: NewIdentScreenName("user-screen-name-2"),
			wantScreenName:   NewIdentScreenName("user-screen-name-2"),
		},
		{
			name:             "lookup does not find match",
			given:            []DisplayScreenName{},
			lookupScreenName: NewIdentScreenName("user-screen-name-3"),
			wantScreenName:   NewIdentScreenName(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewInMemorySessionManager(slog.Default())

			for _, screenName := range tt.given {
				sess, err := sm.AddSession(context.Background(), screenName, false)
				assert.NoError(t, err)
				sess.SetSignonComplete()
			}

			have := sm.RetrieveSession(tt.lookupScreenName, 0)
			if have == nil {
				assert.Empty(t, tt.wantScreenName)
			} else {
				assert.Equal(t, tt.wantScreenName, have.IdentScreenName())
			}
		})
	}
}

func TestInMemorySessionManager_RelayToScreenNames(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()
	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()
	user3, err := sm.AddSession(context.Background(), "user-screen-name-3", false)
	assert.NoError(t, err)
	user3.SetSignonComplete()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	recips := []IdentScreenName{
		NewIdentScreenName("user-screen-name-1"),
		NewIdentScreenName("user-screen-name-2"),
	}
	sm.RelayToScreenNames(context.Background(), recips, want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case have := <-user2.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case <-user3.ReceiveMessage():
		assert.Fail(t, "user 3 should not receive a message")
	default:
	}
}

func TestInMemorySessionManager_Broadcast(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()
	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	sm.RelayToAll(context.Background(), want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case have := <-user2.ReceiveMessage():
		assert.Equal(t, want, have)
	}
}

func TestInMemorySessionManager_Broadcast_SkipClosedSession(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()
	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()
	user2.Close()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	sm.RelayToAll(context.Background(), want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case <-user2.ReceiveMessage():
		assert.Fail(t, "user 2 should not receive a message")
	default:
	}
}

func TestInMemorySessionManager_RelayToScreenName_SessionExists(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()
	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	recip := NewIdentScreenName("user-screen-name-1")
	sm.RelayToScreenName(context.Background(), recip, want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case <-user2.ReceiveMessage():
		assert.Fail(t, "user 2 should not receive a message")
	default:
	}
}

func TestInMemorySessionManager_RelayToScreenName_SessionNotExist(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	recip := NewIdentScreenName("user-screen-name-2")
	sm.RelayToScreenName(context.Background(), recip, want)

	select {
	case <-user1.ReceiveMessage():
		assert.Fail(t, "user 1 should not receive a message")
	default:
	}
}

func TestInMemorySessionManager_RelayToScreenName_SkipFullSession(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()
	msg := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	wantCount := 0
	for {
		if user1.RelayMessage(msg) == SessQueueFull {
			break
		}
		wantCount++
	}

	recip := NewIdentScreenName("user-screen-name-1")
	sm.RelayToScreenName(context.Background(), recip, msg)

	haveCount := 0
loop:
	for {
		select {
		case <-user1.ReceiveMessage():
			haveCount++
		default:
			break loop
		}
	}

	assert.Equal(t, wantCount, haveCount)
}

func TestInMemoryChatSessionManager_RelayToAllExcept_HappyPath(t *testing.T) {
	sm := NewInMemoryChatSessionManager(slog.Default())

	cookie := "the-cookie"
	user1, err := sm.AddSession(context.Background(), cookie, "user-screen-name-1")
	assert.NoError(t, err)
	user1.SetSignonComplete()
	user2, err := sm.AddSession(context.Background(), cookie, "user-screen-name-2")
	assert.NoError(t, err)
	user2.SetSignonComplete()
	user3, err := sm.AddSession(context.Background(), cookie, "user-screen-name-3")
	assert.NoError(t, err)
	user3.SetSignonComplete()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	sm.RelayToAllExcept(context.Background(), cookie, user2.IdentScreenName(), want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case <-user2.ReceiveMessage():
		assert.Fail(t, "user 2 should not receive a message")
	default:
	}

	select {
	case have := <-user3.ReceiveMessage():
		assert.Equal(t, want, have)
	}
}

//func TestInMemoryChatSessionManager_AllSessions_RoomExists(t *testing.T) {
//	sm := NewInMemoryChatSessionManager(slog.Default())
//
//	user1, err := sm.AddSession(context.Background(), "the-cookie", "user-screen-name-1")
//	assert.NoError(t, err)
//	user1.SetSignonComplete()
//	user2, err := sm.AddSession(context.Background(), "the-cookie", "user-screen-name-2")
//	assert.NoError(t, err)
//	user2.SetSignonComplete()
//
//	sessions := sm.AllSessions("the-cookie")
//	assert.Len(t, sessions, 2)
//
//	lookup := make(map[*Session]bool)
//	for _, session := range sessions {
//		lookup[session] = true
//	}
//
//	assert.True(t, lookup[user1])
//	assert.True(t, lookup[user2])
//}

func TestInMemoryChatSessionManager_RelayToScreenName_SessionAndChatRoomExist(t *testing.T) {
	sm := NewInMemoryChatSessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-1")
	assert.NoError(t, err)
	user1.SetSignonComplete()
	user2, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-2")
	assert.NoError(t, err)
	user2.SetSignonComplete()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	recip := NewIdentScreenName("user-screen-name-1")
	sm.RelayToScreenName(context.Background(), "chat-room-1", recip, want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case <-user2.ReceiveMessage():
		assert.Fail(t, "user 2 should not receive a message")
	default:
	}
}

func TestInMemoryChatSessionManager_RemoveSession(t *testing.T) {
	sm := NewInMemoryChatSessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-1")
	assert.NoError(t, err)
	user1.SetSignonComplete()
	user2, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-2")
	assert.NoError(t, err)
	user2.SetSignonComplete()

	assert.Len(t, sm.AllSessions("chat-room-1"), 2)

	sm.RemoveSession(user1)
	sm.RemoveSession(user2)

	assert.Empty(t, sm.AllSessions("chat-room-1"))
}

func TestInMemoryChatSessionManager_RemoveSession_DoubleLogin(t *testing.T) {
	sm := NewInMemoryChatSessionManager(slog.Default())

	chatSess1, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-1")
	assert.NoError(t, err)
	chatSess1.SetSignonComplete()

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		// add the session again. this call blocks until RemoveSession makes
		// room for the new session
		chatSess2, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-1")
		assert.NoError(t, err)
		assert.NotNil(t, chatSess2)
		chatSess2.SetSignonComplete()
		assert.Equal(t, chatSess1.DisplayScreenName(), chatSess2.DisplayScreenName())
		wg.Done()
	}()

	// wait for AddSession() to block
	for sm.mapMutex.TryRLock() {
		sm.mapMutex.RUnlock()
	}

	// AddSession() is blocked waiting for the log. this should unblock
	// AddSession()
	sm.RemoveSession(chatSess1)

	wg.Wait()
}

//func TestInMemoryChatSessionManager_RemoveUserFromAllChats(t *testing.T) {
//	sm := NewInMemoryChatSessionManager(slog.Default())
//
//	user1 := NewIdentScreenName("user-screen-name-1")
//	user1sess, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-1")
//	assert.NoError(t, err)
//	user1sess.SetSignonComplete()
//	user2sess, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-2")
//	assert.NoError(t, err)
//	user2sess.SetSignonComplete()
//
//	assert.Len(t, sm.AllSessions("chat-room-1"), 2)
//
//	sm.RemoveUserFromAllChats(user1)
//
//	lookup := make(map[*Session]bool)
//	for _, session := range sm.AllSessions("chat-room-1") {
//		lookup[session] = true
//	}
//
//	assert.False(t, lookup[user1sess])
//	assert.True(t, lookup[user2sess])
//
//}

func TestInMemorySessionManager_RelayToAll_SkipIncompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	// user2 has not completed signon

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	sm.RelayToAll(context.Background(), want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case <-user2.ReceiveMessage():
		assert.Fail(t, "user 2 should not receive a message because signon is incomplete")
	default:
	}
}

func TestInMemorySessionManager_RetrieveSession_IncompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	// user1 has not completed signon

	sess := sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"), 0)
	assert.Nil(t, sess, "should return nil for session with incomplete signon")

	user1.SetSignonComplete()
	sess = sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"), 0)
	assert.NotNil(t, sess, "should return session after signon is complete")
	assert.Equal(t, user1, sess)
}

func TestInMemorySessionManager_RetrieveSession_CompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	sess := sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"), 0)
	assert.NotNil(t, sess)
	assert.Equal(t, user1, sess)
}

func TestInMemorySessionManager_RelayToScreenNames_SkipIncompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	// user2 has not completed signon

	user3, err := sm.AddSession(context.Background(), "user-screen-name-3", false)
	assert.NoError(t, err)
	user3.SetSignonComplete()

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	recips := []IdentScreenName{
		NewIdentScreenName("user-screen-name-1"),
		NewIdentScreenName("user-screen-name-2"), // incomplete signon
		NewIdentScreenName("user-screen-name-3"),
	}
	sm.RelayToScreenNames(context.Background(), recips, want)

	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	}

	select {
	case <-user2.ReceiveMessage():
		assert.Fail(t, "user 2 should not receive a message because signon is incomplete")
	default:
	}

	select {
	case have := <-user3.ReceiveMessage():
		assert.Equal(t, want, have)
	}
}

func TestInMemorySessionManager_AllSessions_SkipIncompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	// user2 has not completed signon

	user3, err := sm.AddSession(context.Background(), "user-screen-name-3", false)
	assert.NoError(t, err)
	user3.SetSignonComplete()

	sessions := sm.AllSessions()
	assert.Len(t, sessions, 2, "should only return sessions with complete signon")

	// Check that we have sessions for user1 and user3 (by checking SessionGroup identity)
	user1Found := false
	user3Found := false
	user2Found := false

	for _, session := range sessions {
		if session.SessionGroup == user1.SessionGroup {
			user1Found = true
		}
		if session.SessionGroup == user2.SessionGroup {
			user2Found = true
		}
		if session.SessionGroup == user3.SessionGroup {
			user3Found = true
		}
	}

	assert.True(t, user1Found, "user1 should be included (complete signon)")
	assert.False(t, user2Found, "user2 should not be included (incomplete signon)")
	assert.True(t, user3Found, "user3 should be included (complete signon)")
}

func TestInMemorySessionManager_RelayToScreenName_IncompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	// user1 has not completed signon

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	recip := NewIdentScreenName("user-screen-name-1")
	sm.RelayToScreenName(context.Background(), recip, want)

	select {
	case <-user1.ReceiveMessage():
		assert.Fail(t, "user 1 should not receive a message because signon is incomplete")
	default:
	}
}
