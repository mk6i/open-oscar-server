package state

import (
	"context"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mk6i/open-oscar-server/wire"

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
	assert.Contains(t, sm.AllSessions(), sess2.Session())
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

func TestInMemorySessionManager_Remove_Existing(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1Old, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)

	// Verify the old session is in the store
	rec, ok := sm.store[user1Old.IdentScreenName()]
	assert.True(t, ok)
	assert.Equal(t, user1Old.Session(), rec.session)

	// Remove the session
	sm.RemoveSession(user1Old)

	// Verify the session is no longer in the store
	_, ok = sm.store[user1Old.IdentScreenName()]
	assert.False(t, ok)

	// Verify the removed channel was closed
	select {
	case <-rec.removed:
		// Channel was closed, as expected
	default:
		assert.Fail(t, "removed channel should be closed")
	}

	user1New, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1New.SetSignonComplete()

	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()

	// Remove user1New and verify it's gone
	sm.RemoveSession(user1New)
	_, ok = sm.store[user1New.IdentScreenName()]
	assert.False(t, ok)

	if assert.Len(t, sm.AllSessions(), 1) {
		assert.NotContains(t, sm.AllSessions(), user1Old.Session())
		assert.NotContains(t, sm.AllSessions(), user1New.Session())
		assert.Contains(t, sm.AllSessions(), user2.Session())
	}
}

func TestInMemorySessionManager_Remove_MissingSameScreenName(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1Old, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)

	// Verify the old session is in the store
	recOld, ok := sm.store[user1Old.IdentScreenName()]
	assert.True(t, ok)
	assert.Equal(t, user1Old.Session(), recOld.session)

	// Remove the old session
	sm.RemoveSession(user1Old)
	_, ok = sm.store[user1Old.IdentScreenName()]
	assert.False(t, ok)

	// Create a new session with the same screen name but different Session
	user1New, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1New.SetSignonComplete()

	// Verify the new session is in the store with a different Session
	recNew, ok := sm.store[user1New.IdentScreenName()]
	assert.True(t, ok)
	assert.Equal(t, user1New.Session(), recNew.session)
	assert.NotEqual(t, user1Old.Session(), user1New.Session())

	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	user2.SetSignonComplete()

	// Try to remove the old session again - should do nothing because Session doesn't match
	sm.RemoveSession(user1Old)

	// Verify the new session is still in the store (not removed)
	recNewAfter, ok := sm.store[user1New.IdentScreenName()]
	assert.True(t, ok, "new session should still be in store")
	assert.Equal(t, user1New.Session(), recNewAfter.session)

	if assert.Len(t, sm.AllSessions(), 2) {
		assert.NotContains(t, sm.AllSessions(), user1Old.Session())
		assert.Contains(t, sm.AllSessions(), user1New.Session())
		assert.Contains(t, sm.AllSessions(), user2.Session())
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

			have := sm.RetrieveSession(tt.lookupScreenName)
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
	user2.CloseInstance()

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
		if user1.RelayMessageToInstance(msg) == SessQueueFull {
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

func TestInMemorySessionManager_SessionReplacement_NoMultiSess_NoMultiSess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm := NewInMemorySessionManager(slog.Default())

		sess1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
		assert.NoError(t, err)
		sess1.SetSignonComplete()

		wg := &sync.WaitGroup{}
		wg.Add(1)

		go func() {
			defer wg.Done()
			// add the session again. this call blocks until RemoveSession makes
			// room for the new session
			sess2, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
			assert.NoError(t, err)
			if assert.NotNil(t, sess2) {
				sess2.SetSignonComplete()
				assert.Equal(t, sess1.DisplayScreenName(), sess2.DisplayScreenName())
			}
		}()

		// wait for second call to AddSession() to block
		synctest.Wait()

		// AddSession() is blocked waiting for the lock, now unblock it
		sm.RemoveSession(sess1)

		wg.Wait()

		// make sure we got a brand new session
		got := sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"))
		assert.NotEqual(t, sess1, got)
		assert.Equal(t, 1, got.InstanceCount())
	})
}

func TestInMemorySessionManager_SessionReplacement_MultiSess_NoMultiSess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm := NewInMemorySessionManager(slog.Default())
		sm.maxConcurrentSessions = 5

		var sessList []*SessionInstance
		for i := 0; i < sm.maxConcurrentSessions; i++ {
			sess, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
			assert.NoError(t, err)
			sess.SetSignonComplete()
			sessList = append(sessList, sess)
		}

		assert.Equal(t, len(sessList), sessList[0].Session().InstanceCount())

		wg := &sync.WaitGroup{}
		wg.Add(1)

		go func() {
			defer wg.Done()
			// add the session again. this call blocks until RemoveSession makes
			// room for the new session
			sess, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
			assert.NoError(t, err)
			assert.NotNil(t, sess)
			sess.SetSignonComplete()
			assert.Equal(t, "user-screen-name-1", sess.DisplayScreenName().String())
			assert.Equal(t, 1, sess.Session().InstanceCount())
		}()

		// wait for the last call to AddSession() to block
		synctest.Wait()

		// AddSession() is blocked waiting for the lock, now unblock it
		for _, sess := range sessList {
			sm.RemoveSession(sess)
		}

		wg.Wait()

		got := sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"))

		for _, sess := range sessList {
			assert.NotSame(t, sess, got)
		}
		assert.Equal(t, 1, got.InstanceCount())
	})
}

func TestInMemorySessionManager_SessionReplacement_NoMultiSess_MultiSess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm := NewInMemorySessionManager(slog.Default())

		sess1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
		assert.NoError(t, err)
		sess1.SetSignonComplete()

		wg := &sync.WaitGroup{}
		wg.Add(1)

		go func() {
			defer wg.Done()
			// add the session again. this call blocks until RemoveSession makes
			// room for the new session
			sess2, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
			assert.NoError(t, err)
			assert.NotNil(t, sess2)
			assert.Equal(t, sess1.DisplayScreenName(), sess2.DisplayScreenName())
			sess2.SetSignonComplete()
		}()

		// wait for second call to AddSession() to block
		synctest.Wait()

		// AddSession() is blocked waiting for the lock, now unblock it
		sm.RemoveSession(sess1)

		wg.Wait()

		got := sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"))

		if assert.NotNil(t, got) {
			assert.NotSame(t, sess1, got)
			assert.Equal(t, 1, got.InstanceCount())
		}
	})
}

func TestInMemorySessionManager_RemoveSession_DoubleLogin_NoMultiSess_Chaos(t *testing.T) {
	wg := &sync.WaitGroup{}
	sm := NewInMemorySessionManager(slog.Default())

	for i := 0; i < 1000; i++ { // shake out race conditions
		wg.Add(1)

		time.Sleep(time.Duration(rand.Intn(1000)) * time.Microsecond)
		go func() {
			defer wg.Done()
			sess1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
			assert.NoError(t, err)
			time.Sleep(time.Duration(rand.Intn(1000)) * time.Microsecond)
			sm.RemoveSession(sess1)
		}()
	}

	wg.Wait()
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
//	lookup := make(map[*SessionInstance]bool)
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
	for i := 0; i < 50; i++ { // shake out race conditions

		synctest.Test(t, func(t *testing.T) {
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

			// wait for second call to AddSession() to block
			synctest.Wait()

			// AddSession() is blocked waiting for the lock, now unblock it
			sm.RemoveSession(chatSess1)

			wg.Wait()
		})
	}
}

func TestInMemoryChatSessionManager_RemoveUserFromAllChats(t *testing.T) {
	sm := NewInMemoryChatSessionManager(slog.Default())

	user1 := NewIdentScreenName("user-screen-name-1")
	user1sess, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-1")
	assert.NoError(t, err)
	user1sess.SetSignonComplete()
	user2sess, err := sm.AddSession(context.Background(), "chat-room-1", "user-screen-name-2")
	assert.NoError(t, err)
	user2sess.SetSignonComplete()

	assert.Len(t, sm.AllSessions("chat-room-1"), 2)

	sm.RemoveUserFromAllChats(user1)

	lookup := make(map[*Session]bool)
	for _, session := range sm.AllSessions("chat-room-1") {
		lookup[session] = true
	}

	assert.False(t, lookup[user1sess.Session()])
	assert.True(t, lookup[user2sess.Session()])

}

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

	sess := sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"))
	assert.Nil(t, sess, "should return nil for session with incomplete signon")

	user1.SetSignonComplete()
	sess = sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"))
	assert.NotNil(t, sess, "should return session after signon is complete")
	assert.Equal(t, user1.Session(), sess)
}

func TestInMemorySessionManager_RetrieveSession_CompleteSignon(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	sess := sm.RetrieveSession(NewIdentScreenName("user-screen-name-1"))
	assert.NotNil(t, sess)
	assert.Equal(t, user1.Session(), sess)
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

	// Check that we have sessions for user1 and user3 (by checking Session identity)
	user1Found := false
	user3Found := false
	user2Found := false

	for _, session := range sessions {
		if session == user1.Session() {
			user1Found = true
		}
		if session == user2.Session() {
			user2Found = true
		}
		if session == user3.Session() {
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

func TestInMemorySessionManager_RelayToOtherInstances_SkipsNonLiveInstances(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	// Create a session with multiple instances
	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	// Add a second instance that hasn't completed signon
	user1Instance2, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
	assert.NoError(t, err)
	// user1Instance2 has not completed signon, so this instance is not live

	// Add a third instance that has completed signon
	user1Instance3, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
	assert.NoError(t, err)
	user1Instance3.SetSignonComplete()

	// Verify instance-level live() behavior
	assert.True(t, user1.live(), "user1 should be live (not closed and signon complete)")
	assert.False(t, user1Instance2.live(), "user1Instance2 should not be live (signon not complete)")
	assert.True(t, user1Instance3.live(), "user1Instance3 should be live (not closed and signon complete)")

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	// Relay to other instances from user1
	sm.RelayToOtherInstances(context.Background(), user1, want)

	// user1 should not receive the message (it's the sender)
	select {
	case <-user1.ReceiveMessage():
		assert.Fail(t, "user1 should not receive a message relayed from itself")
	default:
	}

	// user1Instance2 should not receive the message (not live - signon incomplete)
	select {
	case <-user1Instance2.ReceiveMessage():
		assert.Fail(t, "user1Instance2 should not receive a message because it's not live")
	default:
	}

	// user1Instance3 should receive the message (is live)
	select {
	case have := <-user1Instance3.ReceiveMessage():
		assert.Equal(t, want, have)
	default:
		assert.Fail(t, "user1Instance3 should receive the message")
	}
}

func TestInMemorySessionManager_MaybeRelayMessage_SkipsNonLiveInstances(t *testing.T) {
	sm := NewInMemorySessionManager(slog.Default())

	// Create a session with multiple instances
	user1, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
	assert.NoError(t, err)
	user1.SetSignonComplete()

	// Add a third instance that has completed signon
	user1Instance3, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
	assert.NoError(t, err)
	user1Instance3.SetSignonComplete()

	// Create a separate session with incomplete signon to test that non-live instances are skipped
	user2, err := sm.AddSession(context.Background(), "user-screen-name-2", false)
	assert.NoError(t, err)
	// user2 has not completed signon, so this instance is not live
	assert.False(t, user2.live(), "instance should not be live when signon is incomplete")

	want := wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.ICBM}}

	// Use maybeRelayMessage (called internally by RelayToScreenName)
	// This should relay to all live instances in the session
	sm.RelayToScreenName(context.Background(), user1.IdentScreenName(), want)

	// user1 should receive the message
	select {
	case have := <-user1.ReceiveMessage():
		assert.Equal(t, want, have)
	default:
		assert.Fail(t, "user1 should receive the message")
	}

	// user1Instance3 should receive the message (session is live)
	select {
	case have := <-user1Instance3.ReceiveMessage():
		assert.Equal(t, want, have)
	default:
		assert.Fail(t, "user1Instance3 should receive the message")
	}

	// Test that non-live instances are skipped in RelayToAll (which calls maybeRelayMessage)
	sm.RelayToAll(context.Background(), want)

	// user2 should not receive the message (instance is not live, so maybeRelayMessage skips it)
	select {
	case <-user2.ReceiveMessage():
		assert.Fail(t, "user2 should not receive a message because the instance is not live")
	default:
	}
}

func TestInMemorySessionManager_AddSession_MaxConcurrentSessions(t *testing.T) {
	t.Run("enforces limit", func(t *testing.T) {
		sm := NewInMemorySessionManager(slog.Default())
		sm.maxConcurrentSessions = 5

		// Create sessions up to the limit (5)
		var sessList []*SessionInstance
		for i := 0; i < sm.maxConcurrentSessions; i++ {
			sess, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
			assert.NoError(t, err)
			sess.SetSignonComplete()
			sessList = append(sessList, sess)
		}

		// Verify we have exactly 5 instances
		assert.Equal(t, sm.maxConcurrentSessions, sessList[0].Session().InstanceCount())

		// Try to add one more session - should fail with ErrMaxConcurrentSessionsReached
		sess, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
		assert.Nil(t, sess)
		assert.ErrorIs(t, err, ErrMaxConcurrentSessionsReached)

		// Verify we still have exactly 5 instances
		assert.Equal(t, sm.maxConcurrentSessions, sessList[0].Session().InstanceCount())
	})

	t.Run("allows new session after removal", func(t *testing.T) {
		sm := NewInMemorySessionManager(slog.Default())
		sm.maxConcurrentSessions = 5

		// Create sessions up to the limit (5)
		var sessList []*SessionInstance
		for i := 0; i < sm.maxConcurrentSessions; i++ {
			sess, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
			assert.NoError(t, err)
			sess.SetSignonComplete()
			sessList = append(sessList, sess)
		}

		// Verify we have exactly 5 instances
		assert.Equal(t, sm.maxConcurrentSessions, sessList[0].Session().InstanceCount())

		// Try to add one more session - should fail
		sess, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
		assert.Nil(t, sess)
		assert.ErrorIs(t, err, ErrMaxConcurrentSessionsReached)

		// Close one instance (this removes it from the Session)
		sessList[0].CloseInstance()

		// Now we should be able to add a new instance to the same session
		newSess, err := sm.AddSession(context.Background(), "user-screen-name-1", true)
		assert.NoError(t, err)
		assert.NotNil(t, newSess)
		newSess.SetSignonComplete()

		// Verify we have exactly 5 instances again (4 remaining + 1 new = 5)
		assert.Equal(t, sm.maxConcurrentSessions, newSess.Session().InstanceCount())
	})

	t.Run("no limit for non-multi-session", func(t *testing.T) {
		sm := NewInMemorySessionManager(slog.Default())

		// Create multiple non-multi-session sessions - should not be limited
		// (though they will replace each other, but that's expected behavior)
		sess1, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
		assert.NoError(t, err)
		sess1.SetSignonComplete()

		// Close and remove the first session to allow a new one
		go func() {
			<-sess1.Closed()
			sm.RemoveSession(sess1)
		}()

		sess2, err := sm.AddSession(context.Background(), "user-screen-name-1", false)
		assert.NoError(t, err)
		sess2.SetSignonComplete()

		// Verify the limit doesn't apply to non-multi-session
		assert.Equal(t, 1, sess2.Session().InstanceCount())
	})
}
