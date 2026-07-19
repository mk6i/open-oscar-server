package state

import (
	"testing"
	"time"
)

// Demonstrates that ScaleWarningAndRateLimit sends on warningCh while holding
// the write lock, so a full buffer wedges every reader of the Session.
func TestProbe_SendUnderWriteLockBlocksReaders(t *testing.T) {
	s := NewSession()
	s.SetIdentScreenName(NewIdentScreenName("probe"))

	// 1. Fill the 1-slot warningCh buffer. Nobody is draining it.
	s.ScaleWarningAndRateLimit(10, 3)

	// 2. Next call blocks on the send -- while holding mutex.Lock().
	blocked := make(chan struct{})
	go func() {
		close(blocked)
		s.ScaleWarningAndRateLimit(10, 3)
	}()
	<-blocked
	time.Sleep(200 * time.Millisecond) // let it reach the send

	// 3. Any reader now blocks forever. This is icbm.go:719 TLVUserInfo().
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.DisplayScreenName()
	}()

	select {
	case <-done:
		t.Log("OK: reader acquired RLock")
	case <-time.After(2 * time.Second):
		t.Fatal("DEADLOCK: reader blocked on RLock because the writer is parked on a channel send")
	}
}
