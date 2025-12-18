package state

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

type sessionSlot struct {
	sessionGroup *Session
	removed      chan bool
	multiSession bool
}

type userLock struct {
	sync.Mutex
	refCount int
}

// InMemorySessionManager handles the lifecycle of a user session and provides
// synchronized message relay between sessions in the session pool. An
// InMemorySessionManager is safe for concurrent use by multiple goroutines.
type InMemorySessionManager struct {
	store          map[IdentScreenName]*sessionSlot
	mapMutex       sync.RWMutex
	userLocks      map[IdentScreenName]*userLock
	userLocksMutex sync.Mutex
	logger         *slog.Logger
}

// NewInMemorySessionManager creates a new instance of InMemorySessionManager.
func NewInMemorySessionManager(logger *slog.Logger) *InMemorySessionManager {
	return &InMemorySessionManager{
		logger:    logger,
		store:     make(map[IdentScreenName]*sessionSlot),
		userLocks: make(map[IdentScreenName]*userLock),
	}
}

func (s *InMemorySessionManager) lockUser(sn IdentScreenName) {
	s.userLocksMutex.Lock()

	lock, ok := s.userLocks[sn]
	if !ok {
		lock = &userLock{}
		s.userLocks[sn] = lock
	}

	lock.refCount++
	s.userLocksMutex.Unlock()

	lock.Lock()
}

func (s *InMemorySessionManager) unlockUser(sn IdentScreenName) {
	s.userLocksMutex.Lock()
	defer s.userLocksMutex.Unlock()

	lock, ok := s.userLocks[sn]
	if !ok {
		return
	}

	lock.Unlock()
	lock.refCount--

	if lock.refCount == 0 {
		delete(s.userLocks, sn)
	}
}

// RelayToAll relays a message to all sessions in the session pool.
func (s *InMemorySessionManager) RelayToAll(ctx context.Context, msg wire.SNACMessage) {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	for _, rec := range s.store {
		// Relay to all active instances in the session group
		for _, instance := range rec.sessionGroup.GetActiveInstances() {
			if !instance.SignonComplete() {
				continue
			}
			s.maybeRelayMessage(ctx, msg, instance)
		}
	}
}

// RelayToScreenName relays a message to a session with a matching screen name.
func (s *InMemorySessionManager) RelayToScreenName(ctx context.Context, screenName IdentScreenName, msg wire.SNACMessage) {
	sess := s.RetrieveSession(screenName, 0)
	if sess == nil {
		s.logger.WarnContext(ctx, "can't send notification because user is not online", "recipient", screenName, "message", msg)
		return
	}
	s.maybeRelayMessage(ctx, msg, sess)
}

// RelayToScreenNames relays a message to sessions with matching screenNames.
func (s *InMemorySessionManager) RelayToScreenNames(ctx context.Context, screenNames []IdentScreenName, msg wire.SNACMessage) {
	for _, sess := range s.retrieveByScreenNames(screenNames) {
		s.maybeRelayMessage(ctx, msg, sess)
	}
}

func (s *InMemorySessionManager) RelayToSelf(ctx context.Context, sess *SessionInstance, msg wire.SNACMessage) {
	select {
	case sess.msgCh <- msg:
	case <-sess.stopCh:
	case <-ctx.Done():
	}
}

func (s *InMemorySessionManager) RelayToOtherSessions(ctx context.Context, sess *SessionInstance, msg wire.SNACMessage) {
	switch sess.RelayMessageExceptSelf(sess, msg) {
	case SessSendClosed:
		s.logger.WarnContext(ctx, "can't send notification because the user's session is closed", "recipient", sess.IdentScreenName(), "message", msg)
	case SessQueueFull:
		s.logger.WarnContext(ctx, "can't send notification because queue is full", "recipient", sess.IdentScreenName(), "message", msg)
		sess.Close()
	}
}

func (s *InMemorySessionManager) RelayToScreenNameActiveOnly(ctx context.Context, screenName IdentScreenName, msg wire.SNACMessage) {
	sess := s.RetrieveSession(screenName, 0)
	if sess == nil {
		s.logger.WarnContext(ctx, "can't send notification because user is not online", "recipient", screenName, "message", msg)
		return
	}
	s.maybeRelayMessageActiveOnly(ctx, msg, sess)
}

func (s *InMemorySessionManager) maybeRelayMessage(ctx context.Context, msg wire.SNACMessage, sess *SessionInstance) {
	switch sess.RelayMessage(msg) {
	case SessSendClosed:
		s.logger.WarnContext(ctx, "can't send notification because the user's session is closed", "recipient", sess.IdentScreenName(), "message", msg)
	case SessQueueFull:
		s.logger.WarnContext(ctx, "can't send notification because queue is full", "recipient", sess.IdentScreenName(), "message", msg)
		sess.Close()
	}
}

func (s *InMemorySessionManager) maybeRelayMessageActiveOnly(ctx context.Context, msg wire.SNACMessage, sess *SessionInstance) {
	switch sess.RelayMessageActiveOnly(msg) {
	case SessSendClosed:
		s.logger.WarnContext(ctx, "can't send notification because the user's session is closed", "recipient", sess.IdentScreenName(), "message", msg)
	case SessQueueFull:
		s.logger.WarnContext(ctx, "can't send notification because queue is full", "recipient", sess.IdentScreenName(), "message", msg)
		sess.Close()
	}
}

func (s *InMemorySessionManager) AddSession(ctx context.Context, screenName DisplayScreenName, doMultiSess bool) (*SessionInstance, error) {
	s.lockUser(screenName.IdentScreenName())
	defer s.unlockUser(screenName.IdentScreenName())

	s.mapMutex.Lock()
	active := s.findRec(screenName.IdentScreenName())
	s.mapMutex.Unlock()

	if active != nil {
		if doMultiSess {
			if !active.multiSession {
				for _, instance := range active.sessionGroup.GetInstances() {
					instance.Close()
				}
				return s.newSessionGroup(screenName, doMultiSess)
			}

			// Create a new instance within the existing session group
			instance := NewInstance(active.sessionGroup)
			active.sessionGroup.AddInstance(instance)
			instance.Session = active.sessionGroup

			// Create a SessionInstance wrapper for backward compatibility
			return instance, nil
		} else {
			// signal to callers that this session group has to go
			// Close all instances in the session group
			for _, instance := range active.sessionGroup.GetInstances() {
				instance.Close()
			}

			select {
			case <-active.removed: // wait for RemoveSession to be called
			case <-ctx.Done():
				return nil, fmt.Errorf("waiting for previous session to terminate: %w", ctx.Err())
			}
		}
	}

	return s.newSessionGroup(screenName, doMultiSess)
}

func (s *InMemorySessionManager) newSessionGroup(screenName DisplayScreenName, doMultiSess bool) (*SessionInstance, error) {
	sessionGroup := NewSessionGroup()
	sessionGroup.SetIdentScreenName(screenName.IdentScreenName())
	sessionGroup.SetDisplayScreenName(screenName)

	// Create a new instance within the session group
	instance := NewInstance(sessionGroup)
	sessionGroup.AddInstance(instance)
	instance.Session = sessionGroup

	s.mapMutex.Lock()
	s.store[instance.IdentScreenName()] = &sessionSlot{
		sessionGroup: sessionGroup,
		removed:      make(chan bool),
		multiSession: doMultiSess,
	}
	s.mapMutex.Unlock()

	return instance, nil
}

func (s *InMemorySessionManager) findRec(identScreenName IdentScreenName) *sessionSlot {
	for _, rec := range s.store {
		if identScreenName == rec.sessionGroup.IdentScreenName() {
			return rec
		}
	}
	return nil
}

// RemoveSession takes a session out of the session pool.
func (s *InMemorySessionManager) RemoveSession(sess *SessionInstance) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	if rec, ok := s.store[sess.IdentScreenName()]; ok && rec.sessionGroup == sess.Session {
		delete(s.store, sess.IdentScreenName())
		close(rec.removed)
	}
}

// RetrieveSession finds a session with a matching sessionID. Returns nil if
// session is not found. If sessionNum is provided (non-zero), returns the
// specific instance with that session number, otherwise returns the first
// active instance.
func (s *InMemorySessionManager) RetrieveSession(screenName IdentScreenName, sessionNum uint8) *SessionInstance {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	if rec, ok := s.store[screenName]; ok {
		activeInstances := rec.sessionGroup.GetActiveInstances()
		if len(activeInstances) > 0 {
			var targetInstance *SessionInstance

			if sessionNum != 0 {
				// Find specific instance by session number
				for _, instance := range activeInstances {
					if instance.InstanceNum() == sessionNum {
						targetInstance = instance
						break
					}
				}
			} else {
				// Return the first active instance for backward compatibility
				targetInstance = activeInstances[0]
			}

			if targetInstance != nil && targetInstance.SignonComplete() { // should we check for signon complete?
				return targetInstance
			}
		}
	}
	return nil
}

func (s *InMemorySessionManager) retrieveByScreenNames(screenNames []IdentScreenName) []*SessionInstance {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	var ret []*SessionInstance
	for _, sn := range screenNames {
		for _, rec := range s.store {
			if sn == rec.sessionGroup.IdentScreenName() {
				// Return the first active instance as a SessionInstance for backward compatibility
				activeInstances := rec.sessionGroup.GetActiveInstances()
				if len(activeInstances) > 0 {
					instance := activeInstances[0]
					if instance.SignonComplete() {
						ret = append(ret, instance)
					}
				}
				break
			}
		}
	}
	return ret
}

// Empty returns true if the session pool contains 0 sessions.
func (s *InMemorySessionManager) Empty() bool {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	return len(s.store) == 0
}

// AllSessions returns all sessions in the session pool.
func (s *InMemorySessionManager) AllSessions() []*SessionInstance {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	var sessions []*SessionInstance
	for _, rec := range s.store {
		// Return all active instances as Sessions for backward compatibility
		for _, instance := range rec.sessionGroup.GetActiveInstances() {
			if instance.SignonComplete() {
				sessions = append(sessions, instance)
			}
		}
	}
	return sessions
}

// NewInMemoryChatSessionManager creates a new instance of
// InMemoryChatSessionManager.
func NewInMemoryChatSessionManager(logger *slog.Logger) *InMemoryChatSessionManager {
	return &InMemoryChatSessionManager{
		store:  make(map[string]*InMemorySessionManager),
		logger: logger,
	}
}

// InMemoryChatSessionManager manages chat sessions for multiple chat rooms
// stored in memory. It provides thread-safe operations to add, remove, and
// manipulate sessions as well as relay messages to participants.
type InMemoryChatSessionManager struct {
	logger   *slog.Logger
	mapMutex sync.RWMutex
	store    map[string]*InMemorySessionManager
}

// AddSession adds a user to a chat room. If screenName already exists, the old
// session is replaced by a new one.
func (s *InMemoryChatSessionManager) AddSession(ctx context.Context, chatCookie string, screenName DisplayScreenName) (*SessionInstance, error) {
	s.mapMutex.Lock()
	if _, ok := s.store[chatCookie]; !ok {
		s.store[chatCookie] = NewInMemorySessionManager(s.logger)
	}
	sessionManager := s.store[chatCookie]
	s.mapMutex.Unlock()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	sess, err := sessionManager.AddSession(ctx, screenName, false)
	if err != nil {
		return nil, fmt.Errorf("AddSession: %w", err)
	}

	sess.SetChatRoomCookie(chatCookie)

	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	// at this point it's guaranteed that the prior chat session and corresponding
	// session manager (if the room count dropped to 0) were removed.
	//
	// - SessionManager.RemoveSession() was called because that unlocks
	//   SessionManager.AddSession(), which unblocks ChatSessionManager.AddSession()
	// - ChatSessionManager.RemoveSession() must call room deletion routine before
	//   releasing mapMutex
	//
	// now restore the chat session manager, which may have been deleted by the
	// call to RemoveSession().
	if _, ok := s.store[chatCookie]; !ok {
		s.store[chatCookie] = sessionManager
	}

	return sess, nil
}

// RemoveSession removes a user session from a chat room. It panics if you
// attempt to remove the session twice.
func (s *InMemoryChatSessionManager) RemoveSession(sess *SessionInstance) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	sessionManager, ok := s.store[sess.ChatRoomCookie()]
	if !ok {
		panic("attempting to remove a session after its room has been deleted")
	}
	sessionManager.RemoveSession(sess)

	if sessionManager.Empty() {
		delete(s.store, sess.ChatRoomCookie())
	}
}

// RemoveUserFromAllChats removes a user's session from all chat rooms.
func (s *InMemoryChatSessionManager) RemoveUserFromAllChats(user IdentScreenName) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	for _, sessionManager := range s.store {
		userSess := sessionManager.RetrieveSession(user, 0)
		if userSess != nil {
			userSess.Close()
			sessionManager.RemoveSession(userSess)
		}
	}
}

// AllSessions returns all chat room participants. Returns
// ErrChatRoomNotFound if the room does not exist.
func (s *InMemoryChatSessionManager) AllSessions(cookie string) []*SessionInstance {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()

	sessionManager, ok := s.store[cookie]
	if !ok {
		s.logger.Debug("trying to get sessions for non-existent room", "cookie", cookie)
		return nil
	}
	return sessionManager.AllSessions()
}

// RelayToAllExcept sends a message to all chat room participants except for
// the participant with a particular screen name. Returns ErrChatRoomNotFound
// if the room does not exist for cookie.
func (s *InMemoryChatSessionManager) RelayToAllExcept(ctx context.Context, cookie string, except IdentScreenName, msg wire.SNACMessage) {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()

	sessionManager, ok := s.store[cookie]
	if !ok {
		s.logger.Error("trying to relay message to all for non-existent room", "cookie", cookie)
		return
	}

	for _, sess := range sessionManager.AllSessions() {
		if sess.IdentScreenName() == except {
			continue
		}
		sessionManager.maybeRelayMessage(ctx, msg, sess)
	}
}

// RelayToScreenName sends a message to a chat room user. Returns
// ErrChatRoomNotFound if the room does not exist for cookie.
func (s *InMemoryChatSessionManager) RelayToScreenName(ctx context.Context, cookie string, recipient IdentScreenName, msg wire.SNACMessage) {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()

	sessionManager, ok := s.store[cookie]
	if !ok {
		s.logger.Error("trying to relay message to screen name for non-existent room", "cookie", cookie)
		return
	}
	sessionManager.RelayToScreenName(ctx, recipient, msg)
}
