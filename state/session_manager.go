package state

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

type sessionSlot struct {
	session      *Session
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
	store                 map[IdentScreenName]*sessionSlot
	mapMutex              sync.RWMutex
	userLocks             map[IdentScreenName]*userLock
	userLocksMutex        sync.Mutex
	logger                *slog.Logger
	maxConcurrentSessions int
}

const (
	// DefaultMaxConcurrentSessions is the default maximum number of concurrent
	// sessions allowed when multi-session is enabled.
	DefaultMaxConcurrentSessions = 5
)

// ErrMaxConcurrentSessionsReached is returned when attempting to add a new
// session instance but the maximum number of concurrent sessions has been
// reached.
var ErrMaxConcurrentSessionsReached = errors.New("maximum number of concurrent sessions reached")

// NewInMemorySessionManager creates a new instance of InMemorySessionManager.
func NewInMemorySessionManager(logger *slog.Logger) *InMemorySessionManager {
	return &InMemorySessionManager{
		logger:                logger,
		store:                 make(map[IdentScreenName]*sessionSlot),
		userLocks:             make(map[IdentScreenName]*userLock),
		maxConcurrentSessions: DefaultMaxConcurrentSessions,
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
		s.maybeRelayMessage(ctx, msg, rec.session)
	}
}

// RelayToScreenName relays a message to a session with a matching screen name.
func (s *InMemorySessionManager) RelayToScreenName(ctx context.Context, screenName IdentScreenName, msg wire.SNACMessage) {
	sess := s.RetrieveSession(screenName)
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

func (s *InMemorySessionManager) RelayToSelf(ctx context.Context, instance *SessionInstance, msg wire.SNACMessage) {
	switch instance.RelayMessageToInstance(msg) {
	case SessSendClosed:
		s.logger.WarnContext(ctx, "can't send notification because the user's session is closed", "recipient", instance.IdentScreenName(), "message", msg)
	case SessQueueFull:
		s.logger.WarnContext(ctx, "can't send notification because queue is full", "recipient", instance.IdentScreenName(), "message", msg)
		instance.CloseInstance()
	}
}

func (s *InMemorySessionManager) RelayToOtherInstances(ctx context.Context, instance *SessionInstance, msg wire.SNACMessage) {
	for _, inst := range instance.Session().Instances() {
		if instance == inst || !inst.live() {
			continue
		}
		switch inst.RelayMessageToInstance(msg) {
		case SessSendClosed:
			s.logger.WarnContext(ctx, "can't send notification because the user's session is closed", "recipient", instance.IdentScreenName(), "message", msg)
		case SessQueueFull:
			s.logger.WarnContext(ctx, "can't send notification because queue is full", "recipient", instance.IdentScreenName(), "message", msg)
			inst.CloseInstance()
		}
	}
}

func (s *InMemorySessionManager) RelayToScreenNameActiveOnly(ctx context.Context, screenName IdentScreenName, msg wire.SNACMessage) {
	sess := s.RetrieveSession(screenName)
	if sess == nil {
		s.logger.WarnContext(ctx, "can't send notification because user is not online", "recipient", screenName, "message", msg)
		return
	}
	s.maybeRelayMessageActiveOnly(ctx, msg, sess)
}

func (s *InMemorySessionManager) maybeRelayMessage(ctx context.Context, msg wire.SNACMessage, sess *Session) {
	for _, instance := range sess.Instances() {
		if !instance.live() {
			continue
		}
		switch instance.RelayMessageToInstance(msg) {
		case SessSendClosed:
			s.logger.WarnContext(ctx, "can't send notification because the user's session is closed", "recipient", sess.IdentScreenName(), "message", msg)
		case SessQueueFull:
			s.logger.WarnContext(ctx, "can't send notification because queue is full", "recipient", sess.IdentScreenName(), "message", msg)
			instance.CloseInstance()
		}
	}
}

func (s *InMemorySessionManager) maybeRelayMessageActiveOnly(ctx context.Context, msg wire.SNACMessage, sess *Session) {
	for _, instance := range sess.Instances() {
		if !instance.active() {
			continue
		}
		switch instance.RelayMessageToInstance(msg) {
		case SessSendClosed:
			s.logger.WarnContext(ctx, "can't send notification because the user's session is closed", "recipient", sess.IdentScreenName(), "message", msg)
		case SessQueueFull:
			s.logger.WarnContext(ctx, "can't send notification because queue is full", "recipient", sess.IdentScreenName(), "message", msg)
			instance.CloseInstance()
		}
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
				active.session.CloseSession()
				return s.newSession(screenName, doMultiSess)
			}

			// Check if we've reached the maximum number of concurrent sessions
			if active.session.InstanceCount() >= s.maxConcurrentSessions {
				return nil, ErrMaxConcurrentSessionsReached
			}

			instance := active.session.AddInstance()

			return instance, nil
		} else {
			// signal to callers that this session group has to go
			active.session.CloseSession()

			select {
			case <-active.removed: // wait for RemoveSession to be called
			case <-ctx.Done():
				return nil, fmt.Errorf("waiting for previous session to terminate: %w", ctx.Err())
			}
		}
	}

	return s.newSession(screenName, doMultiSess)
}

func (s *InMemorySessionManager) newSession(screenName DisplayScreenName, doMultiSess bool) (*SessionInstance, error) {
	sess := NewSession()
	sess.SetIdentScreenName(screenName.IdentScreenName())
	sess.SetDisplayScreenName(screenName)

	// Create a new instance within the session group
	instance := sess.AddInstance()

	s.mapMutex.Lock()
	s.store[instance.IdentScreenName()] = &sessionSlot{
		session:      sess,
		removed:      make(chan bool),
		multiSession: doMultiSess,
	}
	s.mapMutex.Unlock()

	return instance, nil
}

func (s *InMemorySessionManager) findRec(identScreenName IdentScreenName) *sessionSlot {
	for _, rec := range s.store {
		if identScreenName == rec.session.IdentScreenName() {
			return rec
		}
	}
	return nil
}

// RemoveSession takes a session out of the session pool.
func (s *InMemorySessionManager) RemoveSession(instance *SessionInstance) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()
	if rec, ok := s.store[instance.IdentScreenName()]; ok && rec.session == instance.Session() {
		delete(s.store, instance.IdentScreenName())
		close(rec.removed)
	}
}

// RetrieveSession finds a session with a matching screen name. Returns nil if
// session is not found or if there are no active instances with complete signon.
func (s *InMemorySessionManager) RetrieveSession(screenName IdentScreenName) *Session {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	if rec, ok := s.store[screenName]; ok {
		if rec.session.HasLiveInstances() {
			return rec.session
		}
	}
	return nil
}

func (s *InMemorySessionManager) retrieveByScreenNames(screenNames []IdentScreenName) []*Session {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	var ret []*Session
	for _, sn := range screenNames {
		for _, rec := range s.store {
			if sn == rec.session.IdentScreenName() {
				ret = append(ret, rec.session)
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
func (s *InMemorySessionManager) AllSessions() []*Session {
	s.mapMutex.RLock()
	defer s.mapMutex.RUnlock()
	var sessions []*Session
	for _, rec := range s.store {
		if !rec.session.HasLiveInstances() {
			continue
		}
		sessions = append(sessions, rec.session)
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

	sess.Session().SetChatRoomCookie(chatCookie)

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
func (s *InMemoryChatSessionManager) RemoveSession(instance *SessionInstance) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	sessionManager, ok := s.store[instance.ChatRoomCookie()]
	if !ok {
		panic("attempting to remove a session after its room has been deleted")
	}
	sessionManager.RemoveSession(instance)

	if sessionManager.Empty() {
		delete(s.store, instance.ChatRoomCookie())
	}
}

// RemoveUserFromAllChats removes a user's session from all chat rooms.
func (s *InMemoryChatSessionManager) RemoveUserFromAllChats(user IdentScreenName) {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	for _, sessionManager := range s.store {
		userSess := sessionManager.RetrieveSession(user)
		if userSess != nil {
			userSess.CloseSession()
		}
	}
}

// AllSessions returns all chat room participants. Returns
// ErrChatRoomNotFound if the room does not exist.
func (s *InMemoryChatSessionManager) AllSessions(cookie string) []*Session {
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
