package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// ErrNoWebAPISession is returned when a WebAPI session is not found.
	ErrNoWebAPISession = errors.New("WebAPI session not found")
	// ErrWebAPISessionExpired is returned when a WebAPI session has expired.
	ErrWebAPISessionExpired = errors.New("WebAPI session expired")
)

// WebAPISession represents an active Web AIM API session.
type WebAPISession struct {
	AimSID          string            // Unique session ID for web client
	ScreenName      DisplayScreenName // User identity
	OSCARSession    *SessionInstance  // Bridge to existing OSCAR session
	Events          []string          // Subscribed event types
	EventQueue      *types.EventQueue // Per-session event queue
	DevID           string            // Developer ID that created this session
	ClientName      string            // Client application name
	ClientVersion   string            // Client application version
	CreatedAt       time.Time         // SessionInstance creation time
	LastAccessed    time.Time         // Last activity time
	ExpiresAt       time.Time         // SessionInstance expiration time
	FetchTimeout    int               // Long-polling timeout in milliseconds
	TimeToNextFetch int               // Suggested delay before next fetch
	RemoteAddr      string            // Client IP address
	TempBuddies     map[string]bool   // Temporary buddies for this session only
	logger          *slog.Logger      // Logger for debugging
}

// IsExpired checks if the session has expired.
func (s *WebAPISession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Touch updates the last accessed time and extends expiration if needed.
func (s *WebAPISession) Touch() {
	s.LastAccessed = time.Now()
	// Extend expiration by 60 minutes from last access
	newExpiry := s.LastAccessed.Add(60 * time.Minute)
	if newExpiry.After(s.ExpiresAt) {
		s.ExpiresAt = newExpiry
	}
}

// IsSubscribedTo checks if the session is subscribed to a specific event type.
func (s *WebAPISession) IsSubscribedTo(eventType string) bool {
	for _, event := range s.Events {
		if event == eventType {
			return true
		}
	}
	return false
}

// StartListeningToOSCARSession starts a goroutine that listens to the OSCAR session's
// message channel and converts SNAC messages into WebAPI events.
func (s *WebAPISession) StartListeningToOSCARSession() {
	if s.OSCARSession == nil {
		return
	}

	// Start goroutine to listen for OSCAR messages
	go func() {
		msgCh := s.OSCARSession.ReceiveMessage()
		for {
			select {
			case msg, ok := <-msgCh:
				if !ok {
					// Channel closed, OSCAR session ended
					return
				}
				s.handleSNACMessage(msg)
			case <-s.OSCARSession.Closed():
				// OSCAR session closed
				return
			}
		}
	}()
}

// handleSNACMessage converts a SNAC message into WebAPI events and pushes them to the event queue.
func (s *WebAPISession) handleSNACMessage(msg wire.SNACMessage) {
	if s.EventQueue == nil {
		return
	}

	// Convert SNAC message to WebAPI events based on food group and subgroup
	switch msg.Frame.FoodGroup {
	case wire.ICBM:
		s.handleICBMMessage(msg)
	case wire.Buddy:
		s.handleBuddyMessage(msg)
	}
}

// handleICBMMessage handles ICBM (instant messaging) SNAC messages.
func (s *WebAPISession) handleICBMMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.ICBMChannelMsgToClient:
		s.handleIncomingIM(msg)
	case wire.ICBMClientEvent:
		s.handleTypingNotification(msg)
	}
}

// handleIncomingIM handles incoming instant messages.
func (s *WebAPISession) handleIncomingIM(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("im") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x04_0x07_ICBMChannelMsgToClient)
	if !ok {
		return
	}

	// Extract message text from TLV data
	var messageText string
	if msgData, hasMsg := body.TLVRestBlock.Bytes(wire.ICBMTLVAOLIMData); hasMsg {
		if text, err := wire.UnmarshalICBMMessageText(msgData); err == nil {
			messageText = text
		}
	}

	if messageText == "" {
		return
	}

	// Check if it's an auto-response (channel 2)
	autoResponse := body.ChannelID == 0x0002

	// Create IM event
	imEvent := types.IMEvent{
		From:      body.ScreenName,
		Message:   messageText,
		Timestamp: float64(time.Now().Unix()),
		AutoResp:  autoResponse,
	}

	s.EventQueue.Push(types.EventTypeIM, imEvent)
}

// handleTypingNotification handles typing notifications.
func (s *WebAPISession) handleTypingNotification(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("typing") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x04_0x14_ICBMClientEvent)
	if !ok {
		return
	}

	// Event types: 0=stopped typing, 1=text typed, 2=typing
	isTyping := body.Event == 1 || body.Event == 2

	typingEvent := types.TypingEvent{
		From:   body.ScreenName,
		Typing: isTyping,
	}

	s.EventQueue.Push(types.EventTypeTyping, typingEvent)
}

// handleBuddyMessage handles buddy/presence SNAC messages.
func (s *WebAPISession) handleBuddyMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.BuddyArrived:
		s.handleBuddyArrived(msg)
	case wire.BuddyDeparted:
		s.handleBuddyDeparted(msg)
	}
}

// handleBuddyArrived handles when a buddy comes online.
func (s *WebAPISession) handleBuddyArrived(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("presence") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x03_0x0B_BuddyArrived)
	if !ok {
		return
	}

	presenceEvent := types.PresenceEvent{
		AimID:    body.ScreenName,
		State:    "online",
		UserType: "aim",
	}

	s.EventQueue.Push(types.EventTypePresence, presenceEvent)
}

// handleBuddyDeparted handles when a buddy goes offline.
func (s *WebAPISession) handleBuddyDeparted(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("presence") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x03_0x0C_BuddyDeparted)
	if !ok {
		return
	}

	presenceEvent := types.PresenceEvent{
		AimID:    body.ScreenName,
		State:    "offline",
		UserType: "aim",
	}

	s.EventQueue.Push(types.EventTypePresence, presenceEvent)
}

// WebAPISessionManager manages Web API sessions with thread-safe operations.
type WebAPISessionManager struct {
	sessions      map[string]*WebAPISession          // Keyed by aimsid
	byUser        map[IdentScreenName]*WebAPISession // Keyed by screen name
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// NewWebAPISessionManager creates a new WebAPI session manager.
func NewWebAPISessionManager() *WebAPISessionManager {
	mgr := &WebAPISessionManager{
		sessions:    make(map[string]*WebAPISession),
		byUser:      make(map[IdentScreenName]*WebAPISession),
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine to remove expired sessions
	mgr.cleanupTicker = time.NewTicker(1 * time.Minute)
	go mgr.cleanupExpiredSessions()

	return mgr
}

// CreateSession creates a new WebAPI session.
func (m *WebAPISessionManager) CreateSession(ctx context.Context, screenName DisplayScreenName, devID string, events []string, oscarSession *SessionInstance, logger *slog.Logger) (*WebAPISession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if user already has an active session
	identName := screenName.IdentScreenName()
	if existing, exists := m.byUser[identName]; exists {
		// Remove the old session
		delete(m.sessions, existing.AimSID)
	}

	// Generate unique session ID
	aimsid, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &WebAPISession{
		AimSID:          aimsid,
		ScreenName:      screenName,
		OSCARSession:    oscarSession,
		Events:          events,
		EventQueue:      types.NewEventQueue(1000), // Max 1000 events per session
		DevID:           devID,
		CreatedAt:       now,
		LastAccessed:    now,
		ExpiresAt:       now.Add(60 * time.Minute), // 60 minute initial expiry
		FetchTimeout:    60000,                     // 60 seconds default for better stability
		TimeToNextFetch: 500,                       // 500ms suggested delay
		logger:          logger,
	}

	m.sessions[aimsid] = session
	m.byUser[identName] = session

	// Start listening to OSCAR session message channel
	session.StartListeningToOSCARSession()

	return session, nil
}

// GetSession retrieves a session by aimsid.
func (m *WebAPISessionManager) GetSession(ctx context.Context, aimsid string) (*WebAPISession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[aimsid]
	if !exists {
		return nil, ErrNoWebAPISession
	}

	if session.IsExpired() {
		return nil, ErrWebAPISessionExpired
	}

	return session, nil
}

// GetSessionByUser retrieves a session by screen name.
func (m *WebAPISessionManager) GetSessionByUser(ctx context.Context, screenName IdentScreenName) (*WebAPISession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.byUser[screenName]
	if !exists {
		return nil, ErrNoWebAPISession
	}

	if session.IsExpired() {
		return nil, ErrWebAPISessionExpired
	}

	return session, nil
}

// RemoveSession removes a session by aimsid.
func (m *WebAPISessionManager) RemoveSession(ctx context.Context, aimsid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[aimsid]
	if !exists {
		return ErrNoWebAPISession
	}

	delete(m.sessions, aimsid)
	delete(m.byUser, session.ScreenName.IdentScreenName())

	// CloseSession the event queue to unblock any waiting fetches
	if session.EventQueue != nil {
		session.EventQueue.Close()
	}

	return nil
}

// TouchSession updates the last accessed time for a session.
func (m *WebAPISessionManager) TouchSession(ctx context.Context, aimsid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[aimsid]
	if !exists {
		return ErrNoWebAPISession
	}

	session.Touch()
	return nil
}

// GetAllSessions returns all active sessions (for monitoring/admin).
func (m *WebAPISessionManager) GetAllSessions(ctx context.Context) []*WebAPISession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*WebAPISession, 0, len(m.sessions))
	for _, session := range m.sessions {
		if !session.IsExpired() {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// GetSessionsByScreenName returns all sessions for a given screen name.
func (m *WebAPISessionManager) GetSessionsByScreenName(ctx context.Context, screenName DisplayScreenName) []*WebAPISession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sessions []*WebAPISession
	identScreenName := screenName.IdentScreenName()

	// Check both the byUser map and iterate through all sessions
	// since a user might have multiple sessions
	for _, session := range m.sessions {
		if session.ScreenName.IdentScreenName() == identScreenName {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// cleanupExpiredSessions periodically removes expired sessions.
func (m *WebAPISessionManager) cleanupExpiredSessions() {
	for {
		select {
		case <-m.cleanupTicker.C:
			m.mu.Lock()
			now := time.Now()
			var toRemove []string

			for aimsid, session := range m.sessions {
				if now.After(session.ExpiresAt) {
					toRemove = append(toRemove, aimsid)
				}
			}

			for _, aimsid := range toRemove {
				session := m.sessions[aimsid]
				delete(m.sessions, aimsid)
				delete(m.byUser, session.ScreenName.IdentScreenName())
				if session.EventQueue != nil {
					session.EventQueue.Close()
				}
			}
			m.mu.Unlock()

		case <-m.stopCleanup:
			m.cleanupTicker.Stop()
			return
		}
	}
}

// Shutdown stops the session manager and cleans up resources.
func (m *WebAPISessionManager) Shutdown(ctx context.Context) {
	close(m.stopCleanup)

	m.mu.Lock()
	defer m.mu.Unlock()

	// CloseSession all event queues
	for _, session := range m.sessions {
		if session.EventQueue != nil {
			session.EventQueue.Close()
		}
	}

	// Clear all sessions
	m.sessions = make(map[string]*WebAPISession)
	m.byUser = make(map[IdentScreenName]*WebAPISession)
}

// generateSessionID creates a cryptographically secure session ID.
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
