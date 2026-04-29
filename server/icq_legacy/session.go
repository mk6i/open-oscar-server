package icq_legacy

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
)

// LegacySessionManager manages sessions for legacy ICQ clients
type LegacySessionManager struct {
	sessions         map[uint32]*LegacySession    // Indexed by UIN
	addrIndex        map[string]*LegacySession    // Indexed by UDP address string
	sessionMgr       SessionRegistry              // Unified session manager
	bridge           *LegacyMessageBridge         // OSCAR->legacy bridge for message pump
	onSessionExpired func(session *LegacySession) // Called before removing expired sessions
	config           config.ICQLegacyConfig
	logger           *slog.Logger
	mu               sync.RWMutex
}

// SessionRegistry is the interface for the unified session manager
type SessionRegistry interface {
	RemoveSession(session *state.Session)
}

// NewLegacySessionManager creates a new session manager
func NewLegacySessionManager(sessionMgr SessionRegistry, cfg config.ICQLegacyConfig, logger *slog.Logger) *LegacySessionManager {
	return &LegacySessionManager{
		sessions:   make(map[uint32]*LegacySession),
		addrIndex:  make(map[string]*LegacySession),
		sessionMgr: sessionMgr,
		config:     cfg,
		logger:     logger,
	}
}

// SetBridge sets the OSCAR->legacy bridge used to start message pumps for new
// sessions. Must be called before any sessions are created.
func (m *LegacySessionManager) SetBridge(bridge *LegacyMessageBridge) {
	m.bridge = bridge
}

// SetOnSessionExpired sets a callback invoked before an expired session is
// removed. The callback should notify contacts and OSCAR clients that the
// user went offline — mirroring what handleLogoff does for graceful logouts.
func (m *LegacySessionManager) SetOnSessionExpired(fn func(session *LegacySession)) {
	m.onSessionExpired = fn
}

// CreateSession creates a new legacy session backed by an OSCAR session instance.
func (m *LegacySessionManager) CreateSession(uin uint32, addr *net.UDPAddr, version uint16, instance *state.SessionInstance) (*LegacySession, error) {
	if instance == nil {
		return nil, fmt.Errorf("missing OSCAR session instance for UIN %d", uin)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session already exists
	if existing, ok := m.sessions[uin]; ok {
		// Remove old session
		m.removeSessionLocked(existing)
	}

	session := newLegacySession(uin, addr, version, instance)
	m.activateSessionLocked(session)

	m.sessions[uin] = session
	m.addrIndex[addr.String()] = session

	m.logger.Info("created legacy session",
		"uin", uin,
		"addr", addr.String(),
		"version", version,
		"session_id", session.SessionID,
	)

	return session, nil
}

// CreatePendingSession creates a legacy session before the OSCAR session exists.
func (m *LegacySessionManager) CreatePendingSession(uin uint32, addr *net.UDPAddr, version uint16) (*LegacySession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.sessions[uin]; ok {
		m.removeSessionLocked(existing)
	}

	session := newLegacySession(uin, addr, version, nil)
	m.sessions[uin] = session
	m.addrIndex[addr.String()] = session

	m.logger.Info("created pending legacy session",
		"uin", uin,
		"addr", addr.String(),
		"version", version,
		"session_id", session.SessionID,
	)

	return session, nil
}

// AttachOSCARSession attaches an AuthService-created OSCAR instance to a pending legacy session.
func (m *LegacySessionManager) AttachOSCARSession(uin uint32, addr *net.UDPAddr, instance *state.SessionInstance) (*LegacySession, error) {
	if instance == nil {
		return nil, fmt.Errorf("missing OSCAR session instance for UIN %d", uin)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[uin]
	if !ok {
		return nil, fmt.Errorf("pending legacy session not found for UIN %d", uin)
	}
	if session.Instance != nil && session.Instance != instance {
		return nil, fmt.Errorf("legacy session for UIN %d already has an OSCAR session", uin)
	}

	if session.Addr != nil {
		delete(m.addrIndex, session.Addr.String())
	}
	session.Addr = addr
	m.addrIndex[addr.String()] = session
	session.Instance = instance
	m.activateSessionLocked(session)

	m.logger.Info("attached OSCAR session to legacy session",
		"uin", uin,
		"addr", addr.String(),
		"version", session.Version,
		"session_id", session.SessionID,
	)

	return session, nil
}

func newLegacySession(uin uint32, addr *net.UDPAddr, version uint16, instance *state.SessionInstance) *LegacySession {
	return &LegacySession{
		UIN:          uin,
		Addr:         addr,
		Version:      version,
		SessionID:    GenerateSessionID(),
		SeqNumServer: 0, // V2 spec: server starts counting at 0
		Status:       ICQLegacyStatusOnline,
		LastActivity: time.Now(),
		Instance:     instance,
	}
}

func (m *LegacySessionManager) activateSessionLocked(session *LegacySession) {
	session.Instance.SetSignonComplete()

	// Start the OSCAR message pump for this session. This goroutine drains
	// SNAC messages (BuddyArrived/BuddyDeparted) that the OSCAR buddy system
	// sends to this session's unified SessionInstance, and converts them into
	// legacy protocol packets. Without this, OSCAR->legacy status notifications
	// would be silently dropped.
	if m.bridge != nil {
		m.bridge.StartOSCARMessagePump(session)
	}
}

// GetSession retrieves a session by UIN
func (m *LegacySessionManager) GetSession(uin uint32) *LegacySession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[uin]
}

// GetSessionByAddr retrieves a session by UDP address
func (m *LegacySessionManager) GetSessionByAddr(addr *net.UDPAddr) *LegacySession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.addrIndex[addr.String()]
}

// RemoveSession removes a session by UIN
func (m *LegacySessionManager) RemoveSession(uin uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, ok := m.sessions[uin]; ok {
		m.removeSessionLocked(session)
	}
}

// removeSessionLocked removes a session (must be called with lock held)
func (m *LegacySessionManager) removeSessionLocked(session *LegacySession) {
	// Remove from unified session manager
	if session.Instance != nil {
		m.sessionMgr.RemoveSession(session.Instance.Session())
	}

	// Remove from indexes
	delete(m.sessions, session.UIN)
	if session.Addr != nil {
		delete(m.addrIndex, session.Addr.String())
	}

	m.logger.Info("removed legacy session",
		"uin", session.UIN,
	)
}

// UpdateSessionAddr updates the UDP address for a session
// This handles clients that reconnect from a different address
func (m *LegacySessionManager) UpdateSessionAddr(uin uint32, newAddr *net.UDPAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[uin]
	if !ok {
		return
	}

	// Remove old address index
	if session.Addr != nil {
		delete(m.addrIndex, session.Addr.String())
	}

	// Update address
	session.Addr = newAddr
	m.addrIndex[newAddr.String()] = session
}

// CleanupExpired removes sessions that have timed out
func (m *LegacySessionManager) CleanupExpired() int {
	m.mu.Lock()

	timeout := m.config.SessionTimeout
	now := time.Now()

	// Collect expired sessions while holding the lock
	var expired []*LegacySession
	for _, session := range m.sessions {
		if now.Sub(session.GetLastActivity()) > timeout {
			expired = append(expired, session)
		}
	}
	m.mu.Unlock()

	// Notify contacts outside the lock to avoid deadlock
	for _, session := range expired {
		m.logger.Info("cleaning up expired session",
			"uin", session.UIN,
			"last_activity", session.GetLastActivity(),
		)
		if m.onSessionExpired != nil {
			m.onSessionExpired(session)
		}
	}

	// Re-acquire lock and remove the sessions
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for _, session := range expired {
		if _, ok := m.sessions[session.UIN]; ok {
			m.removeSessionLocked(session)
			removed++
		}
	}

	return removed
}

// GetAllSessions returns all active sessions
func (m *LegacySessionManager) GetAllSessions() []*LegacySession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*LegacySession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// GetOnlineContacts returns the online contacts for a session
func (m *LegacySessionManager) GetOnlineContacts(session *LegacySession) []*LegacySession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	contacts := session.GetContactList()
	online := make([]*LegacySession, 0)

	for _, uin := range contacts {
		if contactSession, ok := m.sessions[uin]; ok {
			// Check visibility rules
			if !m.isVisibleTo(contactSession, session.UIN) {
				continue
			}
			online = append(online, contactSession)
		}
	}

	return online
}

// isVisibleTo checks if a session is visible to a specific UIN
func (m *LegacySessionManager) isVisibleTo(session *LegacySession, viewerUIN uint32) bool {
	status := session.GetStatus()

	// If invisible, only visible to those on visible list
	if status&ICQLegacyStatusInvisible != 0 {
		return session.IsOnVisibleList(viewerUIN)
	}

	// If on invisible list, not visible
	if session.IsOnInvisibleList(viewerUIN) {
		return false
	}

	return true
}

// BroadcastToContacts sends a notification to all contacts of a session
func (m *LegacySessionManager) BroadcastToContacts(session *LegacySession, fn func(*LegacySession)) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	contacts := session.GetContactList()

	for _, uin := range contacts {
		if contactSession, ok := m.sessions[uin]; ok {
			fn(contactSession)
		}
	}
}

// NotifyContactsOfStatus notifies contacts of a status change
func (m *LegacySessionManager) NotifyContactsOfStatus(session *LegacySession) []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Find all sessions that have this user in their contact list
	notified := make([]uint32, 0)

	for uin, otherSession := range m.sessions {
		if uin == session.UIN {
			continue
		}

		if otherSession.IsContact(session.UIN) {
			// Check visibility
			if m.isVisibleTo(session, uin) {
				notified = append(notified, uin)
			}
		}
	}

	return notified
}

// Count returns the number of active sessions
func (m *LegacySessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// StartCleanupRoutine starts a goroutine that periodically cleans up expired sessions
func (m *LegacySessionManager) StartCleanupRoutine(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed := m.CleanupExpired()
			if removed > 0 {
				m.logger.Info("session cleanup completed",
					"removed", removed,
					"remaining", m.Count(),
				)
			}
		case <-stop:
			return
		}
	}
}
