package icq_legacy

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/state"
)

// truncateField truncates a string field to maxLen if it exceeds the limit,
// logging a warning when truncation occurs. This prevents oversized data from
// crashing old ICQ clients that have fixed-size buffers.
func truncateField(value string, maxLen int, logger *slog.Logger, fieldName string, uin uint32) string {
	if len(value) <= maxLen {
		return value
	}
	logger.Warn("truncating oversized field for legacy client",
		"uin", uin,
		"field", fieldName,
		"max", maxLen,
		"got", len(value),
	)
	return value[:maxLen]
}

// LegacySession represents a connected legacy ICQ client session.
// It holds all state for a single UDP-based ICQ connection, including
// protocol version, sequence numbers, contact/visibility lists, and
// direct connection info for peer-to-peer messaging.
type LegacySession struct {
	// UIN is the user's ICQ identification number.
	UIN uint32

	// Addr is the UDP address of the connected client.
	Addr *net.UDPAddr

	// Version is the ICQ protocol version (2, 3, 4, or 5).
	Version uint16

	// SessionID is the V5 session identifier used for packet encryption.
	SessionID uint32 // V5 only

	// SeqNumClient is the last received sequence number from the client.
	SeqNumClient uint16

	// SeqNumServer is the next sequence number to send to the client.
	SeqNumServer uint16

	// Status is the user's current online status (online, away, DND, etc.).
	Status uint32

	// LastActivity is the timestamp of the last received packet from this session.
	LastActivity time.Time

	// ContactList is the user's buddy list (UINs of contacts).
	ContactList []uint32

	// VisibleList contains UINs that can see this user when invisible.
	VisibleList []uint32

	// InvisibleList contains UINs that cannot see this user's online status.
	InvisibleList []uint32

	// Password is stored for session validation during the connection lifetime.
	Password string

	// Direct connection info (for peer-to-peer messaging)

	// TCPPort is the client's TCP listening port for direct connections.
	TCPPort uint32

	// InternalIP is the client's internal/LAN IP address for direct connections.
	InternalIP uint32

	// TCPVersion is the client's TCP protocol version for direct connections.
	TCPVersion uint16

	// DCType is the direct connection type (normal, SOCKS, etc.).
	DCType uint8

	// Instance links this legacy session to the unified OSCAR session manager.
	Instance *state.SessionInstance

	mu sync.RWMutex
}

// UpdateActivity updates the last activity timestamp
func (s *LegacySession) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// GetLastActivity returns the last activity timestamp
func (s *LegacySession) GetLastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastActivity
}

// NextServerSeqNum returns and increments the server sequence number
func (s *LegacySession) NextServerSeqNum() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.SeqNumServer
	s.SeqNumServer++
	return seq
}

// SetStatus updates the session status
func (s *LegacySession) SetStatus(status uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = status
}

// GetStatus returns the current status
func (s *LegacySession) GetStatus() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Status
}

// SetContactList updates the contact list
func (s *LegacySession) SetContactList(contacts []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ContactList = make([]uint32, len(contacts))
	copy(s.ContactList, contacts)
}

// GetContactList returns a copy of the contact list
func (s *LegacySession) GetContactList() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	contacts := make([]uint32, len(s.ContactList))
	copy(contacts, s.ContactList)
	return contacts
}

// SetVisibleList updates the visible list with a copy of the provided UINs.
// Users on the visible list can see this session's online status even when invisible.
func (s *LegacySession) SetVisibleList(visible []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.VisibleList = make([]uint32, len(visible))
	copy(s.VisibleList, visible)
}

// SetInvisibleList updates the invisible list with a copy of the provided UINs.
// Users on the invisible list cannot see this session's online status.
func (s *LegacySession) SetInvisibleList(invisible []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.InvisibleList = make([]uint32, len(invisible))
	copy(s.InvisibleList, invisible)
}

// IsOnVisibleList checks if a UIN is on the visible list
func (s *LegacySession) IsOnVisibleList(uin uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.VisibleList {
		if v == uin {
			return true
		}
	}
	return false
}

// IsOnInvisibleList checks if a UIN is on the invisible list
func (s *LegacySession) IsOnInvisibleList(uin uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.InvisibleList {
		if v == uin {
			return true
		}
	}
	return false
}

// IsContact checks if a UIN is in the contact list
func (s *LegacySession) IsContact(uin uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.ContactList {
		if c == uin {
			return true
		}
	}
	return false
}

// GetUIN returns the session's UIN (implements foodgroup.LegacySessionInstance)
func (s *LegacySession) GetUIN() uint32 {
	return s.UIN
}

// GetExternalIP returns the external IP as uint32 (from UDP address)
func (s *LegacySession) GetExternalIP() uint32 {
	if s.Addr == nil || s.Addr.IP == nil {
		return 0
	}
	ip := s.Addr.IP.To4()
	if ip == nil {
		return 0
	}
	// ICQ stores IP in little-endian format
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

// GetTCPPort returns the TCP port for direct connections
func (s *LegacySession) GetTCPPort() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TCPPort
}

// GetInternalIP returns the internal IP for direct connections
func (s *LegacySession) GetInternalIP() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.InternalIP
}

// GetTCPVersion returns the TCP protocol version
func (s *LegacySession) GetTCPVersion() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TCPVersion
}

// SetDirectConnectionInfo sets the direct connection parameters
func (s *LegacySession) SetDirectConnectionInfo(tcpPort, internalIP uint32, tcpVersion uint16, dcType uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TCPPort = tcpPort
	s.InternalIP = internalIP
	s.TCPVersion = tcpVersion
	s.DCType = dcType
}
