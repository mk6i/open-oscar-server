package icq_legacy

import (
	"net"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/state"
)

// LegacySession represents a connected legacy ICQ client session
type LegacySession struct {
	UIN           uint32
	Addr          *net.UDPAddr
	Version       uint16
	SessionID     uint32 // V5 only
	SeqNumClient  uint16 // Last received sequence number
	SeqNumServer  uint16 // Next sequence number to send
	Status        uint32
	LastActivity  time.Time
	ContactList   []uint32
	VisibleList   []uint32
	InvisibleList []uint32
	Password      string // Stored for session validation

	// Direct connection info (for peer-to-peer)
	TCPPort    uint32 // Client's TCP listening port for direct connections
	InternalIP uint32 // Client's internal/LAN IP address
	TCPVersion uint16 // Client's TCP protocol version
	DCType     uint8  // Direct connection type

	// Link to unified session manager
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

// SetVisibleList updates the visible list
func (s *LegacySession) SetVisibleList(visible []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.VisibleList = make([]uint32, len(visible))
	copy(s.VisibleList, visible)
}

// SetInvisibleList updates the invisible list
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
