package icq_legacy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
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

	// DCVersion is the client's direct connection protocol version.
	DCVersion uint16

	// DCType is the direct connection type (normal, SOCKS, etc.).
	DCType uint8

	// Instance links this legacy session to the unified OSCAR session manager.
	Instance *state.SessionInstance

	// knownOnline tracks contacts that have been reported as online via
	// SendUserOnline. Subsequent BuddyArrived for the same contact use
	// SendStatusChange instead, which sends the correct V5 packet type.
	knownOnline map[uint32]bool

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

// MarkContactOnline marks a contact as known-online. Returns true if the
// contact was already known online (i.e. this is a status change, not an
// initial arrival).
func (s *LegacySession) MarkContactOnline(uin uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.knownOnline == nil {
		s.knownOnline = make(map[uint32]bool)
	}
	wasOnline := s.knownOnline[uin]
	s.knownOnline[uin] = true
	return wasOnline
}

// MarkContactOffline removes a contact from the known-online set.
func (s *LegacySession) MarkContactOffline(uin uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.knownOnline != nil {
		delete(s.knownOnline, uin)
	}
}

// GetUIN returns the session's UIN (implements LegacySessionInstance)
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

// GetDCVersion returns the direct connection protocol version
func (s *LegacySession) GetDCVersion() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.DCVersion
}

// SetDirectConnectionInfo sets the direct connection parameters
func (s *LegacySession) SetDirectConnectionInfo(tcpPort, internalIP uint32, dcVersion uint16, dcType uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TCPPort = tcpPort
	s.InternalIP = internalIP
	s.DCVersion = dcVersion
	s.DCType = dcType
}

// UserManager provides user lookup and management for legacy ICQ operations.
type UserManager interface {
	User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)
	InsertUser(ctx context.Context, u state.User) error
	DeleteUser(ctx context.Context, screenName state.IdentScreenName) error
}

// AccountManager provides password management for legacy ICQ operations.
type AccountManager interface {
	SetUserPassword(ctx context.Context, screenName state.IdentScreenName, newPassword string) error
}

// SessionRetriever provides OSCAR session lookup for cross-protocol routing.
type SessionRetriever interface {
	RetrieveSession(screenName state.IdentScreenName) *state.Session
}

// MessageRelayer provides SNAC message delivery for legacy→OSCAR routing.
type MessageRelayer interface {
	RelayToScreenName(ctx context.Context, screenName state.IdentScreenName, msg wire.SNACMessage)
}

// BuddyBroadcaster provides presence broadcast for OSCAR buddy notifications.
type BuddyBroadcaster interface {
	BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error
	BroadcastBuddyDeparted(ctx context.Context, screenName state.IdentScreenName) error
}

// OfflineMessageManager provides offline message storage and retrieval.
type OfflineMessageManager interface {
	DeleteMessages(ctx context.Context, recip state.IdentScreenName) error
	RetrieveMessages(ctx context.Context, recip state.IdentScreenName) ([]state.OfflineMessage, error)
	SaveMessage(ctx context.Context, offlineMessage state.OfflineMessage) (int, error)
}

// ICQUserFinder provides user search capabilities for legacy ICQ operations.
type ICQUserFinder interface {
	FindByUIN(ctx context.Context, UIN uint32) (state.User, error)
	FindByICQEmail(ctx context.Context, email string) (state.User, error)
	FindByICQName(ctx context.Context, firstName, lastName, nickName string) ([]state.User, error)
	FindByICQInterests(ctx context.Context, code uint16, keywords []string) ([]state.User, error)
	FindByICQKeyword(ctx context.Context, keyword string) ([]state.User, error)
}

// ICQUserUpdater provides profile update capabilities for legacy ICQ operations.
type ICQUserUpdater interface {
	SetBasicInfo(ctx context.Context, name state.IdentScreenName, data state.ICQBasicInfo) error
	SetWorkInfo(ctx context.Context, name state.IdentScreenName, data state.ICQWorkInfo) error
	SetMoreInfo(ctx context.Context, name state.IdentScreenName, data state.ICQMoreInfo) error
	SetInterests(ctx context.Context, name state.IdentScreenName, data state.ICQInterests) error
	SetAffiliations(ctx context.Context, name state.IdentScreenName, data state.ICQAffiliations) error
	SetUserNotes(ctx context.Context, name state.IdentScreenName, data state.ICQUserNotes) error
	SetPermissions(ctx context.Context, name state.IdentScreenName, data state.ICQPermissions) error
	SetHomepageCategory(ctx context.Context, name state.IdentScreenName, data state.ICQHomepageCategory) error
}

// FeedbagManager provides server-side buddy list access and modification.
type FeedbagManager interface {
	Feedbag(ctx context.Context, screenName state.IdentScreenName) ([]wire.FeedbagItem, error)
	FeedbagUpsert(ctx context.Context, screenName state.IdentScreenName, items []wire.FeedbagItem) error
}

// RelationshipFetcher provides buddy relationship lookup.
type RelationshipFetcher interface {
	AllRelationships(ctx context.Context, me state.IdentScreenName, filter []state.IdentScreenName) ([]state.Relationship, error)
	Relationship(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) (state.Relationship, error)
}

// BuddyListRegistry provides buddy list registration for cross-protocol
// presence visibility. Legacy sessions must register their buddy list so that
// OSCAR's BroadcastVisibility/AllRelationships can discover them.
type BuddyListRegistry interface {
	RegisterBuddyList(ctx context.Context, user state.IdentScreenName) error
	UnregisterBuddyList(ctx context.Context, user state.IdentScreenName) error
}

// ClientSideBuddyListManager provides client-side buddy list management.
// Legacy ICQ clients use client-side buddy lists (not feedbag), so their
// contacts must be written to the clientSideBuddyList table for the
// relationship query to discover them.
type ClientSideBuddyListManager interface {
	AddBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error
}

// LegacySessionInstance represents a legacy session as seen by the service layer.
// This interface abstracts the session to avoid circular dependencies between
// the foodgroup and server/icq_legacy packages.
type LegacySessionInstance interface {
	// GetUIN returns the session's ICQ identification number.
	GetUIN() uint32

	// GetStatus returns the session's current online status value.
	GetStatus() uint32

	// GetContactList returns a copy of the session's contact list (buddy UINs).
	GetContactList() []uint32

	// IsOnVisibleList checks if the given UIN is on this session's visible list.
	IsOnVisibleList(uin uint32) bool

	// IsOnInvisibleList checks if the given UIN is on this session's invisible list.
	IsOnInvisibleList(uin uint32) bool
}

// LegacyMessageSender is the interface for sending messages to legacy ICQ clients.
// It provides methods for delivering messages and status notifications to
// connected legacy sessions.
type LegacyMessageSender interface {
	// SendMessage delivers a message to a legacy client identified by UIN.
	SendMessage(uin uint32, fromUIN uint32, msgType uint16, message string) error

	// SendStatusUpdate sends a status change notification to a legacy client.
	SendStatusUpdate(uin uint32, targetUIN uint32, status uint32) error

	// SendUserOnline sends a user online notification to a legacy client.
	SendUserOnline(uin uint32, targetUIN uint32, status uint32, ip net.IP, port uint16) error

	// SendUserOffline sends a user offline notification to a legacy client.
	SendUserOffline(uin uint32, targetUIN uint32) error
}

// ICBMService is the interface for sending SNAC messages to the OSCAR ICBM service.
type ICBMService interface {
	ChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error)
}
