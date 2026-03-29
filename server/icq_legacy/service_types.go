package icq_legacy

import (
	"net"
	"time"
)

// This file contains typed request and response structs for the ICQ legacy service layer.
// These types enable clean separation between protocol handlers and business logic,
// following the OSCAR foodgroup architecture pattern.
//
// Request structs are used by handlers to pass parsed packet data to service methods.
// Response structs are returned by service methods for handlers to build protocol-specific packets.

// AuthRequest contains authentication parameters for legacy ICQ login.
// Used by handlers when processing login packets (CMD_LOGIN) from v2-v5 protocols.
type AuthRequest struct {
	// UIN is the user's ICQ identification number
	UIN uint32

	// Password is the user's plaintext password
	Password string

	// Status is the initial status the user wants to set (e.g., online, away, invisible)
	Status uint32

	// TCPPort is the TCP port the client is listening on for direct connections
	TCPPort uint32

	// Version is the protocol version (2, 3, 4, or 5)
	Version uint16
}

// MessageRequest contains message parameters for sending messages between users.
// Used by handlers when processing through-server message packets (CMD_SEND_MESSAGE).
type MessageRequest struct {
	// FromUIN is the sender's UIN
	FromUIN uint32

	// ToUIN is the recipient's UIN
	ToUIN uint32

	// MsgType is the ICQ message type (e.g., 0x0001 for text, 0x0004 for URL)
	MsgType uint16

	// Message is the message content
	Message string
}

// ContactListRequest contains contact list data for processing buddy lists.
// Used by handlers when processing contact list packets (CMD_CONTACT_LIST).
type ContactListRequest struct {
	// UIN is the user's UIN who owns this contact list
	UIN uint32

	// Contacts is the list of UINs in the user's contact list
	Contacts []uint32
}

// StatusChangeRequest contains status change data for presence updates.
// Used by handlers when processing status change packets (CMD_SET_STATUS).
type StatusChangeRequest struct {
	// UIN is the user's UIN whose status is changing
	UIN uint32

	// NewStatus is the new status value
	NewStatus uint32

	// OldStatus is the previous status value (for tracking transitions)
	OldStatus uint32
}

// UserAddRequest contains user add parameters for contact list additions.
// Used by handlers when processing user add packets (CMD_USER_ADD).
type UserAddRequest struct {
	// FromUIN is the UIN of the user adding someone to their contact list
	FromUIN uint32

	// TargetUIN is the UIN of the user being added
	TargetUIN uint32
}

// =============================================================================
// Response Structs
// =============================================================================
// Response structs are returned by service methods for handlers to build
// protocol-specific packets. They contain the results of business logic
// operations without any protocol-specific formatting.

// AuthResult contains authentication outcome from the service layer.
// Returned by AuthenticateUser method after validating credentials.
type AuthResult struct {
	// Success indicates whether authentication was successful
	Success bool

	// SessionID is the unique session identifier assigned on successful login
	SessionID string

	// ClientIP is the IP address of the connecting client
	ClientIP net.IP

	// ErrorCode indicates the failure reason (0 = success)
	// Common error codes:
	// - 0x0001: Bad password
	// - 0x0002: User not found
	// - 0x0003: Already logged in
	ErrorCode uint16
}

// MessageResult contains message routing info from the service layer.
// Returned by ProcessMessage method after handling a message send request.
type MessageResult struct {
	// Delivered indicates whether the message was delivered to an online user
	Delivered bool

	// StoredOffline indicates whether the message was stored for offline delivery
	StoredOffline bool

	// TargetOnline indicates whether the target user is currently online
	TargetOnline bool

	// TargetVersion is the protocol version of the target user (for cross-protocol routing)
	TargetVersion uint16
}

// ContactListResult contains online status for contacts from the service layer.
// Returned by ProcessContactList method after processing a contact list.
type ContactListResult struct {
	// OnlineContacts contains the status of each contact in the submitted list
	OnlineContacts []ContactStatus
}

// ContactStatus represents a contact's online status.
// Used within ContactListResult to report individual contact states.
type ContactStatus struct {
	// UIN is the contact's ICQ identification number
	UIN uint32

	// Online indicates whether the contact is currently online
	Online bool

	// Status is the contact's current status value (e.g., away, DND, invisible)
	Status uint32

	// Version is the protocol version the contact is using
	Version uint16
}

// StatusChangeResult contains notification targets from the service layer.
// Returned by ProcessStatusChange method after processing a status update.
type StatusChangeResult struct {
	// NotifyTargets contains the list of users who should be notified of the status change
	NotifyTargets []NotifyTarget
}

// NotifyTarget represents a user to notify about a status change.
// Used within StatusChangeResult to identify notification recipients.
type NotifyTarget struct {
	// UIN is the user's ICQ identification number
	UIN uint32

	// Version is the protocol version the user is using (for protocol-specific notifications)
	Version uint16
}

// UserInfoResult contains user info for protocol responses.
// Returned by GetUserInfoForProtocol method when retrieving user profile data.
// Contains both basic fields (available in all protocol versions) and extended
// fields (available in V3/V5 protocols).
type UserInfoResult struct {
	// Basic fields (all protocol versions)

	// UIN is the user's ICQ identification number
	UIN uint32

	// Nickname is the user's display name
	Nickname string

	// FirstName is the user's first name
	FirstName string

	// LastName is the user's last name
	LastName string

	// Email is the user's email address
	Email string

	// Gender is the user's gender (0=not specified, 1=female, 2=male)
	Gender uint8

	// Age is the user's age in years
	Age uint8

	// Status is the user's current status value
	Status uint32

	// Online indicates whether the user is currently online
	Online bool

	// AuthRequired indicates whether authorization is required to add this user (0=no, 1=yes)
	AuthRequired uint8

	// Extended fields (V3/V5 protocols)

	// City is the user's city of residence
	City string

	// State is the user's state/province of residence
	State string

	// Country is the user's country code
	Country uint16

	// Phone is the user's phone number
	Phone string

	// Homepage is the user's personal website URL
	Homepage string

	// About is the user's "about me" text
	About string

	// Work info

	// Company is the user's employer name
	Company string

	// Department is the user's department within their company
	Department string

	// Position is the user's job title
	Position string
}

// UserAddResult contains user add outcome from the service layer.
// Returned by ProcessUserAdd method after processing a contact addition.
type UserAddResult struct {
	// TargetOnline indicates whether the added user is currently online
	TargetOnline bool

	// TargetStatus is the current status of the added user
	TargetStatus uint32

	// TargetVersion is the protocol version the added user is using
	TargetVersion uint16

	// SendYouWereAdded indicates whether to send a "you were added" notification to the target
	SendYouWereAdded bool
}

// LegacyOfflineMessage represents an offline message stored for later delivery.
// Messages are stored when the target user is offline and delivered when they log in.
type LegacyOfflineMessage struct {
	// FromUIN is the sender's ICQ identification number.
	FromUIN uint32

	// ToUIN is the recipient's ICQ identification number.
	ToUIN uint32

	// MsgType is the ICQ message type (e.g., 0x0001 for text, 0x0004 for URL).
	MsgType uint16

	// Message is the message text content.
	Message string

	// URL is the URL content for URL-type messages.
	URL string

	// Desc is the description for URL-type messages.
	Desc string

	// Timestamp is when the message was originally sent.
	Timestamp time.Time
}

// LegacyUserSearchResult represents a user search result in legacy ICQ format.
// Used by search operations (by UIN, name, email, white pages) to return
// user profile information to protocol handlers.
type LegacyUserSearchResult struct {
	// UIN is the user's ICQ identification number.
	UIN uint32

	// Nickname is the user's display name.
	Nickname string

	// FirstName is the user's first name.
	FirstName string

	// LastName is the user's last name.
	LastName string

	// Email is the user's email address.
	Email string

	// Gender is the user's gender (0=not specified, 1=female, 2=male).
	Gender uint8

	// Age is the user's age in years.
	Age uint8

	// Status is the user's current online status value.
	Status uint32

	// Online indicates whether the user is currently online.
	Online bool

	// AuthRequired indicates whether authorization is needed to add this user (0=no, 1=yes).
	AuthRequired uint8

	// WebAware indicates whether the user's online status is visible on the web (0=no, 1=yes).
	WebAware uint8

	// Extended fields (from V5 META_USER_MORE response)

	// Homepage is the user's personal website URL.
	Homepage string

	// BirthYear is the user's birth year (full year, e.g., 1985).
	BirthYear uint16

	// BirthMonth is the user's birth month (1-12).
	BirthMonth uint8

	// BirthDay is the user's birth day (1-31).
	BirthDay uint8

	// Lang1 is the user's primary language code.
	Lang1 uint8

	// Lang2 is the user's secondary language code.
	Lang2 uint8

	// Lang3 is the user's tertiary language code.
	Lang3 uint8
}

// WhitePagesSearchCriteria contains all the search criteria for white pages search.
// This is used by the V5 META_SEARCH_WHITE (0x0532) and META_SEARCH_WHITE2 (0x0533) commands.
// From iserverd v5_search_by_white() and v5_search_by_white2() in search.cpp.
type WhitePagesSearchCriteria struct {
	// Personal information

	// FirstName filters by user's first name (partial match).
	FirstName string

	// LastName filters by user's last name (partial match).
	LastName string

	// Nickname filters by user's nickname (partial match).
	Nickname string

	// Email filters by user's email address (exact match).
	Email string

	// Age range

	// MinAge is the minimum age for the search range (0 = no minimum).
	MinAge uint16

	// MaxAge is the maximum age for the search range (0 = no maximum).
	MaxAge uint16

	// Demographics

	// Gender filters by gender (0=unspecified, 1=female, 2=male).
	Gender uint8

	// Language filters by language code (1-127, 0=unspecified).
	Language uint8

	// Location

	// City filters by city name (case-insensitive partial match).
	City string

	// State filters by state/province name (case-insensitive partial match).
	State string

	// Country filters by country code (0=unspecified).
	Country uint16

	// Work information

	// Company filters by company name (case-insensitive partial match).
	Company string

	// Department filters by department name.
	Department string

	// Position filters by job title (case-insensitive partial match).
	Position string

	// WorkCode filters by occupation code (0=unspecified).
	WorkCode uint8

	// Past affiliations

	// PastCode is the past affiliation category code.
	PastCode uint16

	// PastKeywords contains keywords for past affiliation search.
	PastKeywords string

	// Interests

	// InterestIndex is the interest category index for filtering.
	InterestIndex uint16

	// InterestKeywords contains keywords for interest-based search.
	InterestKeywords string

	// Current affiliations

	// AffiliationIndex is the affiliation category index for filtering.
	AffiliationIndex uint16

	// AffiliationKeywords contains keywords for affiliation-based search.
	AffiliationKeywords string

	// Homepage category (White2 only)

	// HomepageIndex is the homepage category index for filtering.
	HomepageIndex uint16

	// HomepageKeywords contains keywords for homepage category search.
	HomepageKeywords string

	// Search options

	// OnlineOnly restricts results to currently online users when true.
	OnlineOnly bool
}
