// Package foodgroup provides service layer functionality for ICQ legacy protocols.
package foodgroup

import "net"

// This file contains typed request and response structs for the ICQ legacy service layer.
// These types enable clean separation between protocol handlers and business logic,
// following the OSCAR foodgroup architecture pattern.
//
// Request structs are used by handlers to pass parsed packet data to service methods.
// Response structs are returned by service methods for handlers to build protocol-specific packets.

// AuthRequest contains authentication parameters for legacy ICQ login.
// Used by handlers when processing login packets (CMD_LOGIN) from v2-v5 protocols.
//
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
//
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
//
type ContactListRequest struct {
	// UIN is the user's UIN who owns this contact list
	UIN uint32

	// Contacts is the list of UINs in the user's contact list
	Contacts []uint32
}

// StatusChangeRequest contains status change data for presence updates.
// Used by handlers when processing status change packets (CMD_SET_STATUS).
//
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
//
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
//
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
//
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
//
type ContactListResult struct {
	// OnlineContacts contains the status of each contact in the submitted list
	OnlineContacts []ContactStatus
}

// ContactStatus represents a contact's online status.
// Used within ContactListResult to report individual contact states.
//
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
//
type StatusChangeResult struct {
	// NotifyTargets contains the list of users who should be notified of the status change
	NotifyTargets []NotifyTarget
}

// NotifyTarget represents a user to notify about a status change.
// Used within StatusChangeResult to identify notification recipients.
//
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
//
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
//
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
