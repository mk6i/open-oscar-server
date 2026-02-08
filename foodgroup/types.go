// Package foodgroup implements OSCAR food group business logic.
//
// The OSCAR protocol passes messages in SNAC (Simple Network Atomic
// Communication) format. SNAC messages are grouped by "food groups" (get it?
// snack, snac, foodgroup...). Each food group is responsible for a discrete
// piece of functionality, such as buddy list management (Feedbag), instant
// messaging (ICBM), and chat messaging (Chat).
//
// Each food group operation is represented by a struct type. The methods
// correspond 1:1 to each food group operation. Each food group operation is
// typically triggered by a client request. The operation may return a
// response. As such, methods receive client requests via SNAC frame and
// body parameters and send responses via returned SNAC objects.
//
// The following is a typical food group method signature. This example
// illustrates the ICBM ChannelMsgToHost operation.
//
//	ChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error)
//
// Params:
//   - ctx context.Context is the client request context.
//   - instance *state.SessionInstance is the client's session object.
//   - inFrame wire.SNACFrame is the request SNAC frame that contains the food group and subgroup parameters.
//   - inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost contains the body of the SNAC message. In this case, it contains instant message text and metadata.
//
// ChannelMsgToHost optionally sends a client response by returning
// *wire.SNACMessage. For operations that always send client responses,
// the methods return wire.SNACMessage value types (not pointer types).
// Methods for operations that never send client responses do not return
// wire.SNACMessage values.
//
// The foodgroup package delegates responsibility for message transport, user
// retrieval, and session management to callers via several interface types.
package foodgroup

import (
	"context"
	"net/mail"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// AccountManager is the interface for managing a user's account settings.
type AccountManager interface {
	// ConfirmStatus returns whether a user account has been confirmed.
	ConfirmStatus(ctx context.Context, screenName state.IdentScreenName) (bool, error)

	// EmailAddress looks up a user's email address by screen name.
	EmailAddress(ctx context.Context, screenName state.IdentScreenName) (*mail.Address, error)

	// RegStatus looks up a user's registration status by screen name.
	// It returns one of the following values:
	//   - wire.AdminInfoRegStatusFullDisclosure
	//   - wire.AdminInfoRegStatusLimitDisclosure
	//   - wire.AdminInfoRegStatusNoDisclosure
	RegStatus(ctx context.Context, screenName state.IdentScreenName) (uint16, error)

	// SetUserPassword sets the user's password hashes and auth key.
	SetUserPassword(ctx context.Context, screenName state.IdentScreenName, newPassword string) error

	// UpdateConfirmStatus sets whether a user account has been confirmed.
	UpdateConfirmStatus(ctx context.Context, screenName state.IdentScreenName, confirmStatus bool) error

	// UpdateDisplayScreenName updates the user's display screen name, which is
	// the screen name visible in the OSCAR client. It derives the user
	// identifier from the display screen name.
	UpdateDisplayScreenName(ctx context.Context, displayScreenName state.DisplayScreenName) error

	// UpdateEmailAddress changes a user's email address.
	UpdateEmailAddress(ctx context.Context, screenName state.IdentScreenName, emailAddress *mail.Address) error

	// UpdateRegStatus updates a user's registration status.
	// The regStatus param can be one of the following values:
	//   - wire.AdminInfoRegStatusFullDisclosure
	//   - wire.AdminInfoRegStatusLimitDisclosure
	//   - wire.AdminInfoRegStatusNoDisclosure
	UpdateRegStatus(ctx context.Context, screenName state.IdentScreenName, regStatus uint16) error

	// User returns all attributes for a user.
	User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)
}

// buddyBroadcaster defines methods for broadcasting buddy presence and visibility events
// to other sessions. These events notify users when a buddy comes online, goes offline,
// or changes visibility status.
type buddyBroadcaster interface {
	// BroadcastBuddyArrived notifies all relevant users that the given user has come online.
	BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error

	// BroadcastBuddyDeparted notifies all relevant users that the given user has gone offline.
	BroadcastBuddyDeparted(ctx context.Context, instance *state.SessionInstance) error

	// BroadcastVisibility sends presence updates to the specified filter list.
	// If sendDepartures is true, departure events are sent as well.
	BroadcastVisibility(ctx context.Context, you *state.SessionInstance, filter []state.IdentScreenName, sendDepartures bool) error
}

// BARTItemManager is the interface for managing BART (Buddy Art) assets.
type BARTItemManager interface {
	// BARTItem retrieves a BART asset by its hash.
	BARTItem(ctx context.Context, hash []byte) ([]byte, error)

	// BuddyIconMetadata retrieves a user's buddy icon metadata. It returns nil
	// if the user does not have a buddy icon.
	BuddyIconMetadata(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error)

	// InsertBARTItem creates or updates a BART asset and blob hash.
	InsertBARTItem(ctx context.Context, hash []byte, blob []byte, itemType uint16) error

	// ListBARTItems returns BART assets filtered by type.
	ListBARTItems(ctx context.Context, itemType uint16) ([]state.BARTItem, error)

	// DeleteBARTItem deletes a BART asset by hash.
	DeleteBARTItem(ctx context.Context, hash []byte) error
}

// RelationshipFetcher is the interface for retrieving relationships between users.
type RelationshipFetcher interface {
	// AllRelationships retrieves the relationships between the specified user (`me`)
	// and other users.
	AllRelationships(ctx context.Context, me state.IdentScreenName, filter []state.IdentScreenName) ([]state.Relationship, error)

	// Relationship retrieves the relationship between the specified user (`me`)
	// and another user (`them`).
	Relationship(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) (state.Relationship, error)
}

// ChatMessageRelayer defines the interface for sending messages to chat room
// participants.
type ChatMessageRelayer interface {
	// AllSessions returns all chat room participants. Returns
	// ErrChatRoomNotFound if the room does not exist.
	AllSessions(chatCookie string) []*state.Session

	// RelayToAllExcept sends a message to all chat room participants except
	// for the participant with a particular screen name. Returns
	// ErrChatRoomNotFound if the room does not exist for cookie.
	RelayToAllExcept(ctx context.Context, chatCookie string, except state.IdentScreenName, msg wire.SNACMessage)

	// RelayToScreenName sends a message to a chat room user. Returns
	// ErrChatRoomNotFound if the room does not exist for cookie.
	RelayToScreenName(ctx context.Context, chatCookie string, recipient state.IdentScreenName, msg wire.SNACMessage)
}

// ChatRoomRegistry defines the interface for storing and retrieving chat
// rooms in a persistent store. The persistent store has two purposes:
//   - Remember user-created chat rooms (exchange 4) so that clients can reconnect
//     to the rooms following server restarts.
//   - Keep track of public chat room created by the server operator (exchange 5).
//     User's can only join public chat rooms that exist in the room registry.
type ChatRoomRegistry interface {
	// ChatRoomByCookie looks up a chat room by exchange. Returns
	// state.ErrChatRoomNotFound if the room does not exist for cookie.
	ChatRoomByCookie(ctx context.Context, chatCookie string) (state.ChatRoom, error)

	// ChatRoomByName looks up a chat room by exchange and name. Returns
	// state.ErrChatRoomNotFound if the room does not exist for exchange and name.
	ChatRoomByName(ctx context.Context, exchange uint16, name string) (state.ChatRoom, error)

	// CreateChatRoom creates a new chat room.
	CreateChatRoom(ctx context.Context, chatRoom *state.ChatRoom) error
}

// ChatSessionRegistry defines the interface for adding and removing chat
// sessions.
type ChatSessionRegistry interface {
	// AddSession adds a session to the chat session manager. The chatCookie
	// param identifies the chat room to which screenName is added. It returns
	// the newly created session instance registered in the chat session
	// manager.
	AddSession(ctx context.Context, chatCookie string, screenName state.DisplayScreenName) (*state.SessionInstance, error)

	// RemoveSession removes a session from the chat session manager.
	RemoveSession(instance *state.SessionInstance)
}

// ClientSideBuddyListManager defines operations for managing a user's buddy list,
// including permissions like allow/deny and buddy group modifications.
//
// This interface manages a client-side buddy list that is temporarily copied
// to the server on a per-session basis. The list is cleared when the user signs out.
type ClientSideBuddyListManager interface {
	// AddBuddy adds 'them' to 'me's buddy list.
	AddBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error

	// DenyBuddy blocks messages and presence visibility from 'them' to 'me'.
	DenyBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error

	// PermitBuddy allows messages and presence visibility from 'them' to 'me',
	// potentially overriding deny settings.
	PermitBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error

	// RemoveBuddy removes 'them' from 'me's buddy list. Does not affect permit/deny status.
	RemoveBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error

	// RemoveDenyBuddy removes 'them' from 'me's deny list, restoring default
	// visibility and messaging behavior.
	RemoveDenyBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error

	// RemovePermitBuddy removes 'them' from 'me's permit list, restoring default
	// visibility and messaging behavior.
	RemovePermitBuddy(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) error

	// SetPDMode sets the permit/deny mode (e.g., allow all, deny all, permit
	// some) for 'me'. It clears any existing permit/deny records.
	SetPDMode(ctx context.Context, me state.IdentScreenName, pdMode wire.FeedbagPDMode) error
}

// CookieBaker defines methods for issuing and verifying AIM authentication tokens ("cookies").
// These tokens are used for authenticating client sessions with AIM services.
type CookieBaker interface {
	// Crack verifies and decodes a previously issued authentication token.
	// Returns the original payload if the token is valid.
	Crack(data []byte) ([]byte, error)

	// Issue creates a new authentication token from the given payload.
	// The resulting token can later be verified using Crack.
	Issue(data []byte) ([]byte, error)
}

// FeedbagManager is the interface for reading and modifying server-side buddy
// lists (feedbag).
type FeedbagManager interface {
	// Feedbag fetches the contents of a user's feedbag.
	Feedbag(ctx context.Context, screenName state.IdentScreenName) ([]wire.FeedbagItem, error)

	// FeedbagDelete deletes an entry from a user's feedbag.
	FeedbagDelete(ctx context.Context, screenName state.IdentScreenName, items []wire.FeedbagItem) error

	// FeedbagLastModified returns the last time a user's feedbag was updated.
	FeedbagLastModified(ctx context.Context, screenName state.IdentScreenName) (time.Time, error)

	// FeedbagUpsert upserts an entry to a user's feedbag.
	FeedbagUpsert(ctx context.Context, screenName state.IdentScreenName, items []wire.FeedbagItem) error

	// UseFeedbag sets the user's session to use feedbag instead of the default
	// client-side buddy list.
	UseFeedbag(ctx context.Context, screenName state.IdentScreenName) error
}

// ICQUserFinder defines methods for searching ICQ users by various attributes.
type ICQUserFinder interface {
	// FindByUIN returns the user with a matching UIN.
	FindByUIN(ctx context.Context, UIN uint32) (state.User, error)

	// FindByICQEmail returns the user with a matching ICQ-registered email address.
	FindByICQEmail(ctx context.Context, email string) (state.User, error)

	// FindByICQName returns users matching the given first name, last name, and/or nickname.
	// Empty values are ignored and not included in the search criteria.
	FindByICQName(ctx context.Context, firstName, lastName, nickName string) ([]state.User, error)

	// FindByICQInterests returns users who share at least one keyword under the
	// specified interest category code.
	FindByICQInterests(ctx context.Context, code uint16, keywords []string) ([]state.User, error)

	// FindByICQKeyword returns users who have the specified keyword in any interest category.
	FindByICQKeyword(ctx context.Context, keyword string) ([]state.User, error)
}

// ICQUserUpdater defines methods for updating various fields of an ICQ user's profile.
type ICQUserUpdater interface {
	// SetAffiliations updates the user's affiliations, such as memberships in organizations or groups.
	SetAffiliations(ctx context.Context, name state.IdentScreenName, data state.ICQAffiliations) error

	// SetBasicInfo updates the user's basic profile information.
	SetBasicInfo(ctx context.Context, name state.IdentScreenName, data state.ICQBasicInfo) error

	// SetInterests updates the user's interests.
	SetInterests(ctx context.Context, name state.IdentScreenName, data state.ICQInterests) error

	// SetMoreInfo updates additional personal details beyond the basic profile.
	SetMoreInfo(ctx context.Context, name state.IdentScreenName, data state.ICQMoreInfo) error

	// SetUserNotes updates the user's profile notes.
	SetUserNotes(ctx context.Context, name state.IdentScreenName, data state.ICQUserNotes) error

	// SetWorkInfo updates the user's professional or employment-related details.
	SetWorkInfo(ctx context.Context, name state.IdentScreenName, data state.ICQWorkInfo) error

	// SetPermissions updates the user's privacy and permission settings.
	SetPermissions(ctx context.Context, name state.IdentScreenName, data state.ICQPermissions) error

	// SetHomepageCategory updates the user's homepage category information.
	// This is used by the V5 META_SET_HPCAT (0x0442) command.
	// From iserverd v5_set_hpcat_info() - updates user's homepage category.
	SetHomepageCategory(ctx context.Context, name state.IdentScreenName, data state.ICQHomepageCategory) error
}

// MessageRelayer defines methods for delivering SNAC messages to one or more
// AIM screen names.
type MessageRelayer interface {
	// RelayToScreenNames sends the given SNAC message to all specified screen names.
	RelayToScreenNames(ctx context.Context, screenNames []state.IdentScreenName, msg wire.SNACMessage)

	// RelayToScreenName sends the given SNAC message to a single screen name.
	RelayToScreenName(ctx context.Context, screenName state.IdentScreenName, msg wire.SNACMessage)

	// RelayToOtherInstances forwards a SNAC to other concurrent instances for the same user
	RelayToOtherInstances(ctx context.Context, instance *state.SessionInstance, msg wire.SNACMessage)

	// RelayToScreenNameActiveOnly sends the given SNAC message to active sessions (not away or idle) for a single screen name.
	RelayToScreenNameActiveOnly(ctx context.Context, screenName state.IdentScreenName, msg wire.SNACMessage)

	// RelayToSelf forwards a SNAC to the current session instance.
	RelayToSelf(ctx context.Context, instance *state.SessionInstance, msg wire.SNACMessage)
}

// OfflineMessageManager defines operations for managing offline messages.
// These messages are stored temporarily when a recipient is unavailable,
// and are retrieved once the recipient comes online. Offline messages are
// available in all ICQ versions and AIM 6+.
type OfflineMessageManager interface {
	// DeleteMessages removes all offline messages for the specified recipient.
	DeleteMessages(ctx context.Context, recip state.IdentScreenName) error

	// RetrieveMessages returns all offline messages for the specified recipient.
	RetrieveMessages(ctx context.Context, recip state.IdentScreenName) ([]state.OfflineMessage, error)

	// SaveMessage stores a new offline message for delivery when the recipient comes online and returns the sender's total queued message count for that recipient.
	SaveMessage(ctx context.Context, offlineMessage state.OfflineMessage) (int, error)

	// SetOfflineMsgCount sets the offline message count for a user.
	SetOfflineMsgCount(ctx context.Context, screenName state.IdentScreenName, count int) error
}

// ProfileManager defines methods for managing and querying AIM user profiles,
// including directory information, interest keywords, and free-form profile content.
type ProfileManager interface {
	// FindByAIMEmail returns the user with the given AIM-associated email address.
	FindByAIMEmail(ctx context.Context, email string) (state.User, error)

	// FindByAIMKeyword returns users who have the specified keyword in their profile interests.
	FindByAIMKeyword(ctx context.Context, keyword string) ([]state.User, error)

	// FindByAIMNameAndAddr returns users matching the specified name and address directory info.
	// Fields left empty in the input are ignored in the query.
	FindByAIMNameAndAddr(ctx context.Context, info state.AIMNameAndAddr) ([]state.User, error)

	// InterestList returns the list of available interest categories and keywords
	// that users can associate with their profiles.
	InterestList(ctx context.Context) ([]wire.ODirKeywordListItem, error)

	// Profile returns the user's profile information for the given screen name.
	Profile(ctx context.Context, screenName state.IdentScreenName) (state.UserProfile, error)

	// SetDirectoryInfo updates the user's directory listing with name, city, state, zip, and country info.
	SetDirectoryInfo(ctx context.Context, screenName state.IdentScreenName, info state.AIMNameAndAddr) error

	// SetKeywords sets up to five interest keywords for the user's profile.
	SetKeywords(ctx context.Context, screenName state.IdentScreenName, keywords [5]string) error

	// SetProfile sets the user's profile information.
	SetProfile(ctx context.Context, screenName state.IdentScreenName, profile state.UserProfile) error

	// User returns the full user record associated with the given screen name.
	User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)
}

// SessionRegistry defines methods for managing active user sessions.
// It ensures that only one session is active per screen name at any given time.
type SessionRegistry interface {
	// AddSession adds a new session to the pool, enforcing a one-session-per-screen-name policy.
	// If a session for the given screen name is already active, this call blocks until the active
	// session is removed via [SessionRegistry.RemoveSession] or the context is canceled.
	//
	// When multiple concurrent calls are made for the same screen name, only one will succeed;
	// the others will return an error once the context is done.
	// If doMultiSess is true, allows multiple sessions for the same screen name.
	AddSession(ctx context.Context, screenName state.DisplayScreenName, doMultiSess bool) (*state.SessionInstance, error)

	// RemoveSession removes the given session from the registry, allowing future sessions
	// to be created for the same screen name.
	RemoveSession(instance *state.SessionInstance)
}

// SessionRetriever defines a method for retrieving an active session
// associated with a given screen name.
type SessionRetriever interface {
	// RetrieveSession returns the session associated with the given screen name,
	// or nil if no active session exists. Returns the Session object if there
	// are active instances with complete signon.
	RetrieveSession(screenName state.IdentScreenName) *state.Session
}

// UserManager defines methods for accessing and inserting AIM user records.
type UserManager interface {
	// InsertUser inserts a new user into the system. Return state.ErrDupUser
	// if a user with the same screen name already exists.
	InsertUser(ctx context.Context, u state.User) error

	// User returns the user record associated with the given screen name.
	User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)

	// SetWarnLevel updates the last warn update time and warning level for a user.
	SetWarnLevel(ctx context.Context, user state.IdentScreenName, lastWarnUpdate time.Time, lastWarnLevel uint16) error

	// DeleteUser removes a user from the system by screen name.
	// Returns state.ErrNoUser if the user does not exist.
	DeleteUser(ctx context.Context, screenName state.IdentScreenName) error
}
