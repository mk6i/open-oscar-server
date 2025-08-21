package http

import (
	"context"
	"net/mail"
	"time"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

// AccountManager defines methods for managing user account attributes
// such as email, confirmation status, registration status, and suspension.
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

	// UpdateSuspendedStatus updates the suspension status of a user account.
	UpdateSuspendedStatus(ctx context.Context, suspendedStatus uint16, screenName state.IdentScreenName) error

	// SetBotStatus updates the flag that indicates whether the user is a bot.
	SetBotStatus(ctx context.Context, isBot bool, screenName state.IdentScreenName) error
}

// BuddyIconRetriever defines a method for retrieving a buddy icon image by its hash.
type BuddyIconRetriever interface {
	// BuddyIcon retrieves a buddy icon image by its md5 hash.
	BuddyIcon(ctx context.Context, itemHash []byte) ([]byte, error)
}

// ChatRoomCreator defines a method for creating a new chat room.
type ChatRoomCreator interface {
	// CreateChatRoom creates a new chat room.
	CreateChatRoom(ctx context.Context, chatRoom *state.ChatRoom) error
}

// ChatRoomRetriever defines a method for retrieving all chat rooms
// under a specific exchange.
type ChatRoomRetriever interface {
	// AllChatRooms returns all chat rooms associated with the given exchange ID.
	AllChatRooms(ctx context.Context, exchange uint16) ([]state.ChatRoom, error)
}

// ChatSessionRetriever defines a method for retrieving all sessions
// associated with a specific chat room.
type ChatSessionRetriever interface {
	// AllSessions returns all active sessions in the chat room identified by cookie.
	AllSessions(cookie string) []*state.Session
}

// DirectoryManager defines methods for managing interest categories and keywords
// used in user profiles and directory listings.
type DirectoryManager interface {
	// Categories returns all existing directory categories.
	Categories(ctx context.Context) ([]state.Category, error)

	// CreateCategory adds a new directory category.
	CreateCategory(ctx context.Context, name string) (state.Category, error)

	// CreateKeyword adds a new keyword to the specified category.
	CreateKeyword(ctx context.Context, name string, categoryID uint8) (state.Keyword, error)

	// DeleteCategory removes a directory category by ID.
	DeleteCategory(ctx context.Context, categoryID uint8) error

	// DeleteKeyword removes a keyword by ID.
	DeleteKeyword(ctx context.Context, id uint8) error

	// KeywordsByCategory returns all keywords under the specified category.
	KeywordsByCategory(ctx context.Context, categoryID uint8) ([]state.Keyword, error)
}

// FeedBagRetriever defines methods for retrieving buddy list metadata.
type FeedBagRetriever interface {
	// BuddyIconMetadata retrieves a user's buddy icon metadata. It returns nil
	// if the user does not have a buddy icon.
	BuddyIconMetadata(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error)
}

// MessageRelayer defines a method for sending a SNAC message to a specific screen name.
type MessageRelayer interface {
	// RelayToScreenName sends the given SNAC message to the specified screen name.
	RelayToScreenName(ctx context.Context, screenName state.IdentScreenName, msg wire.SNACMessage)
}

// ProfileRetriever defines a method for retrieving a user's free-form profile.
type ProfileRetriever interface {
	// Profile returns the free-form profile body for the given screen name.
	Profile(ctx context.Context, screenName state.IdentScreenName) (string, error)
}

// SessionRetriever defines methods for retrieving active sessions,
// either all of them or by screen name.
type SessionRetriever interface {
	// AllSessions returns all active user sessions.
	AllSessions() []*state.Session

	// RetrieveSession returns the session associated with the given screen name,
	// or nil if no active session exists.
	RetrieveSession(screenName state.IdentScreenName) *state.Session
}

// UserManager defines methods for accessing and inserting AIM user records.
type UserManager interface {
	// AllUsers returns all registered users.
	AllUsers(ctx context.Context) ([]state.User, error)

	// DeleteUser removes a user from the system by screen name.
	DeleteUser(ctx context.Context, screenName state.IdentScreenName) error

	// InsertUser inserts a new user into the system. Return state.ErrDupUser
	// if a user with the same screen name already exists.
	InsertUser(ctx context.Context, u state.User) error

	// SetUserPassword sets the user's password hashes and auth key.
	SetUserPassword(ctx context.Context, screenName state.IdentScreenName, newPassword string) error

	// User returns all attributes for a user.
	User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)
}

type userWithPassword struct {
	ScreenName string `json:"screen_name"`
	Password   string `json:"password,omitempty"`
}

type onlineUsers struct {
	Count    int             `json:"count"`
	Sessions []sessionHandle `json:"sessions"`
}

type userHandle struct {
	ID              string `json:"id"`
	ScreenName      string `json:"screen_name"`
	IsICQ           bool   `json:"is_icq"`
	SuspendedStatus string `json:"suspended_status"`
	IsBot           bool   `json:"is_bot"`
}

type aimChatUserHandle struct {
	ID         string `json:"id"`
	ScreenName string `json:"screen_name"`
}

type userAccountHandle struct {
	ID              string `json:"id"`
	ScreenName      string `json:"screen_name"`
	Profile         string `json:"profile"`
	EmailAddress    string `json:"email_address"`
	RegStatus       uint16 `json:"reg_status"`
	Confirmed       bool   `json:"confirmed"`
	IsICQ           bool   `json:"is_icq"`
	SuspendedStatus string `json:"suspended_status"`
	IsBot           bool   `json:"is_bot"`
}

type userAccountPatch struct {
	SuspendedStatusText *string `json:"suspended_status"`
	IsBot               *bool   `json:"is_bot"`
}

type sessionHandle struct {
	ID            string  `json:"id"`
	ScreenName    string  `json:"screen_name"`
	OnlineSeconds float64 `json:"online_seconds"`
	AwayMessage   string  `json:"away_message"`
	IdleSeconds   float64 `json:"idle_seconds"`
	IsICQ         bool    `json:"is_icq"`
	RemoteAddr    string  `json:"remote_addr,omitempty"`
	RemotePort    uint16  `json:"remote_port,omitempty"`
}

type chatRoomCreate struct {
	Name string `json:"name"`
}

type chatRoom struct {
	Name         string              `json:"name"`
	CreateTime   time.Time           `json:"create_time"`
	CreatorID    string              `json:"creator_id,omitempty"`
	URL          string              `json:"url"`
	Participants []aimChatUserHandle `json:"participants"`
}

type instantMessage struct {
	From string `json:"from"`
	To   string `json:"to"`
	Text string `json:"text"`
}

type directoryKeyword struct {
	ID   uint8  `json:"id"`
	Name string `json:"name"`
}

type directoryCategory struct {
	ID   uint8  `json:"id"`
	Name string `json:"name"`
}

type directoryCategoryCreate struct {
	Name string `json:"name"`
}

type directoryKeywordCreate struct {
	CategoryID uint8  `json:"category_id"`
	Name       string `json:"name"`
}

type messageBody struct {
	Message string `json:"message"`
}
