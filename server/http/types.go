package http

import (
	"context"
	"net/mail"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
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

// BARTAssetManager defines methods for managing BART (Buddy ART) assets.
type BARTAssetManager interface {
	// BARTItem retrieves a BART asset by its hash.
	BARTItem(ctx context.Context, hash []byte) ([]byte, error)

	// InsertBARTItem inserts a BART asset.
	InsertBARTItem(ctx context.Context, hash []byte, blob []byte, itemType uint16) error

	// ListBARTItems returns BART assets filtered by type.
	ListBARTItems(ctx context.Context, itemType uint16) ([]state.BARTItem, error)

	// DeleteBARTItem deletes a BART asset by hash.
	DeleteBARTItem(ctx context.Context, hash []byte) error
}

// BuddyBroadcaster defines a method for broadcasting presence updates.
type BuddyBroadcaster interface {
	// BroadcastVisibility sends presence updates to the specified filter list.
	// If sendDepartures is true, departure events are sent as well.
	BroadcastVisibility(ctx context.Context, you *state.SessionInstance, filter []state.IdentScreenName, sendDepartures bool) error
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

// ChatRoomDeleter defines a method for deleting chat rooms.
type ChatRoomDeleter interface {
	// DeleteChatRooms deletes chat rooms by their names under a specific exchange.
	DeleteChatRooms(ctx context.Context, exchange uint16, names []string) error
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

// FeedbagManager defines methods for managing feedbag (buddy list) entries.
// This interface matches foodgroup.FeedbagManager and is implemented by state.SQLiteUserStore.
type FeedbagManager interface {
	// Feedbag retrieves all feedbag items for a user.
	Feedbag(ctx context.Context, screenName state.IdentScreenName) ([]wire.FeedbagItem, error)

	// FeedbagUpsert inserts or updates feedbag items.
	FeedbagUpsert(ctx context.Context, screenName state.IdentScreenName, items []wire.FeedbagItem) error

	// FeedbagDelete deletes feedbag items.
	FeedbagDelete(ctx context.Context, screenName state.IdentScreenName, items []wire.FeedbagItem) error
}

// MessageRelayer defines a method for sending a SNAC message to a specific screen name.
type MessageRelayer interface {
	// RelayToScreenName sends the given SNAC message to the specified screen name.
	RelayToScreenName(ctx context.Context, screenName state.IdentScreenName, msg wire.SNACMessage)
}

// ProfileRetriever defines a method for retrieving a user's free-form profile.
type ProfileRetriever interface {
	// Profile returns the user's profile information for the given screen name.
	Profile(ctx context.Context, screenName state.IdentScreenName) (state.UserProfile, error)
}

// SessionRetriever defines methods for retrieving active sessions,
// either all of them or by screen name.
type SessionRetriever interface {
	// AllSessions returns all active user sessions.
	AllSessions() []*state.Session

	// RetrieveSession returns the session associated with the given screen name,
	// or nil if no active session exists. Returns the Session object if there
	// are active instances with complete signon.
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
	ID            string           `json:"id"`
	ScreenName    string           `json:"screen_name"`
	OnlineSeconds int              `json:"online_seconds"`
	IsAway        bool             `json:"is_away"`
	AwayMessage   string           `json:"away_message"`
	IdleSeconds   int              `json:"idle_seconds"`
	IsInvisible   bool             `json:"is_invisible"`
	IsICQ         bool             `json:"is_icq"`
	InstanceCount int              `json:"instance_count"`
	Instances     []instanceHandle `json:"instances"`
}

type instanceHandle struct {
	Num         int    `json:"num"`
	IdleSeconds int    `json:"idle_seconds"`
	IsAway      bool   `json:"is_away"`
	AwayMessage string `json:"away_message"`
	IsInvisible bool   `json:"is_invisible"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
}

type chatRoomCreate struct {
	Name string `json:"name"`
}

type chatRoomDelete struct {
	Names []string `json:"names"`
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

// Web API key management types

type createWebAPIKeyRequest struct {
	AppName        string   `json:"app_name"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	RateLimit      int      `json:"rate_limit,omitempty"`
	Capabilities   []string `json:"capabilities,omitempty"`
}

type webAPIKeyResponse struct {
	DevID          string     `json:"dev_id"`
	DevKey         string     `json:"dev_key,omitempty"` // Only shown on creation
	AppName        string     `json:"app_name"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsed       *time.Time `json:"last_used,omitempty"`
	IsActive       bool       `json:"is_active"`
	RateLimit      int        `json:"rate_limit"`
	AllowedOrigins []string   `json:"allowed_origins,omitempty"`
	Capabilities   []string   `json:"capabilities,omitempty"`
}

type updateWebAPIKeyRequest struct {
	AppName        *string   `json:"app_name,omitempty"`
	IsActive       *bool     `json:"is_active,omitempty"`
	RateLimit      *int      `json:"rate_limit,omitempty"`
	AllowedOrigins *[]string `json:"allowed_origins,omitempty"`
	Capabilities   *[]string `json:"capabilities,omitempty"`
}
