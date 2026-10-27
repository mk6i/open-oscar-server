package client

import (
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// UserInfo describes a user as reported by the server.
type UserInfo struct {
	ScreenName string
	// WarningLevel is the user's warning level in percent.
	WarningLevel int
	// Flags holds the user class flags (wire.OServiceUserFlag*).
	Flags       uint16
	Away        bool
	IdleMinutes int
	SignonTime  time.Time
}

// newUserInfo converts a user info block received from the server.
func newUserInfo(info wire.TLVUserInfo) UserInfo {
	u := UserInfo{
		ScreenName:   info.ScreenName,
		WarningLevel: int(info.WarningLevel / 10),
		Away:         info.IsAway(),
	}
	u.Flags, _ = info.Uint16BE(wire.OServiceUserInfoUserFlags)
	if idle, ok := info.Uint16BE(wire.OServiceUserInfoIdleTime); ok {
		u.IdleMinutes = int(idle)
	}
	if signon, ok := info.Uint32BE(wire.OServiceUserInfoSignonTOD); ok && signon > 0 {
		u.SignonTime = time.Unix(int64(signon), 0)
	}
	return u
}

// UserProfile is the result of a user info lookup.
type UserProfile struct {
	Info UserInfo
	// Profile is the user's profile, usually HTML.
	Profile string
	// AwayMessage is the user's away message, set only when they are away.
	AwayMessage string
}

// Event is something that happened on the connection to the server. Events
// are delivered on Client.Events.
type Event interface {
	isEvent()
}

// BuddyArrivedEvent reports that a buddy signed on or changed status.
type BuddyArrivedEvent struct {
	Info UserInfo
}

// BuddyDepartedEvent reports that a buddy signed off.
type BuddyDepartedEvent struct {
	ScreenName string
}

// IMEvent reports a received instant message.
type IMEvent struct {
	From UserInfo
	// Message is the message text, usually HTML.
	Message string
	// AutoResponse indicates that the message is an automatic away reply.
	AutoResponse bool
	Time         time.Time
}

// TypingEvent reports a change in a correspondent's typing status.
type TypingEvent struct {
	ScreenName string
	// Status is 0 for idle, 1 for text entered and 2 for typing.
	Status uint16
}

// WarnedEvent reports that the user was warned.
type WarnedEvent struct {
	// NewLevel is the user's new warning level in percent.
	NewLevel int
	// By is the screen name of the warner, empty for anonymous warnings.
	By string
}

// SelfInfoEvent reports a change to the user's own info, such as their
// warning level dropping over time.
type SelfInfoEvent struct {
	Info UserInfo
}

// BuddyListEvent reports that the buddy list or block list changed.
type BuddyListEvent struct{}

// RateLimitEvent reports that the server started or stopped dropping the
// user's requests for sending too fast.
type RateLimitEvent struct {
	Limited bool
}

// ChatInviteEvent reports an invitation to a chat room.
type ChatInviteEvent struct {
	Invite ChatInvite
}

// ChatJoinedEvent reports that the user entered a chat room.
type ChatJoinedEvent struct {
	Room *ChatRoom
}

// ChatMessageEvent reports a message sent to a chat room, including the
// user's own messages as reflected by the server.
type ChatMessageEvent struct {
	Room    *ChatRoom
	From    string
	Message string
	Time    time.Time
}

// ChatUsersEvent reports users entering or leaving a chat room. The first
// such event after joining lists the users already in the room.
type ChatUsersEvent struct {
	Room   *ChatRoom
	Joined bool
	Users  []string
}

// ChatClosedEvent reports that the connection to a chat room closed.
type ChatClosedEvent struct {
	Room *ChatRoom
	Err  error
}

// DisconnectedEvent reports that the connection to the server closed. No
// further events follow.
type DisconnectedEvent struct {
	Err error
}

func (BuddyArrivedEvent) isEvent()  {}
func (BuddyDepartedEvent) isEvent() {}
func (IMEvent) isEvent()            {}
func (TypingEvent) isEvent()        {}
func (WarnedEvent) isEvent()        {}
func (SelfInfoEvent) isEvent()      {}
func (BuddyListEvent) isEvent()     {}
func (RateLimitEvent) isEvent()     {}
func (ChatInviteEvent) isEvent()    {}
func (ChatJoinedEvent) isEvent()    {}
func (ChatMessageEvent) isEvent()   {}
func (ChatUsersEvent) isEvent()     {}
func (ChatClosedEvent) isEvent()    {}
func (DisconnectedEvent) isEvent()  {}
