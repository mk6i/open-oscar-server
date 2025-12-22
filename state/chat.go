package state

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

const (
	// PrivateExchange is the ID of the exchange that hosts non-public created
	// by users.
	PrivateExchange uint16 = 4
	// PublicExchange is the ID of the exchange that hosts public chat rooms
	// created by the server operator exclusively.
	PublicExchange uint16 = 5
)

// ErrChatRoomNotFound indicates that a chat room lookup failed.
var (
	ErrChatRoomNotFound = errors.New("chat room not found")
	ErrDupChatRoom      = errors.New("chat room already exists")
)

// NewChatRoom creates a new ChatRoom instance.
func NewChatRoom(name string, creator IdentScreenName, exchange uint16) ChatRoom {
	return ChatRoom{
		name:     name,
		creator:  creator,
		exchange: exchange,
	}
}

// ChatRoom represents of a chat room.
type ChatRoom struct {
	createTime time.Time
	creator    IdentScreenName
	exchange   uint16
	name       string
}

// Creator returns the screen name of the user who created the chat room.
func (c ChatRoom) Creator() IdentScreenName {
	return c.creator
}

// Exchange returns which exchange the chat room belongs to.
func (c ChatRoom) Exchange() uint16 {
	return c.exchange
}

// Name returns the chat room name.
func (c ChatRoom) Name() string {
	return c.name
}

// InstanceNumber returns which instance chatroom exists in. Overflow chat
// rooms do not exist yet, so all chats happen in the same instance.
func (c ChatRoom) InstanceNumber() uint16 {
	return 0
}

// CreateTime returns when the chat room was inserted in the database.
func (c ChatRoom) CreateTime() time.Time {
	return c.createTime
}

// DetailLevel returns the detail level of the chat room (whatever that means).
func (c ChatRoom) DetailLevel() uint8 {
	return 0x02 // Pidgin 2.13.0 expects value 0x02
}

// Cookie returns the chat room unique identifier.
func (c ChatRoom) Cookie() string {
	// According to Pidgin, the chat cookie is a 3-part identifier. The third
	// segment is the chat name, which is shown explicitly in the Pidgin code.
	// We can assume that the first two parts were the exchange and instance
	// number. As of now, Pidgin is the only client that cares about the cookie
	// format, and it only cares about the chat name segment.
	return fmt.Sprintf("%d-%d-%s", c.exchange, c.InstanceNumber(), c.name)
}

// URL creates a URL that can be used to join a chat room.
func (c ChatRoom) URL() *url.URL {
	// macOS client v4.0.9 requires the `roomname` param to precede `exchange`
	// param. Create the path using string concatenation rather than url.Values
	// because url.Values sorts the params alphabetically.
	opaque := fmt.Sprintf("gochat?roomname=%s&exchange=%d", url.QueryEscape(c.name), c.exchange)
	return &url.URL{
		Scheme: "aim",
		Opaque: opaque,
	}
}

// TLVList returns a TLV list of chat room metadata.
func (c ChatRoom) TLVList() []wire.TLV {
	return []wire.TLV{
		// From protocols/oscar/family_chatnav.c in lib purple, these are the
		// room creation flags:
		// - 1 Evilable
		// - 2 Nav Only
		// - 4 Instancing Allowed
		// - 8 Occupant Peek Allowed
		// It's unclear what effect they actually have.
		wire.NewTLVBE(wire.ChatRoomTLVFlags, uint16(15)),
		wire.NewTLVBE(wire.ChatRoomTLVCreateTime, uint32(c.createTime.Unix())),
		wire.NewTLVBE(wire.ChatRoomTLVMaxMsgLen, uint16(1024)),
		wire.NewTLVBE(wire.ChatRoomTLVMaxOccupancy, uint16(100)),
		// From protocols/oscar/family_chatnav.c in lib purple, these are the
		// room creation permission values:
		// - 0  creation not allowed
		// - 1  room creation allowed
		// - 2  exchange creation allowed
		// It's unclear what effect they actually have.
		wire.NewTLVBE(wire.ChatRoomTLVNavCreatePerms, uint8(2)),
		wire.NewTLVBE(wire.ChatRoomTLVFullyQualifiedName, c.name),
		wire.NewTLVBE(wire.ChatRoomTLVRoomName, c.name),
		wire.NewTLVBE(wire.ChatRoomTLVMaxMsgVisLen, uint16(1024)),
	}
}
