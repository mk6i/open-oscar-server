package toc

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/server/oscarclient"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// tocConn holds the state of one TOC client connection: its connections to
// OSCAR services, the chat rooms it's in, its in-flight SNAC requests, and the
// TOC protocol version it speaks.
type tocConn struct {
	// bos is the connection to the BOS service.
	bos oscarclient.Conn
	// chats tracks the chat rooms the user has been invited to or joined.
	chats *ChatRegistry
	// cache matches SNAC replies to the requests that produced them.
	cache *oscarclient.SNACCache
	// ident is the user's screen name.
	ident state.IdentScreenName
	// isTOC2 is true for TOC2 clients.
	isTOC2 bool
	// supportsMsgEnc is true for TOC2 clients that signed on with toc2_login.
	supportsMsgEnc bool
	// toCh queues TOC responses for the client.
	toCh chan<- []string
	// goAsync runs f in the background alongside the connection's other
	// handlers, such as the message loop of each chat room the user joins.
	// f gets the connection's context, which is cancelled when the
	// connection ends. The connection waits for all of them to finish when it
	// closes, and an error from f ends the connection.
	goAsync func(f func(ctx context.Context) error)
	// clientAddr is the TOC client's address, which the OSCAR server sees as
	// the user's address.
	clientAddr net.Addr
	// limiter rate limits the commands that TOC handles without the OSCAR
	// server. The OSCAR server rate limits everything else.
	limiter *rate.Limiter
	// backlog holds BOS SNACs that arrived during signon, before RecvBOS
	// started.
	backlog []wire.SNACMessage
	// feedbag is the TOC2 user's buddy list.
	feedbag *state.FeedbagMirror
	// feedbagSendMu keeps feedbag changes and reloads in the order they're
	// sent.
	feedbagSendMu sync.Mutex
}

// newTOCConn creates a TOC connection for the signed-on user ident whose BOS
// connection is bos.
func newTOCConn(bos oscarclient.Conn, ident state.IdentScreenName, clientAddr net.Addr) *tocConn {
	return &tocConn{
		bos:        bos,
		chats:      NewChatRegistry(),
		cache:      oscarclient.NewSNACCache(),
		ident:      ident,
		clientAddr: clientAddr,
		limiter:    rate.NewLimiter(rate.Every(1500*time.Millisecond), 5),
		feedbag:    &state.FeedbagMirror{},
	}
}

// IdentScreenName returns the user's screen name.
func (c *tocConn) IdentScreenName() state.IdentScreenName {
	return c.ident
}

// IsTOC2 returns true when the client speaks TOC2, with or without encoded
// messaging.
func (c *tocConn) IsTOC2() bool {
	return c.isTOC2
}

// SupportsTOC2MsgEnc returns true when the client signed on with toc2_login,
// which supports encoded messaging.
func (c *tocConn) SupportsTOC2MsgEnc() bool {
	return c.supportsMsgEnc
}

// NewChatRegistry creates a new ChatRegistry instance.
func NewChatRegistry() *ChatRegistry {
	return &ChatRegistry{
		lookup: make(map[int]wire.ICBMRoomInfo),
		conns:  make(map[int]oscarclient.Conn),
	}
}

// ChatRegistry manages the chat rooms that a user is connected to during a TOC
// session. It maps chat room identifiers to room metadata and to the
// connection for each joined room.
//
// This struct provides thread-safe operations for adding, retrieving, and
// managing chat room metadata and associated connections.
type ChatRegistry struct {
	lookup map[int]wire.ICBMRoomInfo // Maps chat room IDs to their metadata.
	conns  map[int]oscarclient.Conn  // Tracks chat room connections by chat room ID.
	nextID int                       // Incremental identifier for newly added chat rooms.
	m      sync.RWMutex              // Synchronization primitive for concurrent access.
}

// Add registers metadata for a newly joined chat room and returns a unique
// identifier for it. If the room is already registered, it returns the existing ID.
func (c *ChatRegistry) Add(room wire.ICBMRoomInfo) int {
	c.m.Lock()
	defer c.m.Unlock()
	for chatID, r := range c.lookup {
		if r == room {
			return chatID
		}
	}
	id := c.nextID
	c.lookup[id] = room
	c.nextID++
	return id
}

// LookupRoom retrieves metadata for the chat room registered with chatID.
// It returns the room metadata and a boolean indicating whether the chat ID
// was found.
func (c *ChatRegistry) LookupRoom(chatID int) (wire.ICBMRoomInfo, bool) {
	c.m.RLock()
	defer c.m.RUnlock()
	room, found := c.lookup[chatID]
	return room, found
}

// RegisterConn associates a chat room connection with a chat ID. If a
// connection is already registered for the given chat ID, it will be
// overwritten.
func (c *ChatRegistry) RegisterConn(chatID int, conn oscarclient.Conn) {
	c.m.Lock()
	defer c.m.Unlock()
	c.conns[chatID] = conn
}

// RetrieveConn retrieves the chat room connection associated with the given
// chat ID. If no connection is registered for the chat ID, it returns nil.
func (c *ChatRegistry) RetrieveConn(chatID int) oscarclient.Conn {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.conns[chatID]
}

// RemoveConn removes a chat room connection.
func (c *ChatRegistry) RemoveConn(chatID int) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.conns, chatID)
}
