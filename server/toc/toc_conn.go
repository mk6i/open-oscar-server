package toc

import (
	"context"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// tocConn holds the state of one TOC client connection: its connections to
// OSCAR services, the chat rooms it's in, its in-flight SNAC requests, and the
// TOC protocol version it speaks.
type tocConn struct {
	// bos is the connection to the BOS service.
	bos oscarConn
	// chats tracks the chat rooms the user has been invited to or joined.
	chats *ChatRegistry
	// cache matches SNAC replies to the requests that produced them.
	cache *snacCache
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
	feedbag *feedbagMirror
}

// newTOCConn creates a TOC connection for the signed-on user ident whose BOS
// connection is bos.
func newTOCConn(bos oscarConn, ident state.IdentScreenName, clientAddr net.Addr) *tocConn {
	return &tocConn{
		bos:        bos,
		chats:      NewChatRegistry(),
		cache:      newSNACCache(),
		ident:      ident,
		clientAddr: clientAddr,
		limiter:    rate.NewLimiter(rate.Every(1500*time.Millisecond), 5),
		feedbag:    &feedbagMirror{},
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
		conns:  make(map[int]oscarConn),
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
	conns  map[int]oscarConn         // Tracks chat room connections by chat room ID.
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
func (c *ChatRegistry) RegisterConn(chatID int, conn oscarConn) {
	c.m.Lock()
	defer c.m.Unlock()
	c.conns[chatID] = conn
}

// RetrieveConn retrieves the chat room connection associated with the given
// chat ID. If no connection is registered for the chat ID, it returns nil.
func (c *ChatRegistry) RetrieveConn(chatID int) oscarConn {
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

// feedbagMirror is TOC's copy of the user's feedbag (server-side buddy list).
// It holds the feedbag as the server last confirmed it plus the changes TOC
// sent that the server hasn't confirmed yet. Commands work from the
// feedbag as it will be once those changes land, and only confirmed changes
// become part of the confirmed feedbag.
type feedbagMirror struct {
	// sendMu keeps changes and reloads in the order they're sent.
	sendMu sync.Mutex

	mu        sync.Mutex
	confirmed []wire.FeedbagItem
	pending   []feedbagChange
	lastSeq   uint64
}

// feedbagChange is a feedbag change sent to the server and not yet
// confirmed.
type feedbagChange struct {
	seq       uint64
	requestID uint32
	del       bool
	items     []wire.FeedbagItem
}

// snapshot returns the feedbag with all pending changes applied.
func (m *feedbagMirror) snapshot() []wire.FeedbagItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := append([]wire.FeedbagItem(nil), m.confirmed...)
	for _, change := range m.pending {
		items = applyFeedbagChange(items, change.del, change.items)
	}
	return cloneFeedbagItems(items)
}

// reset replaces the confirmed feedbag with items and forgets pending
// changes.
func (m *feedbagMirror) reset(items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.confirmed = cloneFeedbagItems(items)
	m.pending = nil
}

// sent records a change TOC is sending as request requestID. del is true
// when the change deletes items.
func (m *feedbagMirror) sent(requestID uint32, del bool, items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSeq++
	m.pending = append(m.pending, feedbagChange{
		seq:       m.lastSeq,
		requestID: requestID,
		del:       del,
		items:     cloneFeedbagItems(items),
	})
}

// confirm applies the items of change requestID that the server accepted,
// according to results, and forgets the change.
func (m *feedbagMirror) confirm(requestID uint32, results []uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.indexOf(requestID)
	if i < 0 {
		return
	}
	change := m.pending[i]
	var accepted []wire.FeedbagItem
	for j, item := range change.items {
		if j < len(results) && results[j] == 0 {
			accepted = append(accepted, item)
		}
	}
	m.confirmed = applyFeedbagChange(m.confirmed, change.del, accepted)
	m.pending = append(m.pending[:i], m.pending[i+1:]...)
}

// discard forgets change requestID, which the server rejected.
func (m *feedbagMirror) discard(requestID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i := m.indexOf(requestID); i >= 0 {
		m.pending = append(m.pending[:i], m.pending[i+1:]...)
	}
}

// hasPending returns true if any change is awaiting confirmation.
func (m *feedbagMirror) hasPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending) > 0
}

// mark returns a marker for the changes sent so far, for reload.
func (m *feedbagMirror) mark() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSeq
}

// reload replaces the confirmed feedbag with items, the server's feedbag as of
// a query sent after the changes up to marker. Those changes are forgotten,
// since the server either applied them or dropped them. Changes sent after the
// query stay pending.
func (m *feedbagMirror) reload(marker uint64, items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.confirmed = cloneFeedbagItems(items)
	var pending []feedbagChange
	for _, change := range m.pending {
		if change.seq > marker {
			pending = append(pending, change)
		}
	}
	m.pending = pending
}

// applyRemote applies a change made at another of the user's locations. del
// is true when the change deletes items.
func (m *feedbagMirror) applyRemote(del bool, items []wire.FeedbagItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.confirmed = applyFeedbagChange(m.confirmed, del, cloneFeedbagItems(items))
}

// groupNames returns the name of each group by group ID, with all pending
// changes applied.
func (m *feedbagMirror) groupNames() map[uint16]string {
	names := make(map[uint16]string)
	for _, item := range m.snapshot() {
		if item.ClassID == wire.FeedbagClassIdGroup {
			names[item.GroupID] = item.Name
		}
	}
	return names
}

func (m *feedbagMirror) indexOf(requestID uint32) int {
	for i, change := range m.pending {
		if change.requestID == requestID {
			return i
		}
	}
	return -1
}

// cloneFeedbagItems returns a copy of items that shares no TLV lists with
// them, since state.FeedbagList edits TLV lists in place.
func cloneFeedbagItems(items []wire.FeedbagItem) []wire.FeedbagItem {
	items = slices.Clone(items)
	for i := range items {
		items[i].TLVList = slices.Clone(items[i].TLVList)
	}
	return items
}

// applyFeedbagChange returns items with changed upserted, or deleted when del
// is true. Items match by group and item ID.
func applyFeedbagChange(items []wire.FeedbagItem, del bool, changed []wire.FeedbagItem) []wire.FeedbagItem {
	for _, item := range changed {
		i := slices.IndexFunc(items, func(existing wire.FeedbagItem) bool {
			return existing.GroupID == item.GroupID && existing.ItemID == item.ItemID
		})
		switch {
		case del && i >= 0:
			items = slices.Delete(items, i, i+1)
		case !del && i >= 0:
			items[i] = item
		case !del:
			items = append(items, item)
		}
	}
	return items
}
