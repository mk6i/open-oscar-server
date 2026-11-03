package oscarclient

import (
	"maps"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// snacCacheTTL is how long a sent SNAC waits for a reply before it is dropped
// from the cache. Requests the server drops, such as rate-limited ones, never
// get a reply.
const snacCacheTTL = 60 * time.Second

// SNACCache tracks the SNACs a client sends to the OSCAR server by request
// ID, so that a reply can be matched to the request that produced it.
type SNACCache struct {
	mu      sync.Mutex
	lastID  uint32
	entries map[uint32]SentSNAC
	timeNow func() time.Time
}

// SentSNAC is a SNAC request awaiting a reply.
type SentSNAC struct {
	// Frame is the request's SNAC frame.
	Frame wire.SNACFrame
	// Data holds whatever the reply handler needs to know about the request.
	Data   any
	sentAt time.Time
}

// NewSNACCache creates an empty SNACCache.
func NewSNACCache() *SNACCache {
	return &SNACCache{
		entries: make(map[uint32]SentSNAC),
		timeNow: time.Now,
	}
}

// Add assigns the next request ID to frame and records the request along with
// data. Entries older than snacCacheTTL are swept out.
func (c *SNACCache) Add(frame *wire.SNACFrame, data any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.timeNow()
	for id, entry := range c.entries {
		if now.Sub(entry.sentAt) > snacCacheTTL {
			delete(c.entries, id)
		}
	}

	c.lastID++
	if c.lastID >= wire.ReqIDFromServer {
		c.lastID = 1
	}
	frame.RequestID = c.lastID
	c.entries[frame.RequestID] = SentSNAC{
		Frame:  *frame,
		Data:   data,
		sentAt: now,
	}
}

// Take removes and returns the request that reply answers. A reply only
// matches a request in the same food group, so that a relayed SNAC carrying
// another user's request ID is not mistaken for a reply.
func (c *SNACCache) Take(reply wire.SNACFrame) (SentSNAC, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[reply.RequestID]
	if !ok || entry.Frame.FoodGroup != reply.FoodGroup {
		return SentSNAC{}, false
	}
	delete(c.entries, reply.RequestID)
	return entry, true
}

// Peek returns the request that reply answers, without removing it. Like
// Take, it only matches a request in the same food group.
func (c *SNACCache) Peek(reply wire.SNACFrame) (SentSNAC, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[reply.RequestID]
	if !ok || entry.Frame.FoodGroup != reply.FoodGroup {
		return SentSNAC{}, false
	}
	return entry, true
}

// Remove drops the request with the given ID.
func (c *SNACCache) Remove(requestID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, requestID)
}

// Pending returns a copy of the requests awaiting a reply, by request ID.
func (c *SNACCache) Pending() map[uint32]SentSNAC {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.entries)
}
