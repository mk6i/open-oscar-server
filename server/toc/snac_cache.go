package toc

import (
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// snacCacheTTL is how long a sent SNAC waits for a reply before it is dropped
// from the cache. Requests the server drops, such as rate-limited ones, never
// get a reply.
const snacCacheTTL = 60 * time.Second

// snacCache tracks the SNACs a TOC connection sends to the OSCAR server by
// request ID, so that a reply can be matched to the request that produced it.
type snacCache struct {
	mu      sync.Mutex
	lastID  uint32
	entries map[uint32]sentSNAC
	timeNow func() time.Time
}

// sentSNAC is a SNAC request awaiting a reply.
type sentSNAC struct {
	// frame is the request's SNAC frame.
	frame wire.SNACFrame
	// data holds whatever the reply handler needs to know about the request.
	data   any
	sentAt time.Time
}

func newSNACCache() *snacCache {
	return &snacCache{
		entries: make(map[uint32]sentSNAC),
		timeNow: time.Now,
	}
}

// add assigns the next request ID to frame and records the request along with
// data. Entries older than snacCacheTTL are swept out.
func (c *snacCache) add(frame *wire.SNACFrame, data any) {
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
	c.entries[frame.RequestID] = sentSNAC{
		frame:  *frame,
		data:   data,
		sentAt: now,
	}
}

// take removes and returns the request that reply answers. A reply only
// matches a request in the same food group, so that a relayed SNAC carrying
// another user's request ID is not mistaken for a reply.
func (c *snacCache) take(reply wire.SNACFrame) (sentSNAC, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[reply.RequestID]
	if !ok || entry.frame.FoodGroup != reply.FoodGroup {
		return sentSNAC{}, false
	}
	delete(c.entries, reply.RequestID)
	return entry, true
}

// remove drops the request with the given ID.
func (c *snacCache) remove(requestID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, requestID)
}
