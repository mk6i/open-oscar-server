package oscarclient

import (
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// requestTTL is how long a sent SNAC waits for a reply before it is no
// longer tracked. Requests the server drops, such as rate-limited ones, never
// get a reply.
const requestTTL = 60 * time.Second

// RequestTracker tracks the SNACs a client sends to the OSCAR server by
// request ID, so that a reply can be matched to the request that produced it.
type RequestTracker struct {
	mu      sync.Mutex
	lastID  uint32
	entries map[uint32]pendingRequest
	timeNow func() time.Time
}

// pendingRequest is a SNAC request awaiting a reply.
type pendingRequest struct {
	// frame is the request's SNAC frame.
	frame wire.SNACFrame
	// data holds whatever the reply handler needs to know about the request.
	data   any
	sentAt time.Time
}

// NewRequestTracker creates a RequestTracker with no pending requests.
func NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		entries: make(map[uint32]pendingRequest),
		timeNow: time.Now,
	}
}

// Track records the request frame along with data under the next request ID,
// and returns frame with that request ID set. Entries older than requestTTL
// are swept out.
func (c *RequestTracker) Track(frame wire.SNACFrame, data any) wire.SNACFrame {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.timeNow()
	for id, entry := range c.entries {
		if now.Sub(entry.sentAt) > requestTTL {
			delete(c.entries, id)
		}
	}

	c.lastID++
	if c.lastID >= wire.ReqIDFromServer {
		c.lastID = 1
	}
	frame.RequestID = c.lastID
	c.entries[frame.RequestID] = pendingRequest{
		frame:  frame,
		data:   data,
		sentAt: now,
	}
	return frame
}

// Take removes the request that reply answers and returns the frame and data
// it was tracked with. The request ID alone identifies the request: the OSCAR
// server sends a client only its own request IDs, 0, or wire.ReqIDFromServer,
// and Track hands out neither of the latter two.
func (c *RequestTracker) Take(reply wire.SNACFrame) (frame wire.SNACFrame, data any, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[reply.RequestID]
	if !ok {
		return wire.SNACFrame{}, nil, false
	}
	delete(c.entries, reply.RequestID)
	return entry.frame, entry.data, true
}

// Remove drops the request with the given ID.
func (c *RequestTracker) Remove(requestID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, requestID)
}
