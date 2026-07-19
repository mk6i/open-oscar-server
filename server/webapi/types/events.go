package types

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// EventType defines the type of WebAPI event.
type EventType string

const (
	EventTypeBuddyList    EventType = "buddylist"
	EventTypeConversation EventType = "conversation"
	EventTypeIM           EventType = "im"
	EventTypeOfflineIM    EventType = "offlineIM"
	EventTypePreference   EventType = "preference"
	EventTypePresence     EventType = "presence"
	EventTypeRateLimit    EventType = "rateLimit"
	EventTypeSentIM       EventType = "sentIM"
	EventTypeSessionEnded EventType = "sessionEnded"
	EventTypeStatus       EventType = "status"
	EventTypeTyping       EventType = "typing"
	EventTypePermitDeny   EventType = "permitDeny"
)

// Event represents an event to be delivered to a web client.
type Event struct {
	Type      EventType   `json:"type"`
	SeqNum    uint64      `json:"seqNum"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"eventData"`
}

// PresenceEvent represents a presence change event.
// Friendly repeats the viewer's alias for the user. The client's merge deletes any
// alias it already holds, so a presence update that omits it silently renames the
// buddy back to their screen name. See UserInfo.
type PresenceEvent struct {
	AimID      string `json:"aimId"`
	Friendly   string `json:"friendly,omitempty"`
	State      string `json:"state"` // "online", "offline", "away", "idle"
	StatusMsg  string `json:"statusMsg,omitempty"`
	AwayMsg    string `json:"awayMsg,omitempty"`
	IdleTime   int    `json:"idleTime,omitempty"`   // Minutes idle
	OnlineTime int64  `json:"onlineTime,omitempty"` // Unix timestamp
	UserType   string `json:"userType"`             // "aim", "icq", "admin"
	BuddyIcon  string `json:"buddyIcon,omitempty"`  // Absolute icon URL; empty preserves the client's current icon, the placeholder URL clears it
}

// IMEvent represents an instant message event.
type IMEvent struct {
	Source    UserInfo `json:"source"`
	Message   string   `json:"message"`
	MsgID     string   `json:"msgId,omitempty"`
	Timestamp float64  `json:"timestamp"` // float64 for AMF3 encoding
	AutoResp  bool     `json:"autoresponse,omitempty"`
}

// SentIMEvent represents a sent instant message event.
type SentIMEvent struct {
	Sender    UserInfo `json:"sender"` // Sender user info
	Dest      UserInfo `json:"dest"`   // Destination user info
	Message   string   `json:"message"`
	MsgID     string   `json:"msgId,omitempty"`
	Timestamp float64  `json:"timestamp"` // float64 for AMF3 encoding
	AutoResp  bool     `json:"autoResponse,omitempty"`
}

// UserInfo represents basic user information in events.
// AimID is the normalized screen name the client keys users by. DisplayID is the
// screen name as its owner formatted it. Friendly is the viewer's private alias for
// that user, and takes precedence over DisplayID when the client renders a name.
//
// The client merges every user map it receives onto the single user object it holds
// per aimId, and that merge deletes friendly before applying the map. An alias
// therefore has to be repeated on every user map, or it is lost.
type UserInfo struct {
	AimID      string  `json:"aimId"`
	DisplayID  string  `json:"displayId,omitempty"`
	Friendly   string  `json:"friendly,omitempty"`
	UserType   string  `json:"userType,omitempty"`
	State      string  `json:"state,omitempty"`
	OnlineTime float64 `json:"onlineTime,omitempty"` // float64 for AMF3 encoding
}

// TypingEvent represents a typing notification event.
type TypingEvent struct {
	AimID        string `json:"aimId"`
	TypingStatus string `json:"typingStatus"`
}

// EventQueue manages a queue of events for a WebAPI session.
type EventQueue struct {
	events    []Event
	seqNum    uint64
	maxSize   int
	mu        sync.RWMutex
	waitChan  chan struct{}
	closeChan chan struct{}
	closeOnce sync.Once
}

// isClosed reports whether Close has been called.
func (q *EventQueue) isClosed() bool {
	select {
	case <-q.closeChan:
		return true
	default:
		return false
	}
}

// NewEventQueue creates a new event queue with the specified maximum size.
func NewEventQueue(maxSize int) *EventQueue {
	return &EventQueue{
		events:    make([]Event, 0),
		maxSize:   maxSize,
		waitChan:  make(chan struct{}, 1),
		closeChan: make(chan struct{}),
	}
}

// Push adds an event to the queue.
func (q *EventQueue) Push(eventType EventType, data interface{}) {
	if q.isClosed() {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Increment sequence number atomically
	seqNum := atomic.AddUint64(&q.seqNum, 1)

	event := Event{
		Type:      eventType,
		SeqNum:    seqNum,
		Timestamp: time.Now().Unix(),
		Data:      data,
	}

	// Add event to queue
	q.events = append(q.events, event)

	// If queue exceeds max size, remove oldest events
	if len(q.events) > q.maxSize {
		// Keep only the most recent maxSize events
		q.events = q.events[len(q.events)-q.maxSize:]
	}

	// Signal any waiting fetchers
	select {
	case q.waitChan <- struct{}{}:
	default:
		// Channel already has a signal
	}
}

// Fetch retrieves events from the queue, optionally waiting for new events.
func (q *EventQueue) Fetch(ctx context.Context, lastSeqNum uint64, timeout time.Duration) ([]Event, error) {
	if q.isClosed() {
		return []Event{}, nil
	}

	// First, check if we have any events newer than lastSeqNum
	q.mu.RLock()
	events := q.getEventsAfter(lastSeqNum)
	q.mu.RUnlock()

	if len(events) > 0 {
		return events, nil
	}

	// No events available, wait for new ones or timeout
	timeoutChan := time.After(timeout)

	for {
		select {
		case <-q.closeChan:
			return []Event{}, nil

		case <-q.waitChan:
			// New events may be available
			q.mu.RLock()
			events = q.getEventsAfter(lastSeqNum)
			q.mu.RUnlock()

			if len(events) > 0 {
				return events, nil
			}
			// False alarm, keep waiting

		case <-timeoutChan:
			// Timeout reached, return empty array
			return []Event{}, nil

		case <-ctx.Done():
			// Context cancelled
			return nil, ctx.Err()
		}
	}
}

// getEventsAfter returns all events with sequence number greater than the specified value.
// Must be called with at least a read lock held.
func (q *EventQueue) getEventsAfter(seqNum uint64) []Event {
	var result []Event

	for _, event := range q.events {
		if event.SeqNum > seqNum {
			result = append(result, event)
		}
	}

	return result
}

// GetAllEvents returns all events in the queue (for debugging).
func (q *EventQueue) GetAllEvents() []Event {
	q.mu.RLock()
	defer q.mu.RUnlock()

	result := make([]Event, len(q.events))
	copy(result, q.events)
	return result
}

// Close closes the event queue, unblocking any waiting fetchers. Safe to call
// more than once.
func (q *EventQueue) Close() {
	q.closeOnce.Do(func() {
		close(q.closeChan)
	})
}
