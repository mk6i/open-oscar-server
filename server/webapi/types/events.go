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
	EventTypeImserv       EventType = "imserv"
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

// RoomIMEvent represents a group-chat (imserv) room line delivered as an `im`
// event. The web client keys the conversation by Imserv (the room id) via
// Source.AimID, but reads the individual speaker and text from
// SpecialData.ImFromImserv — see the client's qv/Fg/kl parsers. SpecialIM must be
// "imservMsg" for the client to treat the line as a room message.
type RoomIMEvent struct {
	Source      UserInfo        `json:"source"`
	Imserv      string          `json:"imserv"`
	SpecialIM   string          `json:"specialIM"`
	SpecialData RoomSpecialData `json:"specialData"`
	Message     string          `json:"message"`
	MsgID       string          `json:"msgId,omitempty"`
	Timestamp   float64         `json:"timestamp"` // float64 for AMF3 encoding
}

// RoomSpecialData carries the imserv-specific payload of a RoomIMEvent.
type RoomSpecialData struct {
	ImFromImserv RoomImFrom `json:"imFromImserv"`
}

// RoomInviteEvent represents a group-chat invitation, delivered (like a room
// line) as an `im` event. The presence of SpecialData.Invitation is what flags
// the event as an invite to the client (predicate `no()`); Imserv is the room id
// the client passes verbatim to imserv/join to accept.
type RoomInviteEvent struct {
	Source      UserInfo          `json:"source"`
	Imserv      string            `json:"imserv"`
	Message     string            `json:"message,omitempty"`
	MsgID       string            `json:"msgId,omitempty"`
	Timestamp   float64           `json:"timestamp"` // float64 for AMF3 encoding
	SpecialData RoomInviteSpecial `json:"specialData"`
}

// RoomInviteSpecial wraps the invitation object.
type RoomInviteSpecial struct {
	Invitation RoomInvitation `json:"invitation"`
}

// RoomInvitation identifies who invited the user and to which room. From is the
// inviter's screen name (the client renders "<From> has invited you…");
// GroupName is the room's friendly name.
type RoomInvitation struct {
	From      string `json:"from"`
	GroupName string `json:"groupName"`
}

// RoomImFrom identifies the speaker of a room line. The client prefers OrigSender
// and falls back to Sender; both are set to the speaker's aimId. Text is the line
// text (the client renders this in preference to the top-level Message).
type RoomImFrom struct {
	OrigSender string `json:"origSender"`
	Sender     string `json:"sender"`
	Text       string `json:"text"`
}

// ImservEvent carries live group-chat activity (member join/leave) as its own
// `imserv` event type. The client (parser `rB`) reads RecentActivities and, per
// room, applies each activity to the roster (`fC`). See RoomActivity.
type ImservEvent struct {
	RecentActivities []ImservRoomActivity `json:"recentActivities"`
}

// ImservRoomActivity groups a room's activity records under its room id.
type ImservRoomActivity struct {
	Imserv     string           `json:"imserv"`
	Activities []ImservActivity `json:"activities"`
}

// ImservActivity is a single room activity record. Action is the discriminator
// ("memberJoin" / "memberLeft"); the client takes the affected member from
// Member1 for both. Member2 mirrors Member1 for a self join/leave. The friendly
// name is optional and falls back to the screen name client-side.
type ImservActivity struct {
	Action              string  `json:"action"`
	Member1             string  `json:"member1"`
	Member2             string  `json:"member2"`
	Member1FriendlyName string  `json:"member1FriendlyName,omitempty"`
	Timestamp           float64 `json:"timestamp"` // float64 for AMF3 encoding
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
