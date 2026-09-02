package webapi

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
	EventTypeMyInfo       EventType = "myInfo"
	EventTypeOfflineIM    EventType = "offlineIM"
	EventTypePreference   EventType = "preference"
	EventTypePresence     EventType = "presence"
	EventTypeRateLimit    EventType = "rateLimit"
	EventTypeSentIM       EventType = "sentIM"
	EventTypeSessionEnded EventType = "sessionEnded"
	EventTypeTyping       EventType = "typing"
	EventTypePermitDeny   EventType = "permitDeny"
	EventTypeClientError  EventType = "clientError"
)

// Event represents an event to be delivered to a web client.
type Event struct {
	Type      EventType   `json:"type" xml:"type"`
	SeqNum    uint64      `json:"seqNum" xml:"seqNum"`
	Timestamp int64       `json:"timestamp" xml:"timestamp"`
	Data      interface{} `json:"eventData" xml:"eventData"`
}

// PresenceEvent represents a presence change event.
// Friendly repeats the viewer's alias for the user. The client's merge deletes any
// alias it already holds, so a presence update that omits it silently renames the
// buddy back to their screen name. See UserInfo.
type PresenceEvent struct {
	AimID      string `json:"aimId" xml:"aimId"`
	Friendly   string `json:"friendly,omitempty" xml:"friendly,omitempty"`
	State      string `json:"state" xml:"state"` // "online", "offline", "away", "idle"
	StatusMsg  string `json:"statusMsg,omitempty" xml:"statusMsg,omitempty"`
	AwayMsg    string `json:"awayMsg,omitempty" xml:"awayMsg,omitempty"`
	IdleTime   int    `json:"idleTime,omitempty" xml:"idleTime,omitempty"`     // Minutes idle
	OnlineTime int64  `json:"onlineTime,omitempty" xml:"onlineTime,omitempty"` // Unix timestamp
	UserType   string `json:"userType" xml:"userType"`                         // "aim", "icq", "admin"
	BuddyIcon  string `json:"buddyIcon,omitempty" xml:"buddyIcon,omitempty"`   // Absolute icon URL; empty preserves the client's current icon, the placeholder URL clears it
}

// imfPlainText is the message-format tag put on delivered IMs; bodies are always
// plain text.
const imfPlainText = "plain"

// IMEvent represents an instant message event.
type IMEvent struct {
	Source    UserInfo `json:"source" xml:"source"`
	Message   string   `json:"message" xml:"message"`
	MsgID     string   `json:"msgId,omitempty" xml:"msgId,omitempty"`
	Timestamp int64    `json:"timestamp" xml:"timestamp"`
	// Imf is read strictly and then ignored, so its only job is to exist.
	Imf string `json:"imf" xml:"imf"`
	// AutoResp is always sent, false included: clients read it unconditionally.
	AutoResp bool `json:"autoresponse" xml:"autoresponse" amf3:"autoresponse"`
}

// OfflineIMEvent represents a message that was stored while the user was signed
// off and is replayed when they next start a session.
//
// The client models this separately from IMEvent: it reads the sender from a bare
// aimId rather than a source user object, and resolves the display name from the
// buddy list it already holds. Timestamp is when the sender sent the message, not
// when it was delivered.
type OfflineIMEvent struct {
	AimID string `json:"aimId" xml:"aimId"`
	// Friendly is the sender's display name. The client resolves an offline
	// sender from this pair alone, so without it the message renders under the
	// normalized aimId.
	Friendly  string `json:"friendly,omitempty" xml:"friendly,omitempty"`
	Message   string `json:"message" xml:"message"`
	MsgID     string `json:"msgId,omitempty" xml:"msgId,omitempty"`
	Timestamp int64  `json:"timestamp" xml:"timestamp"`
	// Imf and AutoResp must be present, as on IMEvent.
	Imf      string `json:"imf" xml:"imf"`
	AutoResp bool   `json:"autoresponse" xml:"autoresponse" amf3:"autoresponse"`
}

// SentIMEvent represents a sent instant message event.
// The AMF3 spellings differ from the documented JSON ones: the client reads the
// sender from "source" and the flag from "autoresponse", while the spec names
// them "sender" and "autoResponse".
type SentIMEvent struct {
	Sender    UserInfo `json:"sender" xml:"sender" amf3:"source"`
	Dest      UserInfo `json:"dest" xml:"dest"`
	Message   string   `json:"message" xml:"message"`
	MsgID     string   `json:"msgId,omitempty" xml:"msgId,omitempty"`
	Timestamp int64    `json:"timestamp" xml:"timestamp"`
	AutoResp  bool     `json:"autoResponse,omitempty" xml:"autoResponse,omitempty" amf3:"autoresponse"`
}

// ClientErrorEvent tells a sender that the recipient rejected a message the server
// had already delivered. im/sendIM answers synchronously when the ICBM service
// itself refuses a send; a rejection from the recipient's own client arrives here
// instead. Channel "data" names the rendezvous channel.
type ClientErrorEvent struct {
	Source UserInfo `json:"source" xml:"source"`
	// Cookie names the failed message by the msgId im/sendIM returned. It is empty
	// when another instance of the account sent the message.
	Cookie  string `json:"cookie" xml:"cookie"`
	Channel string `json:"channel" xml:"channel"`
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
	AimID      string `json:"aimId" xml:"aimId"`
	DisplayID  string `json:"displayId,omitempty" xml:"displayId,omitempty"`
	Friendly   string `json:"friendly,omitempty" xml:"friendly,omitempty"`
	UserType   string `json:"userType,omitempty" xml:"userType,omitempty"`
	State      string `json:"state,omitempty" xml:"state,omitempty"`
	OnlineTime int64  `json:"onlineTime,omitempty" xml:"onlineTime,omitempty"`
}

// TypingEvent represents a typing notification event.
type TypingEvent struct {
	AimID        string `json:"aimId" xml:"aimId"`
	TypingStatus string `json:"typingStatus" xml:"typingStatus"`
}

// RateLimitEvent tells the client that its rate limit status changed.
//
// The client reads classes[0] only: it takes the status string and feeds it
// straight into a switch on "clear" | "warn" | "limit" | "disconnect" to render
// the in-conversation alert (e.g. "You have been rate limited. Wait for a few
// moments until you can chat again."). The "clear" alert is only shown if the
// client's last recorded status was "limit", so this event must be pushed on
// status transitions rather than on every rate-limited request.
type RateLimitEvent struct {
	Classes []RateLimitClass `json:"classes" xml:"classes>class"`
}

// RateLimitClass is the per-rate-class state carried by a RateLimitEvent.
type RateLimitClass struct {
	ID     int    `json:"id" xml:"id"`
	Status string `json:"status" xml:"status"` // "clear", "warn", "limit", or "disconnect"
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

// ConversationData is a conversation event payload: an operation and the
// conversations it applies to.
type ConversationData struct {
	Operation     string                  `json:"operation" xml:"operation"`
	Conversations []ConversationEntryData `json:"conversations" xml:"conversations>conversation"`
}

// ConversationEntryData is one conversation in the client's list.
type ConversationEntryData struct {
	AimID string `json:"aimId" xml:"aimId"`
	// Active is always sent, zero included, because the client reads it
	// unconditionally.
	Active      int `json:"active" xml:"active"`
	UnreadCount int `json:"unreadCount" xml:"unreadCount"`
	// DisplayID is omitted when empty rather than sent blank: the client falls
	// back to the name it already has for aimID, whereas any value present here
	// replaces it.
	DisplayID string  `json:"displayId,omitempty" xml:"displayId,omitempty"`
	LastIM    *LastIM `json:"lastIM,omitempty" xml:"lastIM,omitempty"`
}

// LastIM is the most recent message in a conversation.
type LastIM struct {
	Message   string `json:"message" xml:"message"`
	MsgID     string `json:"msgId" xml:"msgId"`
	Sender    string `json:"sender" xml:"sender"`
	Sent      bool   `json:"sent" xml:"sent"`
	Timestamp int64  `json:"timestamp" xml:"timestamp"`
}

// ConversationEventData builds a conversation fetchEvents payload.
func ConversationEventData(operation string, conversations []ConversationEntryData) *ConversationData {
	if conversations == nil {
		conversations = []ConversationEntryData{}
	}
	return &ConversationData{
		Operation:     operation,
		Conversations: conversations,
	}
}

// ConversationEntry builds one conversation object for the Web AIM client.
func ConversationEntry(aimID, displayID, message, msgID, sender string, sent bool, unread int) ConversationEntryData {
	entry := ConversationEntryData{
		AimID:       aimID,
		Active:      0,
		UnreadCount: unread,
		DisplayID:   displayID,
	}
	if message != "" {
		entry.LastIM = &LastIM{
			Message:   message,
			MsgID:     msgID,
			Sender:    sender,
			Sent:      sent,
			Timestamp: time.Now().Unix(),
		}
	}
	return entry
}
