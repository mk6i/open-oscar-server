package state

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ChatRoomType represents the type of chat room
type ChatRoomType string

const (
	ChatRoomTypeUserCreated ChatRoomType = "userCreated"
)

// ChatEventType represents the type of chat event
type ChatEventType string

const (
	ChatEventUserInRoom  ChatEventType = "userInRoom"
	ChatEventUserEntered ChatEventType = "userEntered"
	ChatEventUserLeft    ChatEventType = "userLeft"
	ChatEventMessage     ChatEventType = "message"
	ChatEventTyping      ChatEventType = "typing"
	ChatEventClosed      ChatEventType = "closed"
)

// WebAPIChatRoom represents a chat room for Web API
type WebAPIChatRoom struct {
	RoomID            string       `json:"roomId"`
	RoomName          string       `json:"roomName"`
	Description       string       `json:"description,omitempty"`
	RoomType          ChatRoomType `json:"roomType"`
	CategoryID        string       `json:"categoryId,omitempty"`
	CreatorScreenName string       `json:"-"` // Internal only
	CreatedAt         int64        `json:"-"`
	ClosedAt          *int64       `json:"-"`
	MaxParticipants   int          `json:"-"`
	InstanceID        int          `json:"instanceId"`
}

// ChatSession represents a user's session in a chat room
type ChatSession struct {
	ChatSID    string
	AIMSid     string
	RoomID     string
	ScreenName string
	InstanceID int
	JoinedAt   int64
	LeftAt     *int64
}

// ChatMessage represents a message sent in a chat room
type ChatMessage struct {
	ID            int64
	RoomID        string
	ScreenName    string
	Message       string
	WhisperTarget string
	Timestamp     int64
}

// ChatParticipant represents a participant in a chat room
type ChatParticipant struct {
	RoomID          string
	ScreenName      string
	ChatSID         string
	JoinedAt        int64
	TypingStatus    string
	TypingUpdatedAt *int64
}

// ChatEventData represents data for a chat event
type ChatEventData struct {
	ChatSID   string        `json:"chatsid"`
	EventType ChatEventType `json:"eventType"`
	EventData interface{}   `json:"eventData"`
}

// ChatMessageEventData represents chat message event data
type ChatMessageEventData struct {
	ScreenName    string `json:"screenName"`
	Message       string `json:"message"`
	Timestamp     int64  `json:"timestamp"`
	WhisperTarget string `json:"whisperTarget,omitempty"`
}

// ChatUserEventData represents user join/leave event data
type ChatUserEventData struct {
	ScreenName string `json:"screenName"`
	Timestamp  int64  `json:"timestamp"`
}

// ChatTypingEventData represents typing status event data
type ChatTypingEventData struct {
	ScreenName   string `json:"screenName"`
	TypingStatus string `json:"typingStatus"`
}

// ChatParticipantList represents a list of participants in the room
type ChatParticipantList struct {
	Participants []string `json:"participants"`
}

// WebAPIChatManager manages Web API chat rooms
type WebAPIChatManager struct {
	store    *SQLiteUserStore
	logger   *slog.Logger
	sessions *WebAPISessionManager
	mu       sync.RWMutex
	// In-memory cache for active rooms
	activeRooms map[string]*WebAPIChatRoom
	// Track typing timeouts
	typingTimers map[string]*time.Timer
}

// NewWebAPIChatManager creates a new WebAPIChatManager
func (s *SQLiteUserStore) NewWebAPIChatManager(logger *slog.Logger, sessions *WebAPISessionManager) *WebAPIChatManager {
	return &WebAPIChatManager{
		store:        s,
		logger:       logger,
		sessions:     sessions,
		activeRooms:  make(map[string]*WebAPIChatRoom),
		typingTimers: make(map[string]*time.Timer),
	}
}

// CreateAndJoinChat creates a new chat room or joins an existing one
func (m *WebAPIChatManager) CreateAndJoinChat(ctx context.Context, aimsid, roomID, roomName, screenName string) (*ChatSession, *WebAPIChatRoom, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var room *WebAPIChatRoom
	var err error

	// Determine which identifier to use
	if roomID != "" {
		room, err = m.getRoomByID(ctx, roomID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get room by ID: %w", err)
		}
	} else if roomName != "" {
		room, err = m.getRoomByName(ctx, roomName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("failed to get room by name: %w", err)
		}
		// If room doesn't exist, create it
		if room == nil {
			room, err = m.createRoom(ctx, roomName, screenName)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create room: %w", err)
			}
		}
	} else {
		return nil, nil, errors.New("either roomId or roomName must be provided")
	}

	// Check if user is already in the room
	existingSession, _ := m.getUserSessionInRoom(ctx, aimsid, room.RoomID)
	if existingSession != nil {
		return existingSession, room, nil
	}

	// Check room capacity
	count, err := m.getParticipantCount(ctx, room.RoomID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get participant count: %w", err)
	}
	if count >= room.MaxParticipants {
		return nil, nil, errors.New("room is at maximum capacity")
	}

	// Create chat session
	session := &ChatSession{
		ChatSID:    m.generateChatSID(),
		AIMSid:     aimsid,
		RoomID:     room.RoomID,
		ScreenName: screenName,
		InstanceID: room.InstanceID,
		JoinedAt:   time.Now().Unix(),
	}

	// Insert session into database
	_, err = m.store.db.ExecContext(ctx, `
		INSERT INTO web_chat_sessions (chat_sid, aimsid, room_id, screen_name, instance_id, joined_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		session.ChatSID, session.AIMSid, session.RoomID, session.ScreenName, session.InstanceID, session.JoinedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create chat session: %w", err)
	}

	// Add participant to room
	_, err = m.store.db.ExecContext(ctx, `
		INSERT INTO web_chat_participants (room_id, screen_name, chat_sid, joined_at, typing_status)
		VALUES (?, ?, ?, ?, 'none')`,
		room.RoomID, screenName, session.ChatSID, session.JoinedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to add participant: %w", err)
	}

	// Broadcast user joined event
	// Note: Broadcasting doesn't need context as it's fire-and-forget
	m.broadcastChatEvent(room.RoomID, ChatEventData{
		ChatSID:   session.ChatSID,
		EventType: ChatEventUserEntered,
		EventData: ChatUserEventData{
			ScreenName: screenName,
			Timestamp:  session.JoinedAt,
		},
	})

	// Send current participant list to the new user
	participants, _ := m.getParticipants(ctx, room.RoomID)
	m.sendChatEventToUser(aimsid, ChatEventData{
		ChatSID:   session.ChatSID,
		EventType: ChatEventUserInRoom,
		EventData: ChatParticipantList{
			Participants: participants,
		},
	})

	return session, room, nil
}

// SendMessage sends a message to a chat room
func (m *WebAPIChatManager) SendMessage(ctx context.Context, chatsid, message, whisperTarget string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get session
	session, err := m.getSessionByChatSID(ctx, chatsid)
	if err != nil {
		return fmt.Errorf("invalid chat session: %w", err)
	}

	// Verify user is still in room
	if session.LeftAt != nil {
		return errors.New("user has left the chat room")
	}

	// Store message in database
	timestamp := time.Now().Unix()
	_, err = m.store.db.ExecContext(ctx, `
		INSERT INTO web_chat_messages (room_id, screen_name, message, whisper_target, timestamp)
		VALUES (?, ?, ?, ?, ?)`,
		session.RoomID, session.ScreenName, message, whisperTarget, timestamp)
	if err != nil {
		return fmt.Errorf("failed to store message: %w", err)
	}

	// Broadcast message event
	eventData := ChatMessageEventData{
		ScreenName:    session.ScreenName,
		Message:       message,
		Timestamp:     timestamp,
		WhisperTarget: whisperTarget,
	}

	if whisperTarget != "" {
		// For whispers, only send to sender and target
		m.sendChatEventToUser(session.AIMSid, ChatEventData{
			ChatSID:   chatsid,
			EventType: ChatEventMessage,
			EventData: eventData,
		})
		// Find target's session and send to them
		targetSession, _ := m.getUserSessionInRoomByScreenName(ctx, session.RoomID, whisperTarget)
		if targetSession != nil {
			m.sendChatEventToUser(targetSession.AIMSid, ChatEventData{
				ChatSID:   targetSession.ChatSID,
				EventType: ChatEventMessage,
				EventData: eventData,
			})
		}
	} else {
		// Broadcast to all participants
		m.broadcastChatEvent(session.RoomID, ChatEventData{
			ChatSID:   chatsid,
			EventType: ChatEventMessage,
			EventData: eventData,
		})
	}

	return nil
}

// SetTyping sets the typing status for a user in a chat room
func (m *WebAPIChatManager) SetTyping(ctx context.Context, chatsid, typingStatus string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get session
	session, err := m.getSessionByChatSID(ctx, chatsid)
	if err != nil {
		return fmt.Errorf("invalid chat session: %w", err)
	}

	// Verify user is still in room
	if session.LeftAt != nil {
		return errors.New("user has left the chat room")
	}

	// Update typing status
	now := time.Now().Unix()
	_, err = m.store.db.ExecContext(ctx, `
		UPDATE web_chat_participants 
		SET typing_status = ?, typing_updated_at = ?
		WHERE room_id = ? AND screen_name = ?`,
		typingStatus, now, session.RoomID, session.ScreenName)
	if err != nil {
		return fmt.Errorf("failed to update typing status: %w", err)
	}

	// Cancel existing typing timer for this user
	timerKey := fmt.Sprintf("%s:%s", session.RoomID, session.ScreenName)
	if timer, exists := m.typingTimers[timerKey]; exists {
		timer.Stop()
		delete(m.typingTimers, timerKey)
	}

	// If status is "typing" or "typed", set a timer to reset it
	if typingStatus == "typing" || typingStatus == "typed" {
		timer := time.AfterFunc(10*time.Second, func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			// Reset typing status to none
			// Using background context here since this is an async timer callback
			// and the original context may have expired
			if _, err := m.store.db.ExecContext(context.Background(), `
				UPDATE web_chat_participants 
				SET typing_status = 'none', typing_updated_at = ?
				WHERE room_id = ? AND screen_name = ?`,
				time.Now().Unix(), session.RoomID, session.ScreenName); err != nil {
				m.logger.Error("failed to reset typing status", "error", err)
			}
			// Broadcast the reset
			m.broadcastChatEvent(session.RoomID, ChatEventData{
				ChatSID:   chatsid,
				EventType: ChatEventTyping,
				EventData: ChatTypingEventData{
					ScreenName:   session.ScreenName,
					TypingStatus: "none",
				},
			})
			delete(m.typingTimers, timerKey)
		})
		m.typingTimers[timerKey] = timer
	}

	// Broadcast typing event
	m.broadcastChatEvent(session.RoomID, ChatEventData{
		ChatSID:   chatsid,
		EventType: ChatEventTyping,
		EventData: ChatTypingEventData{
			ScreenName:   session.ScreenName,
			TypingStatus: typingStatus,
		},
	})

	return nil
}

// LeaveChat removes a user from a chat room
func (m *WebAPIChatManager) LeaveChat(ctx context.Context, chatsid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get session
	session, err := m.getSessionByChatSID(ctx, chatsid)
	if err != nil {
		return fmt.Errorf("invalid chat session: %w", err)
	}

	// Mark session as left
	now := time.Now().Unix()
	_, err = m.store.db.ExecContext(ctx, `
		UPDATE web_chat_sessions 
		SET left_at = ?
		WHERE chat_sid = ?`,
		now, chatsid)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Remove from participants
	_, err = m.store.db.ExecContext(ctx, `
		DELETE FROM web_chat_participants
		WHERE room_id = ? AND screen_name = ?`,
		session.RoomID, session.ScreenName)
	if err != nil {
		return fmt.Errorf("failed to remove participant: %w", err)
	}

	// Cancel any typing timer
	timerKey := fmt.Sprintf("%s:%s", session.RoomID, session.ScreenName)
	if timer, exists := m.typingTimers[timerKey]; exists {
		timer.Stop()
		delete(m.typingTimers, timerKey)
	}

	// Broadcast user left event
	// Note: Broadcasting doesn't need context as it's fire-and-forget
	m.broadcastChatEvent(session.RoomID, ChatEventData{
		ChatSID:   chatsid,
		EventType: ChatEventUserLeft,
		EventData: ChatUserEventData{
			ScreenName: session.ScreenName,
			Timestamp:  now,
		},
	})

	// Check if room should be closed (no participants left)
	count, _ := m.getParticipantCount(ctx, session.RoomID)
	if count == 0 {
		m.closeRoom(ctx, session.RoomID)
	}

	return nil
}

// Helper methods

func (m *WebAPIChatManager) getRoomByID(ctx context.Context, roomID string) (*WebAPIChatRoom, error) {
	var room WebAPIChatRoom
	err := m.store.db.QueryRowContext(ctx, `
		SELECT room_id, room_name, description, room_type, category_id, 
		       creator_screen_name, created_at, closed_at, max_participants
		FROM web_chat_rooms
		WHERE room_id = ? AND closed_at IS NULL`,
		roomID).Scan(
		&room.RoomID, &room.RoomName, &room.Description, &room.RoomType,
		&room.CategoryID, &room.CreatorScreenName, &room.CreatedAt,
		&room.ClosedAt, &room.MaxParticipants)
	if err != nil {
		return nil, err
	}
	room.InstanceID = m.generateInstanceID()
	return &room, nil
}

func (m *WebAPIChatManager) getRoomByName(ctx context.Context, roomName string) (*WebAPIChatRoom, error) {
	var room WebAPIChatRoom
	err := m.store.db.QueryRowContext(ctx, `
		SELECT room_id, room_name, description, room_type, category_id, 
		       creator_screen_name, created_at, closed_at, max_participants
		FROM web_chat_rooms
		WHERE room_name = ? AND closed_at IS NULL`,
		roomName).Scan(
		&room.RoomID, &room.RoomName, &room.Description, &room.RoomType,
		&room.CategoryID, &room.CreatorScreenName, &room.CreatedAt,
		&room.ClosedAt, &room.MaxParticipants)
	if err != nil {
		return nil, err
	}
	room.InstanceID = m.generateInstanceID()
	return &room, nil
}

func (m *WebAPIChatManager) createRoom(ctx context.Context, roomName, creatorScreenName string) (*WebAPIChatRoom, error) {
	room := &WebAPIChatRoom{
		RoomID:            m.generateRoomID(),
		RoomName:          roomName,
		Description:       fmt.Sprintf("Chat room created by %s", creatorScreenName),
		RoomType:          ChatRoomTypeUserCreated,
		CreatorScreenName: creatorScreenName,
		CreatedAt:         time.Now().Unix(),
		MaxParticipants:   100,
		InstanceID:        m.generateInstanceID(),
	}

	_, err := m.store.db.ExecContext(ctx, `
		INSERT INTO web_chat_rooms (room_id, room_name, description, room_type, 
		                            category_id, creator_screen_name, created_at, max_participants)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		room.RoomID, room.RoomName, room.Description, room.RoomType,
		room.CategoryID, room.CreatorScreenName, room.CreatedAt, room.MaxParticipants)
	if err != nil {
		return nil, err
	}

	// Cache the room
	m.activeRooms[room.RoomID] = room

	return room, nil
}

func (m *WebAPIChatManager) getSessionByChatSID(ctx context.Context, chatsid string) (*ChatSession, error) {
	var session ChatSession
	err := m.store.db.QueryRowContext(ctx, `
		SELECT chat_sid, aimsid, room_id, screen_name, instance_id, joined_at, left_at
		FROM web_chat_sessions
		WHERE chat_sid = ?`,
		chatsid).Scan(
		&session.ChatSID, &session.AIMSid, &session.RoomID,
		&session.ScreenName, &session.InstanceID, &session.JoinedAt, &session.LeftAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (m *WebAPIChatManager) getUserSessionInRoom(ctx context.Context, aimsid, roomID string) (*ChatSession, error) {
	var session ChatSession
	err := m.store.db.QueryRowContext(ctx, `
		SELECT chat_sid, aimsid, room_id, screen_name, instance_id, joined_at, left_at
		FROM web_chat_sessions
		WHERE aimsid = ? AND room_id = ? AND left_at IS NULL`,
		aimsid, roomID).Scan(
		&session.ChatSID, &session.AIMSid, &session.RoomID,
		&session.ScreenName, &session.InstanceID, &session.JoinedAt, &session.LeftAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (m *WebAPIChatManager) getUserSessionInRoomByScreenName(ctx context.Context, roomID, screenName string) (*ChatSession, error) {
	var session ChatSession
	err := m.store.db.QueryRowContext(ctx, `
		SELECT chat_sid, aimsid, room_id, screen_name, instance_id, joined_at, left_at
		FROM web_chat_sessions
		WHERE room_id = ? AND screen_name = ? AND left_at IS NULL`,
		roomID, screenName).Scan(
		&session.ChatSID, &session.AIMSid, &session.RoomID,
		&session.ScreenName, &session.InstanceID, &session.JoinedAt, &session.LeftAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (m *WebAPIChatManager) getParticipantCount(ctx context.Context, roomID string) (int, error) {
	var count int
	err := m.store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM web_chat_participants WHERE room_id = ?`,
		roomID).Scan(&count)
	return count, err
}

func (m *WebAPIChatManager) getParticipants(ctx context.Context, roomID string) ([]string, error) {
	rows, err := m.store.db.QueryContext(ctx, `
		SELECT screen_name FROM web_chat_participants WHERE room_id = ?`,
		roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var participants []string
	for rows.Next() {
		var screenName string
		if err := rows.Scan(&screenName); err != nil {
			continue
		}
		participants = append(participants, screenName)
	}
	return participants, nil
}

func (m *WebAPIChatManager) closeRoom(ctx context.Context, roomID string) {
	now := time.Now().Unix()
	if _, err := m.store.db.ExecContext(ctx, `
		UPDATE web_chat_rooms SET closed_at = ? WHERE room_id = ?`,
		now, roomID); err != nil {
		m.logger.Error("failed to close chat room", "roomID", roomID, "error", err)
	}

	// Remove from cache
	delete(m.activeRooms, roomID)

	// Broadcast room closed event
	// Note: Broadcasting doesn't need context as it's fire-and-forget
	m.broadcastChatEvent(roomID, ChatEventData{
		EventType: ChatEventClosed,
	})
}

func (m *WebAPIChatManager) broadcastChatEvent(roomID string, event ChatEventData) {
	// Get all active sessions in the room
	rows, err := m.store.db.Query(`
		SELECT aimsid, chat_sid FROM web_chat_sessions 
		WHERE room_id = ? AND left_at IS NULL`,
		roomID)
	if err != nil {
		m.logger.Error("failed to get sessions for broadcast", "error", err, "roomID", roomID)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var aimsid, chatsid string
		if err := rows.Scan(&aimsid, &chatsid); err != nil {
			continue
		}
		// Update event with the recipient's chat session ID if not set
		if event.ChatSID == "" {
			event.ChatSID = chatsid
		}
		m.sendChatEventToUser(aimsid, event)
	}
}

func (m *WebAPIChatManager) sendChatEventToUser(aimsid string, event ChatEventData) {
	// Get the user's Web API session
	// Using background context for async event sending
	session, err := m.sessions.GetSession(context.Background(), aimsid)
	if err != nil {
		m.logger.Error("failed to get session for chat event", "error", err, "aimsid", aimsid)
		return
	}

	// Queue the chat event
	session.EventQueue.Push("chat", event)
}

func (m *WebAPIChatManager) generateRoomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *WebAPIChatManager) generateChatSID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *WebAPIChatManager) generateInstanceID() int {
	// In production, this might be based on server instance or other factors
	// For now, use a simple random number
	return int(time.Now().Unix() % 1000000)
}

// GetRecentMessages returns recent messages from a chat room (for history)
func (m *WebAPIChatManager) GetRecentMessages(ctx context.Context, roomID string, limit int) ([]*ChatMessage, error) {
	rows, err := m.store.db.QueryContext(ctx, `
		SELECT id, room_id, screen_name, message, whisper_target, timestamp
		FROM web_chat_messages
		WHERE room_id = ?
		ORDER BY timestamp DESC
		LIMIT ?`,
		roomID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*ChatMessage
	for rows.Next() {
		var msg ChatMessage
		err := rows.Scan(&msg.ID, &msg.RoomID, &msg.ScreenName,
			&msg.Message, &msg.WhisperTarget, &msg.Timestamp)
		if err != nil {
			continue
		}
		messages = append(messages, &msg)
	}

	// Reverse to get chronological order
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, nil
}

// CleanupInactiveSessions removes sessions that have been inactive for too long
func (m *WebAPIChatManager) CleanupInactiveSessions(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Mark sessions as left if they've been inactive for more than 30 minutes
	cutoff := time.Now().Add(-30 * time.Minute).Unix()

	rows, err := m.store.db.QueryContext(ctx, `
		SELECT chat_sid, room_id, screen_name 
		FROM web_chat_sessions 
		WHERE left_at IS NULL AND joined_at < ?`,
		cutoff)
	if err != nil {
		m.logger.Error("failed to get inactive sessions", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var chatsid, roomID, screenName string
		if err := rows.Scan(&chatsid, &roomID, &screenName); err != nil {
			continue
		}

		// Mark as left
		now := time.Now().Unix()
		if _, err := m.store.db.ExecContext(ctx, `UPDATE web_chat_sessions SET left_at = ? WHERE chat_sid = ?`, now, chatsid); err != nil {
			m.logger.Error("failed to mark inactive chat session left", "chatsid", chatsid, "error", err)
			continue
		}
		if _, err := m.store.db.ExecContext(ctx, `DELETE FROM web_chat_participants WHERE room_id = ? AND screen_name = ?`,
			roomID, screenName); err != nil {
			m.logger.Error("failed to remove inactive chat participant", "roomID", roomID, "screenName", screenName, "error", err)
			continue
		}

		// Broadcast user left
		// Note: Broadcasting doesn't need context as it's fire-and-forget
		m.broadcastChatEvent(roomID, ChatEventData{
			ChatSID:   chatsid,
			EventType: ChatEventUserLeft,
			EventData: ChatUserEventData{
				ScreenName: screenName,
				Timestamp:  now,
			},
		})
	}
}
