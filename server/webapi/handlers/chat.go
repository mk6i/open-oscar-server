package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mk6i/open-oscar-server/state"
)

// ChatHandler handles Web API chat endpoints
type ChatHandler struct {
	SessionManager *state.WebAPISessionManager
	ChatManager    *state.WebAPIChatManager
	Logger         *slog.Logger
}

// CreateAndJoinChat creates (if needed) and joins a chat room
// GET /chat/createAndJoinChat
func (h *ChatHandler) CreateAndJoinChat(w http.ResponseWriter, r *http.Request) {
	// Extract parameters
	aimsid := r.URL.Query().Get("aimsid")
	roomID := r.URL.Query().Get("roomId")
	roomName := r.URL.Query().Get("roomName")

	// Validate session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.Logger.Error("invalid session", "aimsid", aimsid, "error", err)
		SendError(w, http.StatusUnauthorized, "Authentication Required")
		return
	}

	// Validate parameters - exactly one of roomId or roomName must be provided
	if (roomID == "" && roomName == "") || (roomID != "" && roomName != "") {
		SendError(w, http.StatusBadRequest, "Exactly one of roomId or roomName must be provided")
		return
	}

	// Create or join the chat room
	chatSession, room, err := h.ChatManager.CreateAndJoinChat(r.Context(), aimsid, roomID, roomName, string(session.ScreenName))
	if err != nil {
		h.Logger.Error("failed to create/join chat", "error", err, "aimsid", aimsid)

		// Determine appropriate error code
		statusCode := http.StatusInternalServerError
		message := "Internal Server Error"
		if strings.Contains(err.Error(), "maximum capacity") {
			statusCode = http.StatusServiceUnavailable
			message = "Room is at maximum capacity"
		} else if strings.Contains(err.Error(), "must be provided") {
			statusCode = http.StatusBadRequest
			message = err.Error()
		}

		SendError(w, statusCode, message)
		return
	}

	// Build response
	roomData := map[string]interface{}{
		"roomName":    room.RoomName,
		"roomId":      room.RoomID,
		"instanceId":  room.InstanceID,
		"description": room.Description,
		"roomType":    string(room.RoomType),
	}

	// Add category ID if present
	if room.CategoryID != "" {
		roomData["categoryId"] = room.CategoryID
	}

	response := BaseResponse{
		Response: ResponseBody{
			StatusCode: 200,
			StatusText: "OK",
			Data: map[string]interface{}{
				"chatsid": chatSession.ChatSID,
				"room":    roomData,
			},
		},
	}

	// Send response
	SendResponse(w, r, response, h.Logger)

	h.Logger.Info("user joined chat room",
		"screenName", session.ScreenName,
		"roomName", room.RoomName,
		"roomID", room.RoomID,
		"chatsid", chatSession.ChatSID)
}

// SendMessage sends a message to a chat room
// GET /chat/sendMessage
func (h *ChatHandler) SendMessage(w http.ResponseWriter, r *http.Request) {
	// Extract parameters
	aimsid := r.URL.Query().Get("aimsid")
	chatsid := r.URL.Query().Get("chatsid")
	message := r.URL.Query().Get("message")
	whisperTarget := r.URL.Query().Get("whisperTarget")

	// Validate session
	_, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.Logger.Error("invalid session", "aimsid", aimsid, "error", err)
		SendError(w, http.StatusUnauthorized, "Authentication Required")
		return
	}

	// Validate required parameters
	if chatsid == "" {
		SendError(w, http.StatusBadRequest, "chatsid is required")
		return
	}

	if message == "" {
		SendError(w, http.StatusBadRequest, "message is required")
		return
	}

	// Send the message
	err = h.ChatManager.SendMessage(r.Context(), chatsid, message, whisperTarget)
	if err != nil {
		h.Logger.Error("failed to send message", "error", err, "chatsid", chatsid)

		// Determine appropriate error code
		statusCode := http.StatusInternalServerError
		message := "Internal Server Error"
		if strings.Contains(err.Error(), "invalid chat session") || strings.Contains(err.Error(), "user has left") {
			statusCode = http.StatusNotFound
			message = "Chat session not found"
		}

		SendError(w, statusCode, message)
		return
	}

	// Build response
	response := BaseResponse{
		Response: ResponseBody{
			StatusCode: 200,
			StatusText: "OK",
			Data:       map[string]interface{}{},
		},
	}

	// Send response
	SendResponse(w, r, response, h.Logger)

	logMsg := "message sent to chat room"
	if whisperTarget != "" {
		logMsg = "whisper sent in chat room"
	}
	h.Logger.Debug(logMsg, "chatsid", chatsid, "whisperTarget", whisperTarget)
}

// SetTyping sets typing status for a chat room
// GET /chat/setTyping
func (h *ChatHandler) SetTyping(w http.ResponseWriter, r *http.Request) {
	// Extract parameters
	aimsid := r.URL.Query().Get("aimsid")
	chatsid := r.URL.Query().Get("chatsid")
	typingStatus := r.URL.Query().Get("typingStatus")

	// Validate session
	_, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.Logger.Error("invalid session", "aimsid", aimsid, "error", err)
		SendError(w, http.StatusUnauthorized, "Authentication Required")
		return
	}

	// Validate required parameters
	if chatsid == "" {
		SendError(w, http.StatusBadRequest, "chatsid is required")
		return
	}

	if typingStatus == "" {
		SendError(w, http.StatusBadRequest, "typingStatus is required")
		return
	}

	// Validate typing status value
	validStatuses := map[string]bool{
		"none":   true,
		"typing": true,
		"typed":  true,
	}
	if !validStatuses[typingStatus] {
		SendError(w, http.StatusBadRequest, "Invalid typingStatus value")
		return
	}

	// Set typing status
	err = h.ChatManager.SetTyping(r.Context(), chatsid, typingStatus)
	if err != nil {
		h.Logger.Error("failed to set typing status", "error", err, "chatsid", chatsid)

		// Determine appropriate error code
		statusCode := http.StatusInternalServerError
		errMessage := "Internal Server Error"
		if strings.Contains(err.Error(), "invalid chat session") || strings.Contains(err.Error(), "user has left") {
			statusCode = http.StatusNotFound
			errMessage = "Chat session not found"
		}

		SendError(w, statusCode, errMessage)
		return
	}

	// Build response
	response := BaseResponse{
		Response: ResponseBody{
			StatusCode: 200,
			StatusText: "OK",
			Data:       map[string]interface{}{},
		},
	}

	// Send response
	SendResponse(w, r, response, h.Logger)

	h.Logger.Debug("typing status updated", "chatsid", chatsid, "status", typingStatus)
}

// LeaveChat leaves the current chat room
// GET /chat/leaveChat
func (h *ChatHandler) LeaveChat(w http.ResponseWriter, r *http.Request) {
	// Extract parameters
	aimsid := r.URL.Query().Get("aimsid")
	chatsid := r.URL.Query().Get("chatsid")

	// Validate session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		h.Logger.Error("invalid session", "aimsid", aimsid, "error", err)
		SendError(w, http.StatusUnauthorized, "Authentication Required")
		return
	}

	// Validate required parameters
	if chatsid == "" {
		SendError(w, http.StatusBadRequest, "chatsid is required")
		return
	}

	// Leave the chat room
	err = h.ChatManager.LeaveChat(r.Context(), chatsid)
	if err != nil {
		h.Logger.Error("failed to leave chat", "error", err, "chatsid", chatsid)

		// Determine appropriate error code
		statusCode := http.StatusInternalServerError
		message := "Internal Server Error"
		if strings.Contains(err.Error(), "invalid chat session") {
			statusCode = http.StatusNotFound
			message = "Chat session not found"
		}

		SendError(w, statusCode, message)
		return
	}

	// Build response
	response := BaseResponse{
		Response: ResponseBody{
			StatusCode: 200,
			StatusText: "OK",
			Data:       map[string]interface{}{},
		},
	}

	// Send response
	SendResponse(w, r, response, h.Logger)

	h.Logger.Info("user left chat room",
		"screenName", session.ScreenName,
		"chatsid", chatsid)
}

// Helper to validate and convert typed JSON data for chat events
func validateChatEventData(data json.RawMessage, eventType string) (interface{}, error) {
	switch eventType {
	case "message":
		var msgData state.ChatMessageEventData
		if err := json.Unmarshal(data, &msgData); err != nil {
			return nil, err
		}
		return msgData, nil
	case "userEntered", "userLeft":
		var userData state.ChatUserEventData
		if err := json.Unmarshal(data, &userData); err != nil {
			return nil, err
		}
		return userData, nil
	case "typing":
		var typingData state.ChatTypingEventData
		if err := json.Unmarshal(data, &typingData); err != nil {
			return nil, err
		}
		return typingData, nil
	case "userInRoom":
		var participantData state.ChatParticipantList
		if err := json.Unmarshal(data, &participantData); err != nil {
			return nil, err
		}
		return participantData, nil
	case "closed":
		// No additional data for closed event
		return nil, nil
	default:
		return nil, errors.New("unknown chat event type")
	}
}
