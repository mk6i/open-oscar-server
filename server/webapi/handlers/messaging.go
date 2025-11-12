package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mk6i/retro-aim-server/server/webapi/types"
	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

// MessageRelayer defines methods for relaying messages between users
type MessageRelayer interface {
	RelayToScreenName(ctx context.Context, recipient state.IdentScreenName, msg wire.SNACMessage)
}

// OfflineMessageManager defines methods for managing offline messages
type OfflineMessageManager interface {
	SaveMessage(ctx context.Context, msg state.OfflineMessage) (int, error)
}

// RelationshipFetcher defines methods for fetching user relationships
type RelationshipFetcher interface {
	Relationship(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) (state.Relationship, error)
}

// MessagingHandler handles Web AIM API messaging endpoints
type MessagingHandler struct {
	SessionManager        *state.WebAPISessionManager
	MessageRelayer        MessageRelayer
	OfflineMessageManager OfflineMessageManager
	SessionRetriever      SessionRetriever
	RelationshipFetcher   RelationshipFetcher
	Logger                *slog.Logger
}

// SendIM handles the /im/sendIM endpoint for sending instant messages
func (h *MessagingHandler) SendIM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session from aimsid
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: aimsid")
		return
	}

	sess, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		if err == state.ErrNoWebAPISession || err == state.ErrWebAPISessionExpired {
			h.sendErrorResponse(w, http.StatusUnauthorized, "invalid or expired session")
		} else {
			h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	// Parse parameters
	recipient := r.URL.Query().Get("t")
	if recipient == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: t (recipient)")
		return
	}

	message := r.URL.Query().Get("message")
	if message == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: message")
		return
	}

	// Parse optional parameters
	autoResponse := r.URL.Query().Get("autoResponse") == "1"
	offlineIM := r.URL.Query().Get("offlineIM") != "0" // default to true

	// Create recipient identifier
	recipientIdent := state.NewIdentScreenName(recipient)

	// Check blocking relationship
	rel, err := h.RelationshipFetcher.Relationship(ctx, sess.ScreenName.IdentScreenName(), recipientIdent)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to fetch relationship", "error", err)
		h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Check if sender blocks recipient or recipient blocks sender
	if rel.BlocksYou {
		// Recipient blocks sender - pretend recipient is offline
		h.sendErrorResponse(w, http.StatusNotFound, "recipient is not online")
		return
	}
	if rel.YouBlock {
		// Sender has blocked recipient - cannot send message
		h.sendErrorResponse(w, http.StatusForbidden, "cannot send message to blocked user")
		return
	}

	// Check if recipient is online
	recipientSession := h.SessionRetriever.RetrieveSession(recipientIdent)

	// Generate message cookie
	var cookie [8]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		h.Logger.ErrorContext(ctx, "failed to generate message cookie", "error", err)
		h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}
	cookieUint64 := binary.BigEndian.Uint64(cookie[:])

	// Get sender's OSCAR session if available
	var senderInfo wire.TLVUserInfo
	if sess.OSCARSession != nil {
		senderInfo = sess.OSCARSession.TLVUserInfo()
	} else {
		// Create minimal user info for web-only sessions
		senderInfo = wire.TLVUserInfo{
			ScreenName:   sess.ScreenName.String(),
			WarningLevel: 0,
		}
		senderInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(sess.CreatedAt.Unix())))
		senderInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000))) // online status
	}

	// Create message ID for response (UUID format like working implementation)
	// Using the cookie bytes to generate a UUID-like string
	messageID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(cookie[:4]),
		binary.BigEndian.Uint16(cookie[4:6]),
		binary.BigEndian.Uint16(cookie[6:8]),
		binary.BigEndian.Uint16([]byte{0x80, 0x00}), // Version bits
		time.Now().UnixNano()&0xffffffffffff)

	if recipientSession == nil {
		// Recipient is offline
		if offlineIM {
			// Save offline message
			offlineMsg := state.OfflineMessage{
				Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
					Cookie:     cookieUint64,
					ChannelID:  wire.ICBMChannelIM,
					ScreenName: recipient,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMTLVAOLIMData, h.encodeIMMessage(message, autoResponse)),
							wire.NewTLVBE(wire.ICBMTLVStore, uint8(1)), // store offline
						},
					},
				},
				Recipient: recipientIdent,
				Sender:    sess.ScreenName.IdentScreenName(),
				Sent:      time.Now().UTC(),
			}

			count, err := h.OfflineMessageManager.SaveMessage(ctx, offlineMsg)
			if err != nil {
				if errors.Is(err, state.ErrOfflineInboxFull) {
					h.Logger.WarnContext(ctx, "offline inbox full",
						"from", sess.ScreenName.String(),
						"to", recipient)
					h.sendErrorResponse(w, http.StatusConflict, "recipient inbox full")
					return
				}
				h.Logger.ErrorContext(ctx, "failed to save offline message",
					"from", sess.ScreenName.String(),
					"to", recipient,
					"error", err)
				h.sendErrorResponse(w, http.StatusInternalServerError, "failed to save offline message")
				return
			}

			h.Logger.DebugContext(ctx, "saved offline message",
				"from", sess.ScreenName.String(),
				"to", recipient,
				"count", count)
		} else {
			// Recipient is offline and offline delivery is disabled
			h.sendErrorResponse(w, http.StatusNotFound, "recipient is not online")
			return
		}
	} else {
		// Recipient is online, deliver message
		clientIM := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			Cookie:       cookieUint64,
			ChannelID:    wire.ICBMChannelIM,
			TLVUserInfo:  senderInfo,
			TLVRestBlock: wire.TLVRestBlock{},
		}

		// Add message data
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, h.encodeIMMessage(message, autoResponse)))

		// Add auto-response flag if applicable
		if autoResponse {
			clientIM.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
		}

		// Send message to recipient
		h.MessageRelayer.RelayToScreenName(ctx, recipientIdent, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: clientIM,
		})

		// Queue IM event for the recipient's WebAPI session if they have one
		if recipientWebSession, err := h.SessionManager.GetSessionByUser(r.Context(), recipientIdent); err == nil && recipientWebSession != nil {
			eventData := types.IMEvent{
				From:      sess.ScreenName.String(),
				Message:   message,
				Timestamp: float64(time.Now().Unix()),
				AutoResp:  autoResponse,
			}
			recipientWebSession.EventQueue.Push(types.EventTypeIM, eventData)
		}

		// Also queue sentIM event for the sender's WebAPI session to show in their UI
		senderEventData := types.SentIMEvent{
			Sender: types.UserInfo{
				AimID:     sess.ScreenName.String(),
				DisplayID: sess.ScreenName.String(),
				UserType:  "aim",
			},
			Dest: types.UserInfo{
				AimID:     recipient,
				DisplayID: recipient,
				UserType:  "aim",
			},
			Message:   message,
			Timestamp: float64(time.Now().Unix()),
			AutoResp:  autoResponse,
		}
		sess.EventQueue.Push(types.EventTypeSentIM, senderEventData)

		h.Logger.DebugContext(ctx, "queued sentIM event for sender",
			"from", sess.ScreenName.String(),
			"to", recipient,
			"eventType", types.EventTypeSentIM,
		)

		h.Logger.DebugContext(ctx, "delivered instant message",
			"from", sess.ScreenName.String(),
			"to", recipient)
	}

	// Send success response
	responseData := map[string]interface{}{
		"msgId": messageID,
		"state": "delivered",
	}
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = responseData
	SendResponse(w, r, response, h.Logger)
}

// encodeIMMessage encodes a text message into the OSCAR IM format
func (h *MessagingHandler) encodeIMMessage(text string, autoResponse bool) []byte {
	// Create ICBM fragment list for the message
	frags, err := wire.ICBMFragmentList(text)
	if err != nil {
		// If fragment creation fails, return simple text bytes
		return []byte(text)
	}

	// Marshal the fragments
	buf := &bytes.Buffer{}
	for _, frag := range frags {
		if err := wire.MarshalBE(frag, buf); err != nil {
			// If marshaling fails, return simple text bytes
			return []byte(text)
		}
	}
	return buf.Bytes()
}

// sendErrorResponse sends an error response in Web AIM API format
func (h *MessagingHandler) sendErrorResponse(w http.ResponseWriter, statusCode int, errorText string) {
	SendError(w, statusCode, errorText)
}

// SetTyping handles the /im/setTyping endpoint for typing indicators
func (h *MessagingHandler) SetTyping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session from aimsid
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: aimsid")
		return
	}

	sess, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		if err == state.ErrNoWebAPISession || err == state.ErrWebAPISessionExpired {
			h.sendErrorResponse(w, http.StatusUnauthorized, "invalid or expired session")
		} else {
			h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Update session activity
	if err := h.SessionManager.TouchSession(r.Context(), aimsid); err != nil {
		h.Logger.WarnContext(ctx, "failed to touch session", "aimsid", aimsid, "error", err)
	}

	// Parse parameters
	recipient := r.URL.Query().Get("t")
	if recipient == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: t (recipient)")
		return
	}

	typingStr := r.URL.Query().Get("typing")
	typing := false
	if typingStr != "" {
		var err error
		typing, err = strconv.ParseBool(typingStr)
		if err != nil {
			// Try numeric format (0/1)
			typing = typingStr == "1"
		}
	}

	// Create recipient identifier
	recipientIdent := state.NewIdentScreenName(recipient)

	// Check blocking relationship
	rel, err := h.RelationshipFetcher.Relationship(ctx, sess.ScreenName.IdentScreenName(), recipientIdent)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to fetch relationship", "error", err)
		h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Check if sender blocks recipient or recipient blocks sender
	if rel.BlocksYou || rel.YouBlock {
		// Either party blocks the other - silently succeed without sending notification
		h.sendSuccessResponse(w, r, nil)
		return
	}

	// Check if recipient is online
	recipientSession := h.SessionRetriever.RetrieveSession(recipientIdent)
	if recipientSession == nil {
		// Silently succeed even if recipient is offline
		h.sendSuccessResponse(w, r, nil)
		return
	}

	// Generate typing notification cookie
	var cookie [8]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		h.Logger.ErrorContext(ctx, "failed to generate typing cookie", "error", err)
		h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}
	cookieUint64 := binary.BigEndian.Uint64(cookie[:])

	// Create typing notification
	var notificationType uint16
	if typing {
		notificationType = 0x0002 // Typing started
	} else {
		notificationType = 0x0001 // Typing stopped
	}

	typingNotification := wire.SNAC_0x04_0x14_ICBMClientEvent{
		Cookie:     cookieUint64,
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: sess.ScreenName.String(),
		Event:      notificationType,
	}

	// Send typing notification to recipient
	h.MessageRelayer.RelayToScreenName(ctx, recipientIdent, wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMClientEvent,
			RequestID: wire.ReqIDFromServer,
		},
		Body: typingNotification,
	})

	// Queue typing event for the recipient's WebAPI session if they have one
	if recipientWebSession, err := h.SessionManager.GetSessionByUser(r.Context(), recipientIdent); err == nil && recipientWebSession != nil {
		eventData := types.TypingEvent{
			From:   sess.ScreenName.String(),
			Typing: typing,
		}
		recipientWebSession.EventQueue.Push(types.EventTypeTyping, eventData)
	}

	h.Logger.DebugContext(ctx, "sent typing notification",
		"from", sess.ScreenName.String(),
		"to", recipient,
		"typing", typing)

	// Send success response
	h.sendSuccessResponse(w, r, nil)
}

// sendSuccessResponse sends a success response in Web AIM API format
func (h *MessagingHandler) sendSuccessResponse(w http.ResponseWriter, r *http.Request, data interface{}) {
	response := BaseResponse{}
	response.Response.StatusCode = 200
	response.Response.StatusText = "OK"
	response.Response.Data = data
	SendResponse(w, r, response, h.Logger)
}
