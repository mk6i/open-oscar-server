package handlers

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ICBMService defines methods for ICBM operations
type ICBMService interface {
	ChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error)
	ClientEvent(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x14_ICBMClientEvent) error
}

// MessagingHandler handles Web AIM API messaging endpoints
type MessagingHandler struct {
	SessionManager *state.WebAPISessionManager
	ICBMService    ICBMService
	Logger         *slog.Logger
}

// queryOrFormParam returns a request parameter from the query string or, for POST
// requests, from application/x-www-form-urlencoded body fields. The Web AIM client
// sends t/offlineIM/etc. on the query string and puts message in the POST body.
func queryOrFormParam(r *http.Request, key string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			return r.FormValue(key)
		}
	}
	return ""
}

// SendIM handles the /im/sendIM endpoint for sending instant messages
func (h *MessagingHandler) SendIM(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	ctx := r.Context()

	// Parse parameters
	recipient := queryOrFormParam(r, "t")
	if recipient == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: t (recipient)")
		return
	}

	message := queryOrFormParam(r, "message")
	if message == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: message")
		return
	}

	// Parse optional parameters
	autoResponse := queryOrFormParam(r, "autoResponse") == "1"
	//offlineIMParam := queryOrFormParam(r, "offlineIM") what is this for
	//offlineIM := offlineIMParam != "0" && offlineIMParam != "false" // default to true

	// Create recipient identifier
	recipientIdent := state.NewIdentScreenName(recipient)

	// Generate message cookie
	var cookie [8]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		h.Logger.ErrorContext(ctx, "failed to generate message cookie", "error", err)
		h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}
	cookieUint64 := binary.BigEndian.Uint64(cookie[:])

	// Create message ID for response (UUID format like working implementation)
	// Using the cookie bytes to generate a UUID-like string
	messageID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(cookie[:4]),
		binary.BigEndian.Uint16(cookie[4:6]),
		binary.BigEndian.Uint16(cookie[6:8]),
		binary.BigEndian.Uint16([]byte{0x80, 0x00}), // Version bits
		time.Now().UnixNano()&0xffffffffffff)

	now := float64(time.Now().Unix())
	nowSec := time.Now().Unix()
	sn := sess.ScreenName.String()
	sess.AddStoredIM(recipient, sn, message, messageID, nowSec)

	// Recipient is online, deliver message
	clientIM := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:       cookieUint64,
		ChannelID:    wire.ICBMChannelIM,
		ScreenName:   recipient,
		TLVRestBlock: wire.TLVRestBlock{},
	}

	// Add message data
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "failed to send message")
		return
	}

	clientIM.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))

	// Add auto-response flag if applicable
	if autoResponse {
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
	}

	frame := wire.SNACFrame{
		FoodGroup: wire.ICBM,
		SubGroup:  wire.ICBMChannelMsgToHost,
		RequestID: wire.ReqIDFromServer,
	}
	resp, err := h.ICBMService.ChannelMsgToHost(r.Context(), sess.OSCARSession, frame, clientIM)

	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "failed to send message")
		return
	}

	if resp != nil {
		switch {
		case resp.Frame.FoodGroup == wire.ICBM && resp.Frame.SubGroup == wire.ICBMErr:
			if errSn, ok := resp.Body.(wire.SNACError); ok {
				switch errSn.Code {
				case wire.ErrorCodeNotLoggedOn:
					subCode, hasSubCode := errSn.Uint16BE(wire.ErrorTLVErrorSubcode)
					if hasSubCode {
						if subCode == wire.ICBMSubErrOfflineIMExceedMax {
							h.Logger.DebugContext(r.Context(), "user's offline messages full")
						}
					} else {
						h.Logger.DebugContext(r.Context(), "recipient offline")
					}
					return
				case wire.ErrorCodeInLocalPermitDeny:
					h.Logger.DebugContext(r.Context(), "you blocked this user")
					return
				}
			}
		case resp.Frame.FoodGroup == wire.ICBM && resp.Frame.SubGroup == wire.ICBMHostAck:
			h.Logger.DebugContext(r.Context(), "received host ack")
		}
	}

	// Queue IM event for the recipient's WebAPI session if they have one
	if recipientWebSession, err := h.SessionManager.GetSessionByUser(r.Context(), recipientIdent); err == nil && recipientWebSession != nil {
		recipientWebSession.AddStoredIM(sn, sn, message, messageID, nowSec)
		eventData := types.IMEvent{
			Source: types.UserInfo{
				AimID:     sn,
				DisplayID: sn,
				UserType:  "aim",
				State:     "online",
			},
			Message:   message,
			MsgID:     messageID,
			Timestamp: now,
			AutoResp:  autoResponse,
		}
		recipientWebSession.EventQueue.Push(types.EventTypeIM, eventData)
		if recipientWebSession.IsSubscribedTo("conversation") {
			recipientWebSession.EventQueue.Push(types.EventTypeConversation, types.ConversationEventData("update", []map[string]interface{}{
				types.ConversationEntry(sn, sn, message, messageID, sn, false, 1),
			}))
		}
	}

	h.pushSenderWebAPIEvents(sess, sn, recipient, message, messageID, now, autoResponse)

	h.Logger.DebugContext(ctx, "queued sentIM event for sender",
		"from", sess.ScreenName.String(),
		"to", recipient,
		"eventType", types.EventTypeSentIM,
	)

	h.Logger.DebugContext(ctx, "delivered instant message",
		"from", sess.ScreenName.String(),
		"to", recipient)

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

func (h *MessagingHandler) pushSenderWebAPIEvents(sess *state.WebAPISession, sender, recipient, message, messageID string, now float64, autoResponse bool) {
	senderEventData := types.SentIMEvent{
		Sender: types.UserInfo{
			AimID:     sender,
			DisplayID: sender,
			UserType:  "aim",
		},
		Dest: types.UserInfo{
			AimID:     recipient,
			DisplayID: recipient,
			UserType:  "aim",
		},
		Message:   message,
		MsgID:     messageID,
		Timestamp: now,
		AutoResp:  autoResponse,
	}
	sess.EventQueue.Push(types.EventTypeSentIM, senderEventData)
	if sess.IsSubscribedTo("conversation") {
		sess.EventQueue.Push(types.EventTypeConversation, types.ConversationEventData("update", []map[string]interface{}{
			types.ConversationEntry(recipient, recipient, message, messageID, sender, true, 0),
		}))
	}
}

// sendErrorResponse sends an error response in Web AIM API format
func (h *MessagingHandler) sendErrorResponse(w http.ResponseWriter, statusCode int, errorText string) {
	SendError(w, statusCode, errorText)
}

// SetTyping handles the /im/setTyping endpoint for typing indicators
func (h *MessagingHandler) SetTyping(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	ctx := r.Context()

	// Parse parameters
	recipient := r.URL.Query().Get("t")
	if recipient == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "missing required parameter: t (recipient)")
		return
	}

	typingStatus := r.URL.Query().Get("typingStatus")
	if typingStatus == "" {
		typingStatus = "none"
	}

	var event uint16
	switch typingStatus {
	case "typing":
		event = 0x0002
	case "typed":
		event = 0x0001
	default:
		event = 0x0000
	}

	inBody := wire.SNAC_0x04_0x14_ICBMClientEvent{
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: recipient,
		Event:      event,
	}
	if err := h.ICBMService.ClientEvent(ctx, sess.OSCARSession, wire.SNACFrame{}, inBody); err != nil {
		h.Logger.ErrorContext(ctx, "failed to send typing notification", "error", err)
		h.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
		return
	}

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
