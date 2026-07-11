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
	LocateService  LocateService
	FeedbagService FeedbagService
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
	// The client sends t as the normalized aimId it keys the conversation by, so
	// it is never a source of display names.
	recipientIdent := state.NewIdentScreenName(recipient)
	sess.AddStoredIM(recipientIdent.String(), sess.ScreenName.IdentScreenName().String(), message, messageID, nowSec)

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

	recipientDisplay := h.resolveDisplayName(ctx, sess.OSCARSession, recipientIdent)
	// The alias lives in the sender's feedbag, so unlike the display name it cannot
	// be read off a locate reply.
	recipientAlias := sess.Aliases(ctx)[recipientIdent.String()]
	h.pushSenderWebAPIEvents(sess, recipientIdent, recipientDisplay, recipientAlias, message, messageID, now, autoResponse)

	h.Logger.DebugContext(ctx, "queued sentIM event for sender",
		"from", sess.ScreenName.String(),
		"to", recipient,
		"eventType", types.EventTypeSentIM,
	)

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

// resolveDisplayName returns the recipient's screen name as they formatted it,
// or "" when it cannot be determined because they are offline or blocked.
func (h *MessagingHandler) resolveDisplayName(ctx context.Context, instance *state.SessionInstance, recipient state.IdentScreenName) string {
	reply, err := h.LocateService.UserInfoQuery(ctx, instance, wire.SNACFrame{},
		wire.SNAC_0x02_0x05_LocateUserInfoQuery{
			Type:       uint16(wire.LocateTypeUnavailable),
			ScreenName: recipient.String(),
		})
	if err != nil {
		h.Logger.DebugContext(ctx, "failed to resolve recipient display name",
			"screenName", recipient.String(), "error", err)
		return ""
	}
	info, ok := reply.Body.(wire.SNAC_0x02_0x06_LocateUserInfoReply)
	if !ok {
		return ""
	}
	return info.ScreenName
}

// pushSenderWebAPIEvents echoes a just-sent IM back to the sender's own event
// queue. recipientDisplay is the recipient's own formatting of their screen name,
// or "" when it could not be resolved; recipientAlias is the sender's private name
// for them, or "" when unaliased.
//
// The web client merges every user map it receives onto the single user object it
// keys by aimId, so a displayId here overwrites the name the buddy list already
// rendered. Echoing the normalized aimId as a displayId would reduce a buddy named
// "Mike Lee" to "mikelee" the moment you message him. Omitting displayId leaves the
// client's existing name untouched. The merge also deletes any alias it holds, so
// friendly has to be repeated here even though the buddy list already sent it.
func (h *MessagingHandler) pushSenderWebAPIEvents(sess *state.WebAPISession, recipient state.IdentScreenName, recipientDisplay, recipientAlias, message, messageID string, now float64, autoResponse bool) {
	senderAimID := sess.ScreenName.IdentScreenName().String()
	recipientAimID := recipient.String()

	senderEventData := types.SentIMEvent{
		Sender: types.UserInfo{
			AimID:     senderAimID,
			DisplayID: sess.ScreenName.String(),
			UserType:  "aim",
		},
		Dest: types.UserInfo{
			AimID:     recipientAimID,
			DisplayID: recipientDisplay,
			Friendly:  recipientAlias,
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
			types.ConversationEntry(recipientAimID, recipientDisplay, message, messageID, senderAimID, true, 0),
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
