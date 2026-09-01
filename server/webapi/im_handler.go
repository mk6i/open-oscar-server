package webapi

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// MessagingHandler handles Web AIM API messaging endpoints
type MessagingHandler struct {
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
func (h *MessagingHandler) SendIM(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx := r.Context()

	// Parse parameters
	recipient := queryOrFormParam(r, "t")
	if recipient == "" {
		SendError(w, r, http.StatusBadRequest, "missing required parameter: t (recipient)")
		return
	}

	message := queryOrFormParam(r, "message")
	if message == "" {
		SendError(w, r, http.StatusBadRequest, "missing required parameter: message")
		return
	}

	// Parse optional parameters
	autoResponse := queryOrFormParam(r, "autoResponse") == "1"
	// The client sets offlineIM once it believes the recipient is offline and
	// storable; it sends the literal "true" rather than "1".
	offlineIM := queryOrFormParam(r, "offlineIM") == "true" || queryOrFormParam(r, "offlineIM") == "1"

	// Generate message cookie
	var cookie [8]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		h.Logger.ErrorContext(ctx, "failed to generate message cookie", "error", err)
		SendError(w, r, http.StatusInternalServerError, "internal server error")
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

	now := time.Now().Unix()
	// The client sends t as the normalized aimId it keys the conversation by, so
	// it is never a source of display names.
	recipientIdent := state.NewIdentScreenName(recipient)

	clientIM := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:       cookieUint64,
		ChannelID:    wire.ICBMChannelIM,
		ScreenName:   recipient,
		TLVRestBlock: wire.TLVRestBlock{},
	}

	// Add message data
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		SendError(w, r, http.StatusInternalServerError, "failed to send message")
		return
	}

	clientIM.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))

	// Add auto-response flag if applicable
	if autoResponse {
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
	}

	// Without this directive the ICBM service rejects messages to offline
	// recipients instead of storing them.
	if offlineIM {
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVStore, []byte{}))
	}

	frame := wire.SNACFrame{
		FoodGroup: wire.ICBM,
		SubGroup:  wire.ICBMChannelMsgToHost,
		RequestID: wire.ReqIDFromServer,
	}
	resp, err := h.ICBMService.ChannelMsgToHost(r.Context(), sess.OSCARSession, frame, clientIM)

	if err != nil {
		SendError(w, r, http.StatusInternalServerError, "failed to send message")
		return
	}

	if resp != nil {
		switch {
		case resp.Frame.FoodGroup == wire.ICBM && resp.Frame.SubGroup == wire.ICBMErr:
			if errSn, ok := resp.Body.(wire.SNACError); ok {
				switch errSn.Code {
				case wire.ErrorCodeNotLoggedOn:
					subCode, hasSubCode := errSn.Uint16BE(wire.ErrorTLVErrorSubcode)
					if hasSubCode && subCode == wire.ICBMSubErrOfflineIMExceedMax {
						h.Logger.DebugContext(ctx, "user's offline messages full")
						h.sendUndeliverable(w, r, "recipient's offline message store is full")
					} else {
						h.Logger.DebugContext(ctx, "recipient offline")
						h.sendUndeliverable(w, r, "recipient is offline and cannot receive offline messages")
					}
					return
				case wire.ErrorCodeInLocalPermitDeny:
					h.Logger.DebugContext(ctx, "you blocked this user")
					h.sendUndeliverable(w, r, "you have blocked this user")
					return
				}
			}
			h.Logger.DebugContext(ctx, "message rejected by ICBM service")
			h.sendUndeliverable(w, r, "failed to send message")
			return
		case resp.Frame.FoodGroup == wire.ICBM && resp.Frame.SubGroup == wire.ICBMHostAck:
			h.Logger.DebugContext(ctx, "received host ack")
		}
	}

	sess.AddStoredIM(recipientIdent.String(), sess.ScreenName.IdentScreenName().String(), message, messageID, now)

	recipientDisplay := h.resolveDisplayName(ctx, sess.OSCARSession, recipientIdent)
	// The alias lives in the sender's feedbag, so unlike the display name it cannot
	// be read off a locate reply.
	recipientAlias := sess.Aliases(ctx)[recipientIdent.String()]
	h.pushSenderWebAPIEvents(sess, recipientIdent, recipientDisplay, recipientAlias, message, messageID, now, autoResponse)

	h.Logger.DebugContext(ctx, "queued sentIM event for sender",
		"from", sess.ScreenName.String(),
		"to", recipient,
		"eventType", EventTypeSentIM,
	)

	// Send success response
	responseData := &SendIMData{MsgID: messageID, State: "delivered"}
	SendOK(w, r, responseData, h.Logger)
}

// sendUndeliverable reports an IM the server accepted but could not deliver.
func (h *MessagingHandler) sendUndeliverable(w http.ResponseWriter, r *http.Request, statusText string) {
	SendEnvelopeStatus(w, r, statusSendFailed, statusText, h.Logger)
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
func (h *MessagingHandler) pushSenderWebAPIEvents(sess *Session, recipient state.IdentScreenName, recipientDisplay, recipientAlias, message, messageID string, now int64, autoResponse bool) {
	senderAimID := sess.ScreenName.IdentScreenName().String()
	recipientAimID := recipient.String()

	senderEventData := SentIMEvent{
		Sender: UserInfo{
			AimID:     senderAimID,
			DisplayID: sess.ScreenName.String(),
			UserType:  "aim",
			State:     "online",
		},
		Dest: UserInfo{
			AimID:     recipientAimID,
			DisplayID: recipientDisplay,
			Friendly:  recipientAlias,
			UserType:  "aim",
			State:     "online",
		},
		Message:   message,
		MsgID:     messageID,
		Timestamp: now,
		AutoResp:  autoResponse,
	}
	sess.EventQueue.Push(EventTypeSentIM, senderEventData)
	if sess.IsSubscribedTo("conversation") {
		sess.EventQueue.Push(EventTypeConversation, ConversationEventData("update", []ConversationEntryData{
			ConversationEntry(recipientAimID, recipientDisplay, message, messageID, senderAimID, true, 0),
		}))
	}
}

// SetTyping handles the /im/setTyping endpoint for typing indicators
func (h *MessagingHandler) SetTyping(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx := r.Context()

	// Parse parameters
	recipient := r.URL.Query().Get("t")
	if recipient == "" {
		SendError(w, r, http.StatusBadRequest, "missing required parameter: t (recipient)")
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
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	SendOK(w, r, nil, h.Logger)
}

// SendIMData reports the fate of an accepted IM.
type SendIMData struct {
	MsgID string `json:"msgId" xml:"msgId"`
	State string `json:"state" xml:"state"`
}

// StoredIMsData is the fetchStoredIMs payload.
type StoredIMsData struct {
	Msgs []StoredIM `json:"msgs" xml:"msgs>msg"`
}

// ConversationStubHandler serves Web AIM conversation/imlog endpoints the
// client calls when syncing chat focus and read state.
type ConversationStubHandler struct {
	Logger *slog.Logger
}

// Update records active/focus time for a conversation (fire-and-forget).
func (h *ConversationStubHandler) Update(w http.ResponseWriter, r *http.Request) {
	SendOK(w, r, nil, h.Logger)
}

// Close acknowledges a conversation was closed in the client.
func (h *ConversationStubHandler) Close(w http.ResponseWriter, r *http.Request) {
	SendOK(w, r, nil, h.Logger)
}

// MarkRead acknowledges IM log read state for a buddy.
func (h *ConversationStubHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	SendOK(w, r, nil, h.Logger)
}

// FetchStoredIMs returns stored IM history for a conversation partner.
func (h *ConversationStubHandler) FetchStoredIMs(w http.ResponseWriter, r *http.Request, sess *Session) {
	partner := r.URL.Query().Get("to")
	if partner == "" {
		SendError(w, r, http.StatusBadRequest, "missing required parameter: to")
		return
	}

	q := StoredIMQuery{
		PartnerAimID: partner,
		SortOrder:    r.URL.Query().Get("sortOrder"),
		SkipMsgID:    r.URL.Query().Get("skipMsgId"),
		StopMsgID:    r.URL.Query().Get("stopMsgId"),
	}
	if n := r.URL.Query().Get("nToGet"); n != "" {
		if v, err := strconv.Atoi(n); err == nil {
			q.NToGet = v
		}
	}
	if start := r.URL.Query().Get("startTime"); start != "" {
		if v, err := strconv.ParseInt(start, 10, 64); err == nil {
			q.StartTime = v
		}
	}
	if end := r.URL.Query().Get("endTime"); end != "" {
		if v, err := strconv.ParseInt(end, 10, 64); err == nil {
			q.EndTime = v
		}
	}

	msgs := sess.GetStoredIMs(q)

	SendOK(w, r, &StoredIMsData{Msgs: msgs}, h.Logger)
}
