package icq_legacy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mk6i/open-oscar-server/wire"
)

// LegacyMessageBridge implements LegacyMessageSender by routing
// messages through the ProtocolDispatcher to the appropriate legacy handler.
// This bridges the OSCAR->legacy gap: when an OSCAR/AIM user sends a message
// to a UIN connected via legacy protocol, the ICBM service uses this bridge
// to deliver the message instead of storing it offline.
//
// All protocol conversion logic (UIN validation, status mapping, character
// encoding) lives here to minimize impact on the main OSCAR codebase.
type LegacyMessageBridge struct {
	sessions   *LegacySessionManager
	dispatcher *ProtocolDispatcher
	userFinder ICQUserFinder
	logger     *slog.Logger
}

// NewLegacyMessageBridge creates a new bridge for OSCAR->legacy message delivery.
func NewLegacyMessageBridge(sessions *LegacySessionManager, dispatcher *ProtocolDispatcher, userFinder ICQUserFinder, logger *slog.Logger) *LegacyMessageBridge {
	return &LegacyMessageBridge{
		sessions:   sessions,
		dispatcher: dispatcher,
		userFinder: userFinder,
		logger:     logger,
	}
}

// SendMessage delivers a message to a legacy client identified by UIN.
// Returns nil if the message was delivered, or an error if the user is not
// online via legacy protocol (caller should fall through to offline storage).
func (b *LegacyMessageBridge) SendMessage(uin uint32, fromUIN uint32, msgType uint16, message string) error {
	session := b.sessions.GetSession(uin)
	if session == nil {
		return fmt.Errorf("UIN %d not online via legacy protocol", uin)
	}
	// Convert message text from OSCAR encoding (UTF-8/Unicode) to legacy
	// single-byte encoding that old ICQ clients can display.
	converted := utf8ToLatin1(message)
	return b.dispatcher.SendOnlineMessage(session, fromUIN, msgType, converted)
}

// SendStatusUpdate sends a status change notification to a legacy client.
func (b *LegacyMessageBridge) SendStatusUpdate(uin uint32, targetUIN uint32, status uint32) error {
	session := b.sessions.GetSession(uin)
	if session == nil {
		return fmt.Errorf("UIN %d not online via legacy protocol", uin)
	}
	return b.dispatcher.SendStatusChange(session, targetUIN, status)
}

// SendUserOnline sends a user online notification to a legacy client.
func (b *LegacyMessageBridge) SendUserOnline(uin uint32, targetUIN uint32, status uint32, ip net.IP, port uint16) error {
	session := b.sessions.GetSession(uin)
	if session == nil {
		return fmt.Errorf("UIN %d not online via legacy protocol", uin)
	}
	return b.dispatcher.SendUserOnline(session, targetUIN, status)
}

// SendUserOffline sends a user offline notification to a legacy client.
func (b *LegacyMessageBridge) SendUserOffline(uin uint32, targetUIN uint32) error {
	session := b.sessions.GetSession(uin)
	if session == nil {
		return fmt.Errorf("UIN %d not online via legacy protocol", uin)
	}
	return b.dispatcher.SendUserOffline(session, targetUIN)
}

// StartOSCARMessagePump starts a goroutine that drains OSCAR SNAC messages
// from a legacy session's unified SessionInstance and converts them into
// legacy protocol packets.
//
// When an OSCAR client changes status or goes online/offline, the buddy
// notification system (BroadcastBuddyArrived/BroadcastBuddyDeparted) sends
// SNAC messages to ALL sessions in InMemorySessionManager - including legacy
// sessions. But legacy clients communicate over UDP, not TCP FLAP, so nobody
// reads those SNACs. This pump consumes them and translates:
//   - BuddyArrived -> SendUserOnline
//   - BuddyDeparted -> SendUserOffline
//   - ICBMChannelMsgToClient -> SendOnlineMessage (OSCAR->legacy IM delivery)
func (b *LegacyMessageBridge) StartOSCARMessagePump(session *LegacySession) {
	if session == nil || session.Instance == nil {
		b.logger.Warn("StartOSCARMessagePump: nil session or instance, pump NOT started")
		return
	}

	b.logger.Info("StartOSCARMessagePump: starting pump",
		"uin", session.UIN,
		"version", session.Version,
		"instance_closed", session.Instance.Closed() == nil,
	)

	go func() {
		instance := session.Instance
		b.logger.Info("OSCAR message pump goroutine started",
			"uin", session.UIN,
		)
		for {
			select {
			case <-instance.Closed():
				b.logger.Info("OSCAR message pump: instance closed, exiting",
					"uin", session.UIN,
				)
				return
			case msg, ok := <-instance.ReceiveMessage():
				if !ok {
					b.logger.Info("OSCAR message pump: channel closed, exiting",
						"uin", session.UIN,
					)
					return
				}
				b.logger.Info("OSCAR message pump: received SNAC",
					"uin", session.UIN,
					"food_group", msg.Frame.FoodGroup,
					"sub_group", msg.Frame.SubGroup,
				)
				b.handleOSCARMessage(session, msg)
			}
		}
	}()
}

// handleOSCARMessage processes a single OSCAR SNAC message destined for a
// legacy session and converts it to the appropriate legacy protocol packet.
func (b *LegacyMessageBridge) handleOSCARMessage(session *LegacySession, msg wire.SNACMessage) {
	switch {
	case msg.Frame.FoodGroup == wire.Buddy && msg.Frame.SubGroup == wire.BuddyArrived:
		b.handleBuddyArrived(session, msg)
	case msg.Frame.FoodGroup == wire.Buddy && msg.Frame.SubGroup == wire.BuddyDeparted:
		b.handleBuddyDeparted(session, msg)
	case msg.Frame.FoodGroup == wire.ICBM && msg.Frame.SubGroup == wire.ICBMChannelMsgToClient:
		b.handleICBMMessage(session, msg)
	case msg.Frame.FoodGroup == wire.Feedbag && msg.Frame.SubGroup == wire.FeedbagRequestAuthorizeToClient:
		b.handleAuthRequest(session, msg)
	case msg.Frame.FoodGroup == wire.Feedbag && msg.Frame.SubGroup == wire.FeedbagRespondAuthorizeToClient:
		b.handleAuthResponse(session, msg)
	default:
		// Silently ignore other SNAC types - legacy clients don't need them.
		// This includes typing notifications, rate limit updates, etc.
	}
}

// handleBuddyArrived converts an OSCAR BuddyArrived SNAC into a legacy
// user online notification.
func (b *LegacyMessageBridge) handleBuddyArrived(session *LegacySession, msg wire.SNACMessage) {
	arrived, ok := msg.Body.(wire.SNAC_0x03_0x0B_BuddyArrived)
	if !ok {
		return
	}

	uin, ok := parseUIN(arrived.ScreenName)
	if !ok {
		return // AIM screen name - legacy clients can't handle non-numeric identifiers
	}

	if !session.IsContact(uin) {
		return
	}

	oscarStatus, _ := arrived.TLVList.Uint32BE(wire.OServiceUserInfoStatus)
	legacyStatus := oscarStatusToLegacy(oscarStatus)

	b.logger.Debug("OSCAR->legacy buddy arrived",
		"to_uin", session.UIN,
		"arrived_uin", uin,
		"oscar_status", fmt.Sprintf("0x%08X", oscarStatus),
		"legacy_status", fmt.Sprintf("0x%08X", legacyStatus),
	)

	// Use SendUserOnline for the first arrival, SendStatusChange for
	// subsequent status updates. V5 clients use different packet types
	// (SRV_USER_ONLINE vs SRV_USER_STATUS) and only update the status
	// icon when the correct packet type is used.
	if session.MarkContactOnline(uin) {
		// Already known online — this is a status change
		if err := b.dispatcher.SendStatusChange(session, uin, legacyStatus); err != nil {
			b.logger.Debug("failed to send status change to legacy client",
				"to_uin", session.UIN,
				"changed_uin", uin,
				"err", err,
			)
		}
	} else {
		// First time seeing this contact online
		if err := b.dispatcher.SendUserOnline(session, uin, legacyStatus); err != nil {
			b.logger.Debug("failed to send user online to legacy client",
				"to_uin", session.UIN,
				"online_uin", uin,
				"err", err,
			)
		}
	}
}

// handleBuddyDeparted converts an OSCAR BuddyDeparted SNAC into a legacy
// user offline notification.
func (b *LegacyMessageBridge) handleBuddyDeparted(session *LegacySession, msg wire.SNACMessage) {
	departed, ok := msg.Body.(wire.SNAC_0x03_0x0C_BuddyDeparted)
	if !ok {
		return
	}

	uin, ok := parseUIN(departed.ScreenName)
	if !ok {
		return
	}

	if !session.IsContact(uin) {
		return
	}

	b.logger.Debug("OSCAR->legacy buddy departed",
		"to_uin", session.UIN,
		"departed_uin", uin,
	)

	session.MarkContactOffline(uin)

	if err := b.dispatcher.SendUserOffline(session, uin); err != nil {
		b.logger.Debug("failed to send user offline to legacy client",
			"to_uin", session.UIN,
			"offline_uin", uin,
			"err", err,
		)
	}
}

// buildLegacyAuthFields looks up a user's profile and returns FE-delimited
// fields (nick, first, last, email) truncated to legacy ICQ limits.
func (b *LegacyMessageBridge) buildLegacyAuthFields(uin uint32) (nick, firstName, lastName, email string) {
	nick = fmt.Sprintf("%d", uin)
	if user, err := b.userFinder.FindByUIN(context.Background(), uin); err == nil {
		if user.ICQInfo.Basic.Nickname != "" {
			nick = user.ICQInfo.Basic.Nickname
		}
		firstName = user.ICQInfo.Basic.FirstName
		lastName = user.ICQInfo.Basic.LastName
		email = user.ICQInfo.Basic.EmailAddress
	}
	if len(nick) > 20 {
		nick = nick[:20]
	}
	if len(firstName) > 30 {
		firstName = firstName[:30]
	}
	if len(lastName) > 30 {
		lastName = lastName[:30]
	}
	if len(email) > 50 {
		email = email[:50]
	}
	return
}

// handleAuthRequest converts an OSCAR FeedbagRequestAuthorizeToClient (0x13,0x19)
// into a legacy ICQ auth request message (type 0x06).
func (b *LegacyMessageBridge) handleAuthRequest(session *LegacySession, msg wire.SNACMessage) {
	body, ok := msg.Body.(wire.SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost)
	if !ok {
		return
	}

	fromUIN, ok := parseUIN(body.ScreenName)
	if !ok {
		return
	}

	nick, first, last, email := b.buildLegacyAuthFields(fromUIN)
	reason := utf8ToLatin1(body.Reason)
	text := fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE1\xFE%s", nick, first, last, email, reason)

	b.logger.Debug("OSCAR->legacy auth request",
		"to_uin", session.UIN,
		"from_uin", fromUIN,
	)

	if err := b.dispatcher.SendOnlineMessage(session, fromUIN, ICQLegacyMsgAuthReq, text); err != nil {
		b.logger.Debug("failed to deliver auth request to legacy client",
			"to_uin", session.UIN,
			"from_uin", fromUIN,
			"err", err,
		)
	}
}

// handleAuthResponse converts an OSCAR FeedbagRespondAuthorizeToClient (0x13,0x1B)
// into a legacy ICQ auth grant (0x08) or deny (0x07) message.
func (b *LegacyMessageBridge) handleAuthResponse(session *LegacySession, msg wire.SNACMessage) {
	body, ok := msg.Body.(wire.SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient)
	if !ok {
		return
	}

	fromUIN, ok := parseUIN(body.ScreenName)
	if !ok {
		return
	}

	nick, first, last, email := b.buildLegacyAuthFields(fromUIN)

	var msgType uint16
	var text string
	if body.Accepted == 1 {
		msgType = ICQLegacyMsgAuthGrant
		text = fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE", nick, first, last, email)
	} else {
		msgType = ICQLegacyMsgAuthDeny
		reason := utf8ToLatin1(body.Reason)
		text = fmt.Sprintf("%s\xFE%s\xFE%s\xFE%s\xFE%s", nick, first, last, email, reason)
	}

	b.logger.Debug("OSCAR->legacy auth response",
		"to_uin", session.UIN,
		"from_uin", fromUIN,
		"accepted", body.Accepted,
	)

	if err := b.dispatcher.SendOnlineMessage(session, fromUIN, msgType, text); err != nil {
		b.logger.Debug("failed to deliver auth response to legacy client",
			"to_uin", session.UIN,
			"from_uin", fromUIN,
			"err", err,
		)
	}
}

// handleICBMMessage converts an OSCAR ICBM channel message into a legacy
// online message. This handles the case where the OSCAR relay system delivers
// a message to a legacy session's SNAC queue (e.g., from another OSCAR user
// who has this legacy user's UIN as a buddy).
func (b *LegacyMessageBridge) handleICBMMessage(session *LegacySession, msg wire.SNACMessage) {
	clientMsg, ok := msg.Body.(wire.SNAC_0x04_0x07_ICBMChannelMsgToClient)
	if !ok {
		b.logger.Warn("handleICBMMessage: body type assertion failed",
			"uin", session.UIN,
			"body_type", fmt.Sprintf("%T", msg.Body),
		)
		return
	}

	b.logger.Debug("handleICBMMessage: received",
		"uin", session.UIN,
		"channel_id", clientMsg.ChannelID,
		"from_screen_name", clientMsg.TLVUserInfo.ScreenName,
		"tlv_count", len(clientMsg.TLVRestBlock.TLVList),
	)

	// Handle channel 1 (IM) and channel 4 (ICQ) messages
	// ICQ 2003b and later send ICQ-to-ICQ messages on channel 4
	if clientMsg.ChannelID != wire.ICBMChannelIM && clientMsg.ChannelID != wire.ICBMChannelICQ {
		b.logger.Debug("handleICBMMessage: skipping unsupported channel",
			"uin", session.UIN,
			"channel_id", clientMsg.ChannelID,
		)
		return
	}

	fromUIN, ok := parseUIN(clientMsg.TLVUserInfo.ScreenName)
	if !ok {
		b.logger.Debug("handleICBMMessage: parseUIN failed",
			"uin", session.UIN,
			"screen_name", clientMsg.TLVUserInfo.ScreenName,
		)
		return // AIM screen name - can't represent as legacy UIN
	}

	// Extract message text and type from ICBM TLVs
	var msgType uint16
	var text string

	if clientMsg.ChannelID == wire.ICBMChannelICQ {
		// Channel 4: extract ICBMCh4Message which has message type
		payload, hasPayload := clientMsg.Bytes(wire.ICBMTLVData)
		if hasPayload {
			ch4Msg := wire.ICBMCh4Message{}
			if err := wire.UnmarshalLE(&ch4Msg, bytes.NewBuffer(payload)); err == nil {
				msgType = uint16(ch4Msg.MessageType)
				text = ch4Msg.Message
			}
		}
	} else {
		// Fallback to channel 1 text extraction
		text = extractAndConvertICBMText(clientMsg)
		msgType = ICQLegacyMsgText
	}

	if text == "" && msgType == 0 {
		b.logger.Debug("handleICBMMessage: no message content",
			"uin", session.UIN,
			"from_uin", fromUIN,
		)
		return
	}

	// For auth grant (0x08), text may be empty — that's OK
	if msgType == 0 {
		msgType = ICQLegacyMsgText
	}

	b.logger.Debug("OSCAR->legacy ICBM message",
		"to_uin", session.UIN,
		"from_uin", fromUIN,
		"msg_type", fmt.Sprintf("0x%04X", msgType),
		"text_len", len(text),
	)

	if err := b.dispatcher.SendOnlineMessage(session, fromUIN, msgType, text); err != nil {
		b.logger.Debug("failed to deliver ICBM to legacy client",
			"to_uin", session.UIN,
			"from_uin", fromUIN,
			"err", err,
		)
	}
}

// ---------------------------------------------------------------------------
// UIN validation
// ---------------------------------------------------------------------------

// parseUIN converts an OSCAR screen name to a numeric UIN.
// Returns (0, false) if the screen name is not a valid numeric UIN.
// Legacy ICQ clients can only process events with numeric UINs - AIM screen
// names like "CoolDude99" must be silently dropped.
func parseUIN(screenName string) (uint32, bool) {
	// Strip spaces (OSCAR normalizes screen names by removing spaces)
	s := strings.ReplaceAll(screenName, " ", "")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint32(v), true
}

// ---------------------------------------------------------------------------
// Status mapping (OSCAR <-> legacy ICQ)
// ---------------------------------------------------------------------------

// oscarStatusToLegacy converts OSCAR status flags to legacy ICQ status value.
// The bit patterns are nearly identical between OSCAR and legacy ICQ, but we
// do an explicit mapping to be safe against future divergence.
//
// OSCAR status bits (wire/snacs.go):
//
//	0x0000 = Available    -> 0x00000000 ICQLegacyStatusOnline
//	0x0001 = Away         -> 0x00000001 ICQLegacyStatusAway
//	0x0002 = DND          -> 0x00000002 ICQLegacyStatusDND
//	0x0004 = Out/NA       -> 0x00000004 ICQLegacyStatusNA
//	0x0010 = Busy         -> 0x00000010 ICQLegacyStatusOccupied
//	0x0020 = Chat/FFC     -> 0x00000020 ICQLegacyStatusFFC
//	0x0100 = Invisible    -> 0x00000100 ICQLegacyStatusInvisible
func oscarStatusToLegacy(oscarStatus uint32) uint32 {
	var legacyStatus uint32

	// ICQ 2003b sends combined status bits:
	//   Available  = 0x00
	//   FFC        = 0x20
	//   Away       = 0x01
	//   N/A        = 0x05 (Away|Out)
	//   Occupied   = 0x11 (Away|Busy)
	//   DND        = 0x13 (Away|DND|Busy)
	// Match exact combined values first, then fall back to bitmask.
	statusByte := oscarStatus & 0xFF
	switch statusByte {
	case 0x00:
		legacyStatus = ICQLegacyStatusOnline
	case 0x01:
		legacyStatus = ICQLegacyStatusAway
	case 0x02:
		legacyStatus = ICQLegacyStatusDND
	case 0x04:
		legacyStatus = ICQLegacyStatusNA
	case 0x05: // Away|Out -> N/A
		legacyStatus = ICQLegacyStatusNA
	case 0x10:
		legacyStatus = ICQLegacyStatusOccupied
	case 0x11: // Away|Busy -> Occupied
		legacyStatus = ICQLegacyStatusOccupied
	case 0x13: // Away|DND|Busy -> DND
		legacyStatus = ICQLegacyStatusDND
	case 0x20:
		legacyStatus = ICQLegacyStatusFFC
	default:
		// Fallback: check bits from most to least specific
		switch {
		case statusByte&0x20 != 0:
			legacyStatus = ICQLegacyStatusFFC
		case statusByte&0x02 != 0 && statusByte&0x10 != 0:
			legacyStatus = ICQLegacyStatusDND
		case statusByte&0x10 != 0:
			legacyStatus = ICQLegacyStatusOccupied
		case statusByte&0x04 != 0:
			legacyStatus = ICQLegacyStatusNA
		case statusByte&0x02 != 0:
			legacyStatus = ICQLegacyStatusDND
		case statusByte&0x01 != 0:
			legacyStatus = ICQLegacyStatusAway
		default:
			legacyStatus = ICQLegacyStatusOnline
		}
	}

	// Map flags
	if oscarStatus&wire.OServiceUserStatusInvisible != 0 {
		legacyStatus |= ICQLegacyStatusInvisible
	}
	if oscarStatus&wire.OServiceUserStatusWebAware != 0 {
		legacyStatus |= ICQLegacyStatusFlagWebAware
	}
	if oscarStatus&wire.OServiceUserStatusBirthday != 0 {
		legacyStatus |= ICQLegacyStatusFlagBirthday
	}
	if oscarStatus&wire.OServiceUserStatusDirectRequireAuth != 0 {
		legacyStatus |= ICQLegacyStatusFlagDCAuth
	}

	return legacyStatus
}

// ---------------------------------------------------------------------------
// Character encoding conversion
// ---------------------------------------------------------------------------

// extractAndConvertICBMText extracts message text from an OSCAR ICBM message,
// handling charset conversion from OSCAR encoding to legacy-compatible text.
//
// OSCAR messages can use three charsets (ICBMCh1Message.Charset):
//   - 0x0000 (ASCII): single-byte, no conversion needed
//   - 0x0002 (Unicode): UCS-2 big-endian, must be converted to single-byte
//   - 0x0003 (Latin-1): single-byte, no conversion needed
//
// Legacy ICQ clients (V2-V5) expect single-byte text. If the message is
// Unicode, we convert to Latin-1 with best-effort transliteration for
// characters outside the Latin-1 range.
func extractAndConvertICBMText(clientMsg wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	switch clientMsg.ChannelID {
	case wire.ICBMChannelIM:
		return extractChannel1Text(clientMsg)
	case wire.ICBMChannelICQ:
		return extractChannel4Text(clientMsg)
	default:
		return ""
	}
}

// extractChannel1Text extracts text from channel 1 (AIM IM) messages.
// Format: TLV 0x0002 (AOLIMData) containing ICBM fragments.
func extractChannel1Text(clientMsg wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	payload, hasPayload := clientMsg.Bytes(wire.ICBMTLVAOLIMData)
	if !hasPayload {
		return ""
	}

	var frags []wire.ICBMCh1Fragment
	if err := wire.UnmarshalBE(&frags, bytes.NewBuffer(payload)); err != nil {
		return ""
	}

	for _, frag := range frags {
		if frag.ID != 1 { // 1 = message text
			continue
		}

		msg := wire.ICBMCh1Message{}
		if err := wire.UnmarshalBE(&msg, bytes.NewBuffer(frag.Payload)); err != nil {
			continue
		}

		switch msg.Charset {
		case wire.ICBMMessageEncodingUnicode:
			return ucs2BEToLatin1(msg.Text)
		default:
			text := string(msg.Text)
			if strings.Contains(text, "<") {
				return stripHTMLSimple(text)
			}
			return text
		}
	}

	return ""
}

// extractChannel4Text extracts text from channel 4 (ICQ) messages.
// Format: TLV 0x0005 (ICBMTLVData) containing ICBMCh4Message (little-endian).
func extractChannel4Text(clientMsg wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	payload, hasPayload := clientMsg.Bytes(wire.ICBMTLVData)
	if !hasPayload {
		return ""
	}

	msg := wire.ICBMCh4Message{}
	if err := wire.UnmarshalLE(&msg, bytes.NewBuffer(payload)); err != nil {
		return ""
	}

	text := msg.Message
	if strings.Contains(text, "<") {
		return stripHTMLSimple(text)
	}
	return text
}

// ucs2BEToLatin1 converts UCS-2 big-endian encoded bytes to a Latin-1 string.
// Characters outside the Latin-1 range (U+0000-U+00FF) are replaced with '?'.
func ucs2BEToLatin1(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	var result []byte
	for i := 0; i+1 < len(data); i += 2 {
		codepoint := binary.BigEndian.Uint16(data[i : i+2])
		if codepoint == 0 {
			continue // skip null
		}
		if codepoint <= 0xFF {
			result = append(result, byte(codepoint))
		} else {
			result = append(result, '?') // outside Latin-1 range
		}
	}

	return string(result)
}

// utf8ToLatin1 converts a UTF-8 string to Latin-1 (ISO 8859-1).
// Characters outside the Latin-1 range are replaced with '?'.
// This is used when delivering messages from OSCAR clients (which use UTF-8
// internally in Go strings) to legacy ICQ clients that expect single-byte text.
func utf8ToLatin1(s string) string {
	// Fast path: if all bytes are ASCII, no conversion needed
	if !utf8.ValidString(s) || isASCII(s) {
		return s
	}

	var result []byte
	for _, r := range s {
		if r <= 0xFF {
			result = append(result, byte(r))
		} else {
			result = append(result, '?')
		}
	}
	return string(result)
}

// isASCII returns true if all bytes in the string are 7-bit ASCII.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

// stripHTMLSimple removes HTML tags from text. This is a minimal
// implementation for the bridge - AIM clients send HTML-formatted messages
// that legacy ICQ clients can't render.
func stripHTMLSimple(s string) string {
	var result strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// Compile-time check that LegacyMessageBridge implements LegacyMessageSender.
var _ LegacyMessageSender = (*LegacyMessageBridge)(nil)
