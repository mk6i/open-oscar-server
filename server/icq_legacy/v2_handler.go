package icq_legacy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/wire"
)

// V2Handler handles ICQ V2 protocol packets
type V2Handler struct {
	BaseHandler
}

// NewV2Handler creates a new V2 protocol handler
func NewV2Handler(
	sessions *LegacySessionManager,
	service LegacyService,
	sender PacketSender,
	logger *slog.Logger,
) *V2Handler {
	return &V2Handler{
		BaseHandler: BaseHandler{
			sessions: sessions,
			service:  service,
			sender:   sender,
			logger:   logger,
		},
	}
}

// SetSender sets the packet sender (for circular dependency resolution)
func (h *V2Handler) SetSender(sender PacketSender) {
	h.sender = sender
}

// Handle processes a V2 protocol packet
func (h *V2Handler) Handle(session *LegacySession, addr *net.UDPAddr, packet []byte) error {
	// Debug: dump raw packet
	h.logger.Debug("raw V2 packet",
		"hex", fmt.Sprintf("%X", packet),
		"len", len(packet),
	)

	pkt, err := wire.UnmarshalV2ClientPacket(packet)
	if err != nil {
		return fmt.Errorf("parsing V2 packet: %w", err)
	}

	h.logger.Debug("V2 packet received",
		"command", fmt.Sprintf("0x%04X", pkt.Command),
		"uin", pkt.UIN,
		"seq", pkt.SeqNum,
		"addr", addr.String(),
		"data_hex", fmt.Sprintf("%X", pkt.Data),
	)

	// Update session activity if we have one
	if session != nil {
		session.UpdateActivity()
		session.SeqNumClient = pkt.SeqNum
	}

	switch pkt.Command {
	case wire.ICQLegacyCmdAck:
		return h.handleAck(session, pkt)
	case wire.ICQLegacyCmdLogin:
		return h.handleLogin(session, addr, pkt)
	case wire.ICQLegacyCmdLogoff:
		return h.handleLogoff(session, pkt)
	case wire.ICQLegacyCmdKeepAlive, wire.ICQLegacyCmdKeepAlive2:
		return h.handleKeepAlive(session, pkt)
	case wire.ICQLegacyCmdContactList:
		return h.handleContactList(session, pkt)
	case wire.ICQLegacyCmdThruServer, wire.ICQLegacyCmdThruServer2:
		return h.handleSendMessage(session, pkt)
	case wire.ICQLegacyCmdSetStatus:
		return h.handleSetStatus(session, pkt)
	case wire.ICQLegacyCmdInfoReq:
		return h.handleInfoReq(session, pkt)
	case wire.ICQLegacyCmdExtInfoReq:
		return h.handleExtInfoReq(session, pkt)
	case wire.ICQLegacyCmdSearchUIN:
		return h.handleSearchUIN(session, pkt)
	case wire.ICQLegacyCmdSearchUser:
		return h.handleSearchUser(session, pkt)
	case wire.ICQLegacyCmdSysMsgReq:
		return h.handleOfflineMsgReq(session, pkt)
	case wire.ICQLegacyCmdSysMsgDoneAck:
		return h.handleOfflineMsgAck(session, pkt)
	case wire.ICQLegacyCmdVisibleList:
		return h.handleVisibleList(session, pkt)
	case wire.ICQLegacyCmdInvisibleList:
		return h.handleInvisibleList(session, pkt)
	case wire.ICQLegacyCmdUserAdd:
		return h.handleUserAdd(session, pkt)
	case wire.ICQLegacyCmdGetDeps:
		// 0x03F2 - Early 1996 client login packet (pre-V2 format)
		// This is NOT "GetDeps" but an early login variant used by 1996 clients
		return h.handleEarlyLogin(session, addr, pkt)
	case wire.ICQLegacyCmdFirstLogin:
		return h.handleFirstLogin(session, addr, pkt)
	default:
		h.logger.Debug("unhandled V2 command",
			"command", fmt.Sprintf("0x%04X", pkt.Command),
			"uin", pkt.UIN,
		)
		// Send ACK for unknown commands to keep client happy
		if session != nil {
			return h.sendAck(session, pkt.SeqNum)
		}
		return nil
	}
}

// handleAck processes an acknowledgment packet
func (h *V2Handler) handleAck(session *LegacySession, pkt *wire.V2ClientPacket) error {
	// ACKs don't require a response
	h.logger.Debug("received ACK", "seq", pkt.SeqNum)
	return nil
}

// handleLogin processes a login request
func (h *V2Handler) handleLogin(session *LegacySession, addr *net.UDPAddr, pkt *wire.V2ClientPacket) error {
	ctx := context.Background()

	loginData, err := wire.ParseV2LoginPacket(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse login packet", "err", err)
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}

	loginData.UIN = pkt.UIN

	h.logger.Info("login attempt",
		"uin", pkt.UIN,
		"ip", loginData.IP,
		"port", loginData.Port,
		"status", loginData.Status,
	)

	// Validate credentials
	valid, err := h.service.ValidateCredentials(ctx, pkt.UIN, loginData.Password)
	if err != nil || !valid {
		h.logger.Info("login failed - invalid credentials", "uin", pkt.UIN)
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}

	// Create session
	newSession, err := h.sessions.CreateSession(pkt.UIN, addr, pkt.Version)
	if err != nil {
		h.logger.Error("failed to create session", "err", err, "uin", pkt.UIN)
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}

	newSession.SetStatus(loginData.Status)
	newSession.Password = loginData.Password

	// Send login success
	if err := h.sendLoginReply(newSession, pkt.SeqNum); err != nil {
		return err
	}

	h.logger.Info("login successful",
		"uin", pkt.UIN,
		"session_id", newSession.SessionID,
	)

	// Notify contacts that user is online
	if err := h.service.NotifyStatusChange(ctx, pkt.UIN, loginData.Status); err != nil {
		h.logger.Debug("failed to notify status change", "err", err)
	}

	return nil
}

// handleLogoff processes a logout request
func (h *V2Handler) handleLogoff(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	h.logger.Info("logout", "uin", session.UIN)

	// Notify contacts that user is offline
	h.sessions.BroadcastToContacts(session, func(contact *LegacySession) {
		h.sendUserOffline(contact, session.UIN)
	})

	// Remove session
	h.sessions.RemoveSession(session.UIN)

	return nil
}

// handleKeepAlive processes a keep-alive ping
func (h *V2Handler) handleKeepAlive(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	// Session activity already updated, just send ACK
	return h.sendAck(session, pkt.SeqNum)
}

// handleContactList processes a contact list update
func (h *V2Handler) handleContactList(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	contactList, err := wire.ParseV2ContactList(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse contact list", "err", err)
		return h.sendAck(session, pkt.SeqNum)
	}

	h.logger.Debug("contact list received",
		"uin", session.UIN,
		"contacts", len(contactList.UINs),
	)

	// Update session contact list
	session.SetContactList(contactList.UINs)

	// Send online status for each contact that is online
	onlineContacts := h.sessions.GetOnlineContacts(session)
	for _, contact := range onlineContacts {
		h.sendUserOnline(session, contact.UIN, contact.GetStatus(), nil, 0)
	}

	// Send contact list done
	return h.sendContactListDone(session, pkt.SeqNum)
}

// handleSendMessage processes a message send request
func (h *V2Handler) handleSendMessage(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	msg, err := wire.ParseV2Message(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse message", "err", err)
		return h.sendAck(session, pkt.SeqNum)
	}

	msg.FromUIN = session.UIN

	h.logger.Debug("message received",
		"from", msg.FromUIN,
		"to", msg.ToUIN,
		"type", msg.MsgType,
	)

	// Send message through service layer
	if err := h.service.SendMessage(ctx, msg.FromUIN, msg.ToUIN, msg.MsgType, msg.Message); err != nil {
		h.logger.Debug("failed to send message", "err", err)
	}

	// Send ACK
	return h.sendAck(session, pkt.SeqNum)
}

// handleSetStatus processes a status change request
func (h *V2Handler) handleSetStatus(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	if len(pkt.Data) < 4 {
		return h.sendAck(session, pkt.SeqNum)
	}

	status := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Debug("status change",
		"uin", session.UIN,
		"status", fmt.Sprintf("0x%08X", status),
	)

	session.SetStatus(status)

	// Notify contacts of status change
	if err := h.service.NotifyStatusChange(ctx, session.UIN, status); err != nil {
		h.logger.Debug("failed to notify status change", "err", err)
	}

	return h.sendAck(session, pkt.SeqNum)
}

// handleInfoReq processes a user info request
func (h *V2Handler) handleInfoReq(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	if len(pkt.Data) < 4 {
		return h.sendAck(session, pkt.SeqNum)
	}

	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Debug("info request",
		"from", session.UIN,
		"target", targetUIN,
	)

	// Get user info
	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err != nil {
		h.logger.Debug("failed to get user info", "err", err)
		return h.sendAck(session, pkt.SeqNum)
	}

	// Send user info response
	return h.sendSearchResult(session, info, true)
}

// handleExtInfoReq processes an extended user info request
func (h *V2Handler) handleExtInfoReq(session *LegacySession, pkt *wire.V2ClientPacket) error {
	// For V2, extended info is same as basic info
	return h.handleInfoReq(session, pkt)
}

// handleSearchUIN processes a search by UIN request
func (h *V2Handler) handleSearchUIN(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	if len(pkt.Data) < 4 {
		return h.sendAck(session, pkt.SeqNum)
	}

	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Debug("search by UIN",
		"from", session.UIN,
		"target", targetUIN,
	)

	// Search for user
	result, err := h.service.SearchByUIN(ctx, targetUIN)
	if err != nil {
		h.logger.Debug("search failed", "err", err)
		// Send empty search result
		return h.sendSearchResult(session, &foodgroup.LegacyUserSearchResult{}, true)
	}

	return h.sendSearchResult(session, result, true)
}

// handleSearchUser processes a search by name/email request
func (h *V2Handler) handleSearchUser(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	// Parse search parameters from packet data
	// Format: nick(len+str) + first(len+str) + last(len+str) + email(len+str)
	// This is a simplified implementation

	h.logger.Debug("search by name/email", "from", session.UIN)

	// For now, send empty result
	// TODO: Parse search parameters and call service
	return h.sendSearchResult(session, &foodgroup.LegacyUserSearchResult{}, true)
}

// handleOfflineMsgReq processes an offline message request
func (h *V2Handler) handleOfflineMsgReq(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	h.logger.Debug("offline message request", "uin", session.UIN)

	// Get offline messages
	messages, err := h.service.GetOfflineMessages(ctx, session.UIN)
	if err != nil {
		h.logger.Debug("failed to get offline messages", "err", err)
	}

	// Send each offline message
	for _, msg := range messages {
		h.sendMessage(session, msg.FromUIN, msg.MsgType, msg.Message)
	}

	// Send end of offline messages
	endPkt := &wire.V2ServerPacket{
		Version: session.Version,
		Command: wire.ICQLegacySrvSysMsgDone,
		SeqNum:  session.NextServerSeqNum(),
	}
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(endPkt))
}

// handleOfflineMsgAck processes an offline message acknowledgment
func (h *V2Handler) handleOfflineMsgAck(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	h.logger.Debug("offline message ack", "uin", session.UIN)

	// Delete offline messages
	if err := h.service.AckOfflineMessages(ctx, session.UIN); err != nil {
		h.logger.Debug("failed to ack offline messages", "err", err)
	}

	return h.sendAck(session, pkt.SeqNum)
}

// handleVisibleList processes a visible list update
func (h *V2Handler) handleVisibleList(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	contactList, err := wire.ParseV2ContactList(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse visible list", "err", err)
		return h.sendAck(session, pkt.SeqNum)
	}

	h.logger.Debug("visible list received",
		"uin", session.UIN,
		"count", len(contactList.UINs),
	)

	session.SetVisibleList(contactList.UINs)
	return h.sendAck(session, pkt.SeqNum)
}

// handleInvisibleList processes an invisible list update
func (h *V2Handler) handleInvisibleList(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	contactList, err := wire.ParseV2ContactList(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse invisible list", "err", err)
		return h.sendAck(session, pkt.SeqNum)
	}

	h.logger.Debug("invisible list received",
		"uin", session.UIN,
		"count", len(contactList.UINs),
	)

	session.SetInvisibleList(contactList.UINs)
	return h.sendAck(session, pkt.SeqNum)
}

// handleUserAdd processes a user add request
func (h *V2Handler) handleUserAdd(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	if len(pkt.Data) < 4 {
		return h.sendAck(session, pkt.SeqNum)
	}

	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Debug("user add",
		"from", session.UIN,
		"target", targetUIN,
	)

	// Add to contact list
	contacts := session.GetContactList()
	contacts = append(contacts, targetUIN)
	session.SetContactList(contacts)

	// Check if target is online and send notification
	targetSession := h.sessions.GetSession(targetUIN)
	if targetSession != nil {
		h.sendUserOnline(session, targetUIN, targetSession.GetStatus(), nil, 0)
	}

	return h.sendAck(session, pkt.SeqNum)
}

// handleFirstLogin processes the initial login setup packet (0x04EC)
// This is sent before the actual login to set up the connection
func (h *V2Handler) handleFirstLogin(session *LegacySession, addr *net.UDPAddr, pkt *wire.V2ClientPacket) error {
	h.logger.Debug("first login packet received",
		"uin", pkt.UIN,
		"addr", addr.String(),
	)

	// The 1996 client sends 0x04EC as a probe/hello packet
	// We need to acknowledge it so the client proceeds with the actual login (0x03F2)
	// Just send ACK - the real login will follow
	ackPkt := &wire.V2ServerPacket{
		Version: pkt.Version,
		Command: wire.ICQLegacySrvAck,
		SeqNum:  pkt.SeqNum,
	}
	return h.sender.SendPacket(addr, wire.MarshalV2ServerPacket(ackPkt))
}

// handleEarlyLogin processes the 1996 client login packet (0x03F2)
// This is an early/pre-V2 login format used by 1996 Mirabilis ICQ clients.
// Packet format (data portion, after 6-byte header):
// - Payload length (2 bytes) - total length of UIN + password fields
// - UIN (4 bytes) - user's ICQ number
// - Password length (2 bytes) - includes null terminator
// - Password (variable) - null-terminated string
// - Status/flags (4 bytes) - initial status
func (h *V2Handler) handleEarlyLogin(session *LegacySession, addr *net.UDPAddr, pkt *wire.V2ClientPacket) error {
	ctx := context.Background()

	h.logger.Debug("early login packet (0x03F2)",
		"addr", addr.String(),
		"data_len", len(pkt.Data),
		"data_hex", fmt.Sprintf("%X", pkt.Data),
	)

	if len(pkt.Data) < 8 {
		h.logger.Debug("early login packet too short")
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}

	offset := 0

	// Read payload length (2 bytes) - skip this, it's just for validation
	payloadLen := binary.LittleEndian.Uint16(pkt.Data[offset : offset+2])
	offset += 2

	h.logger.Debug("parsing early login",
		"payload_len", payloadLen,
		"remaining", len(pkt.Data)-offset,
	)

	// Read UIN (4 bytes)
	if len(pkt.Data) < offset+4 {
		h.logger.Debug("packet too short for UIN")
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}
	uin := binary.LittleEndian.Uint32(pkt.Data[offset : offset+4])
	offset += 4

	// Read password length (2 bytes)
	if len(pkt.Data) < offset+2 {
		h.logger.Debug("packet too short for password length")
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}
	pwdLen := binary.LittleEndian.Uint16(pkt.Data[offset : offset+2])
	offset += 2

	h.logger.Debug("password field",
		"uin", uin,
		"pwd_len", pwdLen,
		"remaining", len(pkt.Data)-offset,
	)

	// Read password
	if len(pkt.Data) < offset+int(pwdLen) || pwdLen == 0 {
		h.logger.Debug("packet too short for password")
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}

	// Strip null terminator if present
	password := string(pkt.Data[offset : offset+int(pwdLen)])
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}
	offset += int(pwdLen)

	// Read status (4 bytes) if present
	var status uint32 = wire.ICQLegacyStatusOnline
	if len(pkt.Data) >= offset+4 {
		status = binary.LittleEndian.Uint32(pkt.Data[offset : offset+4])
	}

	h.logger.Info("early login attempt",
		"uin", uin,
		"password", password,
		"password_len", len(password),
		"status", fmt.Sprintf("0x%08X", status),
	)

	// Validate credentials
	valid, err := h.service.ValidateCredentials(ctx, uin, password)
	if err != nil || !valid {
		h.logger.Info("early login failed - invalid credentials", "uin", uin)
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}

	// Create session
	newSession, err := h.sessions.CreateSession(uin, addr, pkt.Version)
	if err != nil {
		h.logger.Error("failed to create session", "err", err, "uin", uin)
		return h.sendBadPassword(addr, pkt.SeqNum, pkt.Version)
	}

	newSession.SetStatus(status)
	newSession.Password = password

	h.logger.Info("early login successful",
		"uin", uin,
		"session_id", newSession.SessionID,
	)

	// Send login reply (0x005A)
	// The client ACKs this packet, but doesn't transition to connected state
	// Further Ghidra analysis needed to understand why
	if err := h.sendLoginReply(newSession, pkt.SeqNum); err != nil {
		return err
	}

	// Notify contacts that user is online
	if err := h.service.NotifyStatusChange(ctx, uin, status); err != nil {
		h.logger.Debug("failed to notify status change", "err", err)
	}
	return nil
}

// sendDeptsList sends the departments list response for V2 clients
// This is the response to 0x03F2 (GetDeps) - a pseudo-login that validates
// credentials and returns the departments list
// V2 format: VERSION(2) + COMMAND(2) + SEQNUM(2) + UIN(4) + DATA
// Note: The 1996 client may expect UIN in server packets
func (h *V2Handler) sendDeptsList(session *LegacySession, clientSeqNum uint16) error {
	// Build packet data with UIN prefix
	data := make([]byte, 16) // UIN(4) + DEPLIST_VERSION(4) + COUNT(4) + Trailer(4)
	offset := 0

	// UIN (4 bytes) - the 1996 client may expect this
	binary.LittleEndian.PutUint32(data[offset:], session.UIN)
	offset += 4

	// DEPLIST_VERSION (4 bytes)
	binary.LittleEndian.PutUint32(data[offset:], 1)
	offset += 4

	// COUNT (4 bytes) - 0 departments
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	// Trailer (4 bytes) - from iserverd
	binary.LittleEndian.PutUint16(data[offset:], 0x0002)
	binary.LittleEndian.PutUint16(data[offset+2:], 0x002a)

	serverSeq := session.NextServerSeqNum()
	pkt := &wire.V2ServerPacket{
		Version: wire.ICQLegacyVersionV2,
		Command: wire.ICQLegacySrvUserDepsList, // 0x0032
		SeqNum:  serverSeq,
		Data:    data,
	}

	rawPkt := wire.MarshalV2ServerPacket(pkt)
	h.logger.Debug("sending V2 depts list",
		"uin", session.UIN,
		"server_seq", serverSeq,
		"client_seq", clientSeqNum,
		"command", fmt.Sprintf("0x%04X", pkt.Command),
		"raw_hex", fmt.Sprintf("%X", rawPkt),
	)

	return h.sender.SendToSession(session, rawPkt)
}
