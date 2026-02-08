package icq_legacy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/wire"
)

// V2Handler handles ICQ V2 protocol packets
type V2Handler struct {
	BaseHandler
	packetBuilder V2PacketBuilder
	dispatcher    MessageDispatcher
}

// NewV2Handler creates a new V2 protocol handler
func NewV2Handler(
	sessions *LegacySessionManager,
	service LegacyService,
	sender PacketSender,
	packetBuilder V2PacketBuilder,
	logger *slog.Logger,
) *V2Handler {
	return &V2Handler{
		BaseHandler: BaseHandler{
			sessions: sessions,
			service:  service,
			sender:   sender,
			logger:   logger,
		},
		packetBuilder: packetBuilder,
	}
}

// SetSender sets the packet sender (for circular dependency resolution)
func (h *V2Handler) SetSender(sender PacketSender) {
	h.sender = sender
}

// SetDispatcher sets the message dispatcher for cross-protocol message routing
func (h *V2Handler) SetDispatcher(dispatcher MessageDispatcher) {
	h.dispatcher = dispatcher
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

	// If no session exists and this is not a login/registration/ack command,
	// send NOT_CONNECTED to force the client to reconnect.
	if session == nil {
		switch pkt.Command {
		case wire.ICQLegacyCmdAck, wire.ICQLegacyCmdLogin,
			wire.ICQLegacyCmdFirstLogin, wire.ICQLegacyCmdGetDeps,
			wire.ICQLegacyCmdRegNewUser:
			// Allow these through - they don't require a session
		default:
			h.logger.Info("V2 packet from unknown session, sending NOT_CONNECTED",
				"command", fmt.Sprintf("0x%04X", pkt.Command),
				"uin", pkt.UIN,
				"addr", addr.String(),
			)
			return h.sendNotConnectedToAddr(addr, pkt.SeqNum)
		}
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
	case wire.ICQLegacyCmdThruServer:
		return h.handleSendMessage(session, pkt)
	case wire.ICQLegacyCmdAuthorize:
		return h.handleAuthorize(session, pkt)
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
	case wire.ICQLegacyCmdUpdateBasic:
		return h.handleUpdateBasic(session, pkt)
	case wire.ICQLegacyCmdUpdateDetail:
		return h.handleUpdateDetail(session, pkt)
	case wire.ICQLegacyCmdGetDeps:
		// 0x03F2 - Pre-auth pseudo-login (historically "get departments list" in iserverd).
		// Some clients send version=2 in the header but use V3 packet structure.
		// We re-parse the raw packet as V3 format (12-byte header) inline.
		return h.handleGetDeps(addr, packet)
	case wire.ICQLegacyCmdFirstLogin:
		return h.handleFirstLogin(session, addr, pkt)
	case wire.ICQLegacyCmdRegNewUser:
		return h.handleRegNewUser(addr, pkt)
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
// Refactored to use service layer (AuthenticateUser) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> build response
func (h *V2Handler) handleLogin(session *LegacySession, addr *net.UDPAddr, pkt *wire.V2ClientPacket) error {
	ctx := context.Background()

	// 1. Unmarshal packet to typed struct
	loginData, err := wire.ParseV2LoginPacket(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse login packet", "err", err)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SeqNum, pkt.Version))
	}

	loginData.UIN = pkt.UIN

	h.logger.Info("login attempt",
		"uin", pkt.UIN,
		"ip", loginData.IP,
		"port", loginData.Port,
		"status", loginData.Status,
	)

	// 2. Call service layer with typed request
	authReq := foodgroup.AuthRequest{
		UIN:      pkt.UIN,
		Password: loginData.Password,
		Status:   loginData.Status,
		TCPPort:  uint32(loginData.Port),
		Version:  pkt.Version,
	}

	authResult, err := h.service.AuthenticateUser(ctx, authReq)
	if err != nil {
		h.logger.Error("authentication error", "err", err, "uin", pkt.UIN)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SeqNum, pkt.Version))
	}

	if !authResult.Success {
		h.logger.Info("login failed - invalid credentials", "uin", pkt.UIN, "error_code", authResult.ErrorCode)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SeqNum, pkt.Version))
	}

	// 3. Create session (handler responsibility - session management)
	newSession, err := h.sessions.CreateSession(pkt.UIN, addr, pkt.Version)
	if err != nil {
		h.logger.Error("failed to create session", "err", err, "uin", pkt.UIN)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SeqNum, pkt.Version))
	}

	newSession.SetStatus(loginData.Status)
	newSession.Password = loginData.Password

	// 4. Send ACK first, then login reply
	ackPkt := h.packetBuilder.BuildAck(pkt.SeqNum, pkt.Version)
	if err := h.sender.SendToSession(newSession, ackPkt); err != nil {
		return err
	}


	// 5. Build and send login reply using packet builder
	loginReplyPkt := h.packetBuilder.BuildLoginReply(newSession, pkt.SeqNum)
	if err := h.sender.SendToSession(newSession, loginReplyPkt); err != nil {
		return err
	}

	// NOTE: Do NOT send SRV_USER_LIST_DONE or SRV_SYS_MSG_DONE here.
	// The client (center-1.10.7) sends CMD_LOGIN_1/CMD_SYS_MSG_REQ (0x044C),
	// CMD_CONTACT_LIST (0x0406), and CMD_VISIBLE_LIST (0x06AE) after receiving
	// the login reply. SRV_USER_LIST_DONE and SRV_SYS_MSG_DONE are sent as
	// responses to those client-initiated packets (in handleContactList and
	// handleOfflineMsgReq respectively). Sending them proactively here causes
	// the client to receive unsolicited packets before it's ready.

	h.logger.Info("login successful",
		"uin", pkt.UIN,
		"session_id", newSession.SessionID,
	)

	// 5. Notify contacts that user is online (via service layer)
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

// sendNotConnectedToAddr sends a NOT_CONNECTED (0x00F0) response to a V2 client
// address that has no session. This forces the client to reconnect.
// Uses V2 server packet format: VERSION(2) + COMMAND(2) + SEQ(2)
func (h *V2Handler) sendNotConnectedToAddr(addr *net.UDPAddr, seqNum uint16) error {
	pkt := wire.MarshalV2ServerPacket(&wire.V2ServerPacket{
		Version: wire.ICQLegacyVersionV2,
		Command: wire.ICQLegacySrvNotConnected,
		SeqNum:  seqNum,
	})
	return h.sender.SendPacket(addr, pkt)
}

// handleKeepAlive processes a keep-alive ping
func (h *V2Handler) handleKeepAlive(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil // Already handled by the session-nil guard above
	}

	// Session activity already updated, just send ACK
	return h.sendAck(session, pkt.SeqNum)
}

// handleContactList processes a contact list update
// Refactored to use service layer (ProcessContactList) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> build response
//
// IMPORTANT: The client uses SendExpectEvent() which retransmits until it
// receives SRV_ACK with the matching sequence number. We must send ACK first,
// then the data responses. Without the ACK, the client retransmits in a loop.
func (h *V2Handler) handleContactList(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first to stop client retransmission
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// 1. Unmarshal packet to typed struct
	contactList, err := wire.ParseV2ContactList(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse contact list", "err", err)
		return nil
	}

	h.logger.Debug("contact list received",
		"uin", session.UIN,
		"contacts", len(contactList.UINs),
	)

	// Update session contact list (handler responsibility - session management)
	session.SetContactList(contactList.UINs)

	// 2. Call service layer with typed request
	contactReq := foodgroup.ContactListRequest{
		UIN:      session.UIN,
		Contacts: contactList.UINs,
	}

	contactResult, err := h.service.ProcessContactList(ctx, contactReq)
	if err != nil {
		h.logger.Debug("failed to process contact list", "err", err)
		// Still send contact list done even on error
		return h.sender.SendToSession(session, h.packetBuilder.BuildContactListDone(session.NextServerSeqNum()))
	}

	// 3. Build and send responses using packet builder
	// Send online status for each contact that is online
	for _, contact := range contactResult.OnlineContacts {
		if contact.Online {
			onlinePkt := h.packetBuilder.BuildUserOnline(
				session.NextServerSeqNum(),
				contact.UIN,
				contact.Status,
				nil, // IP not available from service layer
				0,   // Port not available from service layer
			)
			h.sender.SendToSession(session, onlinePkt)
		}
	}

	// 4. Send contact list done using packet builder
	return h.sender.SendToSession(session, h.packetBuilder.BuildContactListDone(session.NextServerSeqNum()))
}

// handleSendMessage processes a message send request
// Refactored to use service layer (ProcessMessage) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> build response
//
// IMPORTANT: The client uses SendExpectEvent() which retransmits until it
// receives SRV_ACK with the matching sequence number. We must send ACK
// to stop the retransmission loop.
func (h *V2Handler) handleSendMessage(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first to stop client retransmission
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// 1. Unmarshal packet to typed struct
	msg, err := wire.ParseV2Message(pkt.Data)
	if err != nil {
		h.logger.Debug("failed to parse message", "err", err)
		return nil
	}

	msg.FromUIN = session.UIN

	h.logger.Debug("message received",
		"from", msg.FromUIN,
		"to", msg.ToUIN,
		"type", msg.MsgType,
	)

	// 2. Call service layer with typed request
	msgReq := foodgroup.MessageRequest{
		FromUIN: msg.FromUIN,
		ToUIN:   msg.ToUIN,
		MsgType: msg.MsgType,
		Message: msg.Message,
	}

	msgResult, err := h.service.ProcessMessage(ctx, msgReq)
	if err != nil {
		h.logger.Debug("failed to process message", "err", err)
	} else {
		h.logger.Debug("message processed",
			"from", msg.FromUIN,
			"to", msg.ToUIN,
			"delivered", msgResult.Delivered,
			"stored_offline", msgResult.StoredOffline,
			"target_online", msgResult.TargetOnline,
		)

		// Deliver message to target if online via legacy protocol
		if msgResult.TargetOnline {
			targetSession := h.sessions.GetSession(msg.ToUIN)
			if targetSession != nil {
				if h.dispatcher != nil {
					h.dispatcher.SendOnlineMessage(targetSession, msg.FromUIN, msg.MsgType, msg.Message)
				} else {
					h.sendMessage(targetSession, msg.FromUIN, msg.MsgType, msg.Message)
				}
			}
		}
	}

	return nil
}

// handleSetStatus processes a status change request
// Refactored to use service layer (ProcessStatusChange) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> build response
//
// IMPORTANT: The client uses SendExpectEvent() which retransmits until it
// receives SRV_ACK with the matching sequence number. We must send ACK first.
func (h *V2Handler) handleSetStatus(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first to stop client retransmission
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// 1. Unmarshal packet to typed struct
	if len(pkt.Data) < 4 {
		return nil
	}

	newStatus := binary.LittleEndian.Uint32(pkt.Data[0:4])
	oldStatus := session.GetStatus()

	h.logger.Debug("status change",
		"uin", session.UIN,
		"old_status", fmt.Sprintf("0x%08X", oldStatus),
		"new_status", fmt.Sprintf("0x%08X", newStatus),
	)

	// Update session status (handler responsibility - session management)
	session.SetStatus(newStatus)

	// 2. Call service layer with typed request
	statusReq := foodgroup.StatusChangeRequest{
		UIN:       session.UIN,
		NewStatus: newStatus,
		OldStatus: oldStatus,
	}

	statusResult, err := h.service.ProcessStatusChange(ctx, statusReq)
	if err != nil {
		h.logger.Debug("failed to process status change", "err", err)
	} else {
		h.logger.Debug("status change processed",
			"uin", session.UIN,
			"notify_count", len(statusResult.NotifyTargets),
		)

		// 3. Send status notifications to contacts using packet builder
		// The service layer returns the list of users to notify
		for _, target := range statusResult.NotifyTargets {
			targetSession := h.sessions.GetSession(target.UIN)
			if targetSession != nil {
				statusPkt := h.packetBuilder.BuildStatusUpdate(
					targetSession.NextServerSeqNum(),
					session.UIN,
					newStatus,
				)
				h.sender.SendToSession(targetSession, statusPkt)
			}
		}
	}

	return nil
}

// handleInfoReq processes a user info request
// Client sends: SEQ(2) + UIN(4) as data (from center-1.10.7 icq_SendInfoReq)
// Server responds with SRV_INFO_REPLY (0x0118)
//
// IMPORTANT: This is an "extended event" in the client. The client's retry
// thread is cancelled by SRV_ACK, which moves the event to the extended event
// list. Then SRV_INFO_REPLY calls DoneExtendedEvent() to complete it.
// Without the ACK, the client retransmits AND DoneExtendedEvent can't find
// the event (it was never moved from running to extended).
func (h *V2Handler) handleInfoReq(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first - required for extended events
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// Client sends SEQ(2) + UIN(4) = 6 bytes minimum
	if len(pkt.Data) < 6 {
		return nil
	}

	// Skip SEQ prefix (2 bytes), read UIN at offset 2
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[2:6])

	h.logger.Debug("info request",
		"from", session.UIN,
		"target", targetUIN,
	)

	// Get user info
	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err != nil {
		h.logger.Debug("failed to get user info", "err", err)
		return nil
	}

	// Build and send SRV_INFO_REPLY (0x0118)
	wireInfo := &wire.LegacyUserInfo{
		UIN:       info.UIN,
		Nickname:  truncateField(info.Nickname, 20, h.logger, "nickname", info.UIN),
		FirstName: truncateField(info.FirstName, 64, h.logger, "first_name", info.UIN),
		LastName:  truncateField(info.LastName, 64, h.logger, "last_name", info.UIN),
		Email:     truncateField(info.Email, 64, h.logger, "email", info.UIN),
		Auth:      info.AuthRequired,
	}
	replyPkt := wire.BuildV2InfoReply(session.NextServerSeqNum(), wireInfo)
	replyPkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(replyPkt))
}

// handleExtInfoReq processes an extended user info request
// Client sends: SEQ(2) + UIN(4) as data (from center-1.10.7 icq_SendExtInfoReq)
// Server responds with SRV_EXT_INFO_REPLY (0x0122)
//
// IMPORTANT: This is an "extended event" in the client - ACK must be sent
// first to move the event from running to extended list, then the data reply
// completes it via DoneExtendedEvent().
func (h *V2Handler) handleExtInfoReq(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first - required for extended events
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// Client sends SEQ(2) + UIN(4) = 6 bytes minimum
	if len(pkt.Data) < 6 {
		return nil
	}

	// Skip SEQ prefix (2 bytes), read UIN at offset 2
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[2:6])

	h.logger.Debug("ext info request",
		"from", session.UIN,
		"target", targetUIN,
	)

	// Get full user info for extended fields
	user, err := h.service.GetFullUserInfo(ctx, targetUIN)
	if err != nil {
		h.logger.Debug("failed to get full user info", "err", err)
		return nil
	}

	// Build and send SRV_EXT_INFO_REPLY (0x0122)
	wireInfo := &wire.LegacyUserInfo{
		UIN:      targetUIN,
		City:     truncateField(user.ICQBasicInfo.City, 64, h.logger, "city", targetUIN),
		State:    truncateField(user.ICQBasicInfo.State, 64, h.logger, "state", targetUIN),
		Country:  user.ICQBasicInfo.CountryCode,
		Phone:    truncateField(user.ICQBasicInfo.CellPhone, 30, h.logger, "phone", targetUIN),
		Homepage: truncateField(user.ICQMoreInfo.HomePageAddr, 127, h.logger, "homepage", targetUIN),
		About:    truncateField(user.ICQNotes.Notes, 450, h.logger, "about", targetUIN),
		Age:      user.Age(time.Now),
		Gender:   uint8(user.ICQMoreInfo.Gender),
	}
	replyPkt := wire.BuildV2ExtInfoReply(session.NextServerSeqNum(), wireInfo)
	replyPkt.Version = session.Version
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(replyPkt))
}

// handleSearchUIN processes a search by UIN request
// Client sends: SEQ(2) + UIN(4) as data (from center-1.10.7 icq_SendSearchUINReq)
//
// IMPORTANT: This is an "extended event" in the client - ACK must be sent
// first to move the event from running to extended list.
func (h *V2Handler) handleSearchUIN(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first - required for extended events
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// Client sends SEQ(2) + UIN(4) = 6 bytes minimum
	if len(pkt.Data) < 6 {
		return h.sendSearchResult(session, &foodgroup.LegacyUserSearchResult{}, true)
	}

	// Skip SEQ prefix (2 bytes), read UIN at offset 2
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[2:6])

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
// Client sends: SEQ(2) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST + LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL
// (from center-1.10.7 icq_SendSearchReq)
//
// IMPORTANT: This is an "extended event" in the client - ACK must be sent
// first to move the event from running to extended list.
func (h *V2Handler) handleSearchUser(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first - required for extended events
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	h.logger.Debug("search by name/email", "from", session.UIN)

	// Need at least SEQ(2) + one length-prefixed string
	if len(pkt.Data) < 4 {
		return h.sendSearchResult(session, &foodgroup.LegacyUserSearchResult{}, true)
	}

	// Skip SEQ prefix (2 bytes)
	r := bytes.NewReader(pkt.Data[2:])

	nick, _ := wire.ParseLegacyString(r, true)
	first, _ := wire.ParseLegacyString(r, true)
	last, _ := wire.ParseLegacyString(r, true)
	email, _ := wire.ParseLegacyString(r, true)

	h.logger.Debug("search params",
		"nick", nick,
		"first", first,
		"last", last,
		"email", email,
	)

	results, err := h.service.SearchByName(ctx, nick, first, last, email)
	if err != nil {
		h.logger.Debug("search failed", "err", err)
		return h.sendSearchResult(session, &foodgroup.LegacyUserSearchResult{}, true)
	}

	// Send each result
	for i, result := range results {
		isLast := i == len(results)-1
		r := result // copy for pointer
		if err := h.sendSearchResult(session, &r, isLast); err != nil {
			return err
		}
	}

	// If no results, send empty done
	if len(results) == 0 {
		return h.sendSearchResult(session, &foodgroup.LegacyUserSearchResult{}, true)
	}

	return nil
}

// handleOfflineMsgReq processes an offline message request
//
// IMPORTANT: The client uses SendExpectEvent() which retransmits until it
// receives SRV_ACK with the matching sequence number. We must send ACK first.
// Then offline messages must use SRV_SYS_MSG_OFFLINE (0x00DC) with timestamp
// fields, NOT SRV_SYS_MSG_ONLINE (0x0104). The client parses the timestamp
// from 0x00DC packets to show when the message was originally sent.
func (h *V2Handler) handleOfflineMsgReq(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first to stop client retransmission
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	h.logger.Debug("offline message request", "uin", session.UIN)

	// Get offline messages
	messages, err := h.service.GetOfflineMessages(ctx, session.UIN)
	if err != nil {
		h.logger.Debug("failed to get offline messages", "err", err)
	}

	// Send each offline message using SRV_SYS_MSG_OFFLINE (0x00DC) with timestamp
	for _, msg := range messages {
		ts := msg.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		offlinePkt := wire.BuildV2OfflineMessage(session.NextServerSeqNum(), msg.FromUIN, msg.MsgType, msg.Message, ts)
		offlinePkt.Version = session.Version
		if err := h.sender.SendToSession(session, wire.MarshalV2ServerPacket(offlinePkt)); err != nil {
			h.logger.Debug("failed to send offline message", "err", err)
		}
	}

	// Send end of offline messages (SRV_SYS_MSG_DONE 0x00E6)
	endPkt := &wire.V2ServerPacket{
		Version: session.Version,
		Command: wire.ICQLegacySrvSysMsgDone,
		SeqNum:  session.NextServerSeqNum(),
	}
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(endPkt))
}

// handleOfflineMsgAck processes an offline message acknowledgment
//
// IMPORTANT: The client uses SendExpectEvent() which retransmits until it
// receives SRV_ACK with the matching sequence number. We must send ACK first,
// then do the work (delete offline messages).
func (h *V2Handler) handleOfflineMsgAck(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	ctx := context.Background()

	// Send ACK first to stop client retransmission
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	h.logger.Debug("offline message ack", "uin", session.UIN)

	// Delete offline messages
	if err := h.service.AckOfflineMessages(ctx, session.UIN); err != nil {
		h.logger.Debug("failed to ack offline messages", "err", err)
	}

	return nil
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
//
// IMPORTANT: The client uses SendExpectEvent() which retransmits until it
// receives SRV_ACK with the matching sequence number. We must send ACK first,
// then do the work (add to contact list, check online status, send notification).
func (h *V2Handler) handleUserAdd(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	// Send ACK first to stop client retransmission
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	if len(pkt.Data) < 4 {
		return nil
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

		// Also send the adder's online status to the target.
		// The target won't see the adder as online unless we tell them.
		if h.dispatcher != nil {
			h.dispatcher.SendUserOnline(targetSession, session.UIN, session.GetStatus())
		} else {
			h.sendUserOnline(targetSession, session.UIN, session.GetStatus(), nil, 0)
		}
	}

	return nil
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

// handleGetDeps processes the pre-auth pseudo-login packet (0x03F2).
// Historically called "get departments list" in iserverd (from its Users_Deps database table).
// The server validates credentials, sends V3-format ACK, then sends the pre-auth response (0x0032).
// The client then proceeds with the actual login (0x03E8).
//
// IMPORTANT: Even though the client sends version=2 in the header, this packet
// uses V3 packet structure (12-byte header with seq1, seq2, UIN). The response
// packets (ACK and depslist) are also V3 format, matching iserverd behavior.
//
// Raw packet layout (V3 header):
//   VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + DATA...
// Data layout:
//   PWD_LEN(2) + PASSWORD(pwdLen) + STATUS(4)
func (h *V2Handler) handleGetDeps(addr *net.UDPAddr, packet []byte) error {
	ctx := context.Background()

	if len(packet) < 14 { // 12-byte V3 header + at least 2 bytes for pwd_len
		h.logger.Debug("getdeps packet too short", "len", len(packet))
		return nil
	}

	// Parse as V3 header (12 bytes)
	seq1 := binary.LittleEndian.Uint16(packet[4:6])
	seq2 := binary.LittleEndian.Uint16(packet[6:8])
	uin := binary.LittleEndian.Uint32(packet[8:12])
	data := packet[12:]

	h.logger.Debug("getdeps packet (0x03F2)",
		"addr", addr.String(),
		"seq1", seq1,
		"seq2", seq2,
		"uin", uin,
		"data_len", len(data),
		"data_hex", fmt.Sprintf("%X", data),
	)

	// Parse password from data
	offset := 0
	if len(data) < 2 {
		return nil
	}
	pwdLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	if pwdLen == 0 || pwdLen > 20 || offset+int(pwdLen) > len(data) {
		h.logger.Debug("invalid password in getdeps", "pwd_len", pwdLen)
		return h.sendBadPassword(addr, seq1, 2)
	}

	password := string(data[offset : offset+int(pwdLen)])
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}

	h.logger.Info("getdeps (pseudo-login)",
		"uin", uin,
		"password_len", len(password),
	)

	// Validate credentials - do NOT create a session
	valid, err := h.service.ValidateCredentials(ctx, uin, password)
	if err != nil || !valid {
		h.logger.Info("getdeps failed - invalid credentials", "uin", uin)
		return h.sendBadPassword(addr, seq1, 2)
	}

	h.logger.Debug("credentials validated successfully", "uin", uin)


	// Send V3-format ACK (16 bytes)
	ackPkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(ackPkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(ackPkt[2:4], wire.ICQLegacySrvAck)
	binary.LittleEndian.PutUint16(ackPkt[4:6], seq1)
	binary.LittleEndian.PutUint16(ackPkt[6:8], seq2)
	binary.LittleEndian.PutUint32(ackPkt[8:12], uin)
	binary.LittleEndian.PutUint32(ackPkt[12:16], 0)
	if err := h.sender.SendPacket(addr, ackPkt); err != nil {
		return err
	}

	// Send V3-format depslist (0x0032)
	depsPkt := h.packetBuilder.BuildDepsList(seq2, uin)
	return h.sender.SendPacket(addr, depsPkt)
}

// handleAuthorize processes an authorization grant (CMD_AUTHORIZE 0x0456)
// Client sends: UIN(4) + X1(5) as data (from licq CPU_Authorize)
// The server ACKs and the authorized user is notified.
//
// IMPORTANT: In V2, 0x0456 is AUTHORIZE, not "send message through server".
// The V3/V4/V5 handlers route this to handleMessage which is also acceptable
// since the authorize packet structure is similar to a message, but for V2
// we handle it explicitly.
func (h *V2Handler) handleAuthorize(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	// Send ACK first to stop client retransmission
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	if len(pkt.Data) < 4 {
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Debug("authorize user",
		"from", session.UIN,
		"target", targetUIN,
	)

	// TODO: Implement authorization grant via service layer
	// For now, just ACK - the authorization system is not yet implemented

	return nil
}

// handleUpdateBasic processes a basic profile update (CMD_UPDATExBASIC 0x04A6)
// Client sends: SEQ(2) + ALIAS_LEN(2) + ALIAS + FIRST_LEN(2) + FIRST +
//               LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL + AUTH(1)
// Server responds with SRV_UPDATEDxBASIC (0x00B4) containing SEQ(2) on success,
// or SRV_UPDATExBASICxFAIL (0x00BE) on failure.
//
// IMPORTANT: This is an "extended event" - ACK moves it from running to
// extended list, then the response completes it via DoneExtendedEvent().
func (h *V2Handler) handleUpdateBasic(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	// Send ACK first - required for extended events
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// Need at least SEQ(2) + one length-prefixed string
	if len(pkt.Data) < 4 {
		return h.sendUpdateBasicFail(session, 0)
	}

	// Read the update sequence (2 bytes)
	updateSeq := binary.LittleEndian.Uint16(pkt.Data[0:2])
	r := bytes.NewReader(pkt.Data[2:])

	alias, _ := wire.ParseLegacyString(r, true)
	firstName, _ := wire.ParseLegacyString(r, true)
	lastName, _ := wire.ParseLegacyString(r, true)
	email, _ := wire.ParseLegacyString(r, true)

	var auth uint8
	binary.Read(r, binary.LittleEndian, &auth)

	h.logger.Debug("update basic info",
		"uin", session.UIN,
		"alias", alias,
		"first", firstName,
		"last", lastName,
		"email", email,
		"auth", auth,
	)

	// TODO: Persist via service layer (see docs/TODO_LEGACY_PROFILE_SET.md)
	// For now, send success ACK so the client doesn't hang

	// Send SRV_UPDATEDxBASIC (0x00B4) with the update sequence
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data[0:2], updateSeq)
	replyPkt := &wire.V2ServerPacket{
		Version: session.Version,
		Command: wire.ICQLegacySrvUpdatedBasic,
		SeqNum:  session.NextServerSeqNum(),
		Data:    data,
	}
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(replyPkt))
}

// sendUpdateBasicFail sends SRV_UPDATExBASICxFAIL (0x00BE)
func (h *V2Handler) sendUpdateBasicFail(session *LegacySession, updateSeq uint16) error {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data[0:2], updateSeq)
	pkt := &wire.V2ServerPacket{
		Version: session.Version,
		Command: wire.ICQLegacySrvUpdateBasicFail,
		SeqNum:  session.NextServerSeqNum(),
		Data:    data,
	}
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// handleUpdateDetail processes an extended profile update (CMD_UPDATExDETAIL 0x04B0)
// Client sends: SEQ(2) + CITY_LEN(2) + CITY + COUNTRY(2) + COUNTRY_STAT(1) +
//               STATE_LEN(2) + STATE + AGE(2) + SEX(1) + PHONE_LEN(2) + PHONE +
//               HP_LEN(2) + HP + ABOUT_LEN(2) + ABOUT
// Server responds with SRV_UPDATEDxDETAIL (0x00C8) containing SEQ(2) on success,
// or SRV_UPDATExDETAILxFAIL (0x00D2) on failure.
//
// IMPORTANT: This is an "extended event" - ACK moves it from running to
// extended list, then the response completes it via DoneExtendedEvent().
func (h *V2Handler) handleUpdateDetail(session *LegacySession, pkt *wire.V2ClientPacket) error {
	if session == nil {
		return nil
	}

	// Send ACK first - required for extended events
	if err := h.sendAck(session, pkt.SeqNum); err != nil {
		return err
	}

	// Need at least SEQ(2) + one length-prefixed string
	if len(pkt.Data) < 4 {
		return h.sendUpdateDetailFail(session, 0)
	}

	// Read the update sequence (2 bytes)
	updateSeq := binary.LittleEndian.Uint16(pkt.Data[0:2])
	r := bytes.NewReader(pkt.Data[2:])

	city, _ := wire.ParseLegacyString(r, true)
	var country uint16
	binary.Read(r, binary.LittleEndian, &country)
	var countryStat uint8
	binary.Read(r, binary.LittleEndian, &countryStat)
	state, _ := wire.ParseLegacyString(r, true)
	var age uint16
	binary.Read(r, binary.LittleEndian, &age)
	var sex uint8
	binary.Read(r, binary.LittleEndian, &sex)
	phone, _ := wire.ParseLegacyString(r, true)
	homepage, _ := wire.ParseLegacyString(r, true)
	about, _ := wire.ParseLegacyString(r, true)

	h.logger.Debug("update detail info",
		"uin", session.UIN,
		"city", city,
		"country", country,
		"state", state,
		"age", age,
		"sex", sex,
		"phone", phone,
		"homepage", homepage,
		"about", about,
	)

	// TODO: Persist via service layer (see docs/TODO_LEGACY_PROFILE_SET.md)
	// For now, send success ACK so the client doesn't hang

	// Send SRV_UPDATEDxDETAIL (0x00C8) with the update sequence
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data[0:2], updateSeq)
	replyPkt := &wire.V2ServerPacket{
		Version: session.Version,
		Command: wire.ICQLegacySrvUpdatedDetail,
		SeqNum:  session.NextServerSeqNum(),
		Data:    data,
	}
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(replyPkt))
}

// sendUpdateDetailFail sends SRV_UPDATExDETAILxFAIL (0x00D2)
func (h *V2Handler) sendUpdateDetailFail(session *LegacySession, updateSeq uint16) error {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data[0:2], updateSeq)
	pkt := &wire.V2ServerPacket{
		Version: session.Version,
		Command: wire.ICQLegacySrvUpdateDetailFail,
		SeqNum:  session.NextServerSeqNum(),
		Data:    data,
	}
	return h.sender.SendToSession(session, wire.MarshalV2ServerPacket(pkt))
}

// handleRegNewUser processes a CMD_REG_NEW_USER (0x03FC) registration packet.
// This uses the srv_net_icq_pak format (6-byte header, no UIN).
// Data format from center icq_RegNewUser():
//   CONST(2) + PWD_LEN(2) + PASSWORD(variable, null-terminated) + TRAILING(8)
// Server responds with SRV_NEW_UIN (0x0046) containing the new UIN.
func (h *V2Handler) handleRegNewUser(addr *net.UDPAddr, pkt *wire.V2ClientPacket) error {
	ctx := context.Background()

	h.logger.Debug("registration packet (0x03FC)",
		"addr", addr.String(),
		"data_len", len(pkt.Data),
		"data_hex", fmt.Sprintf("%X", pkt.Data),
	)

	// Need at least: CONST(2) + PWD_LEN(2) + 1 byte password + null
	if len(pkt.Data) < 6 {
		h.logger.Debug("registration packet too short")
		return nil
	}

	offset := 2 // skip 2-byte constant

	// Read password length (2 bytes)
	pwdLen := binary.LittleEndian.Uint16(pkt.Data[offset : offset+2])
	offset += 2

	if pwdLen == 0 || len(pkt.Data) < offset+int(pwdLen) {
		h.logger.Debug("invalid password length in registration", "pwd_len", pwdLen)
		return nil
	}

	// Read password, strip null terminator
	password := string(pkt.Data[offset : offset+int(pwdLen)])
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}

	h.logger.Info("registration attempt",
		"addr", addr.String(),
		"password_len", len(password),
	)

	// Call service layer to create the new user
	newUIN, err := h.service.RegisterNewUser(ctx, "", "", "", "", password)
	if err != nil {
		h.logger.Error("registration failed", "err", err)
		return nil
	}

	h.logger.Info("registration successful",
		"new_uin", newUIN,
		"addr", addr.String(),
	)

	// Send SRV_NEW_UIN (0x0046) response
	replyPkt := wire.BuildV2NewUIN(pkt.SeqNum, newUIN)
	replyBytes := wire.MarshalV2ServerPacket(replyPkt)
	h.logger.Debug("sending SRV_NEW_UIN",
		"new_uin", newUIN,
		"seq", pkt.SeqNum,
		"raw_hex", fmt.Sprintf("%X", replyBytes),
	)
	return h.sender.SendPacket(addr, replyBytes)
}


