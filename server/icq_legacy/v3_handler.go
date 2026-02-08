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

// V3Handler handles ICQ V3 protocol packets
// V3 packet format (from iserverd source):
// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + DATA...
// Total header: 12 bytes (NO checksum in V3, unlike V5!)
type V3Handler struct {
	sessions   *LegacySessionManager
	service    LegacyService
	sender     PacketSender
	dispatcher MessageDispatcher // Central dispatcher for cross-protocol messaging
	logger     *slog.Logger
}

// NewV3Handler creates a new V3 protocol handler
func NewV3Handler(
	sessions *LegacySessionManager,
	service LegacyService,
	sender PacketSender,
	logger *slog.Logger,
) *V3Handler {
	return &V3Handler{
		sessions:   sessions,
		service:    service,
		sender:     sender,
		dispatcher: nil, // Set later via SetDispatcher to avoid circular dependency
		logger:     logger,
	}
}

// SetSender sets the packet sender (for circular dependency resolution)
func (h *V3Handler) SetSender(sender PacketSender) {
	h.sender = sender
}

// SetDispatcher sets the message dispatcher for cross-protocol messaging
func (h *V3Handler) SetDispatcher(dispatcher MessageDispatcher) {
	h.dispatcher = dispatcher
}

// Handle processes a V3 protocol packet
func (h *V3Handler) Handle(session *LegacySession, addr *net.UDPAddr, packet []byte) error {
	// V3 packet format (from iserverd source):
	// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + DATA...
	// Total header: 12 bytes (NO checksum in V3!)

	h.logger.Debug("raw V3 packet",
		"hex", fmt.Sprintf("%X", packet),
		"len", len(packet),
	)

	if len(packet) < 12 {
		return fmt.Errorf("V3 packet too short: %d bytes", len(packet))
	}

	// Parse V3 header directly (iserverd: pack >> vvers >> pcomm >> seq1 >> seq2 >> uin_num)
	version := binary.LittleEndian.Uint16(packet[0:2])
	command := binary.LittleEndian.Uint16(packet[2:4])
	seq1 := binary.LittleEndian.Uint16(packet[4:6])
	seq2 := binary.LittleEndian.Uint16(packet[6:8])
	uin := binary.LittleEndian.Uint32(packet[8:12])

	// Extract data after header
	var data []byte
	if len(packet) > 12 {
		data = packet[12:]
	}

	h.logger.Debug("V3 packet parsed",
		"version", version,
		"command", fmt.Sprintf("0x%04X", command),
		"seq1", seq1,
		"seq2", seq2,
		"uin", uin,
		"data_len", len(data),
	)

	// Update session activity if we have one
	if session != nil {
		session.UpdateActivity()
		session.SeqNumClient = seq1
	}

	// Handle V3 commands directly (matching iserverd's handle_v3_proto)
	switch command {
	case wire.ICQLegacyCmdFirstLogin:
		return h.handleFirstLogin(addr, seq1, seq2, uin)
	case wire.ICQLegacyCmdLogin:
		return h.handleLogin(session, addr, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdGetDeps:
		return h.handleGetDeps(addr, seq1, seq2, data)
	case wire.ICQLegacyCmdUserGetInfo:
		return h.handleGetInfo(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdAck:
		h.logger.Debug("received ACK", "seq1", seq1, "seq2", seq2)
		return nil
	case wire.ICQLegacyCmdKeepAlive, wire.ICQLegacyCmdKeepAlive2:
		return h.handlePing(session, addr, seq1, seq2, uin)
	case wire.ICQLegacyCmdLogoff:
		return h.handleLogoff(session, seq1, seq2, uin)
	case wire.ICQLegacyCmdContactList:
		return h.handleContactList(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdSetStatus:
		return h.handleSetStatus(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdThruServer, wire.ICQLegacyCmdThruServer2: // 0x010E and 0x0456 (auth request)
		return h.handleMessage(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdUserAdd:
		return h.handleUserAdd(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdSysMsgReq:
		return h.handleOfflineMsgReq(session, seq1, seq2, uin)
	case wire.ICQLegacyCmdSetBasicInfo:
		return h.handleSetBasicInfo(session, seq1, seq2, uin, data)
	case 0x0582: // SetHomeInfo
		return h.handleSetHomeInfo(session, seq1, seq2, uin, data)
	case 0x058C: // SetHomeWeb
		return h.handleSetHomeWeb(session, seq1, seq2, uin, data)
	case 0x0578: // SetWorkInfo
		return h.handleSetWorkInfo(session, seq1, seq2, uin, data)
	case 0x05BE: // SetWorkWeb
		return h.handleSetWorkWeb(session, seq1, seq2, uin, data)
	case 0x0604: // ICQ_CMDxRCV_UKNOWN_DEP - unknown department request
		return h.handleUnknownDep(session, seq1, seq2, uin, data)
	case 0x06AE: // ICQ_CMDxRCV_VISxLIST - visible list
		return h.handleVisibleList(session, seq1, seq2, uin, data)
	case 0x06A4: // ICQ_CMDxRCV_INVISxLIST - invisible list
		return h.handleInvisibleList(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdSearchStart: // 0x05C8 - Search user
		return h.handleSearchStart(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdGetDeps1: // 0x05F0 - Get departments list during session
		return h.handleGetDeps1(session, seq1, seq2, uin, data)
	case 0x05AA: // ICQ_CMDxRCV_GETxNOTES - Get notes
		return h.handleGetNotes(session, seq1, seq2, uin, data)
	case 0x0596: // ICQ_CMDxRCV_SETxNOTES - Set notes
		return h.handleSetNotes(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdSetPassword: // 0x049C - Set password
		return h.handleSetPassword(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdSetAuth: // 0x0514 - Set auth mode
		return h.handleSetAuth(session, seq1, seq2, uin, data)
	case 0x0528: // ICQ_CMDxRCV_SETxSTATE - Set client state (not search!)
		return h.handleSetState(session, seq1, seq2, uin, data)
	case 0x0532: // ICQ_CMDxRCV_USAGExSTATS - Usage statistics
		return h.handleUsageStats(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdGetExternals: // 0x04C4 - Get externals
		return h.handleGetExternals(session, seq1, seq2, uin, data)
	case 0x0442: // ICQ_CMDxRCV_SYSxMSGxDONExACK - System message ack
		return h.handleSysAck(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdReconnect: // 0x015E - Reconnect/online info
		return h.handleOnlineInfo(session, seq1, seq2, uin, data)
	case 0x0460: // ICQ_CMDxRCV_USERxGETINFO1 - Get basic info only
		return h.handleGetInfo1(session, seq1, seq2, uin, data)
	default:
		h.logger.Debug("unhandled V3 command",
			"command", fmt.Sprintf("0x%04X", command),
			"uin", uin,
		)
		// Send ACK for unknown commands
		return h.sendAck(addr, seq1, seq2, uin)
	}
}

// handleFirstLogin processes the first login packet (0x04EC)
// From iserverd: v3_process_firstlog() - just sends ACK
func (h *V3Handler) handleFirstLogin(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	h.logger.Debug("first login packet",
		"uin", uin,
		"addr", addr.String(),
	)
	return h.sendAck(addr, seq1, seq2, uin)
}

// handleGetDeps processes the get departments pseudo-login packet (0x03F2)
// From iserverd v3_process_getdeps():
// Data format: JUNK(4) + UIN(4) + PWD_LEN(2) + PASSWORD
// This is a pseudo-login to get the departments list before actual login
func (h *V3Handler) handleGetDeps(addr *net.UDPAddr, seq1, seq2 uint16, data []byte) error {
	ctx := context.Background()

	if len(data) < 10 {
		h.logger.Debug("getdeps packet too short", "len", len(data))
		return nil
	}

	offset := 0

	// Skip junk (4 bytes)
	offset += 4

	// Read UIN (4 bytes)
	uin := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Read password length (2 bytes)
	pwdLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	if pwdLen > 20 {
		pwdLen = 20
	}

	// Read password
	if offset+int(pwdLen) > len(data) {
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}
	password := string(data[offset : offset+int(pwdLen)])
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}

	h.logger.Info("V3 getdeps (pseudo-login)",
		"uin", uin,
		"password_len", len(password),
	)

	// Validate credentials
	valid, err := h.service.ValidateCredentials(ctx, uin, password)
	if err != nil || !valid {
		h.logger.Info("getdeps failed - invalid credentials", "uin", uin)
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	// Send ACK
	h.sendAck(addr, seq1, seq2, uin)

	// Send departments list (simplified - just send empty list for now)
	return h.sendDeptsList(addr, seq2, uin)
}

// handleLogin processes login packet (0x03E8)
// From iserverd v3_process_login():
// After header (12 bytes): TIMESTAMP(4) + TCP_PORT(4) + PWD_LEN(2) + PASSWORD + ...
func (h *V3Handler) handleLogin(session *LegacySession, addr *net.UDPAddr, seq1, seq2 uint16, uin uint32, data []byte) error {
	ctx := context.Background()

	// First send ACK (iserverd does this immediately)
	h.sendAck(addr, seq1, seq2, uin)

	// V3 login data format (from iserverd):
	// TIMESTAMP(4) + TCP_PORT(4) + PWD_LEN(2) + PASSWORD(pwdLen) + ...
	if len(data) < 10 {
		h.logger.Debug("login packet too short", "len", len(data))
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	offset := 0

	// Read timestamp (4 bytes) - skip it
	// timestamp := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Read TCP port (4 bytes)
	port := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Read password length (2 bytes)
	if offset+2 > len(data) {
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}
	pwdLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Sanity check password length
	if pwdLen > 20 {
		pwdLen = 20
	}

	// Read password
	if offset+int(pwdLen) > len(data) {
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}
	password := string(data[offset : offset+int(pwdLen)])
	// Remove null terminator if present
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}

	h.logger.Info("V3 login attempt",
		"uin", uin,
		"port", port,
		"password_len", len(password),
	)

	// Validate credentials
	valid, err := h.service.ValidateCredentials(ctx, uin, password)
	if err != nil || !valid {
		h.logger.Info("login failed - invalid credentials",
			"uin", uin,
			"password", password, // Debug only - remove in production
		)
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	// Create session
	newSession, err := h.sessions.CreateSession(uin, addr, wire.ICQLegacyVersionV3)
	if err != nil {
		h.logger.Error("failed to create session", "err", err, "uin", uin)
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	newSession.Password = password

	// Send login success (HELLO packet)
	if err := h.sendLoginReply(newSession, seq1, seq2); err != nil {
		return err
	}

	h.logger.Info("V3 login successful",
		"uin", uin,
		"session_id", newSession.SessionID,
	)

	return nil
}

// handlePing processes keep-alive packets
func (h *V3Handler) handlePing(session *LegacySession, addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	if session == nil {
		return h.sendNotConnected(addr, seq2, uin)
	}
	return h.sendAck(addr, seq1, seq2, uin)
}

// handleLogoff processes logout
func (h *V3Handler) handleLogoff(session *LegacySession, seq1, seq2 uint16, uin uint32) error {
	if session == nil {
		return nil
	}
	h.logger.Info("V3 logout", "uin", uin)

	// Notify contacts that this user is going offline BEFORE removing session
	h.notifyContactsUserOffline(session)

	h.sessions.RemoveSession(uin)
	return nil
}

// notifyContactsUserOffline notifies all contacts who have this user in their list that we're offline
func (h *V3Handler) notifyContactsUserOffline(session *LegacySession) {
	if h.dispatcher == nil {
		return
	}

	// Find all sessions that have this user in their contact list
	contactsToNotify := h.sessions.NotifyContactsOfStatus(session)

	h.logger.Debug("notifying contacts of user offline",
		"uin", session.UIN,
		"contacts_to_notify", contactsToNotify,
	)

	for _, contactUIN := range contactsToNotify {
		contactSession := h.sessions.GetSession(contactUIN)
		if contactSession != nil {
			// Use dispatcher to send offline notification in correct protocol format
			h.dispatcher.SendUserOffline(contactSession, session.UIN)
		}
	}
}

// handleContactList processes contact list
func (h *V3Handler) handleContactList(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	// Send ACK first
	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse contact list - format: TIMESTAMP(4) + COUNT(1) + UIN(4)*COUNT
	if len(data) < 5 {
		return h.sendContactListDone(session, seq2)
	}

	// Skip timestamp
	offset := 4
	count := int(data[offset])
	offset++

	contacts := make([]uint32, 0, count)
	for i := 0; i < count && offset+4 <= len(data); i++ {
		contactUIN := binary.LittleEndian.Uint32(data[offset : offset+4])
		contacts = append(contacts, contactUIN)
		offset += 4
	}

	h.logger.Debug("V3 contact list",
		"uin", uin,
		"count", len(contacts),
	)

	session.SetContactList(contacts)

	// Send online status for each contact that is online
	// Use dispatcher for cross-protocol support
	onlineContacts := h.sessions.GetOnlineContacts(session)
	for _, contact := range onlineContacts {
		if h.dispatcher != nil {
			// Use central dispatcher - routes to correct protocol based on session's version
			h.dispatcher.SendUserOnline(session, contact.UIN, contact.GetStatus())
		} else {
			// Fallback to V3 format if dispatcher not set
			h.sendUserOnline(session, contact.UIN, contact.GetStatus())
		}
	}

	// Also notify contacts that THIS user is now online
	// This is the key fix - we need to tell contacts who have us in their list
	h.notifyContactsUserOnline(session)

	return h.sendContactListDone(session, seq2)
}

// notifyContactsUserOnline notifies all contacts who have this user in their list that we're online
// Following iserverd's pattern: when user comes online, notify everyone who cares
func (h *V3Handler) notifyContactsUserOnline(session *LegacySession) {
	if h.dispatcher == nil {
		return
	}

	// Find all sessions that have this user in their contact list
	contactsToNotify := h.sessions.NotifyContactsOfStatus(session)

	h.logger.Debug("notifying contacts of user online",
		"uin", session.UIN,
		"contacts_to_notify", contactsToNotify,
	)

	for _, contactUIN := range contactsToNotify {
		contactSession := h.sessions.GetSession(contactUIN)
		if contactSession != nil {
			// Use dispatcher to send in correct protocol format for each contact
			h.dispatcher.SendUserOnline(contactSession, session.UIN, session.GetStatus())
		}
	}
}

// handleSetStatus processes status change
func (h *V3Handler) handleSetStatus(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse status - format: TIMESTAMP(4) + STATUS(4)
	if len(data) < 8 {
		return nil
	}

	status := binary.LittleEndian.Uint32(data[4:8])
	session.SetStatus(status)

	h.logger.Debug("V3 status change",
		"uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
	)

	return nil
}

// handleMessage processes through-server messages (0x010E)
// From iserverd v3_process_sysmsg(): forwards messages to target user
// Format: TIMESTAMP(4) + TO_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (h *V3Handler) handleMessage(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse message - format: TIMESTAMP(4) + TO_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
	if len(data) < 12 {
		h.logger.Debug("V3 message too short", "from", uin, "len", len(data))
		return nil
	}

	offset := 0
	// Skip timestamp
	offset += 4

	// Target UIN
	toUIN := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Message type
	msgType := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Message length
	msgLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Message content
	var message string
	if msgLen > 0 && offset+int(msgLen) <= len(data) {
		message = string(data[offset : offset+int(msgLen)])
		// Remove null terminator if present
		if len(message) > 0 && message[len(message)-1] == 0 {
			message = message[:len(message)-1]
		}
	}

	h.logger.Info("V3 message received",
		"from", uin,
		"to", toUIN,
		"type", fmt.Sprintf("0x%04X", msgType),
		"msg_len", msgLen,
		"msg", message,
	)

	// Forward message to target user if online
	// Use dispatcher for cross-protocol messaging (V3 -> V5 or V3 -> V3)
	targetSession := h.sessions.GetSession(toUIN)
	if targetSession != nil {
		if h.dispatcher != nil {
			// Use central dispatcher - routes to correct protocol based on target's version
			h.dispatcher.SendOnlineMessage(targetSession, uin, msgType, message)
		} else {
			// Fallback to V3 format if dispatcher not set
			h.sendOnlineMessage(targetSession, uin, msgType, message, seq2)
		}
		h.logger.Debug("V3 message forwarded",
			"from", uin,
			"to", toUIN,
			"target_version", targetSession.Version,
		)
	} else {
		// Target user is offline - store message for later delivery
		// From iserverd v3_process_sysmsg(): when target is offline, store in database
		ctx := context.Background()
		if err := h.service.SaveOfflineMessage(ctx, uin, toUIN, msgType, message); err != nil {
			h.logger.Error("failed to store offline message",
				"from", uin,
				"to", toUIN,
				"err", err,
			)
		} else {
			h.logger.Info("V3 message stored for offline delivery",
				"from", uin,
				"to", toUIN,
				"type", fmt.Sprintf("0x%04X", msgType),
			)
		}
	}

	return nil
}

// handleUserAdd processes user add to contact list (0x053C)
// From iserverd v3_process_useradd(): adds user and sends "you were added" notification
func (h *V3Handler) handleUserAdd(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse - format: TIMESTAMP(4) + TARGET_UIN(4)
	if len(data) < 8 {
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[4:8])

	h.logger.Debug("V3 user add",
		"from", uin,
		"target", targetUIN,
	)

	// Add to contact list
	contacts := session.GetContactList()
	contacts = append(contacts, targetUIN)
	session.SetContactList(contacts)

	// Check if target is online and send their status
	targetSession := h.sessions.GetSession(targetUIN)
	if targetSession != nil {
		h.sendUserOnline(session, targetUIN, targetSession.GetStatus())

		// Send "you were added" notification to target user
		// Message format: nick#FE#first#FE#last#FE#email#FE#auth
		// Using UIN as nick for now since we don't have user info
		youWereAddedMsg := fmt.Sprintf("%d\xFE\xFE\xFE\xFE0", uin)
		h.sendOnlineMessage(targetSession, uin, wire.ICQLegacyMsgAdded, youWereAddedMsg, 0)

		h.logger.Debug("V3 sent 'you were added' notification",
			"from", uin,
			"to", targetUIN,
		)
	}

	return nil
}

// handleGetInfo processes user info request (0x05FA)
// From iserverd v3_process_getinfo(): sends basic, home, home_web, work, work_web info
func (h *V3Handler) handleGetInfo(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse - format: TIMESTAMP(4) + TARGET_UIN(4)
	if len(data) < 8 {
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[4:8])

	h.logger.Debug("V3 get info request",
		"from", uin,
		"target", targetUIN,
	)

	// Send all user info packets (matching iserverd v3_process_getinfo)
	h.sendBasicInfo(session, seq2, targetUIN)
	h.sendHomeInfo(session, seq2, targetUIN)
	h.sendHomeWeb(session, seq2, targetUIN)
	h.sendWorkInfo(session, seq2, targetUIN)
	h.sendWorkWeb(session, seq2, targetUIN)

	return nil
}

// V3 packet sending helpers

// sendAck sends ACK packet (V3 format from iserverd v3_send_ack)
func (h *V3Handler) sendAck(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	// V3 ACK format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4)
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvAck)
	binary.LittleEndian.PutUint16(pkt[4:6], seq1)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // reserved

	return h.sender.SendPacket(addr, pkt)
}

// sendBadPassword sends wrong password response
func (h *V3Handler) sendBadPassword(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvWrongPasswd)
	binary.LittleEndian.PutUint16(pkt[4:6], 0)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)

	return h.sender.SendPacket(addr, pkt)
}

// sendNotConnected sends not connected error
func (h *V3Handler) sendNotConnected(addr *net.UDPAddr, seq2 uint16, uin uint32) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvNotConnected)
	binary.LittleEndian.PutUint16(pkt[4:6], 0)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)

	return h.sender.SendPacket(addr, pkt)
}

// sendLoginReply sends login success (HELLO packet)
// From iserverd v3_send_login_reply() - this is a complex packet!
func (h *V3Handler) sendLoginReply(session *LegacySession, seq1, seq2 uint16) error {
	// V3 HELLO format from iserverd:
	// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) +
	// CLIENT_IP(4) + RESERVED(4) + EXTERNALS_NUM(4) + DEPLIST_VERSION(4) +
	// MUST_CHANGE_PASS(1) + CAN_BROADCAST(1) + UNKNOWN(4) +
	// PING_FREQ(2) + PACKET_TIMEOUT(2) + RETRY_TIMEOUT(2) + NUM_RETRIES(2)

	// Get client IP as uint32 (network byte order to ICQ format)
	var clientIP uint32
	if session.Addr != nil && session.Addr.IP != nil {
		ip := session.Addr.IP.To4()
		if ip != nil {
			// ICQ stores IP in little-endian format
			clientIP = uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
		}
	}

	pkt := make([]byte, 46)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvHello)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq1 = 0
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// Client IP
	binary.LittleEndian.PutUint32(pkt[offset:], clientIP)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// Externals number and deplist version
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // externals_num
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 1) // deplist_version
	offset += 4

	// Flags
	pkt[offset] = 0 // must_change_password
	offset++
	pkt[offset] = 0 // can_broadcast
	offset++

	// Unknown value (0xFA)
	binary.LittleEndian.PutUint32(pkt[offset:], 0x000000FA)
	offset += 4

	// Timing parameters
	binary.LittleEndian.PutUint16(pkt[offset:], 50) // ping_frequency (seconds)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 60) // packet_timeout (seconds)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 10) // retry_timeout (seconds)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 3) // num_retries
	offset += 2

	h.logger.Debug("sending V3 login reply",
		"uin", session.UIN,
		"client_ip", clientIP,
		"packet_len", offset,
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendContactListDone sends contact list processed response
func (h *V3Handler) sendContactListDone(session *LegacySession, seq2 uint16) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserListDone)
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)

	return h.sender.SendToSession(session, pkt)
}

// sendUserOnline sends user online notification
// From iserverd v3_send_user_online()
func (h *V3Handler) sendUserOnline(session *LegacySession, uin uint32, status uint32) error {
	// V3 USER_ONLINE format from iserverd:
	// header(16) + UIN(4) + IP(4) + PORT(4) + INT_IP(4) + DC_TYPE(1) + STATUS(2) + ESTAT(2) + TCPVER(2) + UNKNOWN(2)
	// Total: 16 + 4 + 4 + 4 + 4 + 1 + 2 + 2 + 2 + 2 = 41 bytes

	pkt := make([]byte, 41)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserOnline)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// UIN of the user who is online
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4

	// IP address (0 for privacy - V3 clients crash on non-V3 client connect)
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// TCP port (0 for privacy)
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Internal IP (0 for privacy)
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// DC type (0)
	pkt[offset] = 0
	offset++

	// Status (low word)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(status&0xFFFF))
	offset += 2

	// Extended status (high word)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(status>>16))
	offset += 2

	// TCP version
	binary.LittleEndian.PutUint16(pkt[offset:], 0)
	offset += 2

	// Unknown
	binary.LittleEndian.PutUint16(pkt[offset:], 0)
	offset += 2

	h.logger.Debug("sending V3 user online notification",
		"to", session.UIN,
		"online_uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendDeptsList sends the departments list (simplified version)
// From iserverd v3_send_depslist()
func (h *V3Handler) sendDeptsList(addr *net.UDPAddr, seq2 uint16, uin uint32) error {
	// V3 DEPS_LIST format: header(16) + DEPLIST_VERSION(4) + COUNT(4) + [deps...]
	// For now, send empty list with version 1
	pkt := make([]byte, 28)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserDepsList) // 0x0032
	binary.LittleEndian.PutUint16(pkt[4:6], 0)                             // servseq
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // reserved
	binary.LittleEndian.PutUint32(pkt[16:20], 1) // deplist version
	binary.LittleEndian.PutUint32(pkt[20:24], 0) // count = 0 (no departments)
	// Trailer from iserverd
	binary.LittleEndian.PutUint16(pkt[24:26], 0x0002)
	binary.LittleEndian.PutUint16(pkt[26:28], 0x002a)

	return h.sender.SendPacket(addr, pkt)
}

// sendBasicInfo sends basic user info response
// From iserverd v3_send_basic_info()
// Packet format (verified via Ghidra RE of ICQ98a client handler FUN_00429b22):
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: TARGET_UIN(4) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST + LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL + STATUS(1) + AUTH(1)
// All strings are length-prefixed (2 bytes) and null-terminated
// NOTE: Client expects TARGET_UIN at start of data - this was missing in iserverd!
// NOTE: There are TWO bytes at the end - STATUS and AUTH - verified via Ghidra RE of FUN_00429b22
func (h *V3Handler) sendBasicInfo(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	ctx := context.Background()

	// Fetch actual user data from database (matching iserverd behavior)
	info, err := h.service.GetUserInfo(ctx, targetUIN)

	// Default values if user not found (use UIN as nickname fallback)
	nick := fmt.Sprintf("%d", targetUIN)
	first := ""
	last := ""
	email := ""
	status := uint8(0) // Status byte (stored at offset 0xd1 in client user object)
	auth := uint8(0)   // Auth mode (stored at offset 0x911 in client user object)

	if err == nil && info != nil {
		// Use actual user data from database
		if info.Nickname != "" {
			nick = info.Nickname
		}
		first = info.FirstName
		last = info.LastName
		email = info.Email
		auth = info.AuthRequired
	}

	// Calculate packet size
	// Header(16) + TARGET_UIN(4) + nick_len(2) + nick + null(1) + first_len(2) + first + null(1) +
	// last_len(2) + last + null(1) + email_len(2) + email + null(1) + status(1) + auth(1)
	pktSize := 16 + 4 + 2 + len(nick) + 1 + 2 + len(first) + 1 + 2 + len(last) + 1 + 2 + len(email) + 1 + 1 + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	// NOTE: Client expects 0x0118 (ICQLegacySrvInfoReply), NOT 0x02E4 (ICQLegacySrvUserInfoBasic)
	// The client dispatch table only handles 0x0118 for info responses - 0x02E4 falls through to no-op
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3) // VERSION
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvInfoReply) // COMMAND (0x0118)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum()) // SEQ1 (servseq)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // SEQ2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN) // UIN (recipient's UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // RESERVED
	offset += 4

	// TARGET_UIN - the UIN of the user whose info this is (required by client!)
	binary.LittleEndian.PutUint32(pkt[offset:], targetUIN)
	offset += 4

	// Nick (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(nick)+1))
	offset += 2
	copy(pkt[offset:], nick)
	offset += len(nick)
	pkt[offset] = 0
	offset++

	// First name (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(first)+1))
	offset += 2
	copy(pkt[offset:], first)
	offset += len(first)
	pkt[offset] = 0
	offset++

	// Last name (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(last)+1))
	offset += 2
	copy(pkt[offset:], last)
	offset += len(last)
	pkt[offset] = 0
	offset++

	// Email (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(email)+1))
	offset += 2
	copy(pkt[offset:], email)
	offset += len(email)
	pkt[offset] = 0
	offset++

	// Status byte (read first by client, stored at offset 0xd1)
	pkt[offset] = status
	offset++

	// Auth flag (read second by client, stored at offset 0x911)
	pkt[offset] = auth
	offset++

	h.logger.Debug("sending V3 basic info",
		"to", session.UIN,
		"target_uin", targetUIN,
		"nick", nick,
		"first", first,
		"last", last,
		"email", email,
		"auth", auth,
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendHomeInfo sends home info response
// From iserverd v3_send_home_info()
// Packet format (verified against iserverd make_packet.cpp):
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: HADDR_LEN(2) + HADDR + HCITY_LEN(2) + HCITY + HSTATE_LEN(2) + HSTATE +
//         HCOUNTRY(2) + HPHONE_LEN(2) + HPHONE + HFAX_LEN(2) + HFAX + HCELL_LEN(2) + HCELL +
//         HZIP(4) + GENDER(1) + AGE(2) + BDAY(1) + BMONTH(1) + BYEAR(1) + 0x00(1)
// All strings are length-prefixed (2 bytes) and null-terminated
func (h *V3Handler) sendHomeInfo(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	ctx := context.Background()

	// Fetch actual user data from database (matching iserverd behavior)
	user, err := h.service.GetFullUserInfo(ctx, targetUIN)

	// Default values if user not found
	haddr := ""
	hcity := ""
	hstate := ""
	hcountry := uint16(0)
	hphone := ""
	hfax := ""
	hcell := ""
	hzip := uint32(0)
	gender := uint8(0)
	age := uint16(0)
	bday := uint8(0)
	bmonth := uint8(0)
	byear := uint8(0) // Year since 1900

	if err == nil && user != nil {
		// Use actual user data from database (matching iserverd field names)
		haddr = user.ICQBasicInfo.Address
		hcity = user.ICQBasicInfo.City
		hstate = user.ICQBasicInfo.State
		hcountry = user.ICQBasicInfo.CountryCode
		hphone = user.ICQBasicInfo.Phone
		hfax = user.ICQBasicInfo.Fax
		hcell = user.ICQBasicInfo.CellPhone

		// Parse ZIP code from string to uint32
		if user.ICQBasicInfo.ZIPCode != "" {
			var zipVal uint64
			fmt.Sscanf(user.ICQBasicInfo.ZIPCode, "%d", &zipVal)
			hzip = uint32(zipVal)
		}

		// Gender (from ICQMoreInfo)
		gender = uint8(user.ICQMoreInfo.Gender)

		// Age calculation would need birth year, but we can use stored age if available
		// For now, calculate from birth year if available
		if user.ICQMoreInfo.BirthYear > 0 {
			currentYear := uint16(2024) // TODO: use actual current year
			if user.ICQMoreInfo.BirthYear < currentYear {
				age = currentYear - user.ICQMoreInfo.BirthYear
			}
		}

		// Birthday fields (from ICQMoreInfo)
		bday = user.ICQMoreInfo.BirthDay
		bmonth = user.ICQMoreInfo.BirthMonth

		// Year transformation from iserverd:
		// if (tuser.byear < 1900) {temp_year = tuser.byear; }
		// else {temp_year = tuser.byear - 1900; };
		if user.ICQMoreInfo.BirthYear < 1900 {
			byear = uint8(user.ICQMoreInfo.BirthYear)
		} else {
			byear = uint8(user.ICQMoreInfo.BirthYear - 1900)
		}
	}

	// Calculate packet size
	// Header(16) + haddr_len(2) + haddr + null(1) + hcity_len(2) + hcity + null(1) +
	// hstate_len(2) + hstate + null(1) + hcountry(2) + hphone_len(2) + hphone + null(1) +
	// hfax_len(2) + hfax + null(1) + hcell_len(2) + hcell + null(1) +
	// hzip(4) + gender(1) + age(2) + bday(1) + bmonth(1) + byear(1) + unknown(1)
	pktSize := 16 + 2 + len(haddr) + 1 + 2 + len(hcity) + 1 + 2 + len(hstate) + 1 +
		2 + 2 + len(hphone) + 1 + 2 + len(hfax) + 1 + 2 + len(hcell) + 1 +
		4 + 1 + 2 + 1 + 1 + 1 + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header (matching iserverd v3_send_home_info exactly)
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3) // VERSION
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0320) // ICQ_CMDxSND_USERxINFO_HOME
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum()) // SEQ1 (servseq)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // SEQ2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN) // UIN (recipient's UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // RESERVED
	offset += 4

	// Home address (length-prefixed with null terminator) - iserverd: strlen(tuser.haddr)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(haddr)+1))
	offset += 2
	copy(pkt[offset:], haddr)
	offset += len(haddr)
	pkt[offset] = 0
	offset++

	// Home city (length-prefixed with null terminator) - iserverd: strlen(tuser.hcity)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hcity)+1))
	offset += 2
	copy(pkt[offset:], hcity)
	offset += len(hcity)
	pkt[offset] = 0
	offset++

	// Home state (length-prefixed with null terminator) - iserverd: strlen(tuser.hstate)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hstate)+1))
	offset += 2
	copy(pkt[offset:], hstate)
	offset += len(hstate)
	pkt[offset] = 0
	offset++

	// Home country (2 bytes) - iserverd: (unsigned short)tuser.hcountry
	binary.LittleEndian.PutUint16(pkt[offset:], hcountry)
	offset += 2

	// Home phone (length-prefixed with null terminator) - iserverd: strlen(tuser.hphone)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hphone)+1))
	offset += 2
	copy(pkt[offset:], hphone)
	offset += len(hphone)
	pkt[offset] = 0
	offset++

	// Home fax (length-prefixed with null terminator) - iserverd: strlen(tuser.hfax)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hfax)+1))
	offset += 2
	copy(pkt[offset:], hfax)
	offset += len(hfax)
	pkt[offset] = 0
	offset++

	// Home cell (length-prefixed with null terminator) - iserverd: strlen(tuser.hcell)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hcell)+1))
	offset += 2
	copy(pkt[offset:], hcell)
	offset += len(hcell)
	pkt[offset] = 0
	offset++

	// Home zip (4 bytes) - iserverd: (unsigned long)tuser.hzip
	binary.LittleEndian.PutUint32(pkt[offset:], hzip)
	offset += 4

	// Gender (1 byte) - iserverd: (char)tuser.gender
	pkt[offset] = gender
	offset++

	// Age (2 bytes) - iserverd: (unsigned short)tuser.age
	binary.LittleEndian.PutUint16(pkt[offset:], age)
	offset += 2

	// Birthday day (1 byte) - iserverd: (char)tuser.bday
	pkt[offset] = bday
	offset++

	// Birthday month (1 byte) - iserverd: (char)tuser.bmonth
	pkt[offset] = bmonth
	offset++

	// Birthday year (1 byte, since 1900) - iserverd: (char)temp_year
	pkt[offset] = byear
	offset++

	// Trailing zero (1 byte) - iserverd: (char)0x00
	pkt[offset] = 0
	offset++

	h.logger.Debug("sending V3 home info",
		"to", session.UIN,
		"target_uin", targetUIN,
		"haddr", haddr,
		"hcity", hcity,
		"hstate", hstate,
		"hcountry", hcountry,
		"hphone", hphone,
		"hfax", hfax,
		"hcell", hcell,
		"hzip", hzip,
		"gender", gender,
		"age", age,
		"bday", bday,
		"bmonth", bmonth,
		"byear", byear,
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendHomeWeb sends home webpage info response
// sendHomeWeb sends home webpage info response
// From iserverd v3_send_home_web()
// Packet format (verified against iserverd make_packet.cpp):
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: HPAGE_LEN(2) + HPAGE (null-terminated string)
func (h *V3Handler) sendHomeWeb(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	ctx := context.Background()

	// Fetch actual user data from database (matching iserverd behavior)
	user, err := h.service.GetFullUserInfo(ctx, targetUIN)

	// Default value if user not found
	hpage := ""

	if err == nil && user != nil {
		// Use actual user data from database (matching iserverd field: tuser.hpage)
		hpage = user.ICQMoreInfo.HomePageAddr
	}

	// Calculate packet size
	// Header(16) + hpage_len(2) + hpage + null(1)
	pktSize := 16 + 2 + len(hpage) + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header (matching iserverd v3_send_home_web exactly)
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3) // VERSION
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserInfoHWeb) // COMMAND (0x0334)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum()) // SEQ1 (servseq)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // SEQ2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN) // UIN (recipient's UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // RESERVED
	offset += 4

	// Home page URL (length-prefixed with null terminator) - iserverd: strlen(tuser.hpage)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hpage)+1))
	offset += 2
	copy(pkt[offset:], hpage)
	offset += len(hpage)
	pkt[offset] = 0
	offset++

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendWorkInfo sends work info response
// From iserverd v3_send_work_info()
// Packet format (verified against iserverd make_packet.cpp):
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: WADDR_LEN(2) + WADDR + WCITY_LEN(2) + WCITY + WSTATE_LEN(2) + WSTATE +
//         WCOUNTRY(2) + WCOMPANY_LEN(2) + WCOMPANY + WTITLE_LEN(2) + WTITLE +
//         WDEPART(4) + WPHONE_LEN(2) + WPHONE + WFAX_LEN(2) + WFAX +
//         WPAGER_LEN(2) + WPAGER + WZIP(4)
// All strings are length-prefixed (2 bytes) and null-terminated
func (h *V3Handler) sendWorkInfo(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	ctx := context.Background()

	// Fetch actual user data from database (matching iserverd behavior)
	user, err := h.service.GetFullUserInfo(ctx, targetUIN)

	// Default values if user not found
	waddr := ""
	wcity := ""
	wstate := ""
	wcountry := uint16(0)
	wcompany := ""
	wtitle := ""
	wdepart := uint32(0)
	wphone := ""
	wfax := ""
	wpager := "" // Not in ICQWorkInfo struct, always empty
	wzip := uint32(0)

	if err == nil && user != nil {
		// Use actual user data from database (matching iserverd field names)
		waddr = user.ICQWorkInfo.Address
		wcity = user.ICQWorkInfo.City
		wstate = user.ICQWorkInfo.State
		wcountry = user.ICQWorkInfo.CountryCode
		wcompany = user.ICQWorkInfo.Company
		wtitle = user.ICQWorkInfo.Position
		// Department is stored as string in Go, but iserverd uses uint32 (department code)
		// For now, we'll use 0 as the department code since we don't have a mapping
		wdepart = 0
		wphone = user.ICQWorkInfo.Phone
		wfax = user.ICQWorkInfo.Fax
		// wpager not available in ICQWorkInfo struct

		// Parse ZIP code from string to uint32
		if user.ICQWorkInfo.ZIPCode != "" {
			var zipVal uint64
			fmt.Sscanf(user.ICQWorkInfo.ZIPCode, "%d", &zipVal)
			wzip = uint32(zipVal)
		}
	}

	// Calculate packet size
	// Header(16) + waddr_len(2) + waddr + null(1) + wcity_len(2) + wcity + null(1) +
	// wstate_len(2) + wstate + null(1) + wcountry(2) + wcompany_len(2) + wcompany + null(1) +
	// wtitle_len(2) + wtitle + null(1) + wdepart(4) + wphone_len(2) + wphone + null(1) +
	// wfax_len(2) + wfax + null(1) + wpager_len(2) + wpager + null(1) + wzip(4)
	pktSize := 16 + 2 + len(waddr) + 1 + 2 + len(wcity) + 1 + 2 + len(wstate) + 1 +
		2 + 2 + len(wcompany) + 1 + 2 + len(wtitle) + 1 + 4 +
		2 + len(wphone) + 1 + 2 + len(wfax) + 1 + 2 + len(wpager) + 1 + 4
	pkt := make([]byte, pktSize)
	offset := 0

	// Header (matching iserverd v3_send_work_info exactly)
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3) // VERSION
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x02F8) // ICQ_CMDxSND_USERxINFO_WORK
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum()) // SEQ1 (servseq)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // SEQ2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN) // UIN (recipient's UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // RESERVED
	offset += 4

	// Work address (length-prefixed with null terminator) - iserverd: strlen(tuser.waddr)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(waddr)+1))
	offset += 2
	copy(pkt[offset:], waddr)
	offset += len(waddr)
	pkt[offset] = 0
	offset++

	// Work city (length-prefixed with null terminator) - iserverd: strlen(tuser.wcity)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wcity)+1))
	offset += 2
	copy(pkt[offset:], wcity)
	offset += len(wcity)
	pkt[offset] = 0
	offset++

	// Work state (length-prefixed with null terminator) - iserverd: strlen(tuser.wstate)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wstate)+1))
	offset += 2
	copy(pkt[offset:], wstate)
	offset += len(wstate)
	pkt[offset] = 0
	offset++

	// Work country (2 bytes) - iserverd: (unsigned short)tuser.wcountry
	binary.LittleEndian.PutUint16(pkt[offset:], wcountry)
	offset += 2

	// Work company (length-prefixed with null terminator) - iserverd: strlen(tuser.wcompany)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wcompany)+1))
	offset += 2
	copy(pkt[offset:], wcompany)
	offset += len(wcompany)
	pkt[offset] = 0
	offset++

	// Work title (length-prefixed with null terminator) - iserverd: strlen(tuser.wtitle)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wtitle)+1))
	offset += 2
	copy(pkt[offset:], wtitle)
	offset += len(wtitle)
	pkt[offset] = 0
	offset++

	// Work department (4 bytes) - iserverd: (unsigned long)tuser.wdepart
	binary.LittleEndian.PutUint32(pkt[offset:], wdepart)
	offset += 4

	// Work phone (length-prefixed with null terminator) - iserverd: strlen(tuser.wphone)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wphone)+1))
	offset += 2
	copy(pkt[offset:], wphone)
	offset += len(wphone)
	pkt[offset] = 0
	offset++

	// Work fax (length-prefixed with null terminator) - iserverd: strlen(tuser.wfax)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wfax)+1))
	offset += 2
	copy(pkt[offset:], wfax)
	offset += len(wfax)
	pkt[offset] = 0
	offset++

	// Work pager (length-prefixed with null terminator) - iserverd: strlen(tuser.wpager)+1
	// Note: wpager not available in ICQWorkInfo struct, always empty
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wpager)+1))
	offset += 2
	copy(pkt[offset:], wpager)
	offset += len(wpager)
	pkt[offset] = 0
	offset++

	// Work zip (4 bytes) - iserverd: (unsigned long)tuser.wzip
	binary.LittleEndian.PutUint32(pkt[offset:], wzip)
	offset += 4

	h.logger.Debug("sending V3 work info",
		"to", session.UIN,
		"target_uin", targetUIN,
		"waddr", waddr,
		"wcity", wcity,
		"wstate", wstate,
		"wcountry", wcountry,
		"wcompany", wcompany,
		"wtitle", wtitle,
		"wdepart", wdepart,
		"wphone", wphone,
		"wfax", wfax,
		"wzip", wzip,
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendWorkWeb sends work webpage info response
// From iserverd v3_send_work_web()
// Packet format (verified against iserverd make_packet.cpp):
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: WPAGE_LEN(2) + WPAGE (null-terminated string)
func (h *V3Handler) sendWorkWeb(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	ctx := context.Background()

	// Fetch actual user data from database (matching iserverd behavior)
	user, err := h.service.GetFullUserInfo(ctx, targetUIN)

	// Default value if user not found
	wpage := ""

	if err == nil && user != nil {
		// Use actual user data from database (matching iserverd field: tuser.wpage)
		wpage = user.ICQWorkInfo.WebPage
	}

	// Calculate packet size
	// Header(16) + wpage_len(2) + wpage + null(1)
	pktSize := 16 + 2 + len(wpage) + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header (matching iserverd v3_send_work_web exactly)
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3) // VERSION
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserInfoWWeb) // COMMAND (0x030C)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum()) // SEQ1 (servseq)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // SEQ2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN) // UIN (recipient's UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // RESERVED
	offset += 4

	// Work page URL (length-prefixed with null terminator) - iserverd: strlen(tuser.wpage)+1
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wpage)+1))
	offset += 2
	copy(pkt[offset:], wpage)
	offset += len(wpage)
	pkt[offset] = 0
	offset++

	return h.sender.SendToSession(session, pkt[:offset])
}

// handleOfflineMsgReq processes offline message request (0x044C)
// From iserverd v3_process_sysmsg_req()
func (h *V3Handler) handleOfflineMsgReq(session *LegacySession, seq1, seq2 uint16, uin uint32) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	ctx := context.Background()

	// Fetch offline messages from database
	messages, err := h.service.GetOfflineMessages(ctx, uin)
	if err != nil {
		h.logger.Error("failed to get offline messages", "uin", uin, "err", err)
		return h.sendOfflineMsgDone(session, seq2)
	}

	h.logger.Debug("V3 offline message request",
		"uin", uin,
		"message_count", len(messages),
	)

	// Send each offline message
	for _, msg := range messages {
		if err := h.sendOfflineMessage(session, seq2, &msg); err != nil {
			h.logger.Error("failed to send offline message",
				"uin", uin,
				"from", msg.FromUIN,
				"err", err,
			)
		}
	}

	// Send end of offline messages
	return h.sendOfflineMsgDone(session, seq2)
}

// handleSetBasicInfo processes set basic info (0x050A)
func (h *V3Handler) handleSetBasicInfo(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 set basic info", "uin", uin)

	// Send OK response
	return h.sendReplyOK(session, seq2, 0x01E0) // ICQ_CMDxSND_USERxSET_BASIC_INFO_OK
}

// handleSetHomeInfo processes set home info (0x0582)
func (h *V3Handler) handleSetHomeInfo(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 set home info", "uin", uin)

	// Send OK response
	return h.sendReplyOK(session, seq2, 0x0280) // ICQ_CMDxSND_USERxSET_HOME_INFO_OK
}

// handleSetHomeWeb processes set home web (0x058C)
func (h *V3Handler) handleSetHomeWeb(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 set home web", "uin", uin)

	// Send OK response
	return h.sendReplyOK(session, seq2, 0x0294) // ICQ_CMDxSND_USERxSET_HOME_PAGE_OK
}

// handleSetWorkInfo processes set work info (0x0578)
func (h *V3Handler) handleSetWorkInfo(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 set work info", "uin", uin)

	// Send OK response
	return h.sendReplyOK(session, seq2, 0x026C) // ICQ_CMDxSND_USERxSET_WORK_INFO_OK
}

// handleSetWorkWeb processes set work web (0x05BE)
func (h *V3Handler) handleSetWorkWeb(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 set work web", "uin", uin)

	// Send OK response
	return h.sendReplyOK(session, seq2, 0x0258) // ICQ_CMDxSND_USERxSET_WORK_PAGE_OK
}

// handleVisibleList processes visible list (0x06AE)
func (h *V3Handler) handleVisibleList(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 visible list", "uin", uin)

	return nil
}

// handleInvisibleList processes invisible list (0x06A4)
func (h *V3Handler) handleInvisibleList(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 invisible list", "uin", uin)

	return nil
}

// handleUnknownDep processes unknown department request (0x0604)
func (h *V3Handler) handleUnknownDep(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 unknown dep request", "uin", uin)

	return nil
}

// handleSearch processes search request (0x0528)
func (h *V3Handler) handleSearch(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 search request", "uin", uin)

	// Send search done (no results for now)
	return h.sendSearchDone(session, seq2)
}

// handleSearchStart processes search user request (0x05C8)
// From V3 protocol: TIMESTAMP(4) + TYPE(2) + COMP(2) + LEN(2) + STRING
// Type: 0x00FF=UIN, 0x01FF=Nick, 0x02FF=First, 0x03FF=Last, etc.
// Comp: 0x0000=contains, 0x0001=doesn't contain, 0x0002=is, etc.
func (h *V3Handler) handleSearchStart(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	ctx := context.Background()

	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse search parameters - format: TIMESTAMP(4) + TYPE(2) + COMP(2) + LEN(2) + STRING
	if len(data) < 10 {
		h.logger.Debug("V3 search start - packet too short", "uin", uin, "len", len(data))
		return h.sendSearchDone(session, seq2)
	}

	offset := 4 // Skip timestamp

	searchType := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	compType := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	strLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	var searchStr string
	if len(data) >= offset+int(strLen) && strLen > 0 {
		searchStr = string(data[offset : offset+int(strLen)])
		// Remove null terminator if present
		if len(searchStr) > 0 && searchStr[len(searchStr)-1] == 0 {
			searchStr = searchStr[:len(searchStr)-1]
		}
	}

	h.logger.Debug("V3 search start",
		"uin", uin,
		"search_type", fmt.Sprintf("0x%04X", searchType),
		"comp_type", compType,
		"search_str", searchStr,
	)

	// Handle UIN search (type 0x00FF)
	if searchType == 0x00FF && searchStr != "" {
		// Try to parse as UIN
		var targetUIN uint64
		_, err := fmt.Sscanf(searchStr, "%d", &targetUIN)
		if err == nil && targetUIN > 0 {
			// Search in database first (includes both online and offline users)
			result, err := h.service.SearchByUIN(ctx, uint32(targetUIN))
			if err == nil && result != nil {
				// User found in database
				h.sendSearchFound(session, seq2, result.UIN, result.Nickname, result.FirstName, result.LastName, result.Email, 0)
				h.logger.Debug("V3 search found user in database",
					"searcher", uin,
					"found", result.UIN,
					"nick", result.Nickname,
				)
			} else {
				h.logger.Debug("V3 search - user not found",
					"searcher", uin,
					"target", targetUIN,
					"err", err,
				)
			}
		}
	}

	// Send search done
	return h.sendSearchDone(session, seq2)
}

// handleGetDeps1 processes get departments list during session (0x05F0)
// This is used by client to replicate departments list during normal session
// From iserverd v3_process_getdeps1() - sends ICQ_CMDxSND_USERxDEPS_LIST1 (0x0082)
func (h *V3Handler) handleGetDeps1(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 get deps1 request", "uin", uin)

	// Send departments list using 0x0082 (during session, not login)
	return h.sendDeptsList1(session, seq2)
}

// sendDeptsList1 sends the departments list during normal session (0x0082)
// From iserverd v3_send_depslist1() - different from login depslist (0x0032)
func (h *V3Handler) sendDeptsList1(session *LegacySession, seq2 uint16) error {
	// V3 DEPS_LIST1 format from iserverd:
	// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) +
	// UNKNOWN(2) + DEPLIST_VERSION(4) + COUNT(4) + [deps...] + TRAILER(4)

	// For now, send empty list with version 1
	pkt := make([]byte, 32)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserDepsList1) // 0x0082 - ICQ_CMDxSND_USERxDEPS_LIST1
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// Unknown field (0x003C from iserverd)
	binary.LittleEndian.PutUint16(pkt[offset:], 0x003C)
	offset += 2

	// Deplist version
	binary.LittleEndian.PutUint32(pkt[offset:], 1)
	offset += 4

	// Count = 0 (no departments)
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Trailer from iserverd
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0002)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x002a)
	offset += 2

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendOfflineMessage sends an offline message to a V3 client
// From iserverd v3_send_offline_message()
// Format: header(16) + FROM_UIN(4) + YEAR(2) + MONTH(1) + DAY(1) + HOUR(1) + MINUTE(1) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (h *V3Handler) sendOfflineMessage(session *LegacySession, seq2 uint16, msg *foodgroup.LegacyOfflineMessage) error {
	// Build message data
	msgBytes := []byte(msg.Message)
	pktLen := 16 + 4 + 2 + 1 + 1 + 1 + 1 + 2 + 2 + len(msgBytes) + 1
	pkt := make([]byte, pktLen)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvSysMsgOffline) // 0x00DC
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// From UIN
	binary.LittleEndian.PutUint32(pkt[offset:], msg.FromUIN)
	offset += 4

	// Timestamp: YEAR(2) + MONTH(1) + DAY(1) + HOUR(1) + MINUTE(1)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(msg.Timestamp.Year()))
	offset += 2
	pkt[offset] = byte(msg.Timestamp.Month())
	offset++
	pkt[offset] = byte(msg.Timestamp.Day())
	offset++
	pkt[offset] = byte(msg.Timestamp.Hour())
	offset++
	pkt[offset] = byte(msg.Timestamp.Minute())
	offset++

	// Message type
	binary.LittleEndian.PutUint16(pkt[offset:], msg.MsgType)
	offset += 2

	// Message length (including null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(msgBytes)+1))
	offset += 2

	// Message content
	copy(pkt[offset:], msgBytes)
	offset += len(msgBytes)
	pkt[offset] = 0 // null terminator

	h.logger.Debug("sending V3 offline message",
		"to", session.UIN,
		"from", msg.FromUIN,
		"type", fmt.Sprintf("0x%04X", msg.MsgType),
		"timestamp", msg.Timestamp,
	)

	return h.sender.SendToSession(session, pkt)
}

// sendOfflineMsgDone sends end of offline messages
func (h *V3Handler) sendOfflineMsgDone(session *LegacySession, seq2 uint16) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], 0x00E6) // ICQ_CMDxSND_SYSxMSGxDONE
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)

	return h.sender.SendToSession(session, pkt)
}

// sendReplyOK sends a generic OK response
func (h *V3Handler) sendReplyOK(session *LegacySession, seq2 uint16, command uint16) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], command)
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)

	return h.sender.SendToSession(session, pkt)
}

// sendSearchDone sends search complete response
// From iserverd v3_send_search_finished()
// Packet format (17 bytes total):
//   VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) + MORE(1)
// The 'more' parameter indicates if there are more search results available:
//   0 = no more results, 1 = more results available (pagination)
func (h *V3Handler) sendSearchDone(session *LegacySession, seq2 uint16, more ...bool) error {
	pkt := make([]byte, 17)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], 0x00A0) // ICQ_CMDxSND_SEARCHxDONE
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // reserved

	// Set 'more' flag - indicates if more search results are available
	if len(more) > 0 && more[0] {
		pkt[16] = 1 // more results available
	} else {
		pkt[16] = 0 // no more results
	}

	return h.sender.SendToSession(session, pkt)
}

// sendSearchFound sends a search result
// From iserverd v3_send_found_info()
// Format: header(16) + UIN(4) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST +
//         LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL + AUTH(1)
func (h *V3Handler) sendSearchFound(session *LegacySession, seq2 uint16, foundUIN uint32, nick, first, last, email string, auth uint8) error {
	// Calculate packet size
	pktSize := 16 + 4 + 2 + len(nick) + 1 + 2 + len(first) + 1 + 2 + len(last) + 1 + 2 + len(email) + 1 + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x008C) // ICQ_CMDxSND_SEARCHxFOUND
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// Found user UIN
	binary.LittleEndian.PutUint32(pkt[offset:], foundUIN)
	offset += 4

	// Nick (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(nick)+1))
	offset += 2
	copy(pkt[offset:], nick)
	offset += len(nick)
	pkt[offset] = 0
	offset++

	// First name
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(first)+1))
	offset += 2
	copy(pkt[offset:], first)
	offset += len(first)
	pkt[offset] = 0
	offset++

	// Last name
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(last)+1))
	offset += 2
	copy(pkt[offset:], last)
	offset += len(last)
	pkt[offset] = 0
	offset++

	// Email
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(email)+1))
	offset += 2
	copy(pkt[offset:], email)
	offset += len(email)
	pkt[offset] = 0
	offset++

	// Auth flag
	pkt[offset] = auth
	offset++

	h.logger.Debug("V3 sending search found",
		"to", session.UIN,
		"found_uin", foundUIN,
		"nick", nick,
		"packet_hex", fmt.Sprintf("%X", pkt[:offset]),
		"packet_len", offset,
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendOnlineMessage sends an online system message to a V3/V4 client
// From iserverd v3_send_user_message()
// Format: header(16) + FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
// Note: V3 packets do NOT have a checkcode - they have a reserved field (always 0)
func (h *V3Handler) sendOnlineMessage(session *LegacySession, fromUIN uint32, msgType uint16, message string, seq2 uint16) error {
	msgBytes := []byte(message)

	h.logger.Debug("V3 sending online message",
		"to", session.UIN,
		"from", fromUIN,
		"type", fmt.Sprintf("0x%04X", msgType),
		"msg_len", len(msgBytes),
	)

	// Send V3 format packet
	pktSize := 16 + 4 + 2 + 2 + len(msgBytes) + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvSysMsgOnline) // 0x0104
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved (V3 has NO checkcode!)
	offset += 4

	// From UIN
	binary.LittleEndian.PutUint32(pkt[offset:], fromUIN)
	offset += 4

	// Message type (mask high byte for V3 clients)
	binary.LittleEndian.PutUint16(pkt[offset:], msgType&0x00FF)
	offset += 2

	// Message length (including null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(msgBytes)+1))
	offset += 2

	// Message content
	copy(pkt[offset:], msgBytes)
	offset += len(msgBytes)
	pkt[offset] = 0 // null terminator
	offset++

	h.logger.Debug("V3 sending online message packet",
		"to", session.UIN,
		"from", fromUIN,
		"packet_hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendUserOffline sends user offline notification
// From iserverd v3_send_user_offline()
func (h *V3Handler) sendUserOffline(session *LegacySession, uin uint32) error {
	// V3 USER_OFFLINE format: header(16) + UIN(4)
	pkt := make([]byte, 20)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserOffline)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// UIN of the user who went offline
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4

	h.logger.Debug("sending V3 user offline notification",
		"to", session.UIN,
		"offline_uin", uin,
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendUserStatus sends user status change notification
// From iserverd v3_send_user_status() in make_packet.cpp
// This is used when a user changes status while already online
// (e.g., Away -> Online, Online -> DND)
// Format: header(16) + UIN(4) + STATUS(2) + ESTAT(2)
func (h *V3Handler) sendUserStatus(session *LegacySession, uin uint32, status uint32) error {
	// V3 USER_STATUS format from iserverd:
	// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) +
	// TARGET_UIN(4) + STATUS(2) + ESTAT(2)
	pkt := make([]byte, 24)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserStatus) // 0x01A4
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// UIN of the user whose status changed
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4

	// Status (low word)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(status&0xFFFF))
	offset += 2

	// Extended status (high word)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(status>>16))
	offset += 2

	h.logger.Debug("sending V3 user status change notification",
		"to", session.UIN,
		"changed_uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}


// handleGetNotes processes get notes request (0x05AA)
// From iserverd v3_process_notes() - returns user's notes
func (h *V3Handler) handleGetNotes(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse: TIMESTAMP(4) + TARGET_UIN(4)
	if len(data) < 8 {
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[4:8])

	h.logger.Debug("V3 get notes", "uin", uin, "target", targetUIN)

	// Retrieve notes from database via service layer
	ctx := context.Background()
	notes, err := h.service.GetNotes(ctx, targetUIN)
	if err != nil {
		h.logger.Debug("V3 get notes failed", "uin", uin, "target", targetUIN, "err", err)
		// Send empty notes on error
		notes = ""
	}

	// Send notes response
	return h.sendNotes(session, seq2, targetUIN, notes)
}

// handleSetNotes processes set notes request (0x0596)
// From iserverd v3_process_setnotes()
// Data format: TIMESTAMP(4) + NOTES_LEN(2) + NOTES
func (h *V3Handler) handleSetNotes(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse notes from packet
	// Format: TIMESTAMP(4) + NOTES_LEN(2) + NOTES
	if len(data) < 6 {
		h.logger.Debug("V3 set notes - data too short", "uin", uin, "len", len(data))
		return h.sendReplyOK(session, seq2, 0x01CC)
	}

	offset := 4 // Skip timestamp

	// Read notes length (2 bytes)
	notesLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Read notes content
	var notes string
	if notesLen > 0 && offset+int(notesLen) <= len(data) {
		notes = string(data[offset : offset+int(notesLen)])
		// Remove null terminator if present
		if len(notes) > 0 && notes[len(notes)-1] == 0 {
			notes = notes[:len(notes)-1]
		}
	}

	h.logger.Debug("V3 set notes", "uin", uin, "notes_len", len(notes))

	// Save notes to database via service layer
	ctx := context.Background()
	if err := h.service.SetNotes(ctx, uin, notes); err != nil {
		h.logger.Error("V3 set notes failed", "uin", uin, "err", err)
		// Still send OK response to client (matching iserverd behavior)
	}

	// Send OK response (0x01CC = ICQ_CMDxSND_USERxSET_NOTES_OK)
	return h.sendReplyOK(session, seq2, 0x01CC)
}

// handleSetPassword processes set password request (0x049C)
// From iserverd v3_process_setpass()
// Data format: TIMESTAMP(4) + PASSWORD_LEN(2) + NEW_PASSWORD
// Note: iserverd doesn't validate old password, just updates to new password
func (h *V3Handler) handleSetPassword(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse password from data
	// Format: TIMESTAMP(4) + PASSWORD_LEN(2) + NEW_PASSWORD
	if len(data) < 6 {
		h.logger.Debug("V3 set password - data too short", "uin", uin, "len", len(data))
		return h.sendReplyOK(session, seq2, 0x0140)
	}

	offset := 0

	// Skip timestamp (4 bytes)
	offset += 4

	// Read password length (2 bytes)
	pwdLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Sanity check password length
	if pwdLen > 32 {
		pwdLen = 32
	}

	// Read new password
	if offset+int(pwdLen) > len(data) {
		h.logger.Debug("V3 set password - password truncated", "uin", uin)
		return h.sendReplyOK(session, seq2, 0x0140)
	}
	newPassword := string(data[offset : offset+int(pwdLen)])
	// Remove null terminator if present
	if len(newPassword) > 0 && newPassword[len(newPassword)-1] == 0 {
		newPassword = newPassword[:len(newPassword)-1]
	}

	h.logger.Info("V3 set password request",
		"uin", uin,
		"new_password_len", len(newPassword),
	)

	// Update password using service
	// Note: iserverd doesn't validate old password, so we pass empty string
	ctx := context.Background()
	if err := h.service.SetPassword(ctx, uin, "", newPassword); err != nil {
		h.logger.Error("V3 set password failed",
			"uin", uin,
			"err", err,
		)
		// Still send OK response to match iserverd behavior
		// (iserverd doesn't have error handling for this)
	} else {
		h.logger.Info("V3 password updated successfully", "uin", uin)
	}

	// Send OK response (0x0140 = ICQ_CMDxSND_USERxSET_PASSWD_OK)
	return h.sendReplyOK(session, seq2, 0x0140)
}

// handleSetAuth processes set auth mode request (0x0514)
// From iserverd v3_process_setauth()
// Data format: TIMESTAMP(4) + AUTH_MODE(1)
// - AUTH_MODE: 0 = no auth required, 1 = auth required
func (h *V3Handler) handleSetAuth(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse auth mode - format: TIMESTAMP(4) + AUTH_MODE(1)
	// From iserverd v3_process_setauth():
	// int_pack >> ... >> temp_stamp;
	// auth_mode = 0;
	// int_pack >> auth_mode;
	authRequired := false
	if len(data) >= 5 {
		// Skip timestamp (4 bytes), read auth_mode (1 byte)
		authMode := data[4]
		authRequired = authMode != 0
	}

	h.logger.Debug("V3 set auth",
		"uin", uin,
		"auth_required", authRequired,
	)

	// Update auth mode in database
	ctx := context.Background()
	if err := h.service.SetAuthMode(ctx, uin, authRequired); err != nil {
		h.logger.Error("V3 set auth failed",
			"uin", uin,
			"err", err,
		)
		// Still send OK response to match iserverd behavior
	}

	// Send OK response (0x01F4 = ICQ_CMDxSND_USERxSET_AUTH_OK)
	return h.sendReplyOK(session, seq2, 0x01F4)
}

// handleSetState processes set client state request (0x0528)
// From iserverd v3_process_state() - client state/mode changes
// This is the V3 status change command - when a user changes their status
// (e.g., Online -> Away, Away -> DND), this handler updates the session
// and broadcasts the status change to all contacts.
//
// Data format: TIMESTAMP(4) + STATUS(4) + ESTATUS(4)
// - STATUS: Low 16 bits of status (Online=0, Away=1, DND=2, NA=4, etc.)
// - ESTATUS: High 16 bits of status (extended status flags)
func (h *V3Handler) handleSetState(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse status - format: TIMESTAMP(4) + STATUS(4) + ESTATUS(4)
	// From iserverd v3_process_status():
	// int_pack >> ... >> new_status >> new_estatus;
	if len(data) < 12 {
		h.logger.Debug("V3 set state - data too short", "uin", uin, "len", len(data))
		return nil
	}

	// Skip timestamp (4 bytes)
	offset := 4

	// Read status (4 bytes) - low word is status, high word is extended status
	newStatus := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Read extended status (4 bytes) - some clients send this separately
	newEStatus := binary.LittleEndian.Uint32(data[offset : offset+4])

	// Combine status and extended status (iserverd: user.status = new_status, user.estat = new_estatus)
	// The full status is stored as: status | (estatus << 16)
	fullStatus := newStatus | (newEStatus << 16)

	oldStatus := session.GetStatus()
	session.SetStatus(fullStatus)

	h.logger.Info("V3 status change",
		"uin", uin,
		"old_status", fmt.Sprintf("0x%08X", oldStatus),
		"new_status", fmt.Sprintf("0x%08X", fullStatus),
	)

	// Broadcast status change to all contacts who have this user in their list
	// From iserverd v3_process_status(): broadcast_status(user, old_status)
	h.broadcastStatusChange(session, fullStatus)

	return nil
}

// broadcastStatusChange notifies all contacts who have this user in their list
// that the user's status has changed.
// From iserverd broadcast_status() in broadcast.cpp - this function finds all
// online users who have the target user in their contact list and sends them
// a status update notification.
func (h *V3Handler) broadcastStatusChange(session *LegacySession, newStatus uint32) {
	if h.dispatcher == nil {
		return
	}

	// Find all sessions that have this user in their contact list
	// This is the same logic used for online/offline notifications
	contactsToNotify := h.sessions.NotifyContactsOfStatus(session)

	h.logger.Debug("broadcasting status change to contacts",
		"uin", session.UIN,
		"new_status", fmt.Sprintf("0x%08X", newStatus),
		"contacts_to_notify", contactsToNotify,
	)

	for _, contactUIN := range contactsToNotify {
		contactSession := h.sessions.GetSession(contactUIN)
		if contactSession != nil {
			// Use dispatcher to send status change in correct protocol format
			// This routes to V3 or V5 handler based on the contact's protocol version
			h.dispatcher.SendStatusChange(contactSession, session.UIN, newStatus)
		}
	}
}

// handleUsageStats processes usage statistics (0x0532)
// From iserverd v3_process_usagestats() - client sends usage data
func (h *V3Handler) handleUsageStats(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 usage stats", "uin", uin)

	return nil
}

// handleGetExternals processes get externals request (0x04C4)
// From iserverd v3_process_getext() - returns external services list
func (h *V3Handler) handleGetExternals(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 get externals", "uin", uin)

	// Send externals response (empty list)
	return h.sendExternals(session, seq2)
}

// handleSysAck processes system message acknowledgment (0x0442)
// From iserverd v3_process_sysack() - client acknowledges receipt of offline messages
// After receiving this, we delete the offline messages from the database
func (h *V3Handler) handleSysAck(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	ctx := context.Background()

	// Delete offline messages for this user
	if err := h.service.AckOfflineMessages(ctx, uin); err != nil {
		h.logger.Error("failed to delete offline messages", "uin", uin, "err", err)
	} else {
		h.logger.Debug("V3 offline messages deleted", "uin", uin)
	}

	return nil
}

// handleOnlineInfo processes reconnect/online info request (0x015E)
// From iserverd v3_process_onlineinfo()
func (h *V3Handler) handleOnlineInfo(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V3 online info", "uin", uin)

	return nil
}

// handleGetInfo1 processes get basic info only request (0x0460)
// From iserverd v3_process_getinfo1() - sends only basic info (not full 5-packet set)
func (h *V3Handler) handleGetInfo1(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse: TIMESTAMP(4) + TARGET_UIN(4)
	if len(data) < 8 {
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[4:8])

	h.logger.Debug("V3 get info1", "uin", uin, "target", targetUIN)

	// Send only basic info (unlike handleGetInfo which sends all 5 packets)
	return h.sendBasicInfo(session, seq2, targetUIN)
}

// sendNotes sends notes response (0x0352)
// From iserverd v3_send_notes()
func (h *V3Handler) sendNotes(session *LegacySession, seq2 uint16, targetUIN uint32, notes string) error {
	pktSize := 16 + 2 + len(notes) + 1 + 12 // header + notes + timestamps
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0352) // ICQ_CMDxSND_USERxNOTES
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Notes (length-prefixed)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(notes)+1))
	offset += 2
	copy(pkt[offset:], notes)
	offset += len(notes)
	pkt[offset] = 0
	offset++

	// Timestamps: nupdate(4) + lastlogin(4) + ip_addr(4)
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendExternals sends externals list response (0x00B4)
// From iserverd v3_send_externals()
func (h *V3Handler) sendExternals(session *LegacySession, seq2 uint16) error {
	pkt := make([]byte, 20)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x00B4) // ICQ_CMDxSND_USERxEXTERNALS
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Count = 0 (no externals)
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	return h.sender.SendToSession(session, pkt[:offset])
}
