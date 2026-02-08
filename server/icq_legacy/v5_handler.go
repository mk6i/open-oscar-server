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
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// V5Handler handles ICQ V5 protocol packets
// V5 has full packet encryption and META_USER commands
type V5Handler struct {
	sessions      *LegacySessionManager
	service       LegacyService
	sender        PacketSender
	packetBuilder V5PacketBuilder   // Packet builder for constructing V5 protocol packets
	dispatcher    MessageDispatcher // Central dispatcher for cross-protocol messaging
	logger        *slog.Logger
}

// NewV5Handler creates a new V5 protocol handler
func NewV5Handler(
	sessions *LegacySessionManager,
	service LegacyService,
	sender PacketSender,
	packetBuilder V5PacketBuilder,
	logger *slog.Logger,
) *V5Handler {
	return &V5Handler{
		sessions:      sessions,
		service:       service,
		sender:        sender,
		packetBuilder: packetBuilder,
		dispatcher:    nil, // Set later via SetDispatcher to avoid circular dependency
		logger:        logger,
	}
}

// SetSender sets the packet sender (for circular dependency resolution)
func (h *V5Handler) SetSender(sender PacketSender) {
	h.sender = sender
}

// SetDispatcher sets the message dispatcher for cross-protocol messaging
func (h *V5Handler) SetDispatcher(dispatcher MessageDispatcher) {
	h.dispatcher = dispatcher
}

// Handle processes a V5 protocol packet
func (h *V5Handler) Handle(session *LegacySession, addr *net.UDPAddr, packet []byte) error {
	// V5 packet format (encrypted from offset 0x0A):
	// Version(2) + Zero(4) + UIN(4) + [Encrypted: SessionID(4) + Command(2) + SeqNum1(2) + SeqNum2(2)] + CheckCode(4) + [Encrypted: Data...]

	if len(packet) < 24 {
		return fmt.Errorf("V5 packet too short: %d bytes", len(packet))
	}

	h.logger.Debug("raw V5 packet before decryption",
		"hex", fmt.Sprintf("%X", packet),
		"len", len(packet),
	)

	// Make a copy for decryption
	decrypted := make([]byte, len(packet))
	copy(decrypted, packet)

	// Decrypt the packet (sessionID is not used - key is derived from packet)
	wire.DecryptV5Packet(decrypted, 0)

	h.logger.Debug("V5 packet after decryption",
		"hex", fmt.Sprintf("%X", decrypted),
	)

	// Parse decrypted packet
	pkt, err := wire.UnmarshalV5ClientPacket(decrypted)
	if err != nil {
		return fmt.Errorf("parsing V5 packet: %w", err)
	}

	h.logger.Info("V5 packet received",
		"command", fmt.Sprintf("0x%04X", pkt.Command),
		"uin", pkt.UIN,
		"session_id", pkt.SessionID,
		"seq1", pkt.SeqNum1,
		"seq2", pkt.SeqNum2,
		"data_len", len(pkt.Data),
		"addr", addr.String(),
	)

	// Update session activity if we have one
	if session != nil {
		session.UpdateActivity()
		session.SeqNumClient = pkt.SeqNum1
	}

	// If no session exists and this is not a login/registration/ack command,
	// send NOT_CONNECTED (0x00F0) to force the client to reconnect.
	// This handles the case where the server restarted but the UDP client
	// kept sending packets (keep-alives, commands) to the old session.
	// The V5 client (licq) handles this as "Server says you are not logged on"
	// and triggers icqRelogon().
	if session == nil {
		switch pkt.Command {
		case wire.ICQLegacyCmdAck, wire.ICQLegacyCmdFirstLogin,
			wire.ICQLegacyCmdGetDeps, wire.ICQLegacyCmdLogin,
			wire.ICQLegacyCmdRegNewUser:
			// Allow these through - they don't require a session
		default:
			h.logger.Info("V5 packet from unknown session, sending NOT_CONNECTED",
				"command", fmt.Sprintf("0x%04X", pkt.Command),
				"uin", pkt.UIN,
				"addr", addr.String(),
			)
			return h.sendV5NotConnected(addr, pkt.SessionID, pkt.UIN, pkt.SeqNum1, pkt.SeqNum2)
		}
	}

	// Handle ALL V5 commands directly - NO fallback to V2!
	switch pkt.Command {
	case wire.ICQLegacyCmdAck:
		h.logger.Debug("received V5 ACK", "seq1", pkt.SeqNum1, "seq2", pkt.SeqNum2)
		return nil
	case wire.ICQLegacyCmdFirstLogin:
		return h.handleFirstLogin(session, addr, pkt)
	case wire.ICQLegacyCmdGetDeps:
		return h.handleGetDeps(session, addr, pkt)
	case wire.ICQLegacyCmdLogin:
		return h.handleLogin(session, addr, pkt)
	case wire.ICQLegacyCmdContactList:
		return h.handleContactList(session, pkt)
	case wire.ICQLegacyCmdKeepAlive, wire.ICQLegacyCmdKeepAlive2:
		return h.handlePing(session, pkt)
	case wire.ICQLegacyCmdLogoff:
		return h.handleLogoff(session, pkt)
	case wire.ICQLegacyCmdSetStatus:
		return h.handleSetStatus(session, pkt)
	case wire.ICQLegacyCmdThruServer, wire.ICQLegacyCmdAuthorize:
		return h.handleMessage(session, pkt)
	case wire.ICQLegacyCmdUserAdd:
		return h.handleUserAdd(session, pkt)
	case wire.ICQLegacyCmdSysMsgReq:
		return h.handleOfflineMsgReq(session, pkt)
	case wire.ICQLegacyCmdSysMsgDoneAck:
		return h.handleOfflineMsgAck(session, pkt)
	case wire.ICQLegacyCmdMetaUser:
		return h.handleMetaUser(session, addr, pkt)
	case wire.ICQLegacyCmdVisibleList:
		return h.handleVisibleList(session, pkt)
	case wire.ICQLegacyCmdInvisibleList:
		return h.handleInvisibleList(session, pkt)
	case wire.ICQLegacyCmdChangeVILists:
		return h.handleChangeVILists(session, pkt)
	case wire.ICQLegacyCmdSearchUIN:
		return h.handleOldSearchUIN(session, pkt)
	case wire.ICQLegacyCmdSearchUser:
		return h.handleOldSearch(session, pkt)
	case wire.ICQLegacyCmdInfoReq:
		return h.handleOldInfoReq(session, pkt)
	case wire.ICQLegacyCmdExtInfoReq:
		return h.handleOldExtInfoReq(session, pkt)
	case wire.ICQLegacyCmdRegNewUser:
		return h.handleAckNewUIN(session, pkt)
	case 0x0532, 0x0533: // CMD_META_SEARCH_WHITE - white pages search sent directly
		return h.handleDirectWhiteSearch(session, pkt)
	case 0x0514, 0x0515: // CMD_META_SEARCH_NAME - name search sent directly
		return h.handleDirectNameSearch(session, pkt)
	case 0x051F: // CMD_META_SEARCH_UIN2 - UIN search sent directly (0x051E is PING2, handled above)
		return h.handleDirectUINSearch(session, pkt)
	case 0x0528, 0x0529: // CMD_META_SEARCH_EMAIL - email search sent directly
		return h.handleDirectEmailSearch(session, pkt)
	default:
		h.logger.Info("unhandled V5 command",
			"command", fmt.Sprintf("0x%04X", pkt.Command),
			"uin", pkt.UIN,
			"data_len", len(pkt.Data),
		)
		// Send ACK for unknown commands
		if session != nil {
			return h.sendV5Ack(session, pkt.SeqNum1)
		}
		return h.sendV5AckToAddr(addr, pkt.SessionID, pkt.UIN, pkt.SeqNum1, pkt.SeqNum2)
	}
}

// handleMetaUser processes META_USER commands
func (h *V5Handler) handleMetaUser(session *LegacySession, addr *net.UDPAddr, pkt *wire.V5ClientPacket) error {
	if len(pkt.Data) < 2 {
		return fmt.Errorf("META_USER packet too short")
	}

	// Send ACK first (as per iserverd v5_process_user_meta)
	// ACK echoes both seq1 and seq2 from the client
	if session != nil {
		h.sendV5AckWithSeq2(session, pkt.SeqNum1, pkt.SeqNum2)
	}

	subCommand := binary.LittleEndian.Uint16(pkt.Data[0:2])
	subData := pkt.Data[2:]

	h.logger.Info("META_USER command",
		"sub_command", fmt.Sprintf("0x%04X", subCommand),
		"uin", pkt.UIN,
		"sub_data_len", len(subData),
	)

	switch subCommand {
	case 0x07D0: // CMD_META_LOGIN - client requests login meta info
		return h.handleMetaLogin(session, pkt, subData)
	case 0x04CE, 0x04CF: // CMD_META_USER_LOGININFO, CMD_META_USER_LOGININFO2 - request own info after login
		return h.handleMetaLoginInfo(session, pkt, subData)
	case wire.ICQLegacyMetaSetBasic, wire.ICQLegacyMetaSetBasic2:
		return h.handleMetaSetBasic(session, pkt, subData)
	case wire.ICQLegacyMetaSetWork, wire.ICQLegacyMetaSetWork2:
		return h.handleMetaSetWork(session, pkt, subData)
	case wire.ICQLegacyMetaSetMore, wire.ICQLegacyMetaSetMore2:
		return h.handleMetaSetMore(session, pkt, subData)
	case wire.ICQLegacyMetaSetAbout:
		return h.handleMetaSetAbout(session, pkt, subData)
	case wire.ICQLegacyMetaSetInterests:
		return h.handleMetaSetInterests(session, pkt, subData)
	case wire.ICQLegacyMetaSetAffiliations:
		return h.handleMetaSetAffiliations(session, pkt, subData)
	case wire.ICQLegacyMetaSetSecurity:
		return h.handleMetaSetSecurity(session, pkt, subData)
	case wire.ICQLegacyMetaSetPass:
		return h.handleMetaSetPassword(session, pkt, subData)
	case wire.ICQLegacyMetaSetHPCat:
		return h.handleMetaSetHPCat(session, pkt, subData)
	case wire.ICQLegacyMetaUserUnreg:
		return h.handleMetaUnregister(session, pkt, subData)
	case wire.ICQLegacyMetaUserFullInfo:
		return h.handleMetaUserFullInfo(session, pkt, subData)
	case wire.ICQLegacyMetaUserFullInfo2:
		return h.handleMetaUserFullInfo2(session, pkt, subData)
	case wire.ICQLegacyMetaUserInfo:
		return h.handleMetaUserInfo(session, pkt, subData)
	case wire.ICQLegacyMetaSearchName, wire.ICQLegacyMetaSearchName2:
		return h.handleMetaSearchName(session, pkt, subData)
	case wire.ICQLegacyMetaSearchUIN, wire.ICQLegacyMetaSearchUIN2:
		return h.handleMetaSearchUIN(session, pkt, subData)
	case wire.ICQLegacyMetaSearchEmail, wire.ICQLegacyMetaSearchEmail2:
		return h.handleMetaSearchEmail(session, pkt, subData)
	case wire.ICQLegacyMetaSearchWhite:
		return h.handleMetaSearchWhite(session, pkt, subData)
	case wire.ICQLegacyMetaSearchWhite2:
		return h.handleMetaSearchWhite2(session, pkt, subData)
	default:
		h.logger.Info("unhandled META_USER sub-command",
			"sub_command", fmt.Sprintf("0x%04X", subCommand),
			"uin", pkt.UIN,
			"data_len", len(subData),
		)
		return h.sendMetaAck(session, pkt.SeqNum2, subCommand)
	}
}

// handleVisibleList processes a visible list update (V5)
func (h *V5Handler) handleVisibleList(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	contactList, err := wire.ParseV2ContactList(pkt.Data)
	if err != nil {
		h.logger.Info("visible list parse failed", "uin", session.UIN, "err", err)
		return h.sendV5Ack(session, pkt.SeqNum1)
	}

	session.SetVisibleList(contactList.UINs)
	h.logger.Info("visible list updated", "uin", session.UIN, "count", len(contactList.UINs), "uins", contactList.UINs)
	return h.sendV5Ack(session, pkt.SeqNum1)
}

// handleInvisibleList processes an invisible list update (V5)
func (h *V5Handler) handleInvisibleList(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	contactList, err := wire.ParseV2ContactList(pkt.Data)
	if err != nil {
		h.logger.Info("invisible list parse failed", "uin", session.UIN, "err", err)
		return h.sendV5Ack(session, pkt.SeqNum1)
	}

	session.SetInvisibleList(contactList.UINs)
	h.logger.Info("invisible list updated", "uin", session.UIN, "count", len(contactList.UINs), "uins", contactList.UINs)
	return h.sendV5Ack(session, pkt.SeqNum1)
}

// handleChangeVILists processes a change to visible/invisible lists
func (h *V5Handler) handleChangeVILists(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	// Parse the change request
	// Format: action(1) + uin(4)
	// Action: 1=add to visible, 2=remove from visible, 3=add to invisible, 4=remove from invisible

	if len(pkt.Data) < 5 {
		h.logger.Info("change VI lists - data too short", "uin", session.UIN)
		return h.sendV5Ack(session, pkt.SeqNum1)
	}

	action := pkt.Data[0]
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[1:5])

	actionName := "unknown"
	switch action {
	case 1:
		actionName = "add_visible"
	case 2:
		actionName = "remove_visible"
	case 3:
		actionName = "add_invisible"
	case 4:
		actionName = "remove_invisible"
	}

	h.logger.Info("change VI lists",
		"uin", session.UIN,
		"action", actionName,
		"target_uin", targetUIN,
	)

	// TODO: Implement list modifications

	return h.sendV5Ack(session, pkt.SeqNum1)
}

// handleFirstLogin processes the first login packet (0x04EC)
// This is sent before the actual login to set up the connection
// From iserverd v5_process_firstlog()
func (h *V5Handler) handleFirstLogin(session *LegacySession, addr *net.UDPAddr, pkt *wire.V5ClientPacket) error {
	// Parse session_id2 from data (4 bytes at offset 0)
	var sessionID2 uint32
	if len(pkt.Data) >= 4 {
		sessionID2 = binary.LittleEndian.Uint32(pkt.Data[0:4])
	}

	h.logger.Info("V5 first login",
		"uin", pkt.UIN,
		"session_id", pkt.SessionID,
		"session_id2", sessionID2,
		"addr", addr.String(),
	)

	// Send special ACK response with session_id2
	// From iserverd: reply includes session_id2 and 0x0001
	return h.sendV5FirstLoginReply(addr, pkt.SessionID, pkt.UIN, pkt.SeqNum1, pkt.SeqNum2, sessionID2)
}

// handleGetDeps processes the pre-auth pseudo-login packet (0x03F2)
// Historically called "get departments list" in iserverd - the original ICQ server
// had a departments database for organizational hierarchies. In V5, iserverd sends
// a deprecated empty V3-format response. The licq.5 client does NOT use this command;
// it goes straight to login. This is used by older V3/V4 clients (e.g., ICQ98a).
//
// The command validates credentials before the actual login.
// From iserverd v5_process_getdeps()
//
// Refactored to use service layer (AuthenticateUser) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> build response
func (h *V5Handler) handleGetDeps(session *LegacySession, addr *net.UDPAddr, pkt *wire.V5ClientPacket) error {
	ctx := context.Background()

	// 1. Unmarshal packet to typed struct
	// V5 getdeps data format: UIN(4) + PWD_LEN(2) + PASSWORD + CLIENT_VERSION(4)
	if len(pkt.Data) < 6 {
		h.logger.Debug("V5 getdeps packet too short", "len", len(pkt.Data))
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, pkt.UIN, pkt.SeqNum2))
	}

	offset := 0

	// Read UIN (4 bytes)
	uin := binary.LittleEndian.Uint32(pkt.Data[offset : offset+4])
	offset += 4

	// Read password length (2 bytes)
	pwdLen := binary.LittleEndian.Uint16(pkt.Data[offset : offset+2])
	offset += 2

	if pwdLen > 20 {
		pwdLen = 20
	}

	// Read password
	if offset+int(pwdLen) > len(pkt.Data) {
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, uin, pkt.SeqNum2))
	}
	password := string(pkt.Data[offset : offset+int(pwdLen)])
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}

	h.logger.Info("V5 getdeps (pseudo-login)",
		"uin", uin,
		"password", password,
		"session_id", pkt.SessionID,
	)

	// 2. Call service layer with typed request
	authReq := foodgroup.AuthRequest{
		UIN:      uin,
		Password: password,
		Version:  wire.ICQLegacyVersionV5,
	}

	authResult, err := h.service.AuthenticateUser(ctx, authReq)
	if err != nil {
		h.logger.Error("V5 getdeps authentication error", "err", err, "uin", uin)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, uin, pkt.SeqNum2))
	}

	if !authResult.Success {
		h.logger.Info("V5 getdeps FAILED - invalid credentials",
			"uin", uin,
			"error_code", authResult.ErrorCode,
		)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, uin, pkt.SeqNum2))
	}

	h.logger.Info("V5 getdeps OK - credentials valid", "uin", uin)

	// 3. Build and send responses using packet builder
	// Send ACK first
	h.sender.SendPacket(addr, h.packetBuilder.BuildAckToAddr(pkt.SessionID, uin, pkt.SeqNum1, pkt.SeqNum2))

	// Send depslist response (V3 format packet!) using packet builder
	return h.sender.SendPacket(addr, h.packetBuilder.BuildDepsListReply(uin, pkt.SeqNum2))
}

// handleContactList processes contact list (0x0406)
// From iserverd v5_process_contact_list(): processes contact list and sends online notifications
//
// Refactored to use service layer (ProcessContactList) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> send notifications
func (h *V5Handler) handleContactList(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	// 1. Send ACK using packet builder
	h.sender.SendPacket(session.Addr, h.packetBuilder.BuildAck(session, pkt.SeqNum1))

	// 2. Unmarshal packet to typed request struct
	req, err := h.parseContactListPacket(pkt.Data, session.UIN)
	if err != nil {
		h.logger.Debug("V5 contact list parse error", "uin", session.UIN, "err", err)
		// Send contact list done even on parse error
		return h.sender.SendToSession(session, h.packetBuilder.BuildContactListDone(session, pkt.SeqNum2))
	}

	h.logger.Info("V5 contact list",
		"uin", session.UIN,
		"count", len(req.Contacts),
		"contacts", req.Contacts,
	)

	// Store contact list in session (handler responsibility - session management)
	session.SetContactList(req.Contacts)

	// 3. Call service layer with typed request
	ctx := context.Background()
	result, err := h.service.ProcessContactList(ctx, req)
	if err != nil {
		h.logger.Error("contact list processing failed", "uin", session.UIN, "err", err)
		// Still send contact list done on error
		return h.sender.SendToSession(session, h.packetBuilder.BuildContactListDone(session, pkt.SeqNum2))
	}

	// 4. Send online notifications based on service result
	for _, contact := range result.OnlineContacts {
		if contact.Online {
			if h.dispatcher != nil {
				// Use central dispatcher - routes to correct protocol based on session's version
				h.dispatcher.SendUserOnline(session, contact.UIN, contact.Status)
			} else {
				// Fallback to V5 format if dispatcher not set using packet builder
				h.sender.SendToSession(session, h.packetBuilder.BuildUserOnline(session, contact.UIN, contact.Status))
			}
		}
	}

	// Also notify contacts that THIS user is now online
	// This is the key fix - we need to tell contacts who have us in their list
	h.notifyContactsUserOnline(session)

	// 5. Send contact list done using packet builder
	return h.sender.SendToSession(session, h.packetBuilder.BuildContactListDone(session, pkt.SeqNum2))
}

// parseContactListPacket parses a V5 contact list packet into a typed ContactListRequest struct.
// Format: COUNT(1) + UIN(4)*COUNT
func (h *V5Handler) parseContactListPacket(data []byte, ownerUIN uint32) (foodgroup.ContactListRequest, error) {
	req := foodgroup.ContactListRequest{
		UIN:      ownerUIN,
		Contacts: make([]uint32, 0),
	}

	if len(data) < 1 {
		return req, fmt.Errorf("contact list packet too short: %d bytes", len(data))
	}

	// Contact count (1 byte)
	count := int(data[0])
	offset := 1

	// Parse contact UINs
	for i := 0; i < count && offset+4 <= len(data); i++ {
		contactUIN := binary.LittleEndian.Uint32(data[offset : offset+4])
		req.Contacts = append(req.Contacts, contactUIN)
		offset += 4
	}

	return req, nil
}

// notifyContactsUserOnline notifies all contacts who have this user in their list that we're online
// Following iserverd's pattern: when user comes online, notify everyone who cares
func (h *V5Handler) notifyContactsUserOnline(session *LegacySession) {
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

// handlePing processes keep-alive packets (0x042E, 0x051E)
func (h *V5Handler) handlePing(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}
	return h.sendV5Ack(session, pkt.SeqNum1)
}

// handleLogoff processes logout (0x0438)
func (h *V5Handler) handleLogoff(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}
	h.logger.Info("V5 logout",
		"uin", session.UIN,
		"session_id", session.SessionID,
		"addr", session.Addr.String(),
	)

	// Notify contacts that this user is going offline BEFORE removing session
	h.notifyContactsUserOffline(session)

	h.sessions.RemoveSession(session.UIN)
	return nil
}

// notifyContactsUserOffline notifies all contacts who have this user in their list that we're offline
func (h *V5Handler) notifyContactsUserOffline(session *LegacySession) {
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

// handleSetStatus processes status change (0x04D8)
// From iserverd v5_process_status() - when a user changes their status
// (e.g., Online -> Away, Away -> DND), this handler updates the session
// and broadcasts the status change to all contacts.
//
// Refactored to use service layer (ProcessStatusChange) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> broadcast
//
// Data format: STATUS(4)
// - STATUS: Combined status value (low 16 bits = status, high 16 bits = extended status)
func (h *V5Handler) handleSetStatus(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	// 1. Send ACK using packet builder
	h.sender.SendPacket(session.Addr, h.packetBuilder.BuildAck(session, pkt.SeqNum1))

	// 2. Unmarshal packet to typed request struct
	req, err := h.parseStatusChangePacket(pkt.Data, session)
	if err != nil {
		h.logger.Debug("V5 status change parse error", "uin", session.UIN, "err", err)
		return nil
	}

	h.logger.Info("V5 status change",
		"uin", req.UIN,
		"old_status", fmt.Sprintf("0x%08X", req.OldStatus),
		"new_status", fmt.Sprintf("0x%08X", req.NewStatus),
	)

	// Update session status (handler responsibility - session management)
	session.SetStatus(req.NewStatus)

	// 3. Call service layer with typed request
	ctx := context.Background()
	result, err := h.service.ProcessStatusChange(ctx, req)
	if err != nil {
		h.logger.Error("status change processing failed", "uin", req.UIN, "err", err)
		return nil
	}

	// 4. Broadcast status change to contacts based on service result
	h.broadcastStatusChangeToTargets(session, req.NewStatus, result)

	return nil
}

// parseStatusChangePacket parses a V5 status change packet into a typed StatusChangeRequest struct.
// Format: STATUS(4)
func (h *V5Handler) parseStatusChangePacket(data []byte, session *LegacySession) (foodgroup.StatusChangeRequest, error) {
	req := foodgroup.StatusChangeRequest{
		UIN:       session.UIN,
		OldStatus: session.GetStatus(),
	}

	if len(data) < 4 {
		return req, fmt.Errorf("status change packet too short: %d bytes", len(data))
	}

	// Parse new status (4 bytes)
	req.NewStatus = binary.LittleEndian.Uint32(data[0:4])

	return req, nil
}

// broadcastStatusChangeToTargets notifies all contacts in the service result
// that the user's status has changed.
// Following the OSCAR pattern: the service layer determines WHO to notify,
// the handler determines HOW to notify (protocol-specific packets).
func (h *V5Handler) broadcastStatusChangeToTargets(session *LegacySession, newStatus uint32, result *foodgroup.StatusChangeResult) {
	if result == nil || len(result.NotifyTargets) == 0 {
		return
	}

	h.logger.Debug("broadcasting status change to contacts",
		"uin", session.UIN,
		"new_status", fmt.Sprintf("0x%08X", newStatus),
		"notify_count", len(result.NotifyTargets),
	)

	for _, target := range result.NotifyTargets {
		targetSession := h.sessions.GetSession(target.UIN)
		if targetSession != nil {
			if h.dispatcher != nil {
				// Use dispatcher to send status change in correct protocol format
				// This routes to V3 or V5 handler based on the contact's protocol version
				h.dispatcher.SendStatusChange(targetSession, session.UIN, newStatus)
			} else {
				// Fallback to V5 format if dispatcher not set using packet builder
				h.sender.SendToSession(targetSession, h.packetBuilder.BuildUserStatus(targetSession, session.UIN, newStatus))
			}
		}
	}
}

// handleMessage processes through-server messages (0x010E)
// From iserverd v5_process_sysmsg(): forwards messages to target user
// Format: TARGET_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
//
// Refactored to use service layer (ProcessMessage) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> route
func (h *V5Handler) handleMessage(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	// 1. Send ACK using packet builder
	h.sender.SendPacket(session.Addr, h.packetBuilder.BuildAck(session, pkt.SeqNum1))

	// 2. Unmarshal packet to typed request struct
	req, err := h.parseMessagePacket(pkt.Data, session.UIN)
	if err != nil {
		h.logger.Debug("V5 message parse error", "from", session.UIN, "err", err)
		return nil
	}

	h.logger.Info("V5 message received",
		"from", req.FromUIN,
		"to", req.ToUIN,
		"type", fmt.Sprintf("0x%04X", req.MsgType),
		"msg_len", len(req.Message),
	)

	// 3. Call service layer with typed request
	ctx := context.Background()
	result, err := h.service.ProcessMessage(ctx, req)
	if err != nil {
		h.logger.Error("message processing failed",
			"from", req.FromUIN,
			"to", req.ToUIN,
			"err", err,
		)
		return nil
	}

	// 4. Route message based on service result
	if result.TargetOnline {
		// Target is online - forward message via dispatcher or direct send
		targetSession := h.sessions.GetSession(req.ToUIN)
		if targetSession != nil {
			if h.dispatcher != nil {
				// Use central dispatcher - routes to correct protocol based on target's version
				h.dispatcher.SendOnlineMessage(targetSession, req.FromUIN, req.MsgType, req.Message)
			} else {
				// Fallback to V5 format if dispatcher not set
				h.sendOnlineMessage(targetSession, req.FromUIN, req.MsgType, req.Message)
			}
			h.logger.Debug("V5 message forwarded",
				"from", req.FromUIN,
				"to", req.ToUIN,
				"target_version", targetSession.Version,
			)
		}
	} else if result.StoredOffline {
		// Message was stored for offline delivery by the service layer
		h.logger.Info("V5 message stored for offline delivery",
			"from", req.FromUIN,
			"to", req.ToUIN,
			"type", fmt.Sprintf("0x%04X", req.MsgType),
		)
	}

	return nil
}

// parseMessagePacket parses a V5 message packet into a typed MessageRequest struct.
// Format: TARGET_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (h *V5Handler) parseMessagePacket(data []byte, fromUIN uint32) (foodgroup.MessageRequest, error) {
	req := foodgroup.MessageRequest{
		FromUIN: fromUIN,
	}

	if len(data) < 8 {
		return req, fmt.Errorf("message packet too short: %d bytes", len(data))
	}

	offset := 0

	// Target UIN (4 bytes)
	req.ToUIN = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Message type (2 bytes)
	req.MsgType = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Message length (2 bytes)
	msgLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Message content
	if msgLen > 0 && offset+int(msgLen) <= len(data) {
		req.Message = string(data[offset : offset+int(msgLen)])
	}

	return req, nil
}

// handleUserAdd processes user add to contact list (0x053C)
// From iserverd v5_process_useradd(): adds user and sends "you were added" notification
//
// Refactored to use service layer (ProcessUserAdd) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> send notifications
func (h *V5Handler) handleUserAdd(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	// 1. Send ACK using packet builder
	h.sender.SendPacket(session.Addr, h.packetBuilder.BuildAck(session, pkt.SeqNum1))

	// 2. Unmarshal packet to typed request struct
	req, err := h.parseUserAddPacket(pkt.Data, session.UIN)
	if err != nil {
		h.logger.Debug("V5 user add parse error", "uin", session.UIN, "err", err)
		return nil
	}

	h.logger.Info("V5 user add",
		"from", req.FromUIN,
		"target", req.TargetUIN,
	)

	// Add to contact list (handler responsibility - session management)
	contacts := session.GetContactList()
	contacts = append(contacts, req.TargetUIN)
	session.SetContactList(contacts)

	// 3. Call service layer with typed request
	ctx := context.Background()
	result, err := h.service.ProcessUserAdd(ctx, req)
	if err != nil {
		h.logger.Error("user add processing failed", "from", req.FromUIN, "target", req.TargetUIN, "err", err)
		return nil
	}

	// 4. Send notifications based on service result
	if result.TargetOnline {
		// Send target's online status to the user who added them using packet builder
		h.sender.SendToSession(session, h.packetBuilder.BuildUserOnline(session, req.TargetUIN, result.TargetStatus))

		// Send "you were added" notification to target user if service says to
		if result.SendYouWereAdded {
			targetSession := h.sessions.GetSession(req.TargetUIN)
			if targetSession != nil {
				// Message format: nick#FE#first#FE#last#FE#email#FE#auth
				// Using UIN as nick for now since we don't have user info
				youWereAddedMsg := fmt.Sprintf("%d\xFE\xFE\xFE\xFE0", req.FromUIN)

				if h.dispatcher != nil {
					// Use dispatcher for cross-protocol support
					h.dispatcher.SendOnlineMessage(targetSession, req.FromUIN, wire.ICQLegacyMsgAdded, youWereAddedMsg)
				} else {
					// Fallback to V5 format using packet builder
					h.sender.SendToSession(targetSession, h.packetBuilder.BuildOnlineMessage(targetSession, req.FromUIN, wire.ICQLegacyMsgAdded, youWereAddedMsg))
				}

				// Also send the adder's online status to the target.
				// The target receives "you were added" but won't see the
				// adder as online unless we explicitly tell them. Without
				// this, the target's client shows the adder as offline
				// even though they're connected.
				if h.dispatcher != nil {
					h.dispatcher.SendUserOnline(targetSession, req.FromUIN, session.GetStatus())
				} else {
					h.sender.SendToSession(targetSession, h.packetBuilder.BuildUserOnline(targetSession, req.FromUIN, session.GetStatus()))
				}

				h.logger.Debug("V5 sent 'you were added' notification",
					"from", req.FromUIN,
					"to", req.TargetUIN,
				)
			}
		}
	}

	return nil
}

// parseUserAddPacket parses a V5 user add packet into a typed UserAddRequest struct.
// Format: TARGET_UIN(4)
func (h *V5Handler) parseUserAddPacket(data []byte, fromUIN uint32) (foodgroup.UserAddRequest, error) {
	req := foodgroup.UserAddRequest{
		FromUIN: fromUIN,
	}

	if len(data) < 4 {
		return req, fmt.Errorf("user add packet too short: %d bytes", len(data))
	}

	// Target UIN (4 bytes)
	req.TargetUIN = binary.LittleEndian.Uint32(data[0:4])

	return req, nil
}

// handleOfflineMsgReq processes offline message request (0x044C)
func (h *V5Handler) handleOfflineMsgReq(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	ctx := context.Background()

	// Fetch offline messages from database
	messages, err := h.service.GetOfflineMessages(ctx, session.UIN)
	if err != nil {
		h.logger.Error("failed to get offline messages", "uin", session.UIN, "err", err)
		return h.sendV5OfflineMsgDone(session, pkt.SeqNum2)
	}

	h.logger.Info("V5 offline message request",
		"uin", session.UIN,
		"message_count", len(messages),
	)

	// Send each offline message
	for _, msg := range messages {
		if err := h.sendV5OfflineMessage(session, &msg); err != nil {
			h.logger.Error("failed to send offline message",
				"uin", session.UIN,
				"from", msg.FromUIN,
				"err", err,
			)
		}
	}

	// Send end of offline messages
	return h.sendV5OfflineMsgDone(session, pkt.SeqNum2)
}

// handleOfflineMsgAck processes offline message acknowledgment (0x0442)
// From iserverd v5_process_sysmsg_delete() - client acknowledges receipt of offline messages
// After receiving this, we delete the offline messages from the database
func (h *V5Handler) handleOfflineMsgAck(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	ctx := context.Background()

	// Delete offline messages for this user
	if err := h.service.AckOfflineMessages(ctx, session.UIN); err != nil {
		h.logger.Error("failed to delete offline messages", "uin", session.UIN, "err", err)
	} else {
		h.logger.Info("V5 offline messages deleted", "uin", session.UIN)
	}

	return nil
}

// handleOldSearchUIN processes old-style search by UIN (0x041A)
// From iserverd v5_process_old_srchuin()
func (h *V5Handler) handleOldSearchUIN(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	// Parse - format: TARGET_UIN(4)
	if len(pkt.Data) < 4 {
		h.logger.Info("V5 old search by UIN - data too short", "uin", session.UIN)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	ctx := context.Background()
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Info("V5 old search by UIN",
		"uin", session.UIN,
		"target_uin", targetUIN,
	)

	result, err := h.service.SearchByUIN(ctx, targetUIN)
	if err != nil {
		h.logger.Info("V5 old search by UIN - error", "target_uin", targetUIN, "err", err)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}
	if result == nil {
		h.logger.Info("V5 old search by UIN - NOT FOUND", "target_uin", targetUIN)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	h.logger.Info("V5 old search by UIN - FOUND",
		"target_uin", targetUIN,
		"nickname", result.Nickname,
		"firstname", result.FirstName,
		"lastname", result.LastName,
		"email", result.Email,
	)

	// Send search result
	h.sendV5OldSearchFound(session, pkt.SeqNum2, result)
	return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
}

// handleOldSearch processes old-style search by name/email (0x0424)
// From iserverd v5_process_old_search()
func (h *V5Handler) handleOldSearch(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	h.logger.Info("V5 old search", "uin", session.UIN, "data_len", len(pkt.Data), "status", "not_implemented")

	// TODO: Parse search parameters and search
	return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
}

// handleOldInfoReq processes old-style info request (0x0460)
// From iserverd v5_process_old_info()
func (h *V5Handler) handleOldInfoReq(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	// Parse - format: TARGET_UIN(4)
	if len(pkt.Data) < 4 {
		h.logger.Info("V5 old info request - data too short", "uin", session.UIN)
		return nil
	}

	ctx := context.Background()
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Info("V5 old info request",
		"uin", session.UIN,
		"target_uin", targetUIN,
	)

	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err != nil {
		h.logger.Info("V5 old info request - error", "target_uin", targetUIN, "err", err)
		return h.sendV5InvalidUIN(session, targetUIN)
	}
	if info == nil {
		h.logger.Info("V5 old info request - NOT FOUND", "target_uin", targetUIN)
		return h.sendV5InvalidUIN(session, targetUIN)
	}

	h.logger.Info("V5 old info request - FOUND",
		"target_uin", targetUIN,
		"nickname", info.Nickname,
		"firstname", info.FirstName,
		"lastname", info.LastName,
	)

	// Send basic info only - extended info is requested separately via 0x046A
	return h.sendV5OldStyleInfo(session, info)
}

// handleOldExtInfoReq processes old-style extended info request (0x046A)
// From iserverd v5_process_old_info_ext()
func (h *V5Handler) handleOldExtInfoReq(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	// Parse - format: TARGET_UIN(4)
	if len(pkt.Data) < 4 {
		h.logger.Info("V5 old ext info request - data too short", "uin", session.UIN)
		return nil
	}

	ctx := context.Background()
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Info("V5 old ext info request",
		"uin", session.UIN,
		"target_uin", targetUIN,
	)

	// Use GetFullUserInfo to get all extended info fields (city, state, phone, homepage, notes)
	// From iserverd v5_process_old_info_ext() which uses full_user_info and notes_user_info
	user, err := h.service.GetFullUserInfo(ctx, targetUIN)
	if err != nil {
		h.logger.Info("V5 old ext info request - error", "target_uin", targetUIN, "err", err)
		return h.sendV5InvalidUIN(session, targetUIN)
	}
	if user == nil {
		h.logger.Info("V5 old ext info request - NOT FOUND", "target_uin", targetUIN)
		return h.sendV5InvalidUIN(session, targetUIN)
	}

	h.logger.Info("V5 old ext info request - FOUND", "target_uin", targetUIN)
	return h.sendV5OldStyleInfoExt(session, targetUIN, user)
}

// handleAckNewUIN processes registration acknowledgment (0x03FC)
// From iserverd v5_process_ack_new_uin()
func (h *V5Handler) handleAckNewUIN(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	h.logger.Info("V5 ack new UIN", "uin", session.UIN)

	// This is just an acknowledgment from client, no action needed
	return nil
}

// handleLogin processes the login packet (0x03E8)
// From iserverd v5_process_login()
//
// Refactored to use service layer (AuthenticateUser) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> build response
func (h *V5Handler) handleLogin(session *LegacySession, addr *net.UDPAddr, pkt *wire.V5ClientPacket) error {
	ctx := context.Background()

	// 1. Send ACK first (iserverd does this immediately) using packet builder
	h.sender.SendPacket(addr, h.packetBuilder.BuildAckToAddr(pkt.SessionID, pkt.UIN, pkt.SeqNum1, pkt.SeqNum2))

	// 2. Unmarshal packet to typed struct
	// V5 login data format (verified against licq.5 CPU_Logon):
	//   TIME(4) + TCP_PORT(4) + PWD_LEN(2) + PASSWORD + UNKNOWN(4, =0x98) +
	//   REAL_IP(4) + MODE(1) + STATUS(4) + TCP_VERSION(4) + trailing(28 bytes)
	// Note: STATUS and TCP_VERSION are both PackUnsignedLong (4 bytes each).
	if len(pkt.Data) < 10 {
		h.logger.Debug("V5 login packet too short", "len", len(pkt.Data))
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, pkt.UIN, pkt.SeqNum2))
	}

	offset := 0

	// Skip time(NULL) timestamp (4 bytes) - client sends current time here
	offset += 4

	// Read TCP port (4 bytes)
	port := binary.LittleEndian.Uint32(pkt.Data[offset : offset+4])
	offset += 4

	// Read password length (2 bytes)
	if offset+2 > len(pkt.Data) {
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, pkt.UIN, pkt.SeqNum2))
	}
	pwdLen := binary.LittleEndian.Uint16(pkt.Data[offset : offset+2])
	offset += 2

	// Sanity check password length
	if pwdLen > 20 {
		pwdLen = 20
	}

	// Read password
	if offset+int(pwdLen) > len(pkt.Data) {
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, pkt.UIN, pkt.SeqNum2))
	}
	password := string(pkt.Data[offset : offset+int(pwdLen)])
	// Remove null terminator if present
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}
	offset += int(pwdLen)

	// Parse additional fields if available
	// V5 login data format (from licq.5 CPU_Logon):
	//   TIME(4) + PORT(4) + PWD_LEN(2) + PASSWORD + UNKNOWN(4) + REAL_IP(4) +
	//   MODE(1) + STATUS(4) + TCP_VERSION(4) + trailing(28 bytes)
	// Note: STATUS is PackUnsignedLong (4 bytes), NOT 2+2.
	//       TCP_VERSION is PackUnsignedLong (4 bytes), NOT 2 bytes.
	var internalIP uint32
	var dcType uint8
	var status uint32
	var tcpVersion uint32
	if offset+4+4+1+4+4 <= len(pkt.Data) {
		offset += 4 // skip unknown (0x98 constant)
		internalIP = binary.LittleEndian.Uint32(pkt.Data[offset : offset+4])
		offset += 4
		dcType = pkt.Data[offset]
		offset++
		status = binary.LittleEndian.Uint32(pkt.Data[offset : offset+4])
		offset += 4
		tcpVersion = binary.LittleEndian.Uint32(pkt.Data[offset : offset+4])
	}

	h.logger.Info("V5 login attempt",
		"uin", pkt.UIN,
		"password", password,
		"port", port,
		"internal_ip", fmt.Sprintf("0x%08X", internalIP),
		"dc_type", dcType,
		"status", fmt.Sprintf("0x%08X", status),
		"tcp_version", tcpVersion,
		"data_len", len(pkt.Data),
	)

	// 3. Call service layer with typed request
	authReq := foodgroup.AuthRequest{
		UIN:      pkt.UIN,
		Password: password,
		Status:   status,
		TCPPort:  port,
		Version:  wire.ICQLegacyVersionV5,
	}

	authResult, err := h.service.AuthenticateUser(ctx, authReq)
	if err != nil {
		h.logger.Error("V5 login authentication error", "err", err, "uin", pkt.UIN)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, pkt.UIN, pkt.SeqNum2))
	}

	if !authResult.Success {
		h.logger.Info("V5 login FAILED - invalid credentials",
			"uin", pkt.UIN,
			"error_code", authResult.ErrorCode,
		)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, pkt.UIN, pkt.SeqNum2))
	}

	// 4. Create session (handler responsibility - session management)
	newSession, err := h.sessions.CreateSession(pkt.UIN, addr, wire.ICQLegacyVersionV5)
	if err != nil {
		h.logger.Error("failed to create V5 session", "err", err, "uin", pkt.UIN)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(pkt.SessionID, pkt.UIN, pkt.SeqNum2))
	}

	// Use the client's session ID
	newSession.SessionID = pkt.SessionID
	newSession.Password = password
	newSession.SetStatus(status)

	// Store direct connection info for peer-to-peer
	newSession.SetDirectConnectionInfo(port, internalIP, uint16(tcpVersion), dcType)

	// 5. Build and send response using packet builder
	loginReplyPkt := h.packetBuilder.BuildLoginReply(newSession, pkt.SeqNum1, pkt.SeqNum2)
	if err := h.sender.SendToSession(newSession, loginReplyPkt); err != nil {
		return err
	}

	h.logger.Info("V5 login successful",
		"uin", pkt.UIN,
		"session_id", newSession.SessionID,
	)

	return nil
}

// sendV5BadPassword sends a bad password response
func (h *V5Handler) sendV5BadPassword(addr *net.UDPAddr, sessionID uint32, uin uint32, seq2 uint16) error {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: sessionID,
		Command:   wire.ICQLegacySrvWrongPasswd,
		SeqNum1:   0,
		SeqNum2:   seq2,
		UIN:       uin,
	}

	data := wire.MarshalV5ServerPacket(pkt)
	return h.sender.SendPacket(addr, data)
}

// sendV5LoginReply sends the login success (HELLO) packet
// From iserverd v5_send_login_reply()
//
// Data format (20 bytes total):
// - iserverd sends: 0x008C(2) + 0x0000(2) + PING_TIME(2) + TIMEOUT(2) + 0x000A(2) + RETRIES(2) + CLIENT_IP(4) + SERVER_ID(4)
// - Documentation shows: X1(4)=0x0000008C + X2(2)=0x00F0 + X3(2)=0x000A + X4(2)=0x000A + X5(2)=0x0005 + IP(4) + X6(4)
//
// Note: The JUNK(4) in iserverd code is the checkcode placeholder in the HEADER at offset 0x11, NOT data!
func (h *V5Handler) sendV5LoginReply(session *LegacySession, seq2 uint16) error {
	// Get client IP as uint32 (little-endian)
	var clientIP uint32
	if session.Addr != nil && session.Addr.IP != nil {
		ip := session.Addr.IP.To4()
		if ip != nil {
			clientIP = uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
		}
	}

	// Build data - 20 bytes (using iserverd format)
	data := make([]byte, 20)
	offset := 0

	binary.LittleEndian.PutUint16(data[offset:], 0x008C) // keep alive interval low
	offset += 2
	binary.LittleEndian.PutUint16(data[offset:], 0x0000) // keep alive interval high
	offset += 2
	binary.LittleEndian.PutUint16(data[offset:], 50) // ping time (60-10)
	offset += 2
	binary.LittleEndian.PutUint16(data[offset:], 60) // timeout
	offset += 2
	binary.LittleEndian.PutUint16(data[offset:], 0x000A) // unknown
	offset += 2
	binary.LittleEndian.PutUint16(data[offset:], 5) // retries
	offset += 2
	binary.LittleEndian.PutUint32(data[offset:], clientIP) // client IP
	offset += 4
	binary.LittleEndian.PutUint32(data[offset:], 0x80CDC19B) // server ID

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvHello,
		SeqNum1:   0,
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      data,
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	h.logger.Debug("sending V5 login reply",
		"uin", session.UIN,
		"session_id", session.SessionID,
		"client_ip", clientIP,
		"packet_len", len(packetData),
		"packet_hex", fmt.Sprintf("%X", packetData),
	)

	return h.sender.SendToSession(session, packetData)
}

// sendV5ContactListDone sends contact list processed response
func (h *V5Handler) sendV5ContactListDone(session *LegacySession, seq2 uint16) error {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvUserListDone,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5UserOnline sends user online notification
// From iserverd v5_send_user_online()
//
// Verified against licq.5 client (icqd-udp.cpp ICQ_CMDxRCV_USERxONLINE):
// Client reads: UIN(4) + IP(4) + PORT(2) + JUNK_SHORT(2) + REAL_IP(4) +
//               MODE(1) + STATUS(4) + TCP_VERSION(4)
// Total client reads: 25 bytes. Extra bytes after that are ignored.
//
// Our packet format (49 bytes data, iserverd-compatible):
// - UIN(4) + IP(4) + TCP_PORT(4) + INT_IP(4) + DC_TYPE(1) +
//   STATUS(2)+ESTAT(2) + TCPVER(4) + DC_COOKIE(4) + WEB_PORT(4) +
//   CLI_FUTURES(4) + INFO_UTIME(4) + MORE_UTIME(4) + STAT_UTIME(4)
func (h *V5Handler) sendV5UserOnline(session *LegacySession, uin uint32, status uint32) error {
	data := make([]byte, 49)
	offset := 0

	// UIN of the user who is online
	binary.LittleEndian.PutUint32(data[offset:], uin)
	offset += 4

	// Get the online user's session to retrieve their connection info
	onlineSession := h.sessions.GetSession(uin)

	// From iserverd: V3 clients get zeroed connection info for TCP protection
	// V5 clients get real connection info for peer-to-peer
	var externalIP, tcpPort, internalIP uint32
	var dcType uint8
	var tcpVersion uint32

	if onlineSession != nil && onlineSession.Version == wire.ICQLegacyVersionV5 {
		// V5 client - send real connection info for peer-to-peer
		externalIP = onlineSession.GetExternalIP()
		tcpPort = onlineSession.GetTCPPort()
		internalIP = onlineSession.GetInternalIP()
		dcType = onlineSession.DCType
		tcpVersion = uint32(onlineSession.GetTCPVersion())
	}
	// else: V3/V4 clients or unknown - keep zeros for privacy

	// IP address
	binary.LittleEndian.PutUint32(data[offset:], externalIP)
	offset += 4

	// TCP port
	binary.LittleEndian.PutUint32(data[offset:], tcpPort)
	offset += 4

	// Internal IP
	binary.LittleEndian.PutUint32(data[offset:], internalIP)
	offset += 4

	// DC type
	data[offset] = dcType
	offset++

	// Status (low word)
	binary.LittleEndian.PutUint16(data[offset:], uint16(status&0xFFFF))
	offset += 2

	// Extended status (high word)
	binary.LittleEndian.PutUint16(data[offset:], uint16(status>>16))
	offset += 2

	// TCP version
	binary.LittleEndian.PutUint32(data[offset:], tcpVersion)
	offset += 4

	// DC cookie (not implemented - would need to be stored per session)
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	// Web port (not implemented)
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	// Client futures (not implemented)
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	// Info update time (not implemented)
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	// More update time (not implemented)
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	// Status update time (not implemented)
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvUserOnline,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	h.logger.Debug("sending V5 user online notification",
		"to", session.UIN,
		"online_uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
		"external_ip", fmt.Sprintf("0x%08X", externalIP),
		"tcp_port", tcpPort,
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5OfflineMessage sends an offline message to a V5 client
// From iserverd v5_send_offline_message()
// Format: FROM_UIN(4) + YEAR(2) + MONTH(1) + DAY(1) + HOUR(1) + MINUTE(1) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (h *V5Handler) sendV5OfflineMessage(session *LegacySession, msg *foodgroup.LegacyOfflineMessage) error {
	// Build message data
	msgBytes := []byte(msg.Message)
	dataLen := 4 + 2 + 1 + 1 + 1 + 1 + 2 + 2 + len(msgBytes) + 1
	data := make([]byte, dataLen)
	offset := 0

	// From UIN
	binary.LittleEndian.PutUint32(data[offset:], msg.FromUIN)
	offset += 4

	// Timestamp: YEAR(2) + MONTH(1) + DAY(1) + HOUR(1) + MINUTE(1)
	binary.LittleEndian.PutUint16(data[offset:], uint16(msg.Timestamp.Year()))
	offset += 2
	data[offset] = byte(msg.Timestamp.Month())
	offset++
	data[offset] = byte(msg.Timestamp.Day())
	offset++
	data[offset] = byte(msg.Timestamp.Hour())
	offset++
	data[offset] = byte(msg.Timestamp.Minute())
	offset++

	// Message type
	binary.LittleEndian.PutUint16(data[offset:], msg.MsgType)
	offset += 2

	// Message length (including null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(msgBytes)+1))
	offset += 2

	// Message content
	copy(data[offset:], msgBytes)
	offset += len(msgBytes)
	data[offset] = 0 // null terminator

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvSysMsgOffline, // 0x00DC
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	h.logger.Debug("sending V5 offline message",
		"to", session.UIN,
		"from", msg.FromUIN,
		"type", fmt.Sprintf("0x%04X", msg.MsgType),
		"timestamp", msg.Timestamp,
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5OfflineMsgDone sends end of offline messages
func (h *V5Handler) sendV5OfflineMsgDone(session *LegacySession, seq2 uint16) error {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvSysMsgDone,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// META_USER sub-command handlers

// handleMetaLogin handles CMD_META_LOGIN (0x07D0)
// This is sent after login to get login meta info
// From iserverd: v5_send_lmeta()
func (h *V5Handler) handleMetaLogin(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	h.logger.Info("META login request", "uin", pkt.UIN, "status", "sending_reply")

	// Send login meta response
	// From iserverd v5_send_lmeta(): sends 0x07D0 + 0x0000 + 0x0046
	return h.sendMetaLoginReply(session, pkt.SeqNum2)
}

// handleMetaLoginInfo handles CMD_META_USER_LOGININFO/LOGININFO2 (0x04CE/0x04CF)
// This is sent after login to get the user's own info
// From iserverd: v5_reply_metafullinfo_request2()
func (h *V5Handler) handleMetaLoginInfo(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	// Parse target UIN from data (4 bytes)
	var targetUIN uint32
	if len(data) >= 4 {
		targetUIN = binary.LittleEndian.Uint32(data[0:4])
	} else {
		targetUIN = session.UIN
	}

	h.logger.Info("META login info request",
		"uin", pkt.UIN,
		"target_uin", targetUIN,
	)

	ctx := context.Background()
	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err != nil || info == nil {
		h.logger.Info("META login info - NOT FOUND", "target_uin", targetUIN, "err", err)
		// Send fail response
		return h.sendMetaFail(session, pkt.SeqNum2, 0x00C8)
	}

	h.logger.Info("META login info - FOUND, sending 7 info packets",
		"target_uin", targetUIN,
		"nickname", info.Nickname,
	)

	// Send all 7 info packets as per iserverd v5_reply_metafullinfo_request2()
	h.sendMetaInfo3(session, pkt.SeqNum2, info)      // Basic info (0x00C8)
	h.sendMetaMore2(session, pkt.SeqNum2, info)      // More info (0x00DC)
	h.sendMetaHpageCat(session, pkt.SeqNum2, info)   // Homepage category (0x010E)
	h.sendMetaWork2(session, pkt.SeqNum2, info)      // Work info (0x00D2)
	h.sendMetaAbout(session, pkt.SeqNum2, info)      // About/notes (0x00E6)
	h.sendMetaInterests(session, pkt.SeqNum2, info)  // Interests (0x00F0)
	h.sendMetaAffiliations(session, pkt.SeqNum2, info) // Affiliations (0x00FA)

	h.logger.Info("META login info - all packets sent", "target_uin", targetUIN)

	return nil
}

func (h *V5Handler) handleMetaSetBasic(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set basic info", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update basic info
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetBasicAck)
}

func (h *V5Handler) handleMetaSetWork(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set work info", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update work info
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetWorkAck)
}

func (h *V5Handler) handleMetaSetMore(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set more info", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update more info
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetMoreAck)
}

func (h *V5Handler) handleMetaSetAbout(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set about", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update about text
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetAboutAck)
}

func (h *V5Handler) handleMetaSetInterests(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set interests", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update interests
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetInterestsAck)
}

func (h *V5Handler) handleMetaSetAffiliations(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set affiliations", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update affiliations
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetAffilAck)
}

func (h *V5Handler) handleMetaSetSecurity(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set security", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update security settings
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetSecureAck)
}

func (h *V5Handler) handleMetaSetPassword(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	ctx := context.Background()

	// Parse password from data
	// V5 META format: PASSWORD_LEN(2) + PASSWORD
	// From iserverd v5_set_password(): v5_extract_string(password, int_pack, 32, "password", user)
	if len(data) < 2 {
		h.logger.Info("META set password - data too short", "uin", pkt.UIN, "data_len", len(data))
		return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetPassAck)
	}

	offset := 0

	// Read password length (2 bytes)
	pwdLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Sanity check password length
	if pwdLen > 32 {
		pwdLen = 32
	}

	// Read new password
	if offset+int(pwdLen) > len(data) {
		h.logger.Info("META set password - password truncated", "uin", pkt.UIN)
		return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetPassAck)
	}
	newPassword := string(data[offset : offset+int(pwdLen)])
	// Remove null terminator if present
	if len(newPassword) > 0 && newPassword[len(newPassword)-1] == 0 {
		newPassword = newPassword[:len(newPassword)-1]
	}

	h.logger.Info("META set password request",
		"uin", pkt.UIN,
		"new_password_len", len(newPassword),
	)

	// Update password using service
	// Note: iserverd doesn't validate old password, so we pass empty string
	if err := h.service.SetPassword(ctx, pkt.UIN, "", newPassword); err != nil {
		h.logger.Error("META set password failed",
			"uin", pkt.UIN,
			"err", err,
		)
		// Still send ACK to match iserverd behavior
	} else {
		h.logger.Info("META password updated successfully", "uin", pkt.UIN)
	}

	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetPassAck)
}

// handleMetaSetHPCat processes set homepage category (0x0442)
// From iserverd v5_set_hpcat_info()
func (h *V5Handler) handleMetaSetHPCat(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	h.logger.Info("META set homepage category", "uin", pkt.UIN, "data_len", len(data), "status", "ack_sent")
	// TODO: Parse and update homepage category
	return h.sendMetaAck(session, pkt.SeqNum2, wire.ICQLegacySrvMetaSetHPCatAck)
}

// handleMetaUnregister processes unregister account (0x04C4)
// From iserverd v5_unregister_user()
func (h *V5Handler) handleMetaUnregister(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	ctx := context.Background()

	// Parse password from data
	// Format: UIN(4) + PASSWORD_LEN(2) + PASSWORD
	if len(data) < 6 {
		h.logger.Info("META unregister - data too short", "uin", pkt.UIN, "data_len", len(data))
		return h.sendMetaUnregAck(session, pkt.SeqNum2, false)
	}

	offset := 0

	// Skip UIN (4 bytes) - we already have it from the packet
	offset += 4

	// Read password length (2 bytes)
	pwdLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Sanity check password length
	if pwdLen > 32 {
		pwdLen = 32
	}

	// Read password
	if offset+int(pwdLen) > len(data) {
		h.logger.Info("META unregister - password truncated", "uin", pkt.UIN)
		return h.sendMetaUnregAck(session, pkt.SeqNum2, false)
	}
	password := string(data[offset : offset+int(pwdLen)])
	// Remove null terminator if present
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}

	h.logger.Info("META unregister request",
		"uin", pkt.UIN,
		"password_len", len(password),
	)

	// Delete the user account
	err := h.service.DeleteUser(ctx, pkt.UIN, password)
	if err != nil {
		h.logger.Info("META unregister FAILED", "uin", pkt.UIN, "err", err)
		return h.sendMetaUnregAck(session, pkt.SeqNum2, false)
	}

	h.logger.Info("META unregister SUCCESS - user deleted", "uin", pkt.UIN)

	// Send success acknowledgment
	return h.sendMetaUnregAck(session, pkt.SeqNum2, true)
}

// handleMetaUserFullInfo processes CMD_META_USER_FULLINFO requests (0x04B0)
// From iserverd v5_reply_metafullinfo_request() - older format
//
// Sends 7 separate META_USER packets using the older format functions:
// info2, more, hpage_cat, work, about, interests, affiliations
// This matches iserverd's v5_reply_metafullinfo_request() exactly.
func (h *V5Handler) handleMetaUserFullInfo(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	if len(data) < 4 {
		h.logger.Info("META user full info - data too short", "uin", pkt.UIN)
		return h.sendMetaFail(session, pkt.SeqNum2, wire.ICQLegacySrvMetaUserInfo2)
	}

	targetUIN := binary.LittleEndian.Uint32(data[0:4])
	h.logger.Info("META user full info request (0x04B0)",
		"uin", pkt.UIN,
		"target_uin", targetUIN,
	)

	ctx := context.Background()
	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err != nil || info == nil {
		h.logger.Info("META user full info - NOT FOUND", "target_uin", targetUIN, "err", err)
		return h.sendMetaFail(session, pkt.SeqNum2, wire.ICQLegacySrvMetaUserInfo2)
	}

	h.logger.Info("META user full info - FOUND, sending 7 info packets (older format)",
		"target_uin", targetUIN,
		"nickname", info.Nickname,
	)

	// Send all 7 info packets as per iserverd v5_reply_metafullinfo_request()
	// Uses older format: sendMetaFullUserInfo (info2), sendMetaMore, sendMetaWork
	h.sendMetaFullUserInfo(session, pkt.SeqNum2, info) // Basic info (0x00C8) - older format
	h.sendMetaMore(session, pkt.SeqNum2, info)         // More info (0x00DC)
	h.sendMetaHpageCat(session, pkt.SeqNum2, info)     // Homepage category (0x010E)
	h.sendMetaWork(session, pkt.SeqNum2, info)          // Work info (0x00D2) - older format
	h.sendMetaAbout(session, pkt.SeqNum2, info)         // About/notes (0x00E6)
	h.sendMetaInterests(session, pkt.SeqNum2, info)     // Interests (0x00F0)
	h.sendMetaAffiliations(session, pkt.SeqNum2, info)  // Affiliations (0x00FA)

	return nil
}

// handleMetaUserFullInfo2 processes CMD_META_USER_INFO2 requests (0x04B1)
// From iserverd v5_reply_metafullinfo_request2() - newer format
//
// Sends 7 separate META_USER packets using the newer format functions:
// info3, more2, hpage_cat, work2, about, interests, affiliations
// This matches iserverd's v5_reply_metafullinfo_request2() exactly.
func (h *V5Handler) handleMetaUserFullInfo2(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	if len(data) < 4 {
		h.logger.Info("META user full info2 - data too short", "uin", pkt.UIN)
		return h.sendMetaFail(session, pkt.SeqNum2, wire.ICQLegacySrvMetaUserInfo2)
	}

	targetUIN := binary.LittleEndian.Uint32(data[0:4])
	h.logger.Info("META user full info2 request (0x04B1)",
		"uin", pkt.UIN,
		"target_uin", targetUIN,
	)

	ctx := context.Background()
	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err != nil || info == nil {
		h.logger.Info("META user full info2 - NOT FOUND", "target_uin", targetUIN, "err", err)
		return h.sendMetaFail(session, pkt.SeqNum2, wire.ICQLegacySrvMetaUserInfo2)
	}

	h.logger.Info("META user full info2 - FOUND, sending 7 info packets (newer format)",
		"target_uin", targetUIN,
		"nickname", info.Nickname,
	)

	// Send all 7 info packets as per iserverd v5_reply_metafullinfo_request2()
	// Uses newer format: sendMetaInfo3, sendMetaMore2, sendMetaWork2
	h.sendMetaInfo3(session, pkt.SeqNum2, info)        // Basic info (0x00C8) - newer format
	h.sendMetaMore2(session, pkt.SeqNum2, info)        // More info (0x00DC)
	h.sendMetaHpageCat(session, pkt.SeqNum2, info)     // Homepage category (0x010E)
	h.sendMetaWork2(session, pkt.SeqNum2, info)         // Work info (0x00D2) - newer format
	h.sendMetaAbout(session, pkt.SeqNum2, info)         // About/notes (0x00E6)
	h.sendMetaInterests(session, pkt.SeqNum2, info)     // Interests (0x00F0)
	h.sendMetaAffiliations(session, pkt.SeqNum2, info)  // Affiliations (0x00FA)

	return nil
}

// handleMetaUserInfo processes CMD_META_USER_INFO requests (0x04BA)
// From iserverd v5_reply_metainfo_request() - short info only
//
// Unlike handleMetaUserFullInfo/handleMetaUserFullInfo2, this sends only a
// single short user info packet (SRV_META_USER_INFO = 0x0104).
// This matches iserverd's v5_send_meta_info() exactly.
func (h *V5Handler) handleMetaUserInfo(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	if len(data) < 4 {
		h.logger.Info("META user info - data too short", "uin", pkt.UIN)
		return h.sendMetaFail(session, pkt.SeqNum2, wire.ICQLegacySrvMetaUserInfo)
	}

	targetUIN := binary.LittleEndian.Uint32(data[0:4])
	h.logger.Info("META user info request (0x04BA)",
		"uin", pkt.UIN,
		"target_uin", targetUIN,
	)

	ctx := context.Background()
	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err != nil || info == nil {
		h.logger.Info("META user info - NOT FOUND", "target_uin", targetUIN, "err", err)
		return h.sendMetaUserInfo(session, pkt.SeqNum2, nil)
	}

	h.logger.Info("META user info - FOUND",
		"target_uin", targetUIN,
		"nickname", info.Nickname,
	)

	// Send single short info packet (SRV_META_USER_INFO = 0x0104)
	return h.sendMetaUserInfo(session, pkt.SeqNum2, info)
}

// handleMetaSearchName processes META_SEARCH_NAME requests (0x0514, 0x0515)
// From iserverd v5_search_by_name()
//
// Packet format (subData after sub_command):
//   - First string (length-prefixed, null-terminated) - nick in iserverd
//   - Second string (length-prefixed, null-terminated) - first name
//   - Third string (length-prefixed, null-terminated) - last name
//
// Note: iserverd's variable naming is confusing - it reads into first_str, last_str,
// nick_str but the actual packet order from the client is nick, first, last.
func (h *V5Handler) handleMetaSearchName(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	// Parse three length-prefixed strings: nick, first, last
	offset := 0

	nick, n := readLPString(data, offset)
	offset += n
	first, n := readLPString(data, offset)
	offset += n
	last, n := readLPString(data, offset)

	h.logger.Info("META search by name",
		"uin", pkt.UIN,
		"nick", nick,
		"first", first,
		"last", last,
	)

	ctx := context.Background()
	results, err := h.service.SearchByName(ctx, nick, first, last, "")
	if err != nil {
		h.logger.Info("META search by name - error", "uin", pkt.UIN, "err", err)
		return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, nil, true))
	}

	if len(results) == 0 {
		h.logger.Info("META search by name - no results", "uin", pkt.UIN)
		return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, nil, true))
	}

	h.logger.Info("META search by name - found",
		"uin", pkt.UIN,
		"count", len(results),
	)

	// Convert to UserInfoResult and send
	var infoResults []foodgroup.UserInfoResult
	for _, r := range results {
		infoResults = append(infoResults, foodgroup.UserInfoResult{
			UIN:          r.UIN,
			Nickname:     r.Nickname,
			FirstName:    r.FirstName,
			LastName:     r.LastName,
			Email:        r.Email,
			AuthRequired: r.AuthRequired,
		})
	}

	// Send each result, last one with isLast=true
	for i, info := range infoResults {
		isLast := i == len(infoResults)-1
		err := h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, []foodgroup.UserInfoResult{info}, isLast))
		if err != nil {
			return err
		}
	}
	return nil
}

// handleMetaSearchUIN processes META_SEARCH_UIN requests (0x051E, 0x051F)
// From iserverd v5_search_by_uin()
//
// Refactored to use service layer (GetUserInfoForProtocol) and packet builder.
// Following the OSCAR pattern: unmarshal -> call service -> build response
func (h *V5Handler) handleMetaSearchUIN(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	// 1. Unmarshal packet - extract target UIN
	if len(data) < 4 {
		h.logger.Info("META search by UIN - data too short", "uin", pkt.UIN)
		return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, nil, true))
	}

	targetUIN := binary.LittleEndian.Uint32(data[0:4])
	h.logger.Info("META search by UIN",
		"uin", pkt.UIN,
		"target_uin", targetUIN,
	)

	// 2. Call service layer with typed request
	ctx := context.Background()
	result, err := h.service.GetUserInfoForProtocol(ctx, targetUIN)
	if err != nil {
		h.logger.Info("META search by UIN - error",
			"target_uin", targetUIN,
			"err", err,
		)
		return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, nil, true))
	}

	if result == nil {
		h.logger.Info("META search by UIN - NOT FOUND",
			"target_uin", targetUIN,
		)
		return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, nil, true))
	}

	h.logger.Info("META search by UIN - FOUND",
		"target_uin", targetUIN,
		"nickname", result.Nickname,
		"firstname", result.FirstName,
		"lastname", result.LastName,
		"email", result.Email,
	)

	// 3. Build and send response using packet builder
	results := []foodgroup.UserInfoResult{*result}
	return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, results, true))
}

// handleMetaSearchEmail processes META_SEARCH_EMAIL requests (0x0528, 0x0529)
// From iserverd v5_search_by_email()
//
// Packet format (subData after sub_command):
//   - Email string (length-prefixed, null-terminated)
func (h *V5Handler) handleMetaSearchEmail(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	// Parse one length-prefixed string: email
	email, _ := readLPString(data, 0)

	h.logger.Info("META search by email",
		"uin", pkt.UIN,
		"email", email,
	)

	ctx := context.Background()
	results, err := h.service.SearchByName(ctx, "", "", "", email)
	if err != nil {
		h.logger.Info("META search by email - error", "uin", pkt.UIN, "err", err)
		return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, nil, true))
	}

	if len(results) == 0 {
		h.logger.Info("META search by email - no results", "uin", pkt.UIN)
		return h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, nil, true))
	}

	h.logger.Info("META search by email - found",
		"uin", pkt.UIN,
		"count", len(results),
	)

	var infoResults []foodgroup.UserInfoResult
	for _, r := range results {
		infoResults = append(infoResults, foodgroup.UserInfoResult{
			UIN:          r.UIN,
			Nickname:     r.Nickname,
			FirstName:    r.FirstName,
			LastName:     r.LastName,
			Email:        r.Email,
			AuthRequired: r.AuthRequired,
		})
	}

	for i, info := range infoResults {
		isLast := i == len(infoResults)-1
		err := h.sender.SendToSession(session, h.packetBuilder.BuildSearchResult(session, pkt.SeqNum2, []foodgroup.UserInfoResult{info}, isLast))
		if err != nil {
			return err
		}
	}
	return nil
}

// handleMetaSearchWhite processes META_SEARCH_WHITE (0x0532) - white pages search
// From iserverd v5_search_by_white()
//
// This is the original white pages search (without homepage category fields).
// Packet format:
//   - First name (length-prefixed string)
//   - Last name (length-prefixed string)
//   - Nickname (length-prefixed string)
//   - Email (length-prefixed string)
//   - Min age (uint16)
//   - Max age (uint16)
//   - Gender (uint8)
//   - Language (uint8)
//   - City (length-prefixed string)
//   - State (length-prefixed string)
//   - Country (uint16)
//   - Company (length-prefixed string)
//   - Department (length-prefixed string)
//   - Position (length-prefixed string)
//   - Work code/occupation (uint8)
//   - Past code (uint16)
//   - Past keywords (length-prefixed string)
//   - Interest index (uint16)
//   - Interest keywords (length-prefixed string)
//   - Affiliation index (uint16)
//   - Affiliation keywords (length-prefixed string)
//   - Online only (uint8)
func (h *V5Handler) handleMetaSearchWhite(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	h.logger.Info("META white pages search",
		"uin", pkt.UIN,
		"data_len", len(data),
	)

	// Parse the white pages search packet
	// Following iserverd v5_search_by_white() packet format
	offset := 0

	// Helper function to read length-prefixed string
	readString := func(maxLen int) string {
		if offset+2 > len(data) {
			return ""
		}
		strLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if strLen > maxLen {
			strLen = maxLen
		}
		if strLen == 0 || offset+strLen > len(data) {
			return ""
		}
		s := string(data[offset : offset+strLen])
		offset += strLen
		// Remove null terminator if present
		if len(s) > 0 && s[len(s)-1] == 0 {
			s = s[:len(s)-1]
		}
		return s
	}

	// First block - personal information
	firstName := readString(32)
	lastName := readString(32)
	nickname := readString(32)
	email := readString(63)

	// Second block - age, gender, language
	var minAge, maxAge uint16
	var gender, language uint8
	if offset+4 <= len(data) {
		minAge = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
		maxAge = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if offset+2 <= len(data) {
		gender = data[offset]
		offset++
		language = data[offset]
		offset++
	}

	// Third block - location
	city := readString(32)
	state := readString(32)
	var country uint16
	if offset+2 <= len(data) {
		country = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// Fourth block - work information
	company := readString(32)
	department := readString(32)
	position := readString(32)
	var workCode uint8
	if offset+1 <= len(data) {
		workCode = data[offset]
		offset++
	}

	// Fifth block - past information
	var pastCode uint16
	if offset+2 <= len(data) {
		pastCode = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	pastKeywords := readString(127)

	// Sixth block - interests information
	var interestIndex uint16
	if offset+2 <= len(data) {
		interestIndex = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	interestKeywords := readString(127)

	// Seventh block - affiliations information
	var affiliationIndex uint16
	if offset+2 <= len(data) {
		affiliationIndex = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	affiliationKeywords := readString(127)

	// Online only flag
	var onlineOnly uint8
	if offset+1 <= len(data) {
		onlineOnly = data[offset]
		offset++
	}

	h.logger.Info("META white pages search parsed",
		"uin", pkt.UIN,
		"first_name", firstName,
		"last_name", lastName,
		"nickname", nickname,
		"email", email,
		"min_age", minAge,
		"max_age", maxAge,
		"gender", gender,
		"language", language,
		"city", city,
		"state", state,
		"country", country,
		"company", company,
		"department", department,
		"position", position,
		"work_code", workCode,
		"past_code", pastCode,
		"past_keywords", pastKeywords,
		"interest_index", interestIndex,
		"interest_keywords", interestKeywords,
		"affiliation_index", affiliationIndex,
		"affiliation_keywords", affiliationKeywords,
		"online_only", onlineOnly,
	)

	// Build search criteria
	criteria := foodgroup.WhitePagesSearchCriteria{
		FirstName:           firstName,
		LastName:            lastName,
		Nickname:            nickname,
		Email:               email,
		MinAge:              minAge,
		MaxAge:              maxAge,
		Gender:              gender,
		Language:            language,
		City:                city,
		State:               state,
		Country:             country,
		Company:             company,
		Department:          department,
		Position:            position,
		WorkCode:            workCode,
		PastCode:            pastCode,
		PastKeywords:        pastKeywords,
		InterestIndex:       interestIndex,
		InterestKeywords:    interestKeywords,
		AffiliationIndex:    affiliationIndex,
		AffiliationKeywords: affiliationKeywords,
		OnlineOnly:          onlineOnly != 0,
	}

	// Check if we have any basic search criteria
	hasBasicCriteria := firstName != "" || lastName != "" || nickname != "" || email != ""

	if hasBasicCriteria {
		ctx := context.Background()
		results, err := h.service.WhitePagesSearch(ctx, criteria)
		if err != nil {
			h.logger.Info("META white pages search - error", "uin", pkt.UIN, "err", err)
			return h.sendMetaWhiteSearchEnd(session, pkt.SeqNum2, false)
		}

		if len(results) == 0 {
			h.logger.Info("META white pages search - no results", "uin", pkt.UIN)
			return h.sendMetaWhiteSearchEnd(session, pkt.SeqNum2, false)
		}

		// Send results (limit to 40 as per iserverd)
		maxResults := 40
		if len(results) > maxResults {
			results = results[:maxResults]
		}

		for i, result := range results {
			isLast := i == len(results)-1
			moreAvailable := len(results) >= maxResults && isLast
			h.sendMetaWhiteFound(session, pkt.SeqNum2, &result, isLast, moreAvailable)
		}

		return nil
	}

	// No basic search criteria - return empty result
	h.logger.Info("META white pages search - no basic criteria for search", "uin", pkt.UIN)
	return h.sendMetaWhiteSearchEnd(session, pkt.SeqNum2, false)
}

// handleMetaSearchWhite2 processes META_SEARCH_WHITE2 (0x0533) - extended white pages search
// From iserverd v5_search_by_white2()
//
// This is the extended white pages search that includes homepage category search.
// Packet format:
//   - First name (length-prefixed string)
//   - Last name (length-prefixed string)
//   - Nickname (length-prefixed string)
//   - Email (length-prefixed string)
//   - Min age (uint16)
//   - Max age (uint16)
//   - Gender (uint8)
//   - Language (uint8)
//   - City (length-prefixed string)
//   - State (length-prefixed string)
//   - Country (uint16)
//   - Company (length-prefixed string)
//   - Department (length-prefixed string)
//   - Position (length-prefixed string)
//   - Work code/occupation (uint8)
//   - Past code (uint16)
//   - Past keywords (length-prefixed string)
//   - Interest index (uint16)
//   - Interest keywords (length-prefixed string)
//   - Affiliation index (uint16)
//   - Affiliation keywords (length-prefixed string)
//   - Homepage category index (uint16) - EXTRA field in White2
//   - Homepage keywords (length-prefixed string) - EXTRA field in White2
//   - Online only (uint8)
func (h *V5Handler) handleMetaSearchWhite2(session *LegacySession, pkt *wire.V5ClientPacket, data []byte) error {
	if session == nil {
		return nil
	}

	h.logger.Info("META white pages search 2 (extended)",
		"uin", pkt.UIN,
		"data_len", len(data),
	)

	// Parse the extended white pages search packet
	// Following iserverd v5_search_by_white2() packet format
	offset := 0

	// Helper function to read length-prefixed string
	readString := func(maxLen int) string {
		if offset+2 > len(data) {
			return ""
		}
		strLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if strLen > maxLen {
			strLen = maxLen
		}
		if strLen == 0 || offset+strLen > len(data) {
			return ""
		}
		s := string(data[offset : offset+strLen])
		offset += strLen
		// Remove null terminator if present
		if len(s) > 0 && s[len(s)-1] == 0 {
			s = s[:len(s)-1]
		}
		return s
	}

	// First block - personal information
	firstName := readString(32)
	lastName := readString(32)
	nickname := readString(32)
	email := readString(63)

	// Second block - age, gender, language
	var minAge, maxAge uint16
	var gender, language uint8
	if offset+4 <= len(data) {
		minAge = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
		maxAge = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if offset+2 <= len(data) {
		gender = data[offset]
		offset++
		language = data[offset]
		offset++
	}

	// Third block - location
	city := readString(32)
	state := readString(32)
	var country uint16
	if offset+2 <= len(data) {
		country = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// Fourth block - work information
	company := readString(32)
	department := readString(32)
	position := readString(32)
	var workCode uint8
	if offset+1 <= len(data) {
		workCode = data[offset]
		offset++
	}

	// Fifth block - past information
	var pastCode uint16
	if offset+2 <= len(data) {
		pastCode = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	pastKeywords := readString(63)

	// Sixth block - interests
	var interestIndex uint16
	if offset+2 <= len(data) {
		interestIndex = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	interestKeywords := readString(127)

	// Seventh block - affiliations
	var affiliationIndex uint16
	if offset+2 <= len(data) {
		affiliationIndex = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	affiliationKeywords := readString(127)

	// Eighth block - homepage category (EXTRA in White2)
	var pageIndex uint16
	if offset+2 <= len(data) {
		pageIndex = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	pageKeywords := readString(127)

	// Online only flag
	var onlineOnly uint8
	if offset+1 <= len(data) {
		onlineOnly = data[offset]
		offset++
	}

	h.logger.Info("META white pages search 2 - parsed",
		"uin", pkt.UIN,
		"first_name", firstName,
		"last_name", lastName,
		"nickname", nickname,
		"email", email,
		"min_age", minAge,
		"max_age", maxAge,
		"gender", gender,
		"language", language,
		"city", city,
		"state", state,
		"country", country,
		"company", company,
		"department", department,
		"position", position,
		"work_code", workCode,
		"past_code", pastCode,
		"past_keywords", pastKeywords,
		"interest_index", interestIndex,
		"interest_keywords", interestKeywords,
		"affiliation_index", affiliationIndex,
		"affiliation_keywords", affiliationKeywords,
		"page_index", pageIndex,
		"page_keywords", pageKeywords,
		"online_only", onlineOnly,
	)

	// Check if any search criteria was provided
	hasSearchCriteria := firstName != "" || lastName != "" || nickname != "" || email != "" ||
		(minAge > 0 && maxAge > 0) || (gender > 0 && gender < 16) ||
		(language > 0 && language < 127) || city != "" || state != "" ||
		(country > 0 && country < 20000) || company != "" || position != "" ||
		(workCode > 0 && workCode < 127) || (pastCode > 0 && pastCode < 60000) ||
		(interestIndex > 0 && interestIndex < 60000) ||
		(affiliationIndex > 0 && affiliationIndex < 60000) ||
		(pageIndex > 0 && pageIndex < 60000)

	if !hasSearchCriteria {
		// No search criteria provided - return "not implemented" style response
		// Following iserverd behavior when not_implemented is true
		h.logger.Info("META white pages search 2 - no criteria provided", "uin", pkt.UIN)
		return h.sendMetaWhiteSearchEnd(session, pkt.SeqNum2, true)
	}

	// For now, use the basic name/email search if those fields are provided
	// A full implementation would need a more complex search method in the service layer
	ctx := context.Background()

	if nickname != "" || firstName != "" || lastName != "" || email != "" {
		results, err := h.service.SearchByName(ctx, nickname, firstName, lastName, email)
		if err != nil {
			h.logger.Info("META white pages search 2 - error",
				"uin", pkt.UIN,
				"err", err,
			)
			return h.sendMetaWhiteSearchEnd(session, pkt.SeqNum2, false)
		}

		if len(results) == 0 {
			h.logger.Info("META white pages search 2 - no results", "uin", pkt.UIN)
			return h.sendMetaWhiteSearchEnd(session, pkt.SeqNum2, false)
		}

		// Send results (limit to 40 as per iserverd)
		maxResults := 40
		if len(results) > maxResults {
			results = results[:maxResults]
		}

		for i, result := range results {
			isLast := i == len(results)-1
			moreAvailable := len(results) >= maxResults && isLast
			h.sendMetaWhiteSearchResult2(session, pkt.SeqNum2, &result, isLast, moreAvailable)
		}

		return nil
	}

	// No basic search criteria - return empty result
	h.logger.Info("META white pages search 2 - no basic criteria for search", "uin", pkt.UIN)
	return h.sendMetaWhiteSearchEnd(session, pkt.SeqNum2, false)
}

// sendMetaWhiteSearchResult2 sends a META white pages search result (White2 format)
// From iserverd v5_send_white_user_found2()
func (h *V5Handler) sendMetaWhiteSearchResult2(session *LegacySession, seqNum uint16, result *foodgroup.LegacyUserSearchResult, isLast bool, moreAvailable bool) error {
	if session == nil {
		return nil
	}

	// Use White2 response codes (0x01A4 for found, 0x01AE for last found)
	subCommand := wire.ICQLegacySrvMetaWhiteFound // 0x01A4
	if isLast {
		subCommand = wire.ICQLegacySrvMetaWhiteLastFound // 0x01AE
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, subCommand)

	if result != nil {
		buf.WriteByte(0x0A) // success

		// Calculate pack_len: 15 + strings + 4 for users_left
		packLen := uint16(15 + len(result.Nickname) + len(result.FirstName) + len(result.LastName) + len(result.Email) + 4)
		binary.Write(buf, binary.LittleEndian, packLen)

		binary.Write(buf, binary.LittleEndian, result.UIN)
		writeLegacyString(buf, result.Nickname)
		writeLegacyString(buf, result.FirstName)
		writeLegacyString(buf, result.LastName)
		writeLegacyString(buf, result.Email)
		buf.WriteByte(result.AuthRequired) // auth flag
		buf.WriteByte(result.WebAware)     // webaware flag
		buf.WriteByte(0)                   // unknown

		// users_left indicator
		var usersLeft uint32
		if moreAvailable {
			usersLeft = 1 // indicate more results available
		}
		binary.Write(buf, binary.LittleEndian, usersLeft)
	} else {
		buf.WriteByte(0x32) // fail - no results
		binary.Write(buf, binary.LittleEndian, uint32(0)) // users_left
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seqNum,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	if result != nil {
		h.logger.Info("sending META white search 2 result",
			"uin", session.UIN,
			"sub_command", fmt.Sprintf("0x%04X", subCommand),
			"result_uin", result.UIN,
			"result_nickname", result.Nickname,
			"is_last", isLast,
			"more_available", moreAvailable,
			"packet_len", len(packetData),
		)
	}

	return h.sender.SendToSession(session, packetData)
}

// sendMetaWhiteFound sends a META white pages search result (original format)
// From iserverd v5_send_white_user_found()
//
// This is the original white pages search result format (0x01A4).
// Packet format (data portion):
//   - SubCommand (2 bytes): 0x01A4 (found) or 0x01AE (last found)
//   - Success (1 byte): 0x0A (success) or 0x32 (fail)
//   - If success:
//     - UIN (4 bytes)
//     - Nickname (length-prefixed string)
//     - First name (length-prefixed string)
//     - Last name (length-prefixed string)
//     - Email (length-prefixed string)
//     - Auth flag (1 byte)
//     - Webaware flag (1 byte)
//   - If last:
//     - Users left (4 bytes)
//
// Note: Unlike White2 format, this does NOT have a pack_len field.
func (h *V5Handler) sendMetaWhiteFound(session *LegacySession, seqNum uint16, result *foodgroup.LegacyUserSearchResult, isLast bool, moreAvailable bool) error {
	if session == nil {
		return nil
	}

	// Use White response codes (0x01A4 for found, 0x01AE for last found)
	subCommand := wire.ICQLegacySrvMetaWhiteFound // 0x01A4
	if isLast {
		subCommand = wire.ICQLegacySrvMetaWhiteLastFound // 0x01AE
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, subCommand)

	if result != nil {
		buf.WriteByte(0x0A) // success

		// Original format: NO pack_len field (unlike White2)
		binary.Write(buf, binary.LittleEndian, result.UIN)
		writeLegacyString(buf, result.Nickname)
		writeLegacyString(buf, result.FirstName)
		writeLegacyString(buf, result.LastName)
		writeLegacyString(buf, result.Email)
		buf.WriteByte(result.AuthRequired) // auth flag
		buf.WriteByte(result.WebAware)     // webaware flag

		// users_left indicator (only if last)
		if isLast {
			var usersLeft uint32
			if moreAvailable {
				usersLeft = 1 // indicate more results available
			}
			binary.Write(buf, binary.LittleEndian, usersLeft)
		}
	} else {
		buf.WriteByte(0x32) // fail - no results
		// users_left indicator (only if last)
		if isLast {
			binary.Write(buf, binary.LittleEndian, uint32(0)) // users_left
		}
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seqNum,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	if result != nil {
		h.logger.Info("sending META white search result",
			"uin", session.UIN,
			"sub_command", fmt.Sprintf("0x%04X", subCommand),
			"result_uin", result.UIN,
			"result_nickname", result.Nickname,
			"is_last", isLast,
			"more_available", moreAvailable,
			"packet_len", len(packetData),
		)
	}

	return h.sender.SendToSession(session, packetData)
}

// sendMetaWhiteSearchEnd sends an empty white pages search result to indicate end/no results
func (h *V5Handler) sendMetaWhiteSearchEnd(session *LegacySession, seqNum uint16, success bool) error {
	if session == nil {
		return nil
	}

	subCommand := wire.ICQLegacySrvMetaWhiteLastFound // 0x01AE

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, subCommand)

	if success {
		buf.WriteByte(0x0A) // success but no results
	} else {
		buf.WriteByte(0x32) // fail - no results
	}
	binary.Write(buf, binary.LittleEndian, uint32(0)) // users_left

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seqNum,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	h.logger.Info("sending META white search 2 end",
		"uin", session.UIN,
		"success", success,
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// Response helpers

// sendV5AckToAddr sends a V5 ACK to a specific address (for pre-login packets)
func (h *V5Handler) sendV5AckToAddr(addr *net.UDPAddr, sessionID uint32, uin uint32, seq1, seq2 uint16) error {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: sessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seq1,
		SeqNum2:   seq2,
		UIN:       uin,
	}

	// Server packets are NOT encrypted
	data := wire.MarshalV5ServerPacket(pkt)
	return h.sender.SendPacket(addr, data)
}

// sendV5NotConnected sends a NOT_CONNECTED (0x00F0) response to a V5 client
// that has no session. This forces the client to reconnect/relogon.
// From licq.5 source: ICQ_CMDxRCV_ERROR (0x00F0) triggers icqRelogon()
// with message "Server says you are not logged on."
func (h *V5Handler) sendV5NotConnected(addr *net.UDPAddr, sessionID uint32, uin uint32, seq1, seq2 uint16) error {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: sessionID,
		Command:   wire.ICQLegacySrvNotConnected,
		SeqNum1:   seq1,
		SeqNum2:   seq2,
		UIN:       uin,
	}
	return h.sender.SendPacket(addr, wire.MarshalV5ServerPacket(pkt))
}

// sendV5FirstLoginReply sends the first login ACK response
// From iserverd v5_process_firstlog() - special ACK with session_id2
func (h *V5Handler) sendV5FirstLoginReply(addr *net.UDPAddr, sessionID uint32, uin uint32, seq1, seq2 uint16, sessionID2 uint32) error {
	// Build data: 0x0A(1) + SESSION_ID2(4) + 0x0001(2) = 7 bytes
	// Note: The JUNK(4) in iserverd is the checkcode placeholder in the header
	data := make([]byte, 7)
	data[0] = 0x0A
	binary.LittleEndian.PutUint32(data[1:5], sessionID2)
	binary.LittleEndian.PutUint16(data[5:7], 0x0001)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: sessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seq1,
		SeqNum2:   seq2,
		UIN:       uin,
		Data:      data,
	}

	packetData := wire.MarshalV5ServerPacket(pkt)
	return h.sender.SendPacket(addr, packetData)
}

// sendV5DepsListReply sends the pre-auth response (V3 format!)
// Historically called "departments list" in iserverd. In V5, this is a deprecated
// empty V3-format response sent during the pre-auth pseudo-login (0x03F2).
// From iserverd v5_send_depslist()
func (h *V5Handler) sendV5DepsListReply(addr *net.UDPAddr, uin uint32, seq2 uint16) error {
	// V3 format packet: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKSUM(4)
	// Command is 0x0032 (pre-auth response)
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(buf[2:4], wire.ICQLegacySrvUserDepsList)
	binary.LittleEndian.PutUint16(buf[4:6], 0x0000) // seq1
	binary.LittleEndian.PutUint16(buf[6:8], seq2)
	binary.LittleEndian.PutUint32(buf[8:12], uin)
	binary.LittleEndian.PutUint32(buf[12:16], 0x8FFCACBF) // magic checksum

	h.logger.Debug("sending V5 depslist reply (V3 format)",
		"uin", uin,
		"packet_len", len(buf),
	)

	return h.sender.SendPacket(addr, buf)
}

func (h *V5Handler) sendV5Ack(session *LegacySession, seqNum uint16) error {
	if session == nil {
		return nil
	}

	// ACK echoes the client's seq1, and uses 0 for seq2 (as per iserverd)
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seqNum,
		SeqNum2:   0, // ACKs use 0 for seq2
		UIN:       session.UIN,
	}

	// Server packets are NOT encrypted
	data := wire.MarshalV5ServerPacket(pkt)
	return h.sender.SendToSession(session, data)
}

// sendV5AckWithSeq2 sends an ACK echoing both seq1 and seq2 from the client
func (h *V5Handler) sendV5AckWithSeq2(session *LegacySession, seq1, seq2 uint16) error {
	if session == nil {
		return nil
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seq1,
		SeqNum2:   seq2,
		UIN:       session.UIN,
	}

	data := wire.MarshalV5ServerPacket(pkt)
	return h.sender.SendToSession(session, data)
}

func (h *V5Handler) sendMetaAck(session *LegacySession, seq2 uint16, subCommand uint16) error {
	if session == nil {
		return nil
	}

	// Build META response
	metaData := make([]byte, 3)
	binary.LittleEndian.PutUint16(metaData[0:2], subCommand)
	metaData[2] = 0x0A // Success

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      metaData,
	}

	// Server packets are NOT encrypted
	data := wire.MarshalV5ServerPacket(pkt)
	return h.sender.SendToSession(session, data)
}

// sendMetaUnregAck sends the unregister acknowledgment
// From iserverd v5_send_meta_set_ack() with SRV_META_UNREG_ACK
// Success byte: 0x0A for success, 0x32 for failure
func (h *V5Handler) sendMetaUnregAck(session *LegacySession, seq2 uint16, success bool) error {
	if session == nil {
		return nil
	}

	// Build META response
	metaData := make([]byte, 3)
	binary.LittleEndian.PutUint16(metaData[0:2], wire.ICQLegacySrvMetaUnregAck)
	if success {
		metaData[2] = 0x0A // Success
	} else {
		metaData[2] = 0x32 // Failure
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      metaData,
	}

	h.logger.Debug("sending META unregister ack",
		"uin", session.UIN,
		"success", success,
	)

	// Server packets are NOT encrypted
	data := wire.MarshalV5ServerPacket(pkt)
	return h.sender.SendToSession(session, data)
}

// sendMetaLoginReply sends the login meta response
// From iserverd v5_send_lmeta(): sends 0x07D0 + 0x0000 + 0x0046
func (h *V5Handler) sendMetaLoginReply(session *LegacySession, seq2 uint16) error {
	if session == nil {
		return nil
	}

	// Build META login response: SUB_CMD(2) + 0x0000(2) + 0x0046(2)
	metaData := make([]byte, 6)
	binary.LittleEndian.PutUint16(metaData[0:2], 0x07D0) // sub-command echo
	binary.LittleEndian.PutUint16(metaData[2:4], 0x0000) // unknown
	binary.LittleEndian.PutUint16(metaData[4:6], 0x0046) // unknown (70 decimal)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      metaData,
	}

	h.logger.Debug("sending META login reply",
		"uin", session.UIN,
		"seq2", seq2,
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaFail sends a META fail response
func (h *V5Handler) sendMetaFail(session *LegacySession, seq2 uint16, subCommand uint16) error {
	if session == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, subCommand)
	buf.WriteByte(0x32) // fail

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaInfo3 sends basic user info (SRV_META_USER_INFO2 = 0x00C8)
// From iserverd v5_send_meta_info3()
func (h *V5Handler) sendMetaInfo3(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x00C8)) // SRV_META_USER_INFO2
	buf.WriteByte(0x0A) // success
	writeLegacyString(buf, info.Nickname)
	writeLegacyString(buf, info.FirstName)
	writeLegacyString(buf, info.LastName)
	writeLegacyString(buf, info.Email)  // email1
	writeLegacyString(buf, "")          // email2
	writeLegacyString(buf, "")          // email3
	writeLegacyString(buf, "")          // hcity
	writeLegacyString(buf, "")          // hstate
	writeLegacyString(buf, "")          // hphone
	writeLegacyString(buf, "")          // hfax
	writeLegacyString(buf, "")          // haddr
	writeLegacyString(buf, "")          // hcell
	writeLegacyString(buf, "")          // hzip (string in info3)
	binary.Write(buf, binary.LittleEndian, uint16(0))  // hcountry
	binary.Write(buf, binary.LittleEndian, uint16(0))  // gmt_offset
	buf.WriteByte(0x01) // auth
	buf.WriteByte(0x00) // e1publ
	buf.WriteByte(0x00) // unknown
	buf.WriteByte(0x00) // unknown
	buf.WriteByte(0x00) // unknown

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaMore sends more user info (SRV_META_INFO_MORE = 0x00DC)
// From iserverd v5_send_meta_more()
//
// This is the original format used by older ICQ clients (pre-99b).
// The key difference from sendMetaMore2() is the birth year field:
// - sendMetaMore(): birth year is 1 byte (year - 1900)
// - sendMetaMore2(): birth year is 2 bytes (full year)
//
// Packet data format:
// - SRV_META_INFO_MORE(2) = 0x00DC
// - success(1) = 0x0A
// - age(2)
// - gender(1)
// - homepage_len(2) + homepage(string)
// - byear(1) = year - 1900 (if year >= 1900, else raw year)
// - bmonth(1)
// - bday(1)
// - lang1(1)
// - lang2(1)
// - lang3(1)
func (h *V5Handler) sendMetaMore(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	// Calculate birth year as single byte (year - 1900)
	// From iserverd: if (tuser.byear < 1900) {temp_year = tuser.byear;} else {temp_year = tuser.byear - 1900;};
	var tempYear uint8
	if info.BirthYear < 1900 {
		tempYear = uint8(info.BirthYear)
	} else {
		tempYear = uint8(info.BirthYear - 1900)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, wire.ICQLegacySrvMetaInfoMore) // SRV_META_INFO_MORE = 0x00DC
	buf.WriteByte(0x0A)                                                   // success
	binary.Write(buf, binary.LittleEndian, uint16(info.Age))              // age(2)
	buf.WriteByte(info.Gender)                                            // gender(1)
	writeLegacyString(buf, info.Homepage)                                 // homepage_len(2) + homepage
	buf.WriteByte(tempYear)                                               // byear(1) - year minus 1900
	buf.WriteByte(info.BirthMonth)                                        // bmonth(1)
	buf.WriteByte(info.BirthDay)                                          // bday(1)
	buf.WriteByte(info.Lang1)                                             // lang1(1)
	buf.WriteByte(info.Lang2)                                             // lang2(1)
	buf.WriteByte(info.Lang3)                                             // lang3(1)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaMore2 sends more user info (SRV_META_INFO_MORE = 0x00DC)
// From iserverd v5_send_meta_more2()
//
// This is the newer format used by ICQ 99b and later clients.
// The key difference from sendMetaMore() is the birth year field:
// - sendMetaMore(): birth year is 1 byte (year - 1900)
// - sendMetaMore2(): birth year is 2 bytes (full year)
//
// Packet data format:
// - SRV_META_INFO_MORE(2) = 0x00DC
// - success(1) = 0x0A
// - age(2)
// - gender(1)
// - homepage_len(2) + homepage(string)
// - byear(2) = full year
// - bmonth(1)
// - bday(1)
// - lang1(1)
// - lang2(1)
// - lang3(1)
func (h *V5Handler) sendMetaMore2(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, wire.ICQLegacySrvMetaInfoMore) // SRV_META_INFO_MORE = 0x00DC
	buf.WriteByte(0x0A)                                                   // success
	binary.Write(buf, binary.LittleEndian, uint16(info.Age))              // age(2)
	buf.WriteByte(info.Gender)                                            // gender(1)
	writeLegacyString(buf, info.Homepage)                                 // homepage_len(2) + homepage
	binary.Write(buf, binary.LittleEndian, uint16(info.BirthYear))        // byear(2) - full year
	buf.WriteByte(info.BirthMonth)                                        // bmonth(1)
	buf.WriteByte(info.BirthDay)                                          // bday(1)
	buf.WriteByte(info.Lang1)                                             // lang1(1)
	buf.WriteByte(info.Lang2)                                             // lang2(1)
	buf.WriteByte(info.Lang3)                                             // lang3(1)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaHpageCat sends homepage category info (SRV_META_INFO_HPAGE_CAT = 0x010E)
// From iserverd v5_send_meta_hpage_cat()
func (h *V5Handler) sendMetaHpageCat(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x010E)) // SRV_META_INFO_HPAGE_CAT
	buf.WriteByte(0x0A) // success
	buf.WriteByte(0x00) // hpage_cf (enabled)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // hpage_cat
	writeLegacyString(buf, "") // hpage_txt
	buf.WriteByte(0x00) // unknown

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaWork sends work info (SRV_META_INFO_WORK = 0x00D2)
// From iserverd v5_send_meta_work()
// This is the older format that uses uint32 for ZIP code (vs string in sendMetaWork2)
// Field order: wcity, wstate, wphone, wfax, waddr, wzip(uint32), wcountry, wcompany, wdepart, wtitle, wocup, wpage
func (h *V5Handler) sendMetaWork(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x00D2)) // SRV_META_INFO_WORK
	buf.WriteByte(0x0A)                                    // success
	writeLegacyString(buf, "")                             // wcity
	writeLegacyString(buf, "")                             // wstate
	writeLegacyString(buf, "")                             // wphone
	writeLegacyString(buf, "")                             // wfax
	writeLegacyString(buf, "")                             // waddr
	binary.Write(buf, binary.LittleEndian, uint32(0))      // wzip (uint32 in work, string in work2)
	binary.Write(buf, binary.LittleEndian, uint16(0))      // wcountry
	writeLegacyString(buf, "")                             // wcompany
	writeLegacyString(buf, "")                             // wdepart
	writeLegacyString(buf, "")                             // wtitle
	binary.Write(buf, binary.LittleEndian, uint16(0))      // wocup (occupation code)
	writeLegacyString(buf, "")                             // wpage (work webpage)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaWork2 sends work info (SRV_META_INFO_WORK = 0x00D2)
// From iserverd v5_send_meta_work2() - used with ICQ99b
// This is the newer format that uses string for ZIP code (vs uint32 in sendMetaWork)
// Field order: wcity, wstate, wphone, wfax, waddr, wzip(string), wcountry, wcompany, wdepart, wtitle, wocup, wpage
func (h *V5Handler) sendMetaWork2(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x00D2)) // SRV_META_INFO_WORK
	buf.WriteByte(0x0A)                                    // success
	writeLegacyString(buf, "")                             // wcity
	writeLegacyString(buf, "")                             // wstate
	writeLegacyString(buf, "")                             // wphone
	writeLegacyString(buf, "")                             // wfax
	writeLegacyString(buf, "")                             // waddr
	writeLegacyString(buf, "")                             // wzip (string in work2, uint32 in work)
	binary.Write(buf, binary.LittleEndian, uint16(0))      // wcountry
	writeLegacyString(buf, "")                             // wcompany
	writeLegacyString(buf, "")                             // wdepart
	writeLegacyString(buf, "")                             // wtitle
	binary.Write(buf, binary.LittleEndian, uint16(0))      // wocup (occupation code)
	writeLegacyString(buf, "")                             // wpage (work webpage)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaAbout sends about/notes info (SRV_META_INFO_ABOUT = 0x00E6)
// From iserverd v5_send_meta_about()
func (h *V5Handler) sendMetaAbout(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x00E6)) // SRV_META_INFO_ABOUT
	buf.WriteByte(0x0A) // success
	writeLegacyString(buf, "") // notes

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaInterests sends interests info (SRV_META_INFO_INTERESTS = 0x00F0)
// From iserverd v5_send_meta_interestsinfo()
func (h *V5Handler) sendMetaInterests(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x00F0)) // SRV_META_INFO_INTERESTS
	buf.WriteByte(0x0A) // success
	buf.WriteByte(0x00) // int_num (0 interests)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaAffiliations sends affiliations info (SRV_META_INFO_AFFILATIONS = 0x00FA)
// From iserverd v5_send_meta_affilationsinfo()
func (h *V5Handler) sendMetaAffiliations(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x00FA)) // SRV_META_INFO_AFFILATIONS
	buf.WriteByte(0x0A) // success
	// Past backgrounds (3 empty entries)
	buf.WriteByte(0x03) // past_num
	binary.Write(buf, binary.LittleEndian, uint16(0)) // past_ind1
	writeLegacyString(buf, "") // past_key1
	binary.Write(buf, binary.LittleEndian, uint16(0)) // past_ind2
	writeLegacyString(buf, "") // past_key2
	binary.Write(buf, binary.LittleEndian, uint16(0)) // past_ind3
	writeLegacyString(buf, "") // past_key3
	// Affiliations (3 empty entries)
	buf.WriteByte(0x03) // aff_num
	binary.Write(buf, binary.LittleEndian, uint16(0)) // aff_ind1
	writeLegacyString(buf, "") // aff_key1
	binary.Write(buf, binary.LittleEndian, uint16(0)) // aff_ind2
	writeLegacyString(buf, "") // aff_key2
	binary.Write(buf, binary.LittleEndian, uint16(0)) // aff_ind3
	writeLegacyString(buf, "") // aff_key3
	// Trailing bytes
	binary.Write(buf, binary.LittleEndian, uint16(0x0000))
	binary.Write(buf, binary.LittleEndian, uint16(0x0001))
	buf.WriteByte(0x00)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaFullUserInfo sends full user info response (legacy, kept for compatibility)
// From iserverd v5_reply_metafullinfo_request2()
func (h *V5Handler) sendMetaFullUserInfo(session *LegacySession, seq2 uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	// Build basic info response (SRV_META_USER_INFO2 = 0x00C8)
	// Format: SUB_CMD(2) + SUCCESS(1) + UIN(4) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST + LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL + AUTH(1)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x00C8)) // SRV_META_USER_INFO2
	buf.WriteByte(0x0A) // success
	binary.Write(buf, binary.LittleEndian, info.UIN)
	writeLegacyString(buf, info.Nickname)
	writeLegacyString(buf, info.FirstName)
	writeLegacyString(buf, info.LastName)
	writeLegacyString(buf, info.Email)
	buf.WriteByte(0) // auth

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	h.logger.Debug("sending META full user info",
		"uin", session.UIN,
		"target", info.UIN,
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendMetaUserInfo sends a META user info response
// From iserverd v5_send_meta_info() in make_meta.cpp
//
// Packet format (success case):
// - SubCommand (2 bytes): SRV_META_USER_INFO (0x0104)
// - Success (1 byte): 0x0A for success
// - Nickname length (2 bytes) + Nickname (null-terminated string)
// - First name length (2 bytes) + First name (null-terminated string)
// - Last name length (2 bytes) + Last name (null-terminated string)
// - Email length (2 bytes) + Email (null-terminated string)
// - Auth required (1 byte): 0=no auth, 1=auth required
// - Gender (1 byte): 0=unspecified, 1=female, 2=male
// - Zero (1 byte): 0x00
func (h *V5Handler) sendMetaUserInfo(session *LegacySession, seqNum uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil {
		return nil
	}

	buf := new(bytes.Buffer)

	// SubCommand: SRV_META_USER_INFO (0x0104)
	binary.Write(buf, binary.LittleEndian, wire.ICQLegacySrvMetaUserInfo)

	if info != nil {
		// Success byte: 0x0A
		buf.WriteByte(0x0A)

		// Nickname (length-prefixed, null-terminated)
		writeLegacyString(buf, info.Nickname)

		// First name (length-prefixed, null-terminated)
		writeLegacyString(buf, info.FirstName)

		// Last name (length-prefixed, null-terminated)
		writeLegacyString(buf, info.LastName)

		// Email (length-prefixed, null-terminated) - iserverd uses email2 field
		writeLegacyString(buf, info.Email)

		// Auth required (1 byte)
		buf.WriteByte(info.AuthRequired)

		// Gender (1 byte)
		buf.WriteByte(info.Gender)

		// Trailing zero (1 byte) - as per iserverd
		buf.WriteByte(0x00)
	} else {
		// Failure case: send meta fail
		// Success byte: 0x32 (fail)
		buf.WriteByte(0x32)
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seqNum,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	h.logger.Info("sending META user info",
		"uin", session.UIN,
		"sub_command", fmt.Sprintf("0x%04X", wire.ICQLegacySrvMetaUserInfo),
		"target_uin", info.UIN,
		"nickname", info.Nickname,
		"firstname", info.FirstName,
		"lastname", info.LastName,
		"email", info.Email,
		"auth", info.AuthRequired,
		"gender", info.Gender,
		"packet_len", len(packetData),
	)

	return h.sender.SendToSession(session, packetData)
}

// sendMetaUserInfo2 sends an extended META user info response (home info)
// From iserverd v5_send_meta_info2() in make_meta.cpp
//
// This is an extended version of sendMetaUserInfo() that includes home address info.
// Packet format (success case):
// - SubCommand (2 bytes): SRV_META_USER_INFO2 (0x00C8)
// - Success (1 byte): 0x0A for success
// - Nickname length (2 bytes) + Nickname (null-terminated string)
// - First name length (2 bytes) + First name (null-terminated string)
// - Last name length (2 bytes) + Last name (null-terminated string)
// - Email1 length (2 bytes) + Email1 (null-terminated string) - conditionally hidden based on e1publ
// - Email2 length (2 bytes) + Email2 (null-terminated string)
// - Email3 length (2 bytes) + Email3 (null-terminated string)
// - Home city length (2 bytes) + Home city (null-terminated string)
// - Home state length (2 bytes) + Home state (null-terminated string)
// - Home phone length (2 bytes) + Home phone (null-terminated string)
// - Home fax length (2 bytes) + Home fax (null-terminated string)
// - Home address length (2 bytes) + Home address (null-terminated string)
// - Home cell length (2 bytes) + Home cell (null-terminated string)
// - Home ZIP (4 bytes): uint32 little-endian
// - Home country (2 bytes): uint16 little-endian
// - GMT offset (2 bytes): uint16 little-endian
// - Auth required (1 byte): 0=no auth, 1=auth required
// - Web aware (1 byte): 0=not web aware, 1=web aware
// - IP hide (1 byte): 0=show IP, 1=hide IP
// - Zero (1 byte): 0x00
// - Zero (1 byte): 0x00
func (h *V5Handler) sendMetaUserInfo2(session *LegacySession, seqNum uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil {
		return nil
	}

	buf := new(bytes.Buffer)

	// SubCommand: SRV_META_USER_INFO2 (0x00C8)
	binary.Write(buf, binary.LittleEndian, wire.ICQLegacySrvMetaUserInfo2)

	if info != nil {
		// Success byte: 0x0A
		buf.WriteByte(0x0A)

		// Nickname (length-prefixed, null-terminated)
		writeLegacyString(buf, info.Nickname)

		// First name (length-prefixed, null-terminated)
		writeLegacyString(buf, info.FirstName)

		// Last name (length-prefixed, null-terminated)
		writeLegacyString(buf, info.LastName)

		// Email1 (length-prefixed, null-terminated)
		// Note: In iserverd, this is conditionally hidden based on e1publ flag
		// For now, we always send the email (same as sendMetaUserInfo)
		writeLegacyString(buf, info.Email)

		// Email2 (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Email3 (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home city (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home state (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home phone (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home fax (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home address (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home cell (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home ZIP (4 bytes): uint32 little-endian - not in LegacyUserSearchResult
		binary.Write(buf, binary.LittleEndian, uint32(0))

		// Home country (2 bytes): uint16 little-endian - not in LegacyUserSearchResult
		binary.Write(buf, binary.LittleEndian, uint16(0))

		// GMT offset (2 bytes): uint16 little-endian - not in LegacyUserSearchResult
		binary.Write(buf, binary.LittleEndian, uint16(0))

		// Auth required (1 byte)
		buf.WriteByte(info.AuthRequired)

		// Web aware (1 byte)
		buf.WriteByte(info.WebAware)

		// IP hide (1 byte) - not in LegacyUserSearchResult, default to 0 (show IP)
		buf.WriteByte(0x00)

		// Two trailing zeros (as per iserverd)
		buf.WriteByte(0x00)
		buf.WriteByte(0x00)
	} else {
		// Failure case: send meta fail
		// Success byte: 0x32 (fail)
		buf.WriteByte(0x32)
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seqNum,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	h.logger.Info("sending META user info2 (home info)",
		"uin", session.UIN,
		"sub_command", fmt.Sprintf("0x%04X", wire.ICQLegacySrvMetaUserInfo2),
		"target_uin", info.UIN,
		"nickname", info.Nickname,
		"firstname", info.FirstName,
		"lastname", info.LastName,
		"email", info.Email,
		"auth", info.AuthRequired,
		"webaware", info.WebAware,
		"packet_len", len(packetData),
	)

	return h.sender.SendToSession(session, packetData)
}

// sendMetaUserInfo3 sends an extended META user info response (home info) for ICQ99b clients
// From iserverd v5_send_meta_info3() in make_meta.cpp
//
// This is a variant of sendMetaUserInfo2() used with ICQ99b clients.
// The key difference is that the home ZIP code is sent as a string instead of uint32.
//
// Packet format (success case):
// - SubCommand (2 bytes): SRV_META_USER_INFO2 (0x00C8) - same as info2
// - Success (1 byte): 0x0A for success
// - Nickname length (2 bytes) + Nickname (null-terminated string)
// - First name length (2 bytes) + First name (null-terminated string)
// - Last name length (2 bytes) + Last name (null-terminated string)
// - Email1 length (2 bytes) + Email1 (null-terminated string) - conditionally hidden based on e1publ
// - Email2 length (2 bytes) + Email2 (null-terminated string)
// - Email3 length (2 bytes) + Email3 (null-terminated string)
// - Home city length (2 bytes) + Home city (null-terminated string)
// - Home state length (2 bytes) + Home state (null-terminated string)
// - Home phone length (2 bytes) + Home phone (null-terminated string)
// - Home fax length (2 bytes) + Home fax (null-terminated string)
// - Home address length (2 bytes) + Home address (null-terminated string)
// - Home cell length (2 bytes) + Home cell (null-terminated string)
// - Home ZIP length (2 bytes) + Home ZIP (null-terminated STRING) - KEY DIFFERENCE from info2
// - Home country (2 bytes): uint16 little-endian
// - GMT offset (2 bytes): uint16 little-endian
// - 0x01 (1 byte): constant
// - e1publ (1 byte): email1 public flag
// - Zero (1 byte): 0x00
// - Zero (1 byte): 0x00
// - Zero (1 byte): 0x00
func (h *V5Handler) sendMetaUserInfo3(session *LegacySession, seqNum uint16, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil {
		return nil
	}

	buf := new(bytes.Buffer)

	// SubCommand: SRV_META_USER_INFO2 (0x00C8) - same as info2
	binary.Write(buf, binary.LittleEndian, wire.ICQLegacySrvMetaUserInfo2)

	if info != nil {
		// Success byte: 0x0A
		buf.WriteByte(0x0A)

		// Nickname (length-prefixed, null-terminated)
		writeLegacyString(buf, info.Nickname)

		// First name (length-prefixed, null-terminated)
		writeLegacyString(buf, info.FirstName)

		// Last name (length-prefixed, null-terminated)
		writeLegacyString(buf, info.LastName)

		// Email1 (length-prefixed, null-terminated)
		// Note: In iserverd, this is conditionally hidden based on e1publ flag
		// If e1publ != 1 OR requesting own info, show email; otherwise hide it
		// For simplicity, we always send the email (same as sendMetaUserInfo2)
		writeLegacyString(buf, info.Email)

		// Email2 (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Email3 (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home city (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home state (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home phone (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home fax (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home address (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home cell (length-prefixed, null-terminated) - not in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home ZIP as STRING (KEY DIFFERENCE from info2)
		// In iserverd: snprintf(hzip, 31, "%lu", tuser.hzip)
		// For now, we send empty string since we don't have ZIP in LegacyUserSearchResult
		writeLegacyString(buf, "")

		// Home country (2 bytes): uint16 little-endian - not in LegacyUserSearchResult
		binary.Write(buf, binary.LittleEndian, uint16(0))

		// GMT offset (2 bytes): uint16 little-endian - not in LegacyUserSearchResult
		binary.Write(buf, binary.LittleEndian, uint16(0))

		// 0x01 (1 byte): constant - as per iserverd
		buf.WriteByte(0x01)

		// e1publ (1 byte): email1 public flag - default to 1 (public)
		buf.WriteByte(0x01)

		// Three trailing zeros (as per iserverd)
		buf.WriteByte(0x00)
		buf.WriteByte(0x00)
		buf.WriteByte(0x00)
	} else {
		// Failure case: send meta fail
		// Success byte: 0x32 (fail)
		buf.WriteByte(0x32)
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seqNum,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	h.logger.Info("sending META user info3 (home info for ICQ99b)",
		"uin", session.UIN,
		"sub_command", fmt.Sprintf("0x%04X", wire.ICQLegacySrvMetaUserInfo2),
		"target_uin", info.UIN,
		"nickname", info.Nickname,
		"firstname", info.FirstName,
		"lastname", info.LastName,
		"email", info.Email,
		"auth", info.AuthRequired,
		"webaware", info.WebAware,
		"packet_len", len(packetData),
	)

	return h.sender.SendToSession(session, packetData)
}

// sendMetaSearchResult sends a META search result
// From iserverd v5_send_user_found2()
func (h *V5Handler) sendMetaSearchResult(session *LegacySession, seqNum uint16, result *foodgroup.LegacyUserSearchResult, isLast bool) error {
	if session == nil {
		return nil
	}

	subCommand := uint16(0x0190) // SRV_META_USER_FOUND
	if isLast {
		subCommand = 0x019A // SRV_META_USER_LAST_FOUND
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, subCommand)

	if result != nil {
		buf.WriteByte(0x0A) // success

		// Calculate pack_len: 15 + strings + 4 for users_left
		packLen := uint16(15 + len(result.Nickname) + len(result.FirstName) + len(result.LastName) + len(result.Email) + 4)
		binary.Write(buf, binary.LittleEndian, packLen)

		binary.Write(buf, binary.LittleEndian, result.UIN)
		writeLegacyString(buf, result.Nickname)
		writeLegacyString(buf, result.FirstName)
		writeLegacyString(buf, result.LastName)
		writeLegacyString(buf, result.Email)
		buf.WriteByte(0) // auth
		buf.WriteByte(0) // webaware
		buf.WriteByte(0) // unknown

		if isLast {
			binary.Write(buf, binary.LittleEndian, uint32(0)) // users_left
		}
	} else {
		buf.WriteByte(0x32) // fail - no results
		if isLast {
			binary.Write(buf, binary.LittleEndian, uint32(0)) // users_left
		}
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seqNum,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	if result != nil {
		h.logger.Info("sending META search result",
			"uin", session.UIN,
			"sub_command", fmt.Sprintf("0x%04X", subCommand),
			"result_uin", result.UIN,
			"result_nickname", result.Nickname,
			"is_last", isLast,
			"packet_len", len(packetData),
		)
	} else {
		h.logger.Info("sending META search result - no results",
			"uin", session.UIN,
			"sub_command", fmt.Sprintf("0x%04X", subCommand),
			"is_last", isLast,
		)
	}

	return h.sender.SendToSession(session, packetData)
}

func (h *V5Handler) sendMetaSearchEnd(session *LegacySession, seqNum uint16) error {
	// Send empty last result to indicate end of search
	return h.sendMetaSearchResult(session, seqNum, nil, true)
}

// sendV5OldSearchFound sends an old-style search result
// From iserverd v5_send_old_search_found()
//
// Packet data format (after V5 header with JUNK(4) checkcode placeholder):
// - UIN(4): Target user's UIN (tuser.uin)
// - NICK_LEN(2) + NICK: Nickname (length-prefixed, null-terminated)
// - FIRST_LEN(2) + FIRST: First name (length-prefixed, null-terminated)
// - LAST_LEN(2) + LAST: Last name (length-prefixed, null-terminated)
// - EMAIL_LEN(2) + EMAIL: Email address (length-prefixed, null-terminated) - uses email2 in iserverd
// - AUTH(1): Authorization required flag (tuser.auth: 0=no, 1=yes)
// - 0x00(1): Unknown trailing byte
func (h *V5Handler) sendV5OldSearchFound(session *LegacySession, seq2 uint16, result *foodgroup.LegacyUserSearchResult) error {
	if session == nil || result == nil {
		return nil
	}

	// Build data: UIN(4) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST + LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL + AUTH(1) + 0x00(1)
	// Note: The JUNK(4) in iserverd is the checkcode placeholder in the header, not part of data
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, result.UIN)
	writeLegacyString(buf, result.Nickname)
	writeLegacyString(buf, result.FirstName)
	writeLegacyString(buf, result.LastName)
	writeLegacyString(buf, result.Email)
	buf.WriteByte(result.AuthRequired) // auth - from iserverd tuser.auth
	buf.WriteByte(0)                   // unknown trailing byte (as per iserverd)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvSearchFound,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5OldSearchEnd sends old-style search end marker
// From iserverd v5_send_old_search_end()
//
// Packet format (after V5 header):
// - MORE(1): 0x01 if more results available, 0x00 if search complete
//
// Note: iserverd ALWAYS sends the more byte (0x00 or 0x01), not just when more=true
func (h *V5Handler) sendV5OldSearchEnd(session *LegacySession, seq2 uint16, more bool) error {
	if session == nil {
		return nil
	}

	// Build data: MORE(1) - always sent per iserverd v5_send_old_search_end()
	// Note: The JUNK(4) in iserverd is the checkcode placeholder in the header, not part of data
	var moreByte byte
	if more {
		moreByte = 0x01
	} else {
		moreByte = 0x00
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvSearchDone,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      []byte{moreByte},
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5OldStyleInfo sends old-style basic info response
// From iserverd v5_send_old_style_info()
//
// Packet format (after V5 header):
// - UIN(4): Target user's UIN
// - NICK_LEN(2) + NICK: Nickname (length-prefixed, null-terminated)
// - FIRST_LEN(2) + FIRST: First name (length-prefixed, null-terminated)
// - LAST_LEN(2) + LAST: Last name (length-prefixed, null-terminated)
// - EMAIL_LEN(2) + EMAIL: Email address (length-prefixed, null-terminated)
// - AUTH(1): Authorization required flag (0=no, 1=yes)
//
// Note: iserverd uses email2 field, we use primary Email field (functionally equivalent)
func (h *V5Handler) sendV5OldStyleInfo(session *LegacySession, info *foodgroup.LegacyUserSearchResult) error {
	if session == nil || info == nil {
		return nil
	}

	// Build data: UIN(4) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST + LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL + AUTH(1)
	// Note: The JUNK(4) in iserverd is the checkcode placeholder in the header, not part of data
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, info.UIN)
	writeLegacyString(buf, info.Nickname)
	writeLegacyString(buf, info.FirstName)
	writeLegacyString(buf, info.LastName)
	writeLegacyString(buf, info.Email)
	buf.WriteByte(info.AuthRequired) // auth - from iserverd tuser.auth

	seqNum := session.NextServerSeqNum()

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvInfoReply,
		SeqNum1:   seqNum,
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	packetData := wire.MarshalV5ServerPacket(pkt)

	h.logger.Debug("sending V5 old style info",
		"uin", session.UIN,
		"target_uin", info.UIN,
		"seq1", seqNum,
		"packet_len", len(packetData),
		"packet_hex", fmt.Sprintf("%X", packetData),
	)

	return h.sender.SendToSession(session, packetData)
}

// sendV5OldStyleInfoExt sends old-style extended info response
// From iserverd v5_send_old_style_info_ext()
//
// Verified against licq.5 client (icqd-udp.cpp ICQ_CMDxRCV_USERxDETAILS):
// Client reads: UIN(4) + CITY(string) + COUNTRY(2) + TIMEZONE(1) + STATE(string) +
//               AGE(2) + GENDER(1) + PHONE(string) + HOMEPAGE(string) + ABOUT(string) + ZIPCODE(4)
//
// Note: iserverd comments the byte after COUNTRY as "I don't know what is it" but
// the licq.5 client reads it as SetTimezone(packet.UnpackChar()). We send the user's
// timezone value here.
func (h *V5Handler) sendV5OldStyleInfoExt(session *LegacySession, targetUIN uint32, user *state.User) error {
	if session == nil || user == nil {
		return nil
	}

	// Extract fields from user struct (matching iserverd field names)
	// From iserverd: tuser.hcity, tuser.hcountry, tuser.hstate, tuser.age, tuser.gender,
	//                tuser.hphone, tuser.hpage, notes.notes
	hcity := user.ICQBasicInfo.City
	hcountry := user.ICQBasicInfo.CountryCode
	gmtOffset := user.ICQBasicInfo.GMTOffset
	hstate := user.ICQBasicInfo.State
	age := uint16(user.Age(func() time.Time { return time.Now() }))
	gender := uint8(user.ICQMoreInfo.Gender)
	hphone := user.ICQBasicInfo.Phone
	hpage := user.ICQMoreInfo.HomePageAddr
	notes := user.ICQNotes.Notes

	// Parse ZIP code string to uint32 for the old-style ext info format
	// The licq.5 client reads this as UnpackUnsignedLong (4 bytes)
	var zipCode uint32
	if user.ICQBasicInfo.ZIPCode != "" {
		fmt.Sscanf(user.ICQBasicInfo.ZIPCode, "%d", &zipCode)
	}

	// Build data matching licq.5 client's USERxDETAILS parsing:
	// UIN(4) + CITY(string) + COUNTRY(2) + TIMEZONE(1) + STATE(string) +
	// AGE(2) + GENDER(1) + PHONE(string) + HOMEPAGE(string) + ABOUT(string) + ZIPCODE(4)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, targetUIN)
	writeLegacyString(buf, hcity)                       // city (length-prefixed with null terminator)
	binary.Write(buf, binary.LittleEndian, hcountry)    // country code
	buf.WriteByte(gmtOffset)                            // timezone / GMT offset (client reads as SetTimezone)
	writeLegacyString(buf, hstate)                      // state (length-prefixed with null terminator)
	binary.Write(buf, binary.LittleEndian, age)         // age
	buf.WriteByte(gender)                               // gender
	writeLegacyString(buf, hphone)                      // phone (length-prefixed with null terminator)
	writeLegacyString(buf, hpage)                       // homepage (length-prefixed with null terminator)
	writeLegacyString(buf, notes)                       // about/notes (length-prefixed with null terminator)
	binary.Write(buf, binary.LittleEndian, zipCode)     // zip code (uint32, client reads as UnpackUnsignedLong)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvExtInfoReply,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      buf.Bytes(),
	}

	h.logger.Debug("sending V5 old-style extended info",
		"to_uin", session.UIN,
		"target_uin", targetUIN,
		"city", hcity,
		"country", hcountry,
		"gmt_offset", gmtOffset,
		"state", hstate,
		"age", age,
		"gender", gender,
		"phone", hphone,
		"homepage", hpage,
		"notes_len", len(notes),
		"zip_code", zipCode,
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5InvalidUIN sends invalid UIN response
// From iserverd v5_send_invalid_uin()
func (h *V5Handler) sendV5InvalidUIN(session *LegacySession, uin uint32) error {
	if session == nil {
		return nil
	}

	// Build data: UIN(4)
	// Note: The JUNK(4) in iserverd is the checkcode placeholder in the header, not part of data
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], uin)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvInvalidUIN,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// writeLegacyString writes a length-prefixed string to a buffer
func writeLegacyString(buf *bytes.Buffer, s string) {
	length := uint16(len(s) + 1)
	binary.Write(buf, binary.LittleEndian, length)
	buf.WriteString(s)
	buf.WriteByte(0) // null terminator
}

// readLPString reads a length-prefixed null-terminated string from data at offset.
// Returns the string (without null terminator) and the number of bytes consumed.
func readLPString(data []byte, offset int) (string, int) {
	if offset+2 > len(data) {
		return "", 0
	}
	strLen := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if strLen <= 0 || offset+strLen > len(data) {
		return "", 2
	}
	// Strip null terminator if present
	s := string(data[offset : offset+strLen])
	if len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s, 2 + strLen
}

// handleDirectWhiteSearch handles white pages search sent directly (0x0532/0x0533)
// Some older clients send META search commands directly instead of wrapped in META_USER
func (h *V5Handler) handleDirectWhiteSearch(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	h.logger.Info("V5 direct white pages search", "uin", session.UIN, "data_len", len(pkt.Data))

	// Delegate to the META handler - pkt.Data is the same as subData for direct commands
	return h.handleMetaSearchWhite(session, pkt, pkt.Data)
}

// handleDirectNameSearch handles name search sent directly (0x0514/0x0515)
func (h *V5Handler) handleDirectNameSearch(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	// Parse three length-prefixed strings: nick, first, last
	offset := 0
	nick, n := readLPString(pkt.Data, offset)
	offset += n
	first, n := readLPString(pkt.Data, offset)
	offset += n
	last, _ := readLPString(pkt.Data, offset)

	h.logger.Info("V5 direct name search",
		"uin", session.UIN,
		"nick", nick,
		"first", first,
		"last", last,
	)

	ctx := context.Background()
	results, err := h.service.SearchByName(ctx, nick, first, last, "")
	if err != nil {
		h.logger.Info("V5 direct name search - error", "uin", session.UIN, "err", err)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	if len(results) == 0 {
		h.logger.Info("V5 direct name search - no results", "uin", session.UIN)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	h.logger.Info("V5 direct name search - found", "uin", session.UIN, "count", len(results))

	for _, r := range results {
		h.sendV5OldSearchFound(session, pkt.SeqNum2, &r)
	}
	return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
}

// handleDirectUINSearch handles UIN search sent directly (0x051E/0x051F)
func (h *V5Handler) handleDirectUINSearch(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	// Parse target UIN
	if len(pkt.Data) < 4 {
		h.logger.Info("V5 direct UIN search - data too short", "uin", session.UIN)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	ctx := context.Background()
	targetUIN := binary.LittleEndian.Uint32(pkt.Data[0:4])

	h.logger.Info("V5 direct UIN search",
		"uin", session.UIN,
		"target_uin", targetUIN,
	)

	result, err := h.service.SearchByUIN(ctx, targetUIN)
	if err != nil {
		h.logger.Info("V5 direct UIN search - error", "target_uin", targetUIN, "err", err)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}
	if result == nil {
		h.logger.Info("V5 direct UIN search - NOT FOUND", "target_uin", targetUIN)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	h.logger.Info("V5 direct UIN search - FOUND",
		"target_uin", targetUIN,
		"nickname", result.Nickname,
	)

	h.sendV5OldSearchFound(session, pkt.SeqNum2, result)
	return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
}

// handleDirectEmailSearch handles email search sent directly (0x0528/0x0529)
func (h *V5Handler) handleDirectEmailSearch(session *LegacySession, pkt *wire.V5ClientPacket) error {
	if session == nil {
		return nil
	}

	h.sendV5Ack(session, pkt.SeqNum1)

	email, _ := readLPString(pkt.Data, 0)

	h.logger.Info("V5 direct email search",
		"uin", session.UIN,
		"email", email,
	)

	ctx := context.Background()
	results, err := h.service.SearchByName(ctx, "", "", "", email)
	if err != nil {
		h.logger.Info("V5 direct email search - error", "uin", session.UIN, "err", err)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	if len(results) == 0 {
		h.logger.Info("V5 direct email search - no results", "uin", session.UIN)
		return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
	}

	h.logger.Info("V5 direct email search - found", "uin", session.UIN, "count", len(results))

	for _, r := range results {
		h.sendV5OldSearchFound(session, pkt.SeqNum2, &r)
	}
	return h.sendV5OldSearchEnd(session, pkt.SeqNum2, false)
}

// sendOnlineMessage sends an online system message to a V5 client
// Format: header + FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (h *V5Handler) sendOnlineMessage(session *LegacySession, fromUIN uint32, msgType uint16, message string) error {
	msgBytes := []byte(message)

	h.logger.Debug("V5 sending online message",
		"to", session.UIN,
		"from", fromUIN,
		"type", fmt.Sprintf("0x%04X", msgType),
		"msg_len", len(msgBytes),
	)

	// Send V5 format packet
	data := make([]byte, 4+2+2+len(msgBytes)+1)
	offset := 0

	// From UIN
	binary.LittleEndian.PutUint32(data[offset:], fromUIN)
	offset += 4

	// Message type (mask high byte for legacy clients)
	binary.LittleEndian.PutUint16(data[offset:], msgType&0x00FF)
	offset += 2

	// Message length (including null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(msgBytes)+1))
	offset += 2

	// Message content
	copy(data[offset:], msgBytes)
	offset += len(msgBytes)
	data[offset] = 0 // null terminator

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvSysMsgOnline, // 0x0104
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5UserOffline sends user offline notification
// From iserverd v5_send_user_offline()
func (h *V5Handler) sendV5UserOffline(session *LegacySession, uin uint32) error {
	// V5 USER_OFFLINE format: UIN(4)
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], uin)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvUserOffline,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	h.logger.Debug("sending V5 user offline notification",
		"to", session.UIN,
		"offline_uin", uin,
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}

// sendV5UserStatus sends user status change notification
// From iserverd v5_send_user_status() in make_packet.cpp
// This is used when a user changes status while already online
// (e.g., Away -> Online, Online -> DND)
// Format: UIN(4) + STATUS(2) + ESTAT(2)
func (h *V5Handler) sendV5UserStatus(session *LegacySession, uin uint32, status uint32) error {
	// V5 USER_STATUS format from iserverd:
	// UIN(4) + STATUS(2) + ESTAT(2)
	data := make([]byte, 8)
	offset := 0

	// UIN of the user whose status changed
	binary.LittleEndian.PutUint32(data[offset:], uin)
	offset += 4

	// Status (low word)
	binary.LittleEndian.PutUint16(data[offset:], uint16(status&0xFFFF))
	offset += 2

	// Extended status (high word)
	binary.LittleEndian.PutUint16(data[offset:], uint16(status>>16))
	offset += 2

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvUserStatus, // 0x01A4
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	h.logger.Debug("sending V5 user status change notification",
		"to", session.UIN,
		"changed_uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
	)

	return h.sender.SendToSession(session, wire.MarshalV5ServerPacket(pkt))
}
