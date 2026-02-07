package icq_legacy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/mk6i/open-oscar-server/wire"
)

// V4Handler handles ICQ V4 protocol packets
// V4 packet format (from wumpus documentation):
// VERSION(2) + RANDOM(2) + ZEROS(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA...
// Total header: 20 bytes
// V4 uses XOR encryption similar to V3 but with different positions
type V4Handler struct {
	sessions *LegacySessionManager
	service  LegacyService
	sender   PacketSender
	logger   *slog.Logger
}

// NewV4Handler creates a new V4 protocol handler
func NewV4Handler(
	sessions *LegacySessionManager,
	service LegacyService,
	sender PacketSender,
	logger *slog.Logger,
) *V4Handler {
	return &V4Handler{
		sessions: sessions,
		service:  service,
		sender:   sender,
		logger:   logger,
	}
}

// SetSender sets the packet sender (for circular dependency resolution)
func (h *V4Handler) SetSender(sender PacketSender) {
	h.sender = sender
}

// V4 packet offsets (from wumpus documentation)
const (
	v4OffsetVersion   = 0
	v4OffsetRandom    = 2
	v4OffsetZero      = 4
	v4OffsetCommand   = 6
	v4OffsetSeq1      = 8
	v4OffsetSeq2      = 10
	v4OffsetUIN       = 12
	v4OffsetCheckcode = 16
	v4HeaderSize      = 20
)

// Handle processes a V4 protocol packet
func (h *V4Handler) Handle(session *LegacySession, addr *net.UDPAddr, packet []byte) error {
	if len(packet) < v4HeaderSize {
		return fmt.Errorf("V4 packet too short: %d bytes", len(packet))
	}

	h.logger.Debug("raw V4 packet before decryption",
		"hex", fmt.Sprintf("%X", packet),
		"len", len(packet),
	)

	// Make a copy for decryption
	decrypted := make([]byte, len(packet))
	copy(decrypted, packet)

	// Decrypt the V4 packet
	if err := h.decryptV4Packet(decrypted); err != nil {
		h.logger.Debug("V4 decryption failed", "err", err)
		return err
	}

	h.logger.Debug("V4 packet after decryption",
		"hex", fmt.Sprintf("%X", decrypted),
	)

	// Parse V4 header
	command := binary.LittleEndian.Uint16(decrypted[v4OffsetCommand:])
	seq1 := binary.LittleEndian.Uint16(decrypted[v4OffsetSeq1:])
	seq2 := binary.LittleEndian.Uint16(decrypted[v4OffsetSeq2:])
	uin := binary.LittleEndian.Uint32(decrypted[v4OffsetUIN:])

	// Extract data after header
	var data []byte
	if len(decrypted) > v4HeaderSize {
		data = decrypted[v4HeaderSize:]
	}

	h.logger.Info("V4 packet received",
		"command", fmt.Sprintf("0x%04X", command),
		"uin", uin,
		"seq1", seq1,
		"seq2", seq2,
		"data_len", len(data),
		"addr", addr.String(),
		"session_found", session != nil,
	)

	// Update session activity if we have one
	if session != nil {
		session.UpdateActivity()
		session.SeqNumClient = seq1
	}

	// Handle V4 commands (same commands as V3, just different packet format)
	switch command {
	case wire.ICQLegacyCmdFirstLogin:
		return h.handleFirstLogin(addr, seq1, seq2, uin)
	case wire.ICQLegacyCmdRegRequestInfo:
		return h.handleRegRequestInfo(addr, seq1, seq2, uin)
	case wire.ICQLegacyCmdRegNewUserInfo:
		return h.handleRegNewUserInfo(addr, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdLogin:
		return h.handleLogin(session, addr, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdGetDeps:
		return h.handleGetDeps(addr, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdAck:
		h.logger.Debug("received V4 ACK", "seq1", seq1, "seq2", seq2)
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
	case wire.ICQLegacyCmdUserGetInfo:
		return h.handleGetInfo(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdInfoReq:
		return h.handleInfoReq(session, seq1, seq2, uin, data)
	case wire.ICQLegacyCmdExtInfoReq:
		return h.handleExtInfoReq(session, seq1, seq2, uin, data)
	default:
		h.logger.Debug("unhandled V4 command",
			"command", fmt.Sprintf("0x%04X", command),
			"uin", uin,
		)
		// Send ACK for unknown commands
		return h.sendAck(addr, seq1, seq2, uin)
	}
}

// decryptV4Packet decrypts a V4 packet in place
// From wumpus code in v4-notes.txt:
// count = ((length + 3) / 4 + 3) / 4
// This gives the number of DWORDs to encrypt
// Skip DWORD 4 (checkcode at offset 16-19)
func (h *V4Handler) decryptV4Packet(packet []byte) error {
	if len(packet) < v4HeaderSize {
		return fmt.Errorf("packet too short for V4 decryption")
	}

	// Get checkcode from position 16-19 (little-endian)
	checkcode := binary.LittleEndian.Uint32(packet[v4OffsetCheckcode:])

	// Calculate encryption key
	// key = packetLen * 0x66756B65 + checkcode
	packetLen := len(packet)
	key := uint32(packetLen)*0x66756B65 + checkcode

	// Calculate number of DWORDs to decrypt using wumpus formula:
	// count = ((length + 3) / 4 + 3) / 4
	count := ((packetLen + 3) / 4 + 3) / 4

	// Decrypt each DWORD, but skip DWORD 4 (checkcode at offset 16)
	for i := 0; i < count; i++ {
		pos := i * 4

		// Skip checkcode DWORD (position 16-19, i.e., DWORD 4)
		if i == 4 {
			continue
		}

		// Stop if we've gone past the packet
		if pos >= packetLen {
			break
		}

		tableIdx := pos & 0xFF
		xorVal := key + uint32(wire.V4Table[tableIdx])

		// XOR up to 4 bytes
		for j := 0; j < 4 && pos+j < packetLen; j++ {
			packet[pos+j] ^= byte(xorVal >> (j * 8))
		}
	}

	// Restore version bytes (they should be 04 00)
	packet[0] = 0x04
	packet[1] = 0x00

	return nil
}

// handleFirstLogin processes the first login packet (0x04EC)
// This is sent by clients starting the registration wizard
// Server should respond with registration info (admin notes)
func (h *V4Handler) handleFirstLogin(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	h.logger.Info("V4 first login packet - registration request",
		"uin", uin,
		"seq1", seq1,
		"seq2", seq2,
		"addr", addr.String(),
	)

	// Send ACK first
	h.sendAck(addr, seq1, seq2, uin)

	// Send registration info with admin notes
	// This tells the client that registration is enabled and provides any admin notes
	return h.sendRegisterInfo(addr, seq2, uin)
}

// handleRegRequestInfo processes the registration info request (0x05DC)
// Client is asking for admin notes and registration status
func (h *V4Handler) handleRegRequestInfo(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	h.logger.Info("V4 registration info request",
		"uin", uin,
		"seq1", seq1,
		"seq2", seq2,
		"addr", addr.String(),
	)

	// Send ACK first
	h.sendAck(addr, seq1, seq2, uin)

	// Send registration info
	return h.sendRegisterInfo(addr, seq2, uin)
}

// handleRegNewUserInfo processes the registration form submission (0x05E6)
// Client is submitting their registration data
func (h *V4Handler) handleRegNewUserInfo(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32, data []byte) error {
	ctx := context.Background()

	h.logger.Info("V4 registration form received",
		"uin", uin,
		"seq1", seq1,
		"seq2", seq2,
		"data_len", len(data),
		"addr", addr.String(),
	)

	// Send ACK first
	h.sendAck(addr, seq1, seq2, uin)

	// Parse registration data
	// Format from client.html (0x05e6):
	// CLIENT_VERSION(2) + NICK_LEN(2) + NICK + FNAME_LEN(2) + FNAME + LNAME_LEN(2) + LNAME + EMAIL_LEN(2) + EMAIL + ...
	if len(data) < 10 {
		h.logger.Debug("V4 registration data too short", "len", len(data))
		return h.sendNotConnected(addr, seq2, uin)
	}

	offset := 0

	// Read client version (2 bytes)
	// clientVersion := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Read nickname
	if offset+2 > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	nickLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	if nickLen > 32 || offset+int(nickLen) > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	nickname := string(data[offset : offset+int(nickLen)])
	if len(nickname) > 0 && nickname[len(nickname)-1] == 0 {
		nickname = nickname[:len(nickname)-1]
	}
	offset += int(nickLen)

	// Read first name
	if offset+2 > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	fnameLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	if fnameLen > 32 || offset+int(fnameLen) > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	firstName := string(data[offset : offset+int(fnameLen)])
	if len(firstName) > 0 && firstName[len(firstName)-1] == 0 {
		firstName = firstName[:len(firstName)-1]
	}
	offset += int(fnameLen)

	// Read last name
	if offset+2 > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	lnameLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	if lnameLen > 32 || offset+int(lnameLen) > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	lastName := string(data[offset : offset+int(lnameLen)])
	if len(lastName) > 0 && lastName[len(lastName)-1] == 0 {
		lastName = lastName[:len(lastName)-1]
	}
	offset += int(lnameLen)

	// Read email
	if offset+2 > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	emailLen := binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2
	if emailLen > 64 || offset+int(emailLen) > len(data) {
		return h.sendNotConnected(addr, seq2, uin)
	}
	email := string(data[offset : offset+int(emailLen)])
	if len(email) > 0 && email[len(email)-1] == 0 {
		email = email[:len(email)-1]
	}

	h.logger.Info("V4 registration data parsed",
		"nickname", nickname,
		"firstName", firstName,
		"lastName", lastName,
		"email", email,
	)

	// Generate a random password for the new user
	password := h.generatePassword(6)

	// Create the new user account
	newUIN, err := h.service.RegisterNewUser(ctx, nickname, firstName, lastName, email, password)
	if err != nil {
		h.logger.Error("V4 registration failed", "err", err)
		return h.sendNotConnected(addr, seq2, uin)
	}

	h.logger.Info("V4 registration successful",
		"newUIN", newUIN,
		"nickname", nickname,
	)

	// Send registration OK with the new UIN and password
	return h.sendRegistrationOK(addr, seq2, newUIN, password)
}

// generatePassword generates a random alphanumeric password
func (h *V4Handler) generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[i%len(charset)] // Simple deterministic for now
	}
	return string(password)
}

// handleGetDeps processes the get departments pseudo-login packet (0x03F2)
// This is actually the main login packet in V4 - it contains the credentials
func (h *V4Handler) handleGetDeps(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32, data []byte) error {
	ctx := context.Background()

	// V4 getdeps data format: UIN(4) + PWD_LEN(2) + PASSWORD
	if len(data) < 6 {
		h.logger.Debug("V4 getdeps packet too short", "len", len(data))
		return nil
	}

	offset := 0

	// Read UIN (4 bytes)
	dataUIN := binary.LittleEndian.Uint32(data[offset : offset+4])
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

	h.logger.Info("V4 getdeps (login with credentials)",
		"uin", dataUIN,
		"password_len", len(password),
	)

	// Validate credentials
	valid, err := h.service.ValidateCredentials(ctx, dataUIN, password)
	if err != nil || !valid {
		h.logger.Info("V4 login failed - invalid credentials", "uin", dataUIN)
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	// Send ACK for the getdeps packet
	h.sendAck(addr, seq1, seq2, uin)

	// Create session
	newSession, err := h.sessions.CreateSession(uin, addr, wire.ICQLegacyVersionV4)
	if err != nil {
		h.logger.Error("failed to create V4 session", "err", err, "uin", uin)
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	newSession.Password = password

	// GETDEPS (0x03F2) is a "pseudo-login" - it validates credentials but only returns
	// the departments list, NOT a full login reply.
	//
	// From iserverd v3_process_getdeps():
	// 1. Validate credentials
	// 2. Send ACK (already done above)
	// 3. Send depts list (0x0032) - this is the ONLY response packet
	if err := h.sendDeptsListWithCheckcode(newSession, seq2); err != nil {
		h.logger.Error("failed to send depts list", "err", err, "uin", uin)
		return err
	}

	h.logger.Info("V4 login successful",
		"uin", uin,
		"session_id", newSession.SessionID,
	)

	return nil
}

// handleLogin processes login packet (0x03E8)
func (h *V4Handler) handleLogin(session *LegacySession, addr *net.UDPAddr, seq1, seq2 uint16, uin uint32, data []byte) error {
	ctx := context.Background()

	// First send ACK
	h.sendAck(addr, seq1, seq2, uin)

	// V4 login data format (from matt-v4.txt):
	// TIMESTAMP(4) + TCP_PORT(4) + PWD_LEN(2) + PASSWORD + VERSION(4) + IP(4) + FLAG(1) + STATUS(4) + ...
	if len(data) < 10 {
		h.logger.Debug("V4 login packet too short", "len", len(data))
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	offset := 0

	// Skip timestamp (4 bytes)
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

	h.logger.Info("V4 login attempt",
		"uin", uin,
		"port", port,
		"password_len", len(password),
	)

	// Validate credentials
	valid, err := h.service.ValidateCredentials(ctx, uin, password)
	if err != nil || !valid {
		h.logger.Info("V4 login failed - invalid credentials", "uin", uin)
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	// Create session
	newSession, err := h.sessions.CreateSession(uin, addr, wire.ICQLegacyVersionV4)
	if err != nil {
		h.logger.Error("failed to create V4 session", "err", err, "uin", uin)
		return h.sendBadPassword(addr, seq1, seq2, uin)
	}

	newSession.Password = password

	// Send login reply (0x5A)
	if err := h.sendLoginReply(newSession, seq2); err != nil {
		return err
	}

	h.logger.Info("V4 login successful",
		"uin", uin,
		"session_id", newSession.SessionID,
	)

	return nil
}

// handlePing processes keep-alive packets
func (h *V4Handler) handlePing(session *LegacySession, addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	h.logger.Debug("V4 keep-alive received",
		"uin", uin,
		"seq1", seq1,
		"seq2", seq2,
		"addr", addr.String(),
		"session_found", session != nil,
	)

	if session == nil {
		// Try to find session by UIN instead of address
		session = h.sessions.GetSession(uin)
		if session != nil {
			h.logger.Debug("V4 session found by UIN, updating address",
				"uin", uin,
				"old_addr", session.Addr.String(),
				"new_addr", addr.String(),
			)
			// Update session address
			h.sessions.UpdateSessionAddr(uin, addr)
		} else {
			h.logger.Debug("V4 session not found by UIN either", "uin", uin)
			return h.sendNotConnected(addr, seq2, uin)
		}
	}

	session.UpdateActivity()
	return h.sendAck(addr, seq1, seq2, uin)
}

// handleLogoff processes logout
func (h *V4Handler) handleLogoff(session *LegacySession, seq1, seq2 uint16, uin uint32) error {
	if session == nil {
		return nil
	}
	h.logger.Info("V4 logout", "uin", uin)
	h.sessions.RemoveSession(uin)
	return nil
}

// handleContactList processes contact list
func (h *V4Handler) handleContactList(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse contact list - format: TIMESTAMP(4) + COUNT(1) + UIN(4)*COUNT
	if len(data) < 5 {
		return h.sendContactListDone(session, seq2)
	}

	offset := 4 // Skip timestamp
	count := int(data[offset])
	offset++

	contacts := make([]uint32, 0, count)
	for i := 0; i < count && offset+4 <= len(data); i++ {
		contactUIN := binary.LittleEndian.Uint32(data[offset : offset+4])
		contacts = append(contacts, contactUIN)
		offset += 4
	}

	h.logger.Debug("V4 contact list",
		"uin", uin,
		"count", len(contacts),
	)

	session.SetContactList(contacts)

	// Send online status for each contact that is online
	onlineContacts := h.sessions.GetOnlineContacts(session)
	for _, contact := range onlineContacts {
		h.sendUserOnline(session, contact.UIN, contact.GetStatus())
	}

	return h.sendContactListDone(session, seq2)
}

// handleSetStatus processes status change
func (h *V4Handler) handleSetStatus(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
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

	h.logger.Debug("V4 status change",
		"uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
	)

	return nil
}

// handleMessage processes through-server messages (0x010E, 0x0456)
// Format: TIMESTAMP(4) + TO_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (h *V4Handler) handleMessage(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse message - format: TIMESTAMP(4) + TO_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
	if len(data) < 12 {
		h.logger.Debug("V4 message too short", "from", uin, "len", len(data))
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

	h.logger.Debug("V4 message received",
		"from", uin,
		"to", toUIN,
		"type", fmt.Sprintf("0x%04X", msgType),
		"msg_len", msgLen,
	)

	// Forward message to target user if online
	targetSession := h.sessions.GetSession(toUIN)
	if targetSession != nil {
		h.sendOnlineMessage(targetSession, uin, msgType, message, seq2)
	} else {
		// TODO: Store as offline message
		h.logger.Debug("V4 target user offline, message not delivered",
			"from", uin,
			"to", toUIN,
		)
	}

	return nil
}

// handleUserAdd processes user add to contact list (0x053C)
// Sends "you were added" notification to target user
func (h *V4Handler) handleUserAdd(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse - format: TIMESTAMP(4) + TARGET_UIN(4)
	if len(data) < 8 {
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[4:8])

	h.logger.Debug("V4 user add",
		"from", uin,
		"target", targetUIN,
	)

	contacts := session.GetContactList()
	contacts = append(contacts, targetUIN)
	session.SetContactList(contacts)

	targetSession := h.sessions.GetSession(targetUIN)
	if targetSession != nil {
		h.sendUserOnline(session, targetUIN, targetSession.GetStatus())

		// Send "you were added" notification to target user
		// Message format: nick#FE#first#FE#last#FE#email#FE#auth
		youWereAddedMsg := fmt.Sprintf("%d\xFE\xFE\xFE\xFE0", uin)
		h.sendOnlineMessage(targetSession, uin, wire.ICQLegacyMsgAdded, youWereAddedMsg, 0)

		h.logger.Debug("V4 sent 'you were added' notification",
			"from", uin,
			"to", targetUIN,
		)
	}

	return nil
}

// handleGetInfo processes user info request
func (h *V4Handler) handleGetInfo(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse - format: TIMESTAMP(4) + TARGET_UIN(4)
	if len(data) < 8 {
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[4:8])

	h.logger.Debug("V4 get info request",
		"from", uin,
		"target", targetUIN,
	)

	// Send basic info
	h.sendBasicInfo(session, seq2, targetUIN)

	return nil
}

// handleInfoReq processes old-style user info request (0x0460)
// Format: TARGET_UIN(4) - no timestamp prefix
// Response: 0x0118 (INFO_REPLY)
func (h *V4Handler) handleInfoReq(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse - format: TARGET_UIN(4) only
	if len(data) < 4 {
		h.logger.Debug("V4 info request too short", "len", len(data))
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[0:4])

	h.logger.Debug("V4 info request (0x0460)",
		"from", uin,
		"target", targetUIN,
	)

	// Send basic info response (0x0118 - ICQLegacySrvInfoReply)
	return h.sendBasicInfoResponse(session, seq2, targetUIN)
}

// handleExtInfoReq processes extended info request (0x046A)
// Format: TARGET_UIN(4) - no timestamp prefix
// Response: 0x0122 (EXT_INFO_REPLY) - NOT 0x0118!
func (h *V4Handler) handleExtInfoReq(session *LegacySession, seq1, seq2 uint16, uin uint32, data []byte) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	// Parse - format: TARGET_UIN(4) only
	if len(data) < 4 {
		h.logger.Debug("V4 ext info request too short", "len", len(data))
		return nil
	}

	targetUIN := binary.LittleEndian.Uint32(data[0:4])

	h.logger.Debug("V4 ext info request (0x046A)",
		"from", uin,
		"target", targetUIN,
	)

	// Send extended info response (0x0122 - ICQLegacySrvExtInfoReply)
	return h.sendExtInfoResponse(session, seq2, targetUIN)
}

// handleOfflineMsgReq processes offline message request
func (h *V4Handler) handleOfflineMsgReq(session *LegacySession, seq1, seq2 uint16, uin uint32) error {
	if session == nil {
		return nil
	}

	h.sendAck(session.Addr, seq1, seq2, uin)

	h.logger.Debug("V4 offline message request", "uin", uin)

	return h.sendOfflineMsgDone(session, seq2)
}

// V4 packet sending helpers
// Server sends V3 format packets to V4 clients (confirmed in documentation)
// V3 packets need a checkcode at the end

// calculateV4Checkcode calculates the checkcode for server packets to V4 clients
// Based on reverse engineering of ICQ 98a client (encrypt_v4_packet and validate_v4_checkcode)
//
// The client validates checkcode as follows:
//   checkA = (byte[8] << 24) | (byte[4] << 16) | (byte[2] << 8) | byte[6]
//   result = checkA ^ checkcode
//   valid if: (result >> 16) & 0xFF == ~packet[result >> 24]
//         and: result & 0xFF == ~table[(result >> 8) & 0xFF]
//
// So we construct checkcode such that after XOR with checkA, the result contains:
//   byte 3 (bits 24-31): packetOfs - offset into packet
//   byte 2 (bits 16-23): ~packet[packetOfs] - inverted byte at that offset
//   byte 1 (bits 8-15):  tableOfs - offset into table
//   byte 0 (bits 0-7):   ~table[tableOfs] - inverted byte at that table offset
func (h *V4Handler) calculateV4Checkcode(packet []byte) uint32 {
	if len(packet) < 12 {
		return 0
	}

	// checkA: pack bytes 8, 4, 2, 6 from packet (MSB to LSB)
	checkA := uint32(packet[8])<<24 | uint32(packet[4])<<16 | uint32(packet[2])<<8 | uint32(packet[6])

	// Choose offsets (we use fixed values, but could be random)
	// Avoid offset 0x10-0x13 (checkcode position) - use offset 4 (seq1 low byte)
	packetOfs := byte(4)
	tableOfs := byte(0)

	// Get values and INVERT them (this is what the client expects)
	packetVal := ^packet[packetOfs]           // inverted
	tableVal := ^wire.V4Table[tableOfs]       // inverted

	// Build checkB with inverted values
	checkB := uint32(packetOfs)<<24 | uint32(packetVal)<<16 | uint32(tableOfs)<<8 | uint32(tableVal)

	// checkcode = checkA ^ checkB
	result := checkA ^ checkB

	h.logger.Debug("V4 checkcode calculation",
		"byte8", fmt.Sprintf("0x%02X", packet[8]),
		"byte4", fmt.Sprintf("0x%02X", packet[4]),
		"byte2", fmt.Sprintf("0x%02X", packet[2]),
		"byte6", fmt.Sprintf("0x%02X", packet[6]),
		"checkA", fmt.Sprintf("0x%08X", checkA),
		"packetOfs", packetOfs,
		"packetVal_inverted", fmt.Sprintf("0x%02X", packetVal),
		"tableOfs", tableOfs,
		"tableVal_inverted", fmt.Sprintf("0x%02X", tableVal),
		"checkB", fmt.Sprintf("0x%08X", checkB),
		"checkcode", fmt.Sprintf("0x%08X", result),
	)

	return result
}

// sendAck sends ACK packet in V3 format with checkcode
func (h *V4Handler) sendAck(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvAck)
	binary.LittleEndian.PutUint16(pkt[4:6], seq1)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	h.logger.Debug("sending V4 ACK",
		"to", addr.String(),
		"seq1", seq1,
		"seq2", seq2,
		"uin", uin,
		"checkcode", fmt.Sprintf("0x%08X", checkcode),
		"hex", fmt.Sprintf("%X", pkt),
	)

	return h.sender.SendPacket(addr, pkt)
}

// sendBadPassword sends wrong password response
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + ZERO(4)
func (h *V4Handler) sendBadPassword(addr *net.UDPAddr, seq1, seq2 uint16, uin uint32) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvWrongPasswd)
	binary.LittleEndian.PutUint16(pkt[4:6], seq1)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // Zero field

	return h.sender.SendPacket(addr, pkt)
}

// sendNotConnected sends not connected error
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + ZERO(4)
func (h *V4Handler) sendNotConnected(addr *net.UDPAddr, seq2 uint16, uin uint32) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvNotConnected)
	binary.LittleEndian.PutUint16(pkt[4:6], 0)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // Zero field

	return h.sender.SendPacket(addr, pkt)
}

// sendLoginReply sends login success (HELLO packet)
// V3 server packet format (from server.html):
// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA...
// V3 packets need a checkcode at offset 12 for the client to accept them
// Server uses its own seq1 counter, seq2 references the client's login packet
func (h *V4Handler) sendLoginReply(session *LegacySession, seq2 uint16) error {
	// Get client IP as 4 bytes in network byte order (big-endian)
	// Example from docs: c0 a8 0a 01 = 192.168.10.1
	var ipBytes [4]byte
	if session.Addr != nil && session.Addr.IP != nil {
		ip := session.Addr.IP.To4()
		if ip != nil {
			copy(ipBytes[:], ip)
		}
	}

	// LOGIN_REPLY packet format based on ICQ98a client reverse engineering:
	// Header: 16 bytes (VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4))
	// Data: IP(4) + 10 WORDs(20) = 24 bytes
	// Total: 40 bytes

	pkt := make([]byte, 40)
	offset := 0

	// V3 Header (16 bytes)
	// Server uses its own seq1, but keeps client's seq2 as reference
	serverSeq := session.NextServerSeqNum()

	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3) // 03 00
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvHello) // 5a 00
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], serverSeq) // server's seq1
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // seq2 of login packet
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN) // UIN
	offset += 4

	// Calculate and add checkcode (V3 packets need this for client to accept)
	// Note: The server.html example shows 00 00 00 00 at this position.
	// Some implementations may not verify the checkcode, so we calculate it properly.
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// Data section for LOGIN_REPLY (0x005A):
	// Based on reverse engineering ICQ98a client handle_login_reply_005A:
	// The client reads: IP(4) + 6 WORDs (stored) + 4 WORDs (discarded) + conditional data
	// Total: 4 + 20 = 24 bytes of data after header
	//
	// IP is in network byte order (big-endian): c0 a8 0a 01 = 192.168.10.1
	pkt[offset] = ipBytes[0]
	pkt[offset+1] = ipBytes[1]
	pkt[offset+2] = ipBytes[2]
	pkt[offset+3] = ipBytes[3]
	offset += 4

	// 6 WORDs that get stored in globals:
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0000) // → DAT_004df54c
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0000) // → DAT_004df438
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0019) // → DAT_004df7a8 (keep-alive interval suggestion = 25)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0002) // → DAT_004df550
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0001) // → DAT_004d4178
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x00FA) // → DAT_004df820 (250 = timeout?)
	offset += 2

	// 4 WORDs that are discarded:
	binary.LittleEndian.PutUint16(pkt[offset:], 0x002D) // discarded
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0005) // discarded
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x000A) // discarded
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0005) // discarded
	offset += 2

	h.logger.Debug("sending V4 login reply",
		"uin", session.UIN,
		"client_ip", fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]),
		"packet_len", offset,
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendContactListDone sends contact list processed response
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4)
// seq2 should be the seq2 of the client's contact list packet, or 0 if unsolicited
func (h *V4Handler) sendContactListDone(session *LegacySession, clientSeq2 uint16) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserListDone)
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], clientSeq2) // seq2 of contact list packet, or 0 if unsolicited
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	h.logger.Debug("sending V4 contact list done",
		"uin", session.UIN,
		"seq2", clientSeq2,
		"hex", fmt.Sprintf("%X", pkt),
	)

	return h.sender.SendToSession(session, pkt)
}

// sendUserOnline sends user online notification
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// From server.html: User online packet (command 0x006e)
func (h *V4Handler) sendUserOnline(session *LegacySession, uin uint32, status uint32) error {
	pkt := make([]byte, 24)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserOnline)
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], 0)
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	// User info
	binary.LittleEndian.PutUint32(pkt[16:20], uin)
	binary.LittleEndian.PutUint32(pkt[20:24], status)

	return h.sender.SendToSession(session, pkt)
}

// sendUserOnlineNotification sends a full user online notification for the session user
// This is the detailed USER_ONLINE packet from server.html with IP, port, status etc.
func (h *V4Handler) sendUserOnlineNotification(session *LegacySession) error {
	// Get client IP
	var ipBytes [4]byte
	if session.Addr != nil && session.Addr.IP != nil {
		ip := session.Addr.IP.To4()
		if ip != nil {
			copy(ipBytes[:], ip)
		}
	}

	// From server.html USER_ONLINE (0x006E):
	// Header (16 bytes) + UIN(4) + IP(4) + PORT(4) + REAL_IP(4) + GAP(1) + STATUS(4) + UNKNOWN(4)
	pkt := make([]byte, 41)
	offset := 0

	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserOnline)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2 = 0 for notifications
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// Event user UIN (the user who came online - themselves)
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4

	// User IP (network byte order)
	pkt[offset] = ipBytes[0]
	pkt[offset+1] = ipBytes[1]
	pkt[offset+2] = ipBytes[2]
	pkt[offset+3] = ipBytes[3]
	offset += 4

	// User port
	binary.LittleEndian.PutUint32(pkt[offset:], 0x00000000)
	offset += 4

	// User real IP (same as IP)
	pkt[offset] = ipBytes[0]
	pkt[offset+1] = ipBytes[1]
	pkt[offset+2] = ipBytes[2]
	pkt[offset+3] = ipBytes[3]
	offset += 4

	// Gap byte
	pkt[offset] = 0x04
	offset++

	// User status (online)
	binary.LittleEndian.PutUint32(pkt[offset:], wire.ICQLegacyStatusOnline)
	offset += 4

	// Unknown field
	binary.LittleEndian.PutUint32(pkt[offset:], 0x00000002)
	offset += 4

	h.logger.Debug("sending V4 user online notification",
		"uin", session.UIN,
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendDeptsList sends the departments list
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + ZERO(4) + DATA
func (h *V4Handler) sendDeptsList(addr *net.UDPAddr, seq2 uint16, uin uint32) error {
	pkt := make([]byte, 28)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserDepsList)
	binary.LittleEndian.PutUint16(pkt[4:6], 0)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // Zero field

	// Departments data
	binary.LittleEndian.PutUint32(pkt[16:20], 1)
	binary.LittleEndian.PutUint32(pkt[20:24], 0)
	binary.LittleEndian.PutUint16(pkt[24:26], 0x0002)
	binary.LittleEndian.PutUint16(pkt[26:28], 0x002a)

	return h.sender.SendPacket(addr, pkt)
}

// sendDeptsListWithCheckcode sends the departments list with proper checkcode for V4 clients
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// From iserverd v3_send_depslist() - this completes the login sequence for V4 clients
func (h *V4Handler) sendDeptsListWithCheckcode(session *LegacySession, seq2 uint16) error {
	// Packet: header(16) + DEPLIST_VERSION(4) + COUNT(4) + UNKNOWN(4) = 28 bytes
	pkt := make([]byte, 28)
	offset := 0

	// V3 Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserDepsList) // 0x0032
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum()) // server seq1
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // client's seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// Departments data (simplified - empty list)
	// DEPLIST_VERSION(4) + COUNT(4) + UNKNOWN(4)
	binary.LittleEndian.PutUint32(pkt[offset:], 1) // version
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // count (empty list)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0x002A0002) // unknown fields from iserverd
	offset += 4

	h.logger.Debug("sending V4 depts list (0x0032)",
		"uin", session.UIN,
		"seq2", seq2,
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendDeptsListUnsolicited sends the departments list as an unsolicited notification (seq1=0)
// This is used during direct login (0x03E8) to set the client's internal flag before
// sending the login reply. Using seq1=0 ensures the login reply can still get seq1=1.
//
// sendRegisterInfo sends registration info (admin notes) to the client
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// From iserverd v3_send_registration_info(): sends 0x037A with admin notes
func (h *V4Handler) sendRegisterInfo(addr *net.UDPAddr, seq2 uint16, uin uint32) error {
	// Admin notes message - tells the user about registration
	adminNotes := "Welcome to Open OSCAR Server!\nRegistration is enabled.\x00"

	// Build packet
	// Header (16 bytes) + NOTES_LEN(2) + NOTES + REG_ENABLED(1) + UNKNOWN(4)
	pktSize := 16 + 2 + len(adminNotes) + 1 + 4
	pkt := make([]byte, pktSize)
	offset := 0

	// V3 Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvRegisterInfo)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq1 = 0 for server-initiated
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// Admin notes length and string
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(adminNotes)))
	offset += 2
	copy(pkt[offset:], adminNotes)
	offset += len(adminNotes)

	// Registration enabled flag (1 = enabled)
	pkt[offset] = 0x01
	offset++

	// Unknown fields (from iserverd: 0x0002, 0x002A)
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0002)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x002A)
	offset += 2

	h.logger.Debug("sending V4 registration info",
		"uin", uin,
		"seq2", seq2,
		"admin_notes_len", len(adminNotes),
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendPacket(addr, pkt[:offset])
}

// sendRegisterInfoForLogin sends registration info (0x037A) as a response to Login (0x03E8)
// EXPERIMENT: Testing if this triggers the client to send GetDeps, enabling the normal login flow
func (h *V4Handler) sendRegisterInfoForLogin(session *LegacySession, seq2 uint16) error {
	// Admin notes message
	adminNotes := "Login accepted.\x00"

	// Build packet
	// Header (16 bytes) + NOTES_LEN(2) + NOTES + REG_ENABLED(1) + UNKNOWN(4)
	pktSize := 16 + 2 + len(adminNotes) + 1 + 4
	pkt := make([]byte, pktSize)
	offset := 0

	// V3 Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvRegisterInfo) // 0x037A
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum()) // server seq1
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2) // client's seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// Admin notes length and string
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(adminNotes)))
	offset += 2
	copy(pkt[offset:], adminNotes)
	offset += len(adminNotes)

	// Registration enabled flag (0 = disabled, since this is login not registration)
	pkt[offset] = 0x00
	offset++

	// Unknown fields (from iserverd: 0x0002, 0x002A)
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0002)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x002A)
	offset += 2

	h.logger.Info("EXPERIMENT: sending RegInfo (0x037A) instead of LoginReply for login",
		"uin", session.UIN,
		"seq2", seq2,
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// From iserverd v3_send_registration_ok(): sends 0x0384 with message containing UIN and password
func (h *V4Handler) sendRegistrationOK(addr *net.UDPAddr, seq2 uint16, newUIN uint32, password string) error {
	// Build the registration success message
	// This message tells the user their new UIN and password
	message := fmt.Sprintf("Registration successful!\n\nYour new UIN: %d\nYour password: %s\n\nPlease save this information!\x00", newUIN, password)

	// Build packet
	// Header (16 bytes) + MSG_LEN(2) + MESSAGE
	pktSize := 16 + 2 + len(message)
	pkt := make([]byte, pktSize)
	offset := 0

	// V3 Header - note: UIN field contains the NEW UIN
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvRegistrationOK)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq1 = 0 for server-initiated
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], newUIN) // NEW UIN goes here!
	offset += 4

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// Message length and string
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(message)))
	offset += 2
	copy(pkt[offset:], message)
	offset += len(message)

	h.logger.Info("sending V4 registration OK",
		"newUIN", newUIN,
		"seq2", seq2,
		"message_len", len(message),
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendPacket(addr, pkt[:offset])
}

// sendBasicInfo sends basic user info response
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// Data format: TARGET_UIN(4) + NICK_LEN(2) + NICK + FNAME_LEN(2) + FNAME + LNAME_LEN(2) + LNAME + EMAIL_LEN(2) + EMAIL + AUTH(1)
func (h *V4Handler) sendBasicInfo(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	nick := fmt.Sprintf("%d", targetUIN)

	// header(16) + TARGET_UIN(4) + nick(2+len+1) + fname(2+1) + lname(2+1) + email(2+1) + auth(1)
	pktSize := 16 + 4 + 2 + len(nick) + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 1
	pkt := make([]byte, pktSize)
	offset := 0

	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvInfoReply) // 0x0118
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4

	// Calculate checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// TARGET_UIN - the UIN of the user whose info this is
	binary.LittleEndian.PutUint32(pkt[offset:], targetUIN)
	offset += 4

	// Nick
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(nick)+1))
	offset += 2
	copy(pkt[offset:], nick)
	offset += len(nick)
	pkt[offset] = 0
	offset++

	// First name (empty)
	binary.LittleEndian.PutUint16(pkt[offset:], 1)
	offset += 2
	pkt[offset] = 0
	offset++

	// Last name (empty)
	binary.LittleEndian.PutUint16(pkt[offset:], 1)
	offset += 2
	pkt[offset] = 0
	offset++

	// Email (empty)
	binary.LittleEndian.PutUint16(pkt[offset:], 1)
	offset += 2
	pkt[offset] = 0
	offset++

	// Auth flag
	pkt[offset] = 0
	offset++

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendBasicInfoResponse sends basic user info response (0x0118) with checkcode
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// Data format (verified via Ghidra RE of ICQ98a client handler FUN_00429b22):
//   TARGET_UIN(4) + NICK_LEN(2) + NICK + FNAME_LEN(2) + FNAME + LNAME_LEN(2) + LNAME + EMAIL_LEN(2) + EMAIL + STATUS(1) + AUTH(1)
// NOTE: Client expects 0x0118 (ICQLegacySrvInfoReply), NOT 0x02E4 - verified via Ghidra RE
// NOTE: There are TWO bytes at the end - STATUS and AUTH - verified via Ghidra RE of FUN_00429b22
func (h *V4Handler) sendBasicInfoResponse(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	ctx := context.Background()

	// Try to get actual user info from the service
	nick := fmt.Sprintf("%d", targetUIN)
	firstName := ""
	lastName := ""
	email := ""
	statusByte := byte(0) // Status byte (stored at offset 0xd1 in client user object)
	authMode := byte(0)   // Auth mode (stored at offset 0x911 in client user object)

	info, err := h.service.GetUserInfo(ctx, targetUIN)
	if err == nil && info != nil {
		if info.Nickname != "" {
			nick = info.Nickname
		}
		firstName = info.FirstName
		lastName = info.LastName
		email = info.Email
	}

	// Calculate packet size: header(16) + TARGET_UIN(4) + nick(2+len+1) + fname(2+len+1) + lname(2+len+1) + email(2+len+1) + status(1) + auth(1)
	pktSize := 16 + 4 + (2 + len(nick) + 1) + (2 + len(firstName) + 1) + (2 + len(lastName) + 1) + (2 + len(email) + 1) + 1 + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// V3 Header with checkcode
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvInfoReply) // 0x0118
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4

	// Calculate and add checkcode - client validates this!
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// TARGET_UIN - the UIN of the user whose info this is (required by client!)
	binary.LittleEndian.PutUint32(pkt[offset:], targetUIN)
	offset += 4

	// NickName (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(nick)+1))
	offset += 2
	copy(pkt[offset:], nick)
	offset += len(nick)
	pkt[offset] = 0
	offset++

	// First name (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(firstName)+1))
	offset += 2
	copy(pkt[offset:], firstName)
	offset += len(firstName)
	pkt[offset] = 0
	offset++

	// Last name (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(lastName)+1))
	offset += 2
	copy(pkt[offset:], lastName)
	offset += len(lastName)
	pkt[offset] = 0
	offset++

	// Email (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(email)+1))
	offset += 2
	copy(pkt[offset:], email)
	offset += len(email)
	pkt[offset] = 0
	offset++

	// Status byte (read first by client, stored at offset 0xd1)
	pkt[offset] = statusByte
	offset++

	// Auth mode (read second by client, stored at offset 0x911)
	pkt[offset] = authMode
	offset++

	h.logger.Debug("sending V4 basic info response",
		"to", session.UIN,
		"target", targetUIN,
		"nick", nick,
		"seq2", seq2,
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendExtInfoResponse sends extended user info response (0x0122) with checkcode
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// Data format (verified via Ghidra RE of ICQ98a client handler FUN_00429c84):
//   TARGET_UIN(4) + CITY_LEN(2) + CITY + COUNTRY(2) + TIMEZONE(1) +
//   STATE_LEN(2) + STATE + AGE(2) + GENDER(1) +
//   PHONE_LEN(2) + PHONE + HOMEPAGE_LEN(2) + HOMEPAGE + ABOUT_LEN(2) + ABOUT + UNKNOWN(4)
func (h *V4Handler) sendExtInfoResponse(session *LegacySession, seq2 uint16, targetUIN uint32) error {
	ctx := context.Background()

	// Default values
	city := ""
	country := uint16(0)
	timezone := byte(0)
	state := ""
	age := uint16(0)
	gender := byte(0)
	phone := ""
	homepage := ""
	about := ""

	// Try to get full user info from the service
	user, err := h.service.GetFullUserInfo(ctx, targetUIN)
	if err == nil && user != nil {
		city = user.ICQBasicInfo.City
		country = user.ICQBasicInfo.CountryCode
		timezone = user.ICQBasicInfo.GMTOffset
		state = user.ICQBasicInfo.State
		phone = user.ICQBasicInfo.Phone
		homepage = user.ICQMoreInfo.HomePageAddr
		about = user.ICQNotes.Notes

		// Calculate age from birth year
		if user.ICQMoreInfo.BirthYear > 0 {
			currentYear := uint16(2026) // Current year
			age = currentYear - user.ICQMoreInfo.BirthYear
		}

		// Gender (ICQ uses 1=female, 2=male, 0=unspecified)
		gender = byte(user.ICQMoreInfo.Gender)
	}

	// Calculate packet size: header(16) + TARGET_UIN(4) + city(2+len+1) + country(2) + timezone(1) +
	// state(2+len+1) + age(2) + gender(1) + phone(2+len+1) + homepage(2+len+1) + about(2+len+1) + unknown(4)
	pktSize := 16 + 4 + (2 + len(city) + 1) + 2 + 1 + (2 + len(state) + 1) + 2 + 1 +
		(2 + len(phone) + 1) + (2 + len(homepage) + 1) + (2 + len(about) + 1) + 4
	pkt := make([]byte, pktSize)
	offset := 0

	// V3 Header with checkcode
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvExtInfoReply) // 0x0122
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], session.NextServerSeqNum())
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], session.UIN)
	offset += 4

	// Calculate and add checkcode - client validates this!
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// TARGET_UIN
	binary.LittleEndian.PutUint32(pkt[offset:], targetUIN)
	offset += 4

	// City (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(city)+1))
	offset += 2
	copy(pkt[offset:], city)
	offset += len(city)
	pkt[offset] = 0
	offset++

	// Country code
	binary.LittleEndian.PutUint16(pkt[offset:], country)
	offset += 2

	// Timezone
	pkt[offset] = timezone
	offset++

	// State (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(state)+1))
	offset += 2
	copy(pkt[offset:], state)
	offset += len(state)
	pkt[offset] = 0
	offset++

	// Age
	binary.LittleEndian.PutUint16(pkt[offset:], age)
	offset += 2

	// Gender
	pkt[offset] = gender
	offset++

	// Phone (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(phone)+1))
	offset += 2
	copy(pkt[offset:], phone)
	offset += len(phone)
	pkt[offset] = 0
	offset++

	// Homepage (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(homepage)+1))
	offset += 2
	copy(pkt[offset:], homepage)
	offset += len(homepage)
	pkt[offset] = 0
	offset++

	// About (length + string + null)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(about)+1))
	offset += 2
	copy(pkt[offset:], about)
	offset += len(about)
	pkt[offset] = 0
	offset++

	// Unknown DWORD at end
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	h.logger.Debug("sending V4 ext info response",
		"to", session.UIN,
		"target", targetUIN,
		"seq2", seq2,
		"hex", fmt.Sprintf("%X", pkt[:offset]),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}

// sendOfflineMsgDone sends end of offline messages
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4)
// seq2 should be the seq2 of the client's offline msg request, or 0 if unsolicited
func (h *V4Handler) sendOfflineMsgDone(session *LegacySession, clientSeq2 uint16) error {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvSysMsgDone)
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], clientSeq2) // seq2 of offline msg request, or 0 if unsolicited
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	h.logger.Debug("sending V4 offline msg done",
		"uin", session.UIN,
		"seq2", clientSeq2,
		"hex", fmt.Sprintf("%X", pkt),
	)

	return h.sender.SendToSession(session, pkt)
}

// sendUserStatus sends user status change notification
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// From server.html: User changed his status (command 0x01a4)
func (h *V4Handler) sendUserStatus(session *LegacySession, uin uint32, status uint32) error {
	pkt := make([]byte, 24)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserStatus)
	binary.LittleEndian.PutUint16(pkt[4:6], session.NextServerSeqNum())
	binary.LittleEndian.PutUint16(pkt[6:8], 0)
	binary.LittleEndian.PutUint32(pkt[8:12], session.UIN)

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	// User status data
	binary.LittleEndian.PutUint32(pkt[16:20], uin)
	binary.LittleEndian.PutUint32(pkt[20:24], status)

	h.logger.Debug("sending V4 user status",
		"uin", session.UIN,
		"target_uin", uin,
		"status", fmt.Sprintf("0x%08X", status),
		"hex", fmt.Sprintf("%X", pkt),
	)

	return h.sender.SendToSession(session, pkt)
}

// sendOnlineMessage sends an online system message to a user
// V3 server packet format with checkcode
// Format: header(16) + FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (h *V4Handler) sendOnlineMessage(session *LegacySession, fromUIN uint32, msgType uint16, message string, seq2 uint16) error {
	// Calculate packet size
	msgBytes := []byte(message)
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

	// Calculate and add checkcode
	checkcode := h.calculateV4Checkcode(pkt[:12])
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
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

	h.logger.Debug("V4 sending online message",
		"to", session.UIN,
		"from", fromUIN,
		"type", fmt.Sprintf("0x%04X", msgType),
		"msg_len", len(msgBytes),
	)

	return h.sender.SendToSession(session, pkt[:offset])
}
