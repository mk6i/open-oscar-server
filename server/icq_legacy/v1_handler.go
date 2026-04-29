package icq_legacy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
)

// V1Handler handles ICQ V1 protocol packets.
// V1 uses the same wire format as V2 for most commands, so this embeds
// V2Handler. The key difference is that V1's CMD_GET_DEPS (0x03F2) uses
// the standard V2 10-byte header (VERSION+CMD+SEQ+UIN), whereas V2 clients
// that send 0x03F2 use a V3-style 12-byte header. V1Handler overrides
// Handle to intercept 0x03F2 and parse it with the correct layout.
type V1Handler struct {
	*V2Handler
}

// NewV1Handler creates a new V1 protocol handler.
func NewV1Handler(
	sessions *LegacySessionManager,
	service LegacyService,
	sender PacketSender,
	logger *slog.Logger,
) *V1Handler {
	v1pb := NewV1PacketBuilder()
	return &V1Handler{
		V2Handler: &V2Handler{
			BaseHandler: BaseHandler{
				sessions: sessions,
				service:  service,
				sender:   sender,
				logger:   logger,
			},
			packetBuilder: v1pb,
		},
	}
}

// Handle processes a V1 protocol packet.
// Intercepts CMD_GET_DEPS (0x03F2) to parse with V1's 10-byte header layout,
// then delegates everything else to V2Handler.
func (h *V1Handler) Handle(session *LegacySession, addr *net.UDPAddr, packet []byte) error {
	// Peek at the command field (bytes 2-4) to check for 0x03F2
	if len(packet) >= 4 {
		cmd := binary.LittleEndian.Uint16(packet[2:4])
		if cmd == ICQLegacyCmdGetDeps {
			return h.handleV1Login(session, addr, packet)
		}
	}

	// Everything else uses the same format as V2
	return h.V2Handler.Handle(session, addr, packet)
}

// handleV1Login processes the V1 login packet (0x03F2).
// V1 clients use 0x03F2 as their actual login command (not a pre-auth step).
// The packet uses the standard 10-byte header: VERSION(2) + CMD(2) + SEQ(2) + UIN(4)
// Data payload: PWD_LEN(2) + PASSWORD(variable, null-terminated) + STATUS(4)
//
// Unlike V2 clients which send 0x03E8 (CMD_LOGIN) directly, and V3+ clients
// which use 0x03F2 as a pre-auth step before 0x03E8, V1 clients use 0x03F2
// as their only login command and expect SRV_HELLO (0x005A) in response.
func (h *V1Handler) handleV1Login(session *LegacySession, addr *net.UDPAddr, packet []byte) error {
	ctx := context.Background()

	// V1 header: VERSION(2) + CMD(2) + SEQ(2) + UIN(4) = 10 bytes
	if len(packet) < 12 { // 10-byte header + at least 2 bytes for pwd_len
		h.logger.Debug("V1 login packet too short", "len", len(packet))
		return nil
	}

	seqNum := binary.LittleEndian.Uint16(packet[4:6])
	uin := binary.LittleEndian.Uint32(packet[6:10])
	data := packet[10:]

	h.logger.Debug("V1 login packet (0x03F2)",
		"addr", addr.String(),
		"seq", seqNum,
		"uin", uin,
		"data_len", len(data),
		"data_hex", fmt.Sprintf("%X", data),
	)

	// Parse password from data: PWD_LEN(2) + PASSWORD
	if len(data) < 2 {
		return nil
	}
	pwdLen := binary.LittleEndian.Uint16(data[0:2])
	offset := 2

	if pwdLen == 0 || pwdLen > 20 || offset+int(pwdLen) > len(data) {
		h.logger.Debug("invalid password in V1 login", "pwd_len", pwdLen)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(seqNum, ICQLegacyVersionV1))
	}

	password := string(data[offset : offset+int(pwdLen)])
	if len(password) > 0 && password[len(password)-1] == 0 {
		password = password[:len(password)-1]
	}
	offset += int(pwdLen)

	// Parse status (4 bytes) if present
	var status uint32
	if offset+4 <= len(data) {
		status = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	h.logger.Info("V1 login attempt",
		"uin", uin,
		"password_len", len(password),
		"status", fmt.Sprintf("0x%08X", status),
	)

	// Authenticate using service layer
	authReq := AuthRequest{
		UIN:      uin,
		Password: password,
		Status:   status,
		Version:  ICQLegacyVersionV1,
	}

	authResult, err := h.service.AuthenticateUser(ctx, authReq)
	if err != nil || !authResult.Success {
		h.logger.Info("V1 login failed - invalid credentials", "uin", uin)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(seqNum, ICQLegacyVersionV1))
	}

	// Create session
	newSession, err := h.sessions.CreateSession(uin, addr, ICQLegacyVersionV1, authResult.oscarSession)
	if err != nil {
		h.logger.Error("failed to create V1 session", "err", err, "uin", uin)
		return h.sender.SendPacket(addr, h.packetBuilder.BuildBadPassword(seqNum, ICQLegacyVersionV1))
	}

	newSession.SetStatus(status)
	newSession.Password = password

	// Send ACK
	ackPkt := h.packetBuilder.BuildAck(seqNum, ICQLegacyVersionV1)
	if err := h.sender.SendToSession(newSession, ackPkt); err != nil {
		return err
	}

	// Send SRV_HELLO (0x005A) login reply — same as V2 gets for CMD_LOGIN
	loginReplyPkt := h.packetBuilder.BuildLoginReply(newSession, seqNum)
	if err := h.sender.SendToSession(newSession, loginReplyPkt); err != nil {
		return err
	}

	h.logger.Info("V1 login successful",
		"uin", uin,
		"session_id", newSession.SessionID,
	)

	// Notify contacts that user is online
	if err := h.service.NotifyStatusChange(ctx, uin, status); err != nil {
		h.logger.Debug("failed to notify status change", "err", err)
	}

	return nil
}

// SetSender sets the packet sender (for circular dependency resolution).
func (h *V1Handler) SetSender(sender PacketSender) {
	h.V2Handler.SetSender(sender)
}

// SetDispatcher sets the message dispatcher for cross-protocol message routing.
func (h *V1Handler) SetDispatcher(dispatcher MessageDispatcher) {
	h.V2Handler.SetDispatcher(dispatcher)
}
