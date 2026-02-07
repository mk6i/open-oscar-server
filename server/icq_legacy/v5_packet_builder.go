package icq_legacy

import (
	"encoding/binary"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/wire"
)

// V5PacketBuilder constructs V5 protocol packets (encrypted).
// This interface separates packet construction from business logic,
// following the OSCAR foodgroup architecture pattern.
//
// V5 packet format (from iserverd source):
// Server packets: VERSION(2) + ZERO(1) + SESSION_ID(4) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA
// Total header: 21 bytes
//
// V5 uses full packet encryption via AddV5ServerCheckcode() which computes
// and inserts the checkcode at offset 0x11 (17).
//
type V5PacketBuilder interface {
	// BuildLoginReply constructs a login success (HELLO) response packet.
	// The packet contains timing parameters and client IP information.
	BuildLoginReply(session *LegacySession, seq1, seq2 uint16) []byte

	// BuildBadPassword constructs a bad password/authentication failure response.
	BuildBadPassword(sessionID uint32, uin uint32, seq2 uint16) []byte

	// BuildAck constructs an acknowledgment packet for the given sequence number.
	BuildAck(session *LegacySession, seq1 uint16) []byte

	// BuildAckWithSeq2 constructs an ACK echoing both seq1 and seq2 from the client.
	BuildAckWithSeq2(session *LegacySession, seq1, seq2 uint16) []byte

	// BuildUserOnline constructs a user online notification packet.
	// Sent to notify a user that one of their contacts has come online.
	BuildUserOnline(session *LegacySession, uin uint32, status uint32) []byte

	// BuildUserOffline constructs a user offline notification packet.
	// Sent to notify a user that one of their contacts has gone offline.
	BuildUserOffline(session *LegacySession, uin uint32) []byte

	// BuildUserStatus constructs a user status change notification packet.
	// Sent when a user changes status while already online.
	BuildUserStatus(session *LegacySession, uin uint32, status uint32) []byte

	// BuildContactListDone constructs a contact list processing complete response.
	BuildContactListDone(session *LegacySession, seq2 uint16) []byte

	// BuildOnlineMessage constructs an online system message packet.
	BuildOnlineMessage(session *LegacySession, fromUIN uint32, msgType uint16, message string) []byte

	// BuildOfflineMessage constructs an offline message packet.
	// Format: FROM_UIN(4) + YEAR(2) + MONTH(1) + DAY(1) + HOUR(1) + MINUTE(1) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
	BuildOfflineMessage(session *LegacySession, msg *foodgroup.LegacyOfflineMessage) []byte

	// BuildOfflineMsgDone constructs an end of offline messages packet.
	BuildOfflineMsgDone(session *LegacySession, seq2 uint16) []byte

	// BuildMetaAck constructs a META_USER acknowledgment packet.
	// seq2 is the client's seq2 from the request, echoed back for correlation.
	// The server's own seq1 (servseq) is obtained from session.NextServerSeqNum().
	BuildMetaAck(session *LegacySession, seq2 uint16, subCommand uint16) []byte

	// BuildMetaUserInfo constructs a META_USER info response packet.
	// seq2 is the client's seq2 from the request, echoed back for correlation.
	BuildMetaUserInfo(session *LegacySession, seq2 uint16, info *foodgroup.UserInfoResult) []byte

	// BuildSearchResult constructs a search result packet.
	// seq2 is the client's seq2 from the request, echoed back for correlation.
	// From iserverd: server uses user.servseq for seq1 and echoes client's seq2.
	BuildSearchResult(session *LegacySession, seq2 uint16, results []foodgroup.UserInfoResult, isLast bool) []byte

	// BuildDepsListReply constructs a pre-auth response packet (V3 format).
	// Historically called "departments list" in iserverd. In V5, this is a deprecated
	// empty V3-format response sent during the pre-auth pseudo-login (0x03F2).
	// From iserverd v5_send_depslist() - sends a V3 packet with magic checksum.
	BuildDepsListReply(uin uint32, seq2 uint16) []byte

	// BuildAckToAddr constructs an ACK packet for sending to an address (before session exists).
	// Used during login flow when session is not yet established.
	BuildAckToAddr(sessionID uint32, uin uint32, seq1, seq2 uint16) []byte

	// BuildFirstLoginReply constructs a first login reply packet.
	// From iserverd v5_process_firstlog() - sent in response to CMD_FIRST_LOGIN.
	BuildFirstLoginReply(sessionID uint32, uin uint32, seq1, seq2 uint16, sessionID2 uint32) []byte

	// EncryptPacket encrypts a V5 packet using the session ID.
	// Note: V5 server packets use AddV5ServerCheckcode() which is called by MarshalV5ServerPacket.
	EncryptPacket(packet []byte, sessionID uint32) []byte
}

// V5PacketBuilderImpl implements the V5PacketBuilder interface.
// It constructs V5 protocol packets following the iserverd packet formats.
type V5PacketBuilderImpl struct {
	// sessionManager is used to look up online user connection info for peer-to-peer
	sessionManager *LegacySessionManager
}

// NewV5PacketBuilder creates a new V5PacketBuilder instance.
func NewV5PacketBuilder(sessionManager *LegacySessionManager) V5PacketBuilder {
	return &V5PacketBuilderImpl{
		sessionManager: sessionManager,
	}
}

// BuildLoginReply constructs a login success (HELLO) response packet.
// From iserverd v5_send_login_reply()
//
// Data format (20 bytes total):
// - 0x008C(2) + 0x0000(2) + PING_TIME(2) + TIMEOUT(2) + 0x000A(2) + RETRIES(2) + CLIENT_IP(4) + SERVER_ID(4)
func (b *V5PacketBuilderImpl) BuildLoginReply(session *LegacySession, seq1, seq2 uint16) []byte {
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

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildBadPassword constructs a bad password response.
func (b *V5PacketBuilderImpl) BuildBadPassword(sessionID uint32, uin uint32, seq2 uint16) []byte {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: sessionID,
		Command:   wire.ICQLegacySrvWrongPasswd,
		SeqNum1:   0,
		SeqNum2:   seq2,
		UIN:       uin,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildAck constructs an ACK packet.
func (b *V5PacketBuilderImpl) BuildAck(session *LegacySession, seq1 uint16) []byte {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seq1,
		SeqNum2:   0,
		UIN:       session.UIN,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildAckWithSeq2 constructs an ACK echoing both seq1 and seq2 from the client.
func (b *V5PacketBuilderImpl) BuildAckWithSeq2(session *LegacySession, seq1, seq2 uint16) []byte {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seq1,
		SeqNum2:   seq2,
		UIN:       session.UIN,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildUserOnline constructs a user online notification packet.
// From iserverd v5_send_user_online()
//
// Verified against licq.5 client (icqd-udp.cpp ICQ_CMDxRCV_USERxONLINE):
// Client reads: UIN(4) + IP(4) + PORT(2) + JUNK_SHORT(2) + REAL_IP(4) +
//               MODE(1) + STATUS(4) + TCP_VERSION(4)
// Total client reads: 25 bytes. Extra bytes after that are ignored.
//
// Our packet format (49 bytes data, iserverd-compatible):
// - UIN(4): UIN of user who is online
// - IP(4): External IP (0 for V3 clients, real IP for V5)
// - TCP_PORT(4): TCP port - client reads low 2 bytes as port, high 2 as junk
// - INT_IP(4): Internal/LAN IP (0 for V3)
// - DC_TYPE(1): Direct connection type (0 for V3)
// - STATUS(2)+ESTAT(2): Combined status - client reads as single uint32
// - TCPVER(4): TCP protocol version
// - DC_COOKIE(4): Direct connection cookie
// - WEB_PORT(4): Web port
// - CLI_FUTURES(4): Client futures/capabilities
// - INFO_UTIME(4): Info update timestamp
// - MORE_UTIME(4): More info update timestamp
// - STAT_UTIME(4): Status update timestamp
func (b *V5PacketBuilderImpl) BuildUserOnline(session *LegacySession, uin uint32, status uint32) []byte {
	data := make([]byte, 49)
	offset := 0

	// UIN of the user who is online
	binary.LittleEndian.PutUint32(data[offset:], uin)
	offset += 4

	// Get the online user's session to retrieve their connection info
	var onlineSession *LegacySession
	if b.sessionManager != nil {
		onlineSession = b.sessionManager.GetSession(uin)
	}

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

	// DC cookie (not implemented)
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

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvUserOnline,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildUserOffline constructs a user offline notification packet.
// From iserverd v5_send_user_offline()
func (b *V5PacketBuilderImpl) BuildUserOffline(session *LegacySession, uin uint32) []byte {
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

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildUserStatus constructs a user status change notification packet.
// From iserverd v5_send_user_status()
func (b *V5PacketBuilderImpl) BuildUserStatus(session *LegacySession, uin uint32, status uint32) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], uin)
	binary.LittleEndian.PutUint16(data[4:6], uint16(status&0xFFFF))
	binary.LittleEndian.PutUint16(data[6:8], uint16(status>>16))

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvUserStatus,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildContactListDone constructs a contact list processed response.
func (b *V5PacketBuilderImpl) BuildContactListDone(session *LegacySession, seq2 uint16) []byte {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvUserListDone,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildOnlineMessage constructs an online system message packet.
// From iserverd v5_send_user_message()
// Format: FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (b *V5PacketBuilderImpl) BuildOnlineMessage(session *LegacySession, fromUIN uint32, msgType uint16, message string) []byte {
	msgBytes := []byte(message)

	dataLen := 4 + 2 + 2 + len(msgBytes) + 1
	data := make([]byte, dataLen)
	offset := 0

	// From UIN
	binary.LittleEndian.PutUint32(data[offset:], fromUIN)
	offset += 4

	// Message type
	binary.LittleEndian.PutUint16(data[offset:], msgType)
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
		Command:   wire.ICQLegacySrvSysMsgOnline,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   0,
		UIN:       session.UIN,
		Data:      data,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildOfflineMessage constructs an offline message packet.
// From iserverd v5_send_offline_message()
// Format: FROM_UIN(4) + YEAR(2) + MONTH(1) + DAY(1) + HOUR(1) + MINUTE(1) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (b *V5PacketBuilderImpl) BuildOfflineMessage(session *LegacySession, msg *foodgroup.LegacyOfflineMessage) []byte {
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

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildOfflineMsgDone constructs an end of offline messages packet.
func (b *V5PacketBuilderImpl) BuildOfflineMsgDone(session *LegacySession, seq2 uint16) []byte {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvSysMsgDone,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildMetaAck constructs a META_USER acknowledgment packet.
// From iserverd v5_send_meta_set_ack()
func (b *V5PacketBuilderImpl) BuildMetaAck(session *LegacySession, seq2 uint16, subCommand uint16) []byte {
	// META ACK data: SUB_COMMAND(2) + RESULT(1)
	data := make([]byte, 3)
	binary.LittleEndian.PutUint16(data[0:2], subCommand)
	data[2] = 0x0A // Success code

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      data,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildMetaUserInfo constructs a META_USER info response packet.
// From iserverd v5_send_meta_user_info()
func (b *V5PacketBuilderImpl) BuildMetaUserInfo(session *LegacySession, seq2 uint16, info *foodgroup.UserInfoResult) []byte {
	if info == nil {
		// Send empty/fail response
		data := make([]byte, 3)
		binary.LittleEndian.PutUint16(data[0:2], wire.ICQLegacySrvMetaUserInfo)
		data[2] = 0x32 // Fail code
		
		pkt := &wire.V5ServerPacket{
			Version:   wire.ICQLegacyVersionV5,
			SessionID: session.SessionID,
			Command:   wire.ICQLegacySrvMetaUser,
			SeqNum1:   session.NextServerSeqNum(),
			SeqNum2:   seq2,
			UIN:       session.UIN,
			Data:      data,
		}
		return wire.MarshalV5ServerPacket(pkt)
	}

	// Build user info data
	// Format: SUB_COMMAND(2) + RESULT(1) + UIN(4) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST +
	//         LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL + AUTH(1) + ZERO(1) + ZERO(1)
	nick := info.Nickname
	first := info.FirstName
	last := info.LastName
	email := info.Email

	dataLen := 3 + 4 + 2 + len(nick) + 1 + 2 + len(first) + 1 + 2 + len(last) + 1 + 2 + len(email) + 1 + 3
	data := make([]byte, dataLen)
	offset := 0

	// Sub-command
	binary.LittleEndian.PutUint16(data[offset:], wire.ICQLegacySrvMetaUserInfo)
	offset += 2

	// Result code (0x0A = success)
	data[offset] = 0x0A
	offset++

	// UIN
	binary.LittleEndian.PutUint32(data[offset:], info.UIN)
	offset += 4

	// Nickname (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(nick)+1))
	offset += 2
	copy(data[offset:], nick)
	offset += len(nick)
	data[offset] = 0
	offset++

	// First name (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(first)+1))
	offset += 2
	copy(data[offset:], first)
	offset += len(first)
	data[offset] = 0
	offset++

	// Last name (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(last)+1))
	offset += 2
	copy(data[offset:], last)
	offset += len(last)
	data[offset] = 0
	offset++

	// Email (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(email)+1))
	offset += 2
	copy(data[offset:], email)
	offset += len(email)
	data[offset] = 0
	offset++

	// Auth required
	data[offset] = info.AuthRequired
	offset++

	// Two trailing zeros
	data[offset] = 0
	offset++
	data[offset] = 0

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      data,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildSearchResult constructs a search result packet.
// From iserverd v5_send_user_found2()
//
// Format matches iserverd exactly:
//   SUB_COMMAND(2) + RESULT(1) + [PACK_LEN(2) + UIN(4) + NICK_LEN(2) + NICK +
//   FIRST_LEN(2) + FIRST + LAST_LEN(2) + LAST + EMAIL_LEN(2) + EMAIL +
//   AUTH(1) + WEBAWARE(1) + 0x00(1)] + [USERS_LEFT(4) if last]
func (b *V5PacketBuilderImpl) BuildSearchResult(session *LegacySession, seq2 uint16, results []foodgroup.UserInfoResult, isLast bool) []byte {
	if len(results) == 0 {
		// Send empty last result with failure code to indicate no results
		// From iserverd: sub_cmd + result(0x32=failure)
		data := make([]byte, 3)
		binary.LittleEndian.PutUint16(data[0:2], wire.ICQLegacySrvMetaUserLastFound)
		data[2] = 0x32 // META_FAILURE - no results found

		pkt := &wire.V5ServerPacket{
			Version:   wire.ICQLegacyVersionV5,
			SessionID: session.SessionID,
			Command:   wire.ICQLegacySrvMetaUser,
			SeqNum1:   session.NextServerSeqNum(),
			SeqNum2:   seq2,
			UIN:       session.UIN,
			Data:      data,
		}
		return wire.MarshalV5ServerPacket(pkt)
	}

	info := results[0]
	nick := info.Nickname
	first := info.FirstName
	last := info.LastName
	email := info.Email

	// Calculate pack length matching iserverd:
	// UIN(4) + 4xLEN_PREFIX(8) + 4xNULL_TERM(4) + AUTH(1) + WEBAWARE(1) + 0x00(1) = 19
	// Plus string content lengths. users_left is OUTSIDE pack_len.
	// iserverd: pack_len = 15 + strlen(nick) + strlen(first) + strlen(last) + strlen(email) + 4
	//   where 15 = UIN(4) + 4xLEN(8) + AUTH(1) + WEBAWARE(1) + PAD(1)
	//   and +4 = 4 null terminators
	packLen := 19 + len(nick) + len(first) + len(last) + len(email)

	// Total data: sub_cmd(2) + result(1) + pack_len(2) + payload(packLen) + [users_left(4) if last]
	dataLen := 3 + 2 + packLen
	if isLast {
		dataLen += 4 // users_left is outside pack_len
	}
	data := make([]byte, dataLen)
	offset := 0

	// Sub-command
	subCmd := wire.ICQLegacySrvMetaUserFound
	if isLast {
		subCmd = wire.ICQLegacySrvMetaUserLastFound
	}
	binary.LittleEndian.PutUint16(data[offset:], subCmd)
	offset += 2

	// Result code (0x0A = META_SUCCESS)
	data[offset] = 0x0A
	offset++

	// Pack length
	binary.LittleEndian.PutUint16(data[offset:], uint16(packLen))
	offset += 2

	// UIN
	binary.LittleEndian.PutUint32(data[offset:], info.UIN)
	offset += 4

	// Nickname (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(nick)+1))
	offset += 2
	copy(data[offset:], nick)
	offset += len(nick)
	data[offset] = 0
	offset++

	// First name (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(first)+1))
	offset += 2
	copy(data[offset:], first)
	offset += len(first)
	data[offset] = 0
	offset++

	// Last name (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(last)+1))
	offset += 2
	copy(data[offset:], last)
	offset += len(last)
	data[offset] = 0
	offset++

	// Email (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(data[offset:], uint16(len(email)+1))
	offset += 2
	copy(data[offset:], email)
	offset += len(email)
	data[offset] = 0
	offset++

	// Auth required (from iserverd: tuser.auth)
	data[offset] = info.AuthRequired
	offset++

	// Web aware (from iserverd: tuser.webaware)
	data[offset] = 0
	offset++

	// Padding byte (from iserverd: 0x00)
	data[offset] = 0x00
	offset++

	// Users left (only on last result, from iserverd)
	if isLast {
		binary.LittleEndian.PutUint32(data[offset:], 0)
	}

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: session.SessionID,
		Command:   wire.ICQLegacySrvMetaUser,
		SeqNum1:   session.NextServerSeqNum(),
		SeqNum2:   seq2,
		UIN:       session.UIN,
		Data:      data,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// EncryptPacket encrypts a V5 packet using the session ID.
// Note: V5 server packets use AddV5ServerCheckcode() which is called by MarshalV5ServerPacket.
// This method is provided for interface completeness but the encryption is handled
// automatically by MarshalV5ServerPacket.
func (b *V5PacketBuilderImpl) EncryptPacket(packet []byte, sessionID uint32) []byte {
	// V5 server packets are already processed by MarshalV5ServerPacket which calls
	// AddV5ServerCheckcode(). This method returns the packet as-is since encryption
	// is handled during marshaling.
	return packet
}

// BuildDepsListReply constructs a pre-auth response packet (V3 format).
// Historically called "departments list" in iserverd. In V5, this is a deprecated
// empty V3-format response sent during the pre-auth pseudo-login (0x03F2).
// From iserverd v5_send_depslist()
// V3 format packet: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKSUM(4)
func (b *V5PacketBuilderImpl) BuildDepsListReply(uin uint32, seq2 uint16) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(buf[2:4], wire.ICQLegacySrvUserDepsList)
	binary.LittleEndian.PutUint16(buf[4:6], 0x0000) // seq1
	binary.LittleEndian.PutUint16(buf[6:8], seq2)
	binary.LittleEndian.PutUint32(buf[8:12], uin)
	binary.LittleEndian.PutUint32(buf[12:16], 0x8FFCACBF) // magic checksum

	return buf
}

// BuildAckToAddr constructs an ACK packet for sending to an address (before session exists).
// Used during login flow when session is not yet established.
func (b *V5PacketBuilderImpl) BuildAckToAddr(sessionID uint32, uin uint32, seq1, seq2 uint16) []byte {
	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: sessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seq1,
		SeqNum2:   seq2,
		UIN:       uin,
	}

	return wire.MarshalV5ServerPacket(pkt)
}

// BuildFirstLoginReply constructs a first login reply packet.
// From iserverd v5_process_firstlog() - sent in response to CMD_FIRST_LOGIN.
// Reply includes session_id2 and 0x0001.
func (b *V5PacketBuilderImpl) BuildFirstLoginReply(sessionID uint32, uin uint32, seq1, seq2 uint16, sessionID2 uint32) []byte {
	// Data: SESSION_ID2(4) + 0x0001(2)
	data := make([]byte, 6)
	binary.LittleEndian.PutUint32(data[0:4], sessionID2)
	binary.LittleEndian.PutUint16(data[4:6], 0x0001)

	pkt := &wire.V5ServerPacket{
		Version:   wire.ICQLegacyVersionV5,
		SessionID: sessionID,
		Command:   wire.ICQLegacySrvAck,
		SeqNum1:   seq1,
		SeqNum2:   seq2,
		UIN:       uin,
		Data:      data,
	}

	return wire.MarshalV5ServerPacket(pkt)
}
