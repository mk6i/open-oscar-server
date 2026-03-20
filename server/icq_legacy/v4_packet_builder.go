package icq_legacy

import (
	"encoding/binary"
	"fmt"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/wire"
)

// V4PacketBuilder constructs V4 protocol packets.
// V4 is similar to V3 but with checkcode calculation for packet validation.
// This interface separates packet construction from business logic,
// following the OSCAR foodgroup architecture pattern.
//
// V4 packet format (from wumpus documentation):
// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4) + DATA...
// Total header: 16 bytes (V3 format with checkcode at offset 12)
//
// Note: Server sends V3 format packets to V4 clients, but with a valid checkcode
// that the client validates using the V4 checkcode algorithm.
//
type V4PacketBuilder interface {
	// BuildLoginReply constructs a login success (HELLO) response packet.
	// The packet contains timing parameters and client IP information.
	BuildLoginReply(session *LegacySession, seq2 uint16) []byte

	// BuildBadPassword constructs a bad password/authentication failure response.
	BuildBadPassword(seq1, seq2 uint16, uin uint32) []byte

	// BuildAck constructs an acknowledgment packet for the given sequence numbers.
	BuildAck(seq1, seq2 uint16, uin uint32) []byte

	// BuildNotConnected constructs a "not connected" error response.
	BuildNotConnected(seq2 uint16, uin uint32) []byte

	// BuildUserOnline constructs a user online notification packet.
	// Sent to notify a user that one of their contacts has come online.
	BuildUserOnline(seqNum uint16, uin uint32, status uint32) []byte

	// BuildContactListDone constructs a contact list processing complete response.
	BuildContactListDone(seqNum uint16, seq2 uint16, uin uint32) []byte

	// BuildOnlineMessage constructs an online system message packet.
	BuildOnlineMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte

	// BuildBasicInfo constructs a basic user info response packet.
	BuildBasicInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte

	// BuildRegisterInfo constructs a registration info response packet.
	// Sent to clients starting the registration wizard.
	BuildRegisterInfo(seq2 uint16, uin uint32) []byte

	// BuildRegistrationOK constructs a registration success response packet.
	// Contains the new UIN and password for the registered user.
	BuildRegistrationOK(seq2 uint16, newUIN uint32, password string) []byte

	// CalculateCheckcode calculates the V4 checkcode for a packet.
	// The checkcode is used by V4 clients to validate server packets.
	CalculateCheckcode(packet []byte) uint32
}

// V4PacketBuilderImpl implements the V4PacketBuilder interface.
// It constructs V4 protocol packets with proper checkcode calculation.
type V4PacketBuilderImpl struct{}

// NewV4PacketBuilder creates a new V4PacketBuilder instance.
func NewV4PacketBuilder() V4PacketBuilder {
	return &V4PacketBuilderImpl{}
}

// CalculateCheckcode calculates the checkcode for server packets to V4 clients.
// Based on reverse engineering of ICQ 98a client (encrypt_v4_packet and validate_v4_checkcode)
//
// The client validates checkcode as follows:
//
//	checkA = (byte[8] << 24) | (byte[4] << 16) | (byte[2] << 8) | byte[6]
//	result = checkA ^ checkcode
//	valid if: (result >> 16) & 0xFF == ~packet[result >> 24]
//	      and: result & 0xFF == ~table[(result >> 8) & 0xFF]
//
// So we construct checkcode such that after XOR with checkA, the result contains:
//
//	byte 3 (bits 24-31): packetOfs - offset into packet
//	byte 2 (bits 16-23): ~packet[packetOfs] - inverted byte at that offset
//	byte 1 (bits 8-15):  tableOfs - offset into table
//	byte 0 (bits 0-7):   ~table[tableOfs] - inverted byte at that table offset
func (b *V4PacketBuilderImpl) CalculateCheckcode(packet []byte) uint32 {
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
	packetVal := ^packet[packetOfs]     // inverted
	tableVal := ^wire.V4Table[tableOfs] // inverted

	// Build checkB with inverted values
	checkB := uint32(packetOfs)<<24 | uint32(packetVal)<<16 | uint32(tableOfs)<<8 | uint32(tableVal)

	// checkcode = checkA ^ checkB
	return checkA ^ checkB
}

// BuildLoginReply constructs a login success (HELLO) response packet.
// V3 server packet format with checkcode for V4 clients.
// From ICQ98a client reverse engineering:
// Header: 16 bytes (VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4))
// Data: IP(4) + 10 WORDs(20) = 24 bytes
// Total: 40 bytes
func (b *V4PacketBuilderImpl) BuildLoginReply(session *LegacySession, seq2 uint16) []byte {
	// Get client IP as 4 bytes in network byte order (big-endian)
	var ipBytes [4]byte
	if session.Addr != nil && session.Addr.IP != nil {
		ip := session.Addr.IP.To4()
		if ip != nil {
			copy(ipBytes[:], ip)
		}
	}

	pkt := make([]byte, 40)
	offset := 0

	// V3 Header (16 bytes)
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

	// Calculate and add checkcode
	checkcode := b.CalculateCheckcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// Data section for LOGIN_REPLY (0x005A):
	// IP is in network byte order (big-endian): c0 a8 0a 01 = 192.168.10.1
	pkt[offset] = ipBytes[0]
	pkt[offset+1] = ipBytes[1]
	pkt[offset+2] = ipBytes[2]
	pkt[offset+3] = ipBytes[3]
	offset += 4

	// 6 WORDs that get stored in globals:
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0000) // -> DAT_004df54c
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0000) // -> DAT_004df438
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0019) // -> DAT_004df7a8 (keep-alive interval = 25)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0002) // -> DAT_004df550
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0001) // -> DAT_004d4178
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x00FA) // -> DAT_004df820 (250 = timeout?)
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

	return pkt[:offset]
}

// BuildBadPassword constructs a wrong password response.
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + ZERO(4)
func (b *V4PacketBuilderImpl) BuildBadPassword(seq1, seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvWrongPasswd)
	binary.LittleEndian.PutUint16(pkt[4:6], seq1)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // Zero field
	return pkt
}

// BuildAck constructs an ACK packet in V3 format with checkcode.
func (b *V4PacketBuilderImpl) BuildAck(seq1, seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvAck)
	binary.LittleEndian.PutUint16(pkt[4:6], seq1)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)

	// Calculate and add checkcode
	checkcode := b.CalculateCheckcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	return pkt
}

// BuildNotConnected constructs a not connected error response.
// V3 server packet format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + ZERO(4)
func (b *V4PacketBuilderImpl) BuildNotConnected(seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvNotConnected)
	binary.LittleEndian.PutUint16(pkt[4:6], 0)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // Zero field
	return pkt
}

// BuildUserOnline constructs a user online notification packet.
// From iserverd v3_send_user_online() - V3 and V4 share the same server packet format.
// Data: UIN(4) + IP(4) + PORT(4) + REAL_IP(4) + DC_TYPE(1) + STATUS(2) + ESTATUS(2) + TCPVER(2) + UNKNOWN(2)
// Total data: 25 bytes, total packet: 41 bytes
func (b *V4PacketBuilderImpl) BuildUserOnline(seqNum uint16, uin uint32, status uint32) []byte {
	pkt := make([]byte, 41)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserOnline)
	binary.LittleEndian.PutUint16(pkt[4:6], seqNum)
	binary.LittleEndian.PutUint16(pkt[6:8], 0)
	binary.LittleEndian.PutUint32(pkt[8:12], 0) // recipient UIN (set by caller)

	// Calculate and add checkcode
	checkcode := b.CalculateCheckcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	offset := 16
	// UIN of user who came online
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4
	// IP address (4 bytes, 0 for privacy)
	offset += 4
	// TCP port (4 bytes, 0 for privacy)
	offset += 4
	// Internal/real IP (4 bytes, 0 for privacy)
	offset += 4
	// DC type (1 byte)
	offset++
	// Status (low 16 bits)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(status&0xFFFF))
	offset += 2
	// Extended status (high 16 bits)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(status>>16))
	offset += 2
	// TCP version (2 bytes)
	offset += 2
	// Unknown (2 bytes)
	offset += 2

	return pkt[:offset]
}

// BuildContactListDone constructs a contact list processed response.
// V3 server packet format with checkcode: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4)
func (b *V4PacketBuilderImpl) BuildContactListDone(seqNum uint16, seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserListDone)
	binary.LittleEndian.PutUint16(pkt[4:6], seqNum)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)

	// Calculate and add checkcode
	checkcode := b.CalculateCheckcode(pkt)
	binary.LittleEndian.PutUint32(pkt[12:16], checkcode)

	return pkt
}

// BuildOnlineMessage constructs an online system message packet.
// V3 server packet format with checkcode.
// Format: header(16) + FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (b *V4PacketBuilderImpl) BuildOnlineMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte {
	msgBytes := []byte(message)

	pktSize := 16 + 4 + 2 + 2 + len(msgBytes) + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvSysMsgOnline) // 0x0104
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // recipient UIN (set by caller)
	offset += 4

	// Calculate and add checkcode
	checkcode := b.CalculateCheckcode(pkt)
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

	return pkt[:offset]
}

// BuildBasicInfo constructs a basic user info response packet.
// V3 server packet format with checkcode.
// Data format (verified via Ghidra RE of ICQ98a client handler):
//
//	TARGET_UIN(4) + NICK_LEN(2) + NICK + FNAME_LEN(2) + FNAME + LNAME_LEN(2) + LNAME +
//	EMAIL_LEN(2) + EMAIL + STATUS(1) + AUTH(1)
func (b *V4PacketBuilderImpl) BuildBasicInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte {
	// Default values if info is nil
	nick := ""
	first := ""
	last := ""
	email := ""
	statusByte := byte(0)
	auth := byte(0)
	targetUIN := uint32(0)

	if info != nil {
		nick = info.Nickname
		first = info.FirstName
		last = info.LastName
		email = info.Email
		auth = info.AuthRequired
		targetUIN = info.UIN
		if nick == "" {
			nick = fmt.Sprintf("%d", targetUIN)
		}
	}

	// Calculate packet size
	// Header(16) + TARGET_UIN(4) + nick_len(2) + nick + null(1) + first_len(2) + first + null(1) +
	// last_len(2) + last + null(1) + email_len(2) + email + null(1) + status(1) + auth(1)
	pktSize := 16 + 4 + 2 + len(nick) + 1 + 2 + len(first) + 1 + 2 + len(last) + 1 + 2 + len(email) + 1 + 1 + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header - Client expects 0x0118 (ICQLegacySrvInfoReply)
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvInfoReply) // 0x0118
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], uin) // recipient's UIN
	offset += 4

	// Calculate and add checkcode
	checkcode := b.CalculateCheckcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	// TARGET_UIN - the UIN of the user whose info this is
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

	// Status byte
	pkt[offset] = statusByte
	offset++

	// Auth flag
	pkt[offset] = auth
	offset++

	return pkt[:offset]
}

// BuildRegisterInfo constructs a registration info response packet.
// V3 server packet format with checkcode.
// From iserverd v3_send_registration_info(): sends 0x037A with admin notes
func (b *V4PacketBuilderImpl) BuildRegisterInfo(seq2 uint16, uin uint32) []byte {
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
	checkcode := b.CalculateCheckcode(pkt)
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

	return pkt[:offset]
}

// BuildRegistrationOK constructs a registration success response packet.
// V4 client (licq) expects ICQ_CMDxRCV_NEWxUIN (0x0046).
// The client reads the new UIN from the header's UIN field, then calls icqLogon().
// V3 server packet format with checkcode: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + CHECKCODE(4)
func (b *V4PacketBuilderImpl) BuildRegistrationOK(seq2 uint16, newUIN uint32, password string) []byte {
	pkt := make([]byte, 16)
	offset := 0

	// V3 Header - UIN field contains the NEW UIN
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvNewUIN) // 0x0046
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq1 = 0 for server-initiated
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], newUIN) // NEW UIN in header
	offset += 4

	// Calculate and add checkcode
	checkcode := b.CalculateCheckcode(pkt)
	binary.LittleEndian.PutUint32(pkt[offset:], checkcode)
	offset += 4

	return pkt[:offset]
}
