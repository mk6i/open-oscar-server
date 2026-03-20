package icq_legacy

import (
	"encoding/binary"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/wire"
)

// V3PacketBuilder constructs V3 protocol packets.
// This interface separates packet construction from business logic,
// following the OSCAR foodgroup architecture pattern.
//
// V3 packet format (from iserverd source):
// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + DATA...
// Total header: 12 bytes (NO checksum in V3, unlike V5!)
//
type V3PacketBuilder interface {
	// BuildLoginReply constructs a login success (HELLO) response packet.
	// The packet contains timing parameters and client IP information.
	BuildLoginReply(session *LegacySession, seq1, seq2 uint16) []byte

	// BuildBadPassword constructs a bad password/authentication failure response.
	BuildBadPassword(seq1, seq2 uint16, uin uint32) []byte

	// BuildAck constructs an acknowledgment packet for the given sequence numbers.
	BuildAck(seq1, seq2 uint16, uin uint32) []byte

	// BuildNotConnected constructs a "not connected" error response.
	BuildNotConnected(seq2 uint16, uin uint32) []byte

	// BuildUserOnline constructs a user online notification packet.
	// Sent to notify a user that one of their contacts has come online.
	BuildUserOnline(seqNum uint16, uin uint32, status uint32) []byte

	// BuildUserOffline constructs a user offline notification packet.
	// Sent to notify a user that one of their contacts has gone offline.
	BuildUserOffline(seqNum uint16, uin uint32) []byte

	// BuildUserStatus constructs a user status change notification packet.
	// Sent when a user changes status while already online.
	BuildUserStatus(seqNum uint16, uin uint32, status uint32) []byte

	// BuildContactListDone constructs a contact list processing complete response.
	BuildContactListDone(seqNum uint16, seq2 uint16, uin uint32) []byte

	// BuildOnlineMessage constructs an online system message packet.
	BuildOnlineMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte

	// BuildBasicInfo constructs a basic user info response packet.
	BuildBasicInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte

	// BuildHomeInfo constructs a home info response packet.
	BuildHomeInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte

	// BuildWorkInfo constructs a work info response packet.
	BuildWorkInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte

	// BuildHomeWeb constructs a home webpage info response packet.
	BuildHomeWeb(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte

	// BuildWorkWeb constructs a work webpage info response packet.
	BuildWorkWeb(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte

	// BuildDeptsList constructs a pre-auth deps list response packet.
	// Historically called "departments list" in iserverd (from its Users_Deps database table).
	BuildDeptsList(seq2 uint16, uin uint32) []byte
}

// V3PacketBuilderImpl implements the V3PacketBuilder interface.
// It constructs V3 protocol packets following the iserverd packet formats.
type V3PacketBuilderImpl struct{}

// NewV3PacketBuilder creates a new V3PacketBuilder instance.
func NewV3PacketBuilder() V3PacketBuilder {
	return &V3PacketBuilderImpl{}
}

// buildV3Header creates a standard V3 packet header (16 bytes).
// Format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4)
func (b *V3PacketBuilderImpl) buildV3Header(command uint16, seq1, seq2 uint16, uin uint32) []byte {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint16(header[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(header[2:4], command)
	binary.LittleEndian.PutUint16(header[4:6], seq1)
	binary.LittleEndian.PutUint16(header[6:8], seq2)
	binary.LittleEndian.PutUint32(header[8:12], uin)
	binary.LittleEndian.PutUint32(header[12:16], 0) // reserved
	return header
}

// BuildLoginReply constructs a login success (HELLO) response packet.
// From iserverd v3_send_login_reply() - this is a complex packet!
// V3 HELLO format:
// VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) +
// CLIENT_IP(4) + RESERVED(4) + EXTERNALS_NUM(4) + DEPLIST_VERSION(4) +
// MUST_CHANGE_PASS(1) + CAN_BROADCAST(1) + UNKNOWN(4) +
// PING_FREQ(2) + PACKET_TIMEOUT(2) + RETRY_TIMEOUT(2) + NUM_RETRIES(2)
func (b *V3PacketBuilderImpl) BuildLoginReply(session *LegacySession, seq1, seq2 uint16) []byte {
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

	return pkt[:offset]
}

// BuildBadPassword constructs a wrong password response.
func (b *V3PacketBuilderImpl) BuildBadPassword(seq1, seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvWrongPasswd)
	binary.LittleEndian.PutUint16(pkt[4:6], 0)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)
	return pkt
}

// BuildAck constructs an ACK packet (V3 format from iserverd v3_send_ack).
// V3 ACK format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4)
func (b *V3PacketBuilderImpl) BuildAck(seq1, seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvAck)
	binary.LittleEndian.PutUint16(pkt[4:6], seq1)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // reserved
	return pkt
}

// BuildNotConnected constructs a not connected error response.
func (b *V3PacketBuilderImpl) BuildNotConnected(seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvNotConnected)
	binary.LittleEndian.PutUint16(pkt[4:6], 0)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)
	return pkt
}

// BuildUserOnline constructs a user online notification packet.
// From iserverd v3_send_user_online()
// V3 USER_ONLINE format:
// header(16) + UIN(4) + IP(4) + PORT(4) + INT_IP(4) + DC_TYPE(1) + STATUS(2) + ESTAT(2) + TCPVER(2) + UNKNOWN(2)
// Total: 16 + 4 + 4 + 4 + 4 + 1 + 2 + 2 + 2 + 2 = 41 bytes
func (b *V3PacketBuilderImpl) BuildUserOnline(seqNum uint16, uin uint32, status uint32) []byte {
	pkt := make([]byte, 41)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserOnline)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2
	offset += 2
	// Note: UIN field in header will be set by caller (recipient's UIN)
	// For now we use 0 as placeholder - caller should set session.UIN
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // recipient UIN (set by caller)
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

	return pkt[:offset]
}

// BuildUserOffline constructs a user offline notification packet.
// From iserverd v3_send_user_offline()
// V3 USER_OFFLINE format: header(16) + UIN(4)
func (b *V3PacketBuilderImpl) BuildUserOffline(seqNum uint16, uin uint32) []byte {
	pkt := make([]byte, 20)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserOffline)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // recipient UIN (set by caller)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// UIN of the user who went offline
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4

	return pkt[:offset]
}

// BuildUserStatus constructs a user status change notification packet.
// From iserverd v3_send_user_status() in make_packet.cpp
// This is used when a user changes status while already online.
// Format: header(16) + UIN(4) + STATUS(2) + ESTAT(2)
func (b *V3PacketBuilderImpl) BuildUserStatus(seqNum uint16, uin uint32, status uint32) []byte {
	pkt := make([]byte, 24)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserStatus) // 0x01A4
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0) // seq2
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // recipient UIN (set by caller)
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

	return pkt[:offset]
}

// BuildContactListDone constructs a contact list processed response.
func (b *V3PacketBuilderImpl) BuildContactListDone(seqNum uint16, seq2 uint16, uin uint32) []byte {
	pkt := make([]byte, 16)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserListDone)
	binary.LittleEndian.PutUint16(pkt[4:6], seqNum)
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0)
	return pkt
}

// BuildOnlineMessage constructs an online system message packet.
// From iserverd v3_send_user_message()
// Format: header(16) + FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
// Note: V3 packets do NOT have a checkcode - they have a reserved field (always 0)
func (b *V3PacketBuilderImpl) BuildOnlineMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte {
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

	return pkt[:offset]
}

// BuildBasicInfo constructs a basic user info response packet.
// From iserverd v3_send_basic_info()
// Packet format (verified via Ghidra RE of ICQ98a client handler):
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: TARGET_UIN(4) + NICK_LEN(2) + NICK + FIRST_LEN(2) + FIRST + LAST_LEN(2) + LAST +
//         EMAIL_LEN(2) + EMAIL + STATUS(1) + AUTH(1)
// All strings are length-prefixed (2 bytes) and null-terminated
func (b *V3PacketBuilderImpl) BuildBasicInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte {
	// Default values if info is nil
	nick := ""
	first := ""
	last := ""
	email := ""
	status := uint8(0)
	auth := uint8(0)

	if info != nil {
		nick = info.Nickname
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
	binary.LittleEndian.PutUint32(pkt[offset:], 0) // reserved
	offset += 4

	// TARGET_UIN - the UIN of the user whose info this is
	targetUIN := uint32(0)
	if info != nil {
		targetUIN = info.UIN
	}
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
	pkt[offset] = status
	offset++

	// Auth flag
	pkt[offset] = auth
	offset++

	return pkt[:offset]
}

// BuildHomeInfo constructs a home info response packet.
// From iserverd v3_send_home_info()
// Packet format:
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: HADDR_LEN(2) + HADDR + HCITY_LEN(2) + HCITY + HSTATE_LEN(2) + HSTATE +
//         HCOUNTRY(2) + HPHONE_LEN(2) + HPHONE + HFAX_LEN(2) + HFAX + HCELL_LEN(2) + HCELL +
//         HZIP(4) + GENDER(1) + AGE(2) + BDAY(1) + BMONTH(1) + BYEAR(1) + 0x00(1)
func (b *V3PacketBuilderImpl) BuildHomeInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte {
	// Default values
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
	byear := uint8(0)

	if info != nil {
		hcity = info.City
		hstate = info.State
		hcountry = info.Country
		hphone = info.Phone
		gender = info.Gender
		age = uint16(info.Age)
	}

	// Calculate packet size
	pktSize := 16 + 2 + len(haddr) + 1 + 2 + len(hcity) + 1 + 2 + len(hstate) + 1 +
		2 + 2 + len(hphone) + 1 + 2 + len(hfax) + 1 + 2 + len(hcell) + 1 +
		4 + 1 + 2 + 1 + 1 + 1 + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x0320) // ICQ_CMDxSND_USERxINFO_HOME
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Home address
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(haddr)+1))
	offset += 2
	copy(pkt[offset:], haddr)
	offset += len(haddr)
	pkt[offset] = 0
	offset++

	// Home city
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hcity)+1))
	offset += 2
	copy(pkt[offset:], hcity)
	offset += len(hcity)
	pkt[offset] = 0
	offset++

	// Home state
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hstate)+1))
	offset += 2
	copy(pkt[offset:], hstate)
	offset += len(hstate)
	pkt[offset] = 0
	offset++

	// Home country
	binary.LittleEndian.PutUint16(pkt[offset:], hcountry)
	offset += 2

	// Home phone
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hphone)+1))
	offset += 2
	copy(pkt[offset:], hphone)
	offset += len(hphone)
	pkt[offset] = 0
	offset++

	// Home fax
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hfax)+1))
	offset += 2
	copy(pkt[offset:], hfax)
	offset += len(hfax)
	pkt[offset] = 0
	offset++

	// Home cell
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hcell)+1))
	offset += 2
	copy(pkt[offset:], hcell)
	offset += len(hcell)
	pkt[offset] = 0
	offset++

	// Home zip
	binary.LittleEndian.PutUint32(pkt[offset:], hzip)
	offset += 4

	// Gender
	pkt[offset] = gender
	offset++

	// Age
	binary.LittleEndian.PutUint16(pkt[offset:], age)
	offset += 2

	// Birthday: day, month, year
	pkt[offset] = bday
	offset++
	pkt[offset] = bmonth
	offset++
	pkt[offset] = byear
	offset++

	// Trailing zero
	pkt[offset] = 0
	offset++

	return pkt[:offset]
}

// BuildWorkInfo constructs a work info response packet.
// From iserverd v3_send_work_info()
// Packet format:
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: WADDR_LEN(2) + WADDR + WCITY_LEN(2) + WCITY + WSTATE_LEN(2) + WSTATE +
//         WCOUNTRY(2) + WCOMPANY_LEN(2) + WCOMPANY + WTITLE_LEN(2) + WTITLE +
//         WDEPART(4) + WPHONE_LEN(2) + WPHONE + WFAX_LEN(2) + WFAX +
//         WPAGER_LEN(2) + WPAGER + WZIP(4)
func (b *V3PacketBuilderImpl) BuildWorkInfo(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte {
	// Default values
	waddr := ""
	wcity := ""
	wstate := ""
	wcountry := uint16(0)
	wcompany := ""
	wtitle := ""
	wdepart := uint32(0)
	wphone := ""
	wfax := ""
	wpager := ""
	wzip := uint32(0)

	if info != nil {
		wcompany = info.Company
		wtitle = info.Position
	}

	// Calculate packet size
	pktSize := 16 + 2 + len(waddr) + 1 + 2 + len(wcity) + 1 + 2 + len(wstate) + 1 +
		2 + 2 + len(wcompany) + 1 + 2 + len(wtitle) + 1 + 4 +
		2 + len(wphone) + 1 + 2 + len(wfax) + 1 + 2 + len(wpager) + 1 + 4
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], 0x02F8) // ICQ_CMDxSND_USERxINFO_WORK
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Work address
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(waddr)+1))
	offset += 2
	copy(pkt[offset:], waddr)
	offset += len(waddr)
	pkt[offset] = 0
	offset++

	// Work city
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wcity)+1))
	offset += 2
	copy(pkt[offset:], wcity)
	offset += len(wcity)
	pkt[offset] = 0
	offset++

	// Work state
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wstate)+1))
	offset += 2
	copy(pkt[offset:], wstate)
	offset += len(wstate)
	pkt[offset] = 0
	offset++

	// Work country
	binary.LittleEndian.PutUint16(pkt[offset:], wcountry)
	offset += 2

	// Work company
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wcompany)+1))
	offset += 2
	copy(pkt[offset:], wcompany)
	offset += len(wcompany)
	pkt[offset] = 0
	offset++

	// Work title
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wtitle)+1))
	offset += 2
	copy(pkt[offset:], wtitle)
	offset += len(wtitle)
	pkt[offset] = 0
	offset++

	// Work department
	binary.LittleEndian.PutUint32(pkt[offset:], wdepart)
	offset += 4

	// Work phone
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wphone)+1))
	offset += 2
	copy(pkt[offset:], wphone)
	offset += len(wphone)
	pkt[offset] = 0
	offset++

	// Work fax
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wfax)+1))
	offset += 2
	copy(pkt[offset:], wfax)
	offset += len(wfax)
	pkt[offset] = 0
	offset++

	// Work pager
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wpager)+1))
	offset += 2
	copy(pkt[offset:], wpager)
	offset += len(wpager)
	pkt[offset] = 0
	offset++

	// Work zip
	binary.LittleEndian.PutUint32(pkt[offset:], wzip)
	offset += 4

	return pkt[:offset]
}

// BuildHomeWeb constructs a home webpage info response packet.
// From iserverd v3_send_home_web()
// Packet format:
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: HPAGE_LEN(2) + HPAGE (null-terminated string)
func (b *V3PacketBuilderImpl) BuildHomeWeb(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte {
	// Default value
	hpage := ""

	if info != nil {
		hpage = info.Homepage
	}

	// Calculate packet size
	// Header(16) + hpage_len(2) + hpage + null(1)
	pktSize := 16 + 2 + len(hpage) + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserInfoHWeb) // 0x0334
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Home page URL (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(hpage)+1))
	offset += 2
	copy(pkt[offset:], hpage)
	offset += len(hpage)
	pkt[offset] = 0
	offset++

	return pkt[:offset]
}

// BuildWorkWeb constructs a work webpage info response packet.
// From iserverd v3_send_work_web()
// Packet format:
//   Header: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4) = 16 bytes
//   Data: WPAGE_LEN(2) + WPAGE (null-terminated string)
func (b *V3PacketBuilderImpl) BuildWorkWeb(seqNum uint16, seq2 uint16, uin uint32, info *foodgroup.UserInfoResult) []byte {
	// Default value - work webpage is not in UserInfoResult, so we use empty string
	// In the future, this could be added to UserInfoResult if needed
	wpage := ""

	// Calculate packet size
	// Header(16) + wpage_len(2) + wpage + null(1)
	pktSize := 16 + 2 + len(wpage) + 1
	pkt := make([]byte, pktSize)
	offset := 0

	// Header
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacyVersionV3)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], wire.ICQLegacySrvUserInfoWWeb) // 0x030C
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seqNum)
	offset += 2
	binary.LittleEndian.PutUint16(pkt[offset:], seq2)
	offset += 2
	binary.LittleEndian.PutUint32(pkt[offset:], uin)
	offset += 4
	binary.LittleEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	// Work page URL (length-prefixed with null terminator)
	binary.LittleEndian.PutUint16(pkt[offset:], uint16(len(wpage)+1))
	offset += 2
	copy(pkt[offset:], wpage)
	offset += len(wpage)
	pkt[offset] = 0
	offset++

	return pkt[:offset]
}

// BuildDeptsList constructs a pre-auth deps list response packet.
// Historically called "departments list" in iserverd (from its Users_Deps database table).
// From iserverd v3_send_depslist()
// V3 DEPS_LIST format: header(16) + DEPLIST_VERSION(4) + COUNT(4) + [deps...] + TRAILER(4)
func (b *V3PacketBuilderImpl) BuildDeptsList(seq2 uint16, uin uint32) []byte {
	// For now, send empty list with version 1
	pkt := make([]byte, 28)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserDepsList) // 0x0032
	binary.LittleEndian.PutUint16(pkt[4:6], 0)                             // servseq
	binary.LittleEndian.PutUint16(pkt[6:8], seq2)
	binary.LittleEndian.PutUint32(pkt[8:12], uin)
	binary.LittleEndian.PutUint32(pkt[12:16], 0) // reserved
	binary.LittleEndian.PutUint32(pkt[16:20], 1) // deplist version
	binary.LittleEndian.PutUint32(pkt[20:24], 0) // count = 0 (empty deps list)
	// Trailer from iserverd
	binary.LittleEndian.PutUint16(pkt[24:26], 0x0002)
	binary.LittleEndian.PutUint16(pkt[26:28], 0x002a)

	return pkt
}
