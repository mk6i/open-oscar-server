package icq_legacy

import (
	"encoding/binary"
	"net"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/wire"
)

// V2PacketBuilder constructs V2 protocol packets.
// This interface separates packet construction from business logic,
// following the OSCAR foodgroup architecture pattern.
//
// V2 is the simplest ICQ protocol version with no encryption.
// Packet format: VERSION(2) + COMMAND(2) + SEQNUM(2) + DATA
//
type V2PacketBuilder interface {
	// BuildLoginReply constructs a login success response packet.
	// The packet contains the user's UIN, IP address, and session info.
	BuildLoginReply(session *LegacySession, clientSeqNum uint16) []byte

	// BuildBadPassword constructs a bad password/authentication failure response.
	BuildBadPassword(seqNum uint16, version uint16) []byte

	// BuildAck constructs an acknowledgment packet for the given sequence number.
	BuildAck(seqNum uint16, version uint16) []byte

	// BuildUserOnline constructs a user online notification packet.
	// Sent to notify a user that one of their contacts has come online.
	BuildUserOnline(seqNum uint16, uin uint32, status uint32, ip net.IP, port uint16) []byte

	// BuildUserOffline constructs a user offline notification packet.
	// Sent to notify a user that one of their contacts has gone offline.
	BuildUserOffline(seqNum uint16, uin uint32) []byte

	// BuildContactListDone constructs a contact list processing complete response.
	// Sent after processing a user's contact list to indicate completion.
	BuildContactListDone(seqNum uint16) []byte

	// BuildMessage constructs a message delivery packet.
	// Used for both online messages and offline message delivery.
	BuildMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte

	// BuildSearchResult constructs a user search result packet.
	// If isLast is true, uses the "search done" command; otherwise "search found".
	BuildSearchResult(seqNum uint16, info *foodgroup.UserInfoResult, isLast bool) []byte

	// BuildStatusUpdate constructs a status change notification packet.
	// Sent to notify contacts when a user changes their status.
	BuildStatusUpdate(seqNum uint16, uin uint32, status uint32) []byte

	// BuildOfflineMsgDone constructs an end-of-offline-messages packet.
	// Sent after delivering all offline messages to indicate completion.
	BuildOfflineMsgDone(seqNum uint16) []byte

	// BuildDepsList constructs a pre-auth response packet (0x0032).
	// Historically called "departments list" in iserverd (from its Users_Deps database table).
	// Used in the pre-login flow: client sends 0x03F2 with credentials, server validates
	// and sends this response, then the client proceeds with the real login (0x03E8).
	BuildDepsList(seqNum uint16, uin uint32) []byte
}

// V2PacketBuilderImpl implements the V2PacketBuilder interface.
// It constructs V2 protocol packets using the wire package helpers.
type V2PacketBuilderImpl struct{}

// NewV2PacketBuilder creates a new V2PacketBuilder instance.
func NewV2PacketBuilder() V2PacketBuilder {
	return &V2PacketBuilderImpl{}
}

// BuildLoginReply constructs a login success response packet.
// V2 LOGIN_REPLY format (from protocol spec):
// USER_UIN(4) + USER_IP(4) + LOGIN_SEQ_NUM(2) + X1(4) + X2(4) + X3(4) + X4(4) + X5(6) = 32 bytes
func (b *V2PacketBuilderImpl) BuildLoginReply(session *LegacySession, clientSeqNum uint16) []byte {
	var clientIP net.IP
	if session.Addr != nil {
		clientIP = session.Addr.IP
	}

	serverSeq := session.NextServerSeqNum()
	pkt := wire.BuildV2LoginReply(serverSeq, clientSeqNum, session.UIN, clientIP)
	pkt.Version = session.Version

	return wire.MarshalV2ServerPacket(pkt)
}

// BuildBadPassword constructs a bad password/authentication failure response.
func (b *V2PacketBuilderImpl) BuildBadPassword(seqNum uint16, version uint16) []byte {
	pkt := wire.BuildV2BadPassword(seqNum)
	pkt.Version = version
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildAck constructs an acknowledgment packet.
func (b *V2PacketBuilderImpl) BuildAck(seqNum uint16, version uint16) []byte {
	pkt := wire.BuildV2Ack(seqNum)
	pkt.Version = version
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildUserOnline constructs a user online notification packet.
// V2 USER_ONLINE format (from protocol spec):
// REMOTE_UIN(4) + REMOTE_IP(4) + REMOTE_PORT(4) + REMOTE_REAL_IP(4) + X1(1) + STATUS(4) + X2(4) = 25 bytes
func (b *V2PacketBuilderImpl) BuildUserOnline(seqNum uint16, uin uint32, status uint32, ip net.IP, port uint16) []byte {
	pkt := wire.BuildV2UserOnline(seqNum, uin, status, ip, port)
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildUserOffline constructs a user offline notification packet.
func (b *V2PacketBuilderImpl) BuildUserOffline(seqNum uint16, uin uint32) []byte {
	pkt := wire.BuildV2UserOffline(seqNum, uin)
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildContactListDone constructs a contact list processing complete response.
func (b *V2PacketBuilderImpl) BuildContactListDone(seqNum uint16) []byte {
	pkt := wire.BuildV2ContactListDone(seqNum)
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildMessage constructs a message delivery packet.
// Format: FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (b *V2PacketBuilderImpl) BuildMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte {
	pkt := wire.BuildV2Message(seqNum, fromUIN, msgType, message)
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildSearchResult constructs a user search result packet.
// Format: SEQ(2) + UIN(4) + NICK_LEN(2) + NICK + FNAME_LEN(2) + FNAME + LNAME_LEN(2) + LNAME + EMAIL_LEN(2) + EMAIL + AUTH(1)
func (b *V2PacketBuilderImpl) BuildSearchResult(seqNum uint16, info *foodgroup.UserInfoResult, isLast bool) []byte {
	// Convert UserInfoResult to wire.LegacyUserInfo
	wireInfo := &wire.LegacyUserInfo{
		UIN:       info.UIN,
		Nickname:  info.Nickname,
		FirstName: info.FirstName,
		LastName:  info.LastName,
		Email:     info.Email,
		Auth:      info.AuthRequired,
	}

	pkt := wire.BuildV2SearchResult(seqNum, wireInfo, isLast)
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildStatusUpdate constructs a status change notification packet.
// Format: UIN(4) + STATUS(4)
func (b *V2PacketBuilderImpl) BuildStatusUpdate(seqNum uint16, uin uint32, status uint32) []byte {
	pkt := wire.BuildV2StatusUpdate(seqNum, uin, status)
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildOfflineMsgDone constructs an end-of-offline-messages packet.
func (b *V2PacketBuilderImpl) BuildOfflineMsgDone(seqNum uint16) []byte {
	pkt := &wire.V2ServerPacket{
		Version: wire.ICQLegacyVersionV2,
		Command: wire.ICQLegacySrvSysMsgDone,
		SeqNum:  seqNum,
	}
	return wire.MarshalV2ServerPacket(pkt)
}

// BuildDepsList constructs a pre-auth response packet (0x0032).
// Historically called "departments list" in iserverd (from its Users_Deps database table).
// Used in the pre-login flow: client sends 0x03F2 with credentials, server validates
// and sends this response, then the client proceeds with the real login (0x03E8).
//
// IMPORTANT: The depslist is ALWAYS sent in V3 packet format, even to V2
// clients. This matches iserverd's v3_send_depslist() which always uses
// V3_PROTO header. The V2 client that sends 0x03F2 expects a V3-format
// response.
//
// V3 format: VERSION(2) + COMMAND(2) + SEQ1(2) + SEQ2(2) + UIN(4) + RESERVED(4)
//            + DEPLIST_VERSION(4) + COUNT(4) + [deps...] + TRAILER(4)
func (b *V2PacketBuilderImpl) BuildDepsList(seqNum uint16, uin uint32) []byte {
	pkt := make([]byte, 28)
	binary.LittleEndian.PutUint16(pkt[0:2], wire.ICQLegacyVersionV3)          // V3 format always
	binary.LittleEndian.PutUint16(pkt[2:4], wire.ICQLegacySrvUserDepsList)    // 0x0032
	binary.LittleEndian.PutUint16(pkt[4:6], 0)                                // servseq
	binary.LittleEndian.PutUint16(pkt[6:8], seqNum)                           // seq2 = client's seq
	binary.LittleEndian.PutUint32(pkt[8:12], uin)                             // UIN
	binary.LittleEndian.PutUint32(pkt[12:16], 0)                              // reserved
	binary.LittleEndian.PutUint32(pkt[16:20], 1)                              // deplist version
	binary.LittleEndian.PutUint32(pkt[20:24], 0)                              // count = 0
	binary.LittleEndian.PutUint16(pkt[24:26], 0x0002)                         // trailer
	binary.LittleEndian.PutUint16(pkt[26:28], 0x002a)                         // trailer

	return pkt
}
