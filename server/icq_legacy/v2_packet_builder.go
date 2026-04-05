package icq_legacy

import (
	"encoding/binary"
	"net"
)

// V2PacketBuilder constructs V2 protocol packets.
// This interface separates packet construction from business logic,
// following the OSCAR foodgroup architecture pattern.
//
// V2 is the simplest ICQ protocol version with no encryption.
// Packet format: VERSION(2) + COMMAND(2) + SEQNUM(2) + DATA
type V2PacketBuilder interface {
	// BuildLoginReply constructs a login success response packet.
	// The packet contains the user's UIN, IP address, and session info.
	BuildLoginReply(session *LegacySession, clientConnectionID uint16) []byte

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
	BuildSearchResult(seqNum uint16, info *UserInfoResult, isLast bool) []byte

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
func (b *V2PacketBuilderImpl) BuildLoginReply(session *LegacySession, clientConnectionID uint16) []byte {
	var clientIP net.IP
	if session.Addr != nil {
		clientIP = session.Addr.IP
	}

	serverSeq := session.NextServerSeqNum()
	pkt := BuildV2LoginReply(serverSeq, clientConnectionID, session.UIN, clientIP)
	pkt.Version = session.Version

	return MarshalV2ServerPacket(pkt)
}

// BuildBadPassword constructs a bad password/authentication failure response.
func (b *V2PacketBuilderImpl) BuildBadPassword(seqNum uint16, version uint16) []byte {
	pkt := BuildV2BadPassword(seqNum)
	pkt.Version = version
	return MarshalV2ServerPacket(pkt)
}

// BuildAck constructs an acknowledgment packet.
func (b *V2PacketBuilderImpl) BuildAck(seqNum uint16, version uint16) []byte {
	pkt := BuildV2Ack(seqNum)
	pkt.Version = version
	return MarshalV2ServerPacket(pkt)
}

// BuildUserOnline constructs a user online notification packet.
// V2 USER_ONLINE format (from protocol spec):
// REMOTE_UIN(4) + REMOTE_IP(4) + REMOTE_PORT(4) + REMOTE_REAL_IP(4) + X1(1) + STATUS(4) + X2(4) = 25 bytes
func (b *V2PacketBuilderImpl) BuildUserOnline(seqNum uint16, uin uint32, status uint32, ip net.IP, port uint16) []byte {
	pkt := BuildV2UserOnline(seqNum, uin, status, ip, port)
	return MarshalV2ServerPacket(pkt)
}

// BuildUserOffline constructs a user offline notification packet.
func (b *V2PacketBuilderImpl) BuildUserOffline(seqNum uint16, uin uint32) []byte {
	pkt := BuildV2UserOffline(seqNum, uin)
	return MarshalV2ServerPacket(pkt)
}

// BuildContactListDone constructs a contact list processing complete response.
func (b *V2PacketBuilderImpl) BuildContactListDone(seqNum uint16) []byte {
	pkt := BuildV2ContactListDone(seqNum)
	return MarshalV2ServerPacket(pkt)
}

// BuildMessage constructs a message delivery packet.
// Format: FROM_UIN(4) + MSG_TYPE(2) + MSG_LEN(2) + MESSAGE
func (b *V2PacketBuilderImpl) BuildMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte {
	pkt := BuildV2Message(seqNum, fromUIN, msgType, message)
	return MarshalV2ServerPacket(pkt)
}

// BuildSearchResult constructs a user search result packet.
// Format: SEQ(2) + UIN(4) + NICK_LEN(2) + NICK + FNAME_LEN(2) + FNAME + LNAME_LEN(2) + LNAME + EMAIL_LEN(2) + EMAIL + AUTH(1)
func (b *V2PacketBuilderImpl) BuildSearchResult(seqNum uint16, info *UserInfoResult, isLast bool) []byte {
	// Convert UserInfoResult to LegacyUserInfo
	wireInfo := &LegacyUserInfo{
		UIN:       info.UIN,
		Nickname:  info.Nickname,
		FirstName: info.FirstName,
		LastName:  info.LastName,
		Email:     info.Email,
		Auth:      info.AuthRequired,
	}

	pkt := BuildV2SearchResult(seqNum, wireInfo, isLast)
	return MarshalV2ServerPacket(pkt)
}

// BuildStatusUpdate constructs a status change notification packet.
// Format: UIN(4) + STATUS(4)
func (b *V2PacketBuilderImpl) BuildStatusUpdate(seqNum uint16, uin uint32, status uint32) []byte {
	pkt := BuildV2StatusUpdate(seqNum, uin, status)
	return MarshalV2ServerPacket(pkt)
}

// BuildOfflineMsgDone constructs an end-of-offline-messages packet.
func (b *V2PacketBuilderImpl) BuildOfflineMsgDone(seqNum uint16) []byte {
	pkt := &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvSysMsgDone,
		SeqNum:  seqNum,
	}
	return MarshalV2ServerPacket(pkt)
}

// BuildDepsList constructs a pre-auth response packet (0x0032).
// Historically called "departments list" in iserverd (from its Users_Deps database table).
// Used in the pre-login flow: client sends 0x03F2 with credentials, server validates
// and sends this response, then the client proceeds with the real login (0x03E8).
//
// V2 format: VERSION(2) + COMMAND(2) + SEQ(2) + DATA
// Data: UIN(4) + DEPLIST_VERSION(4) + COUNT(4) + TRAILER(4)
func (b *V2PacketBuilderImpl) BuildDepsList(seqNum uint16, uin uint32) []byte {
	data := make([]byte, 16)
	offset := 0

	// UIN (4 bytes)
	binary.LittleEndian.PutUint32(data[offset:], uin)
	offset += 4

	// Deplist version (4 bytes)
	binary.LittleEndian.PutUint32(data[offset:], 1)
	offset += 4

	// Count = 0 (empty list) (4 bytes)
	binary.LittleEndian.PutUint32(data[offset:], 0)
	offset += 4

	// Trailer (from iserverd)
	binary.LittleEndian.PutUint16(data[offset:], 0x0002)
	offset += 2
	binary.LittleEndian.PutUint16(data[offset:], 0x002A)
	offset += 2

	pkt := &V2ServerPacket{
		Version: ICQLegacyVersionV2,
		Command: ICQLegacySrvUserDepsList,
		SeqNum:  seqNum,
		Data:    data[:offset],
	}
	return MarshalV2ServerPacket(pkt)
}
