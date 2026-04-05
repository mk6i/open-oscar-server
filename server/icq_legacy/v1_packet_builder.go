package icq_legacy

import (
	"encoding/binary"
	"net"
)

// V1PacketBuilder constructs V1 protocol packets.
// V1 uses the same wire format as V2, but stamps version 1 in the header.
// This wraps V2PacketBuilder and patches the version field in each response.
type V1PacketBuilder struct {
	v2 V2PacketBuilder
}

// NewV1PacketBuilder creates a new V1PacketBuilder instance.
func NewV1PacketBuilder() *V1PacketBuilder {
	return &V1PacketBuilder{v2: NewV2PacketBuilder()}
}

// patchVersion overwrites the first 2 bytes (version field) with V1.
func patchVersion(pkt []byte) []byte {
	if len(pkt) >= 2 {
		binary.LittleEndian.PutUint16(pkt[0:2], ICQLegacyVersionV1)
	}
	return pkt
}

func (b *V1PacketBuilder) BuildLoginReply(session *LegacySession, clientSeqNum uint16) []byte {
	return patchVersion(b.v2.BuildLoginReply(session, clientSeqNum))
}

func (b *V1PacketBuilder) BuildBadPassword(seqNum uint16, version uint16) []byte {
	return patchVersion(b.v2.BuildBadPassword(seqNum, version))
}

func (b *V1PacketBuilder) BuildAck(seqNum uint16, version uint16) []byte {
	return patchVersion(b.v2.BuildAck(seqNum, version))
}

func (b *V1PacketBuilder) BuildUserOnline(seqNum uint16, uin uint32, status uint32, ip net.IP, port uint16) []byte {
	return patchVersion(b.v2.BuildUserOnline(seqNum, uin, status, ip, port))
}

func (b *V1PacketBuilder) BuildUserOffline(seqNum uint16, uin uint32) []byte {
	return patchVersion(b.v2.BuildUserOffline(seqNum, uin))
}

func (b *V1PacketBuilder) BuildContactListDone(seqNum uint16) []byte {
	return patchVersion(b.v2.BuildContactListDone(seqNum))
}

func (b *V1PacketBuilder) BuildMessage(seqNum uint16, fromUIN uint32, msgType uint16, message string) []byte {
	return patchVersion(b.v2.BuildMessage(seqNum, fromUIN, msgType, message))
}

func (b *V1PacketBuilder) BuildSearchResult(seqNum uint16, info *UserInfoResult, isLast bool) []byte {
	return patchVersion(b.v2.BuildSearchResult(seqNum, info, isLast))
}

func (b *V1PacketBuilder) BuildStatusUpdate(seqNum uint16, uin uint32, status uint32) []byte {
	return patchVersion(b.v2.BuildStatusUpdate(seqNum, uin, status))
}

func (b *V1PacketBuilder) BuildOfflineMsgDone(seqNum uint16) []byte {
	return patchVersion(b.v2.BuildOfflineMsgDone(seqNum))
}

// BuildDepsList returns a V1-format depslist response.
// Unlike V2 which sends V3-format depslist, V1 clients expect a simpler
// V1/V2-format response: VERSION(2) + COMMAND(2) + SEQ(2) + DATA
func (b *V1PacketBuilder) BuildDepsList(seqNum uint16, uin uint32) []byte {
	// Build a minimal V1-format depslist response
	// The client just needs to see a successful response to proceed to CMD_LOGIN
	data := make([]byte, 12)
	// Deplist version (4 bytes)
	binary.LittleEndian.PutUint32(data[0:4], 1)
	// Count = 0 (4 bytes)
	binary.LittleEndian.PutUint32(data[4:8], 0)
	// Trailer
	binary.LittleEndian.PutUint16(data[8:10], 0x0002)
	binary.LittleEndian.PutUint16(data[10:12], 0x002a)

	pkt := &V2ServerPacket{
		Version: ICQLegacyVersionV1,
		Command: ICQLegacySrvUserDepsList,
		SeqNum:  seqNum,
		Data:    data,
	}
	return MarshalV2ServerPacket(pkt)
}
