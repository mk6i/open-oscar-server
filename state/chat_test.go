package state

import (
	"testing"

	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
)

func TestChatRoom_TLVList(t *testing.T) {
	room := NewChatRoom("chat-room-name", NewIdentScreenName(""), PublicExchange)

	have := room.TLVList()
	want := []wire.TLV{
		wire.NewTLVBE(wire.ChatRoomTLVFlags, uint16(15)),
		wire.NewTLVBE(wire.ChatRoomTLVCreateTime, uint32(room.createTime.Unix())),
		wire.NewTLVBE(wire.ChatRoomTLVMaxMsgLen, uint16(1024)),
		wire.NewTLVBE(wire.ChatRoomTLVMaxOccupancy, uint16(100)),
		wire.NewTLVBE(wire.ChatRoomTLVNavCreatePerms, uint8(2)),
		wire.NewTLVBE(wire.ChatRoomTLVFullyQualifiedName, room.name),
		wire.NewTLVBE(wire.ChatRoomTLVRoomName, room.name),
		wire.NewTLVBE(wire.ChatRoomTLVMaxMsgVisLen, uint16(1024)),
	}

	assert.Equal(t, want, have)
}
