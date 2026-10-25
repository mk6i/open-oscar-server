package toc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestSNACCache_addAndTake(t *testing.T) {
	c := newSNACCache()

	first := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.add(&first, getStatusReqCtx{screenName: "them"})
	second := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilRequest}
	c.add(&second, evilReqCtx{})

	assert.Equal(t, uint32(1), first.RequestID)
	assert.Equal(t, uint32(2), second.RequestID)

	req, ok := c.take(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: 1})
	assert.True(t, ok)
	assert.Equal(t, first, req.frame)
	assert.Equal(t, getStatusReqCtx{screenName: "them"}, req.data)

	// an entry is removed once taken
	_, ok = c.take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: 1})
	assert.False(t, ok)

	req, ok = c.take(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMErr, RequestID: 2})
	assert.True(t, ok)
	assert.Equal(t, evilReqCtx{}, req.data)
}

func TestSNACCache_takeRequiresMatchingFoodGroup(t *testing.T) {
	c := newSNACCache()

	frame := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.add(&frame, getStatusReqCtx{screenName: "them"})

	// a relayed SNAC that happens to carry the same request ID is not a reply
	_, ok := c.take(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent, RequestID: 1})
	assert.False(t, ok)

	// the real reply still finds the request
	_, ok = c.take(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: 1})
	assert.True(t, ok)
}

func TestSNACCache_remove(t *testing.T) {
	c := newSNACCache()

	frame := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.add(&frame, nil)
	c.remove(frame.RequestID)

	_, ok := c.take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: frame.RequestID})
	assert.False(t, ok)
}

func TestSNACCache_sweepsExpiredEntries(t *testing.T) {
	now := time.Now()
	c := newSNACCache()
	c.timeNow = func() time.Time { return now }

	old := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}
	c.add(&old, nil)

	now = now.Add(snacCacheTTL + time.Second)
	fresh := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}
	c.add(&fresh, nil)

	_, ok := c.take(wire.SNACFrame{FoodGroup: wire.ICBM, RequestID: old.RequestID})
	assert.False(t, ok)
	_, ok = c.take(wire.SNACFrame{FoodGroup: wire.ICBM, RequestID: fresh.RequestID})
	assert.True(t, ok)
}

func TestSNACCache_requestIDWrapsBeforeServerRange(t *testing.T) {
	c := newSNACCache()
	c.lastID = wire.ReqIDFromServer - 1

	frame := wire.SNACFrame{FoodGroup: wire.ICBM}
	c.add(&frame, nil)

	assert.Equal(t, uint32(1), frame.RequestID)
}
