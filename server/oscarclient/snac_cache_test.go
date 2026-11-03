package oscarclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestSNACCache_addAndTake(t *testing.T) {
	c := NewSNACCache()

	first := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.Add(&first, statusQuery{screenName: "them"})
	second := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilRequest}
	c.Add(&second, warning{})

	assert.Equal(t, uint32(1), first.RequestID)
	assert.Equal(t, uint32(2), second.RequestID)

	req, ok := c.Take(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: 1})
	assert.True(t, ok)
	assert.Equal(t, first, req.Frame)
	assert.Equal(t, statusQuery{screenName: "them"}, req.Data)

	// an entry is removed once taken
	_, ok = c.Take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: 1})
	assert.False(t, ok)

	req, ok = c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMErr, RequestID: 2})
	assert.True(t, ok)
	assert.Equal(t, warning{}, req.Data)
}

func TestSNACCache_takeRequiresMatchingFoodGroup(t *testing.T) {
	c := NewSNACCache()

	frame := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.Add(&frame, statusQuery{screenName: "them"})

	// a relayed SNAC that happens to carry the same request ID is not a reply
	_, ok := c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent, RequestID: 1})
	assert.False(t, ok)

	// the real reply still finds the request
	_, ok = c.Take(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: 1})
	assert.True(t, ok)
}

func TestSNACCache_remove(t *testing.T) {
	c := NewSNACCache()

	frame := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.Add(&frame, nil)
	c.Remove(frame.RequestID)

	_, ok := c.Take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: frame.RequestID})
	assert.False(t, ok)
}

func TestSNACCache_sweepsExpiredEntries(t *testing.T) {
	now := time.Now()
	c := NewSNACCache()
	c.timeNow = func() time.Time { return now }

	old := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}
	c.Add(&old, nil)

	now = now.Add(snacCacheTTL + time.Second)
	fresh := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}
	c.Add(&fresh, nil)

	_, ok := c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, RequestID: old.RequestID})
	assert.False(t, ok)
	_, ok = c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, RequestID: fresh.RequestID})
	assert.True(t, ok)
}

func TestSNACCache_requestIDWrapsBeforeServerRange(t *testing.T) {
	c := NewSNACCache()
	c.lastID = wire.ReqIDFromServer - 1

	frame := wire.SNACFrame{FoodGroup: wire.ICBM}
	c.Add(&frame, nil)

	assert.Equal(t, uint32(1), frame.RequestID)
}

func TestSNACCache_Pending(t *testing.T) {
	c := NewSNACCache()

	first := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.Add(&first, statusQuery{screenName: "them"})
	second := wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilRequest}
	c.Add(&second, warning{})

	pending := c.Pending()
	assert.Len(t, pending, 2)
	assert.Equal(t, first, pending[first.RequestID].Frame)
	assert.Equal(t, warning{}, pending[second.RequestID].Data)

	// the copy doesn't change with the cache
	c.Remove(first.RequestID)
	assert.Len(t, pending, 2)
	assert.Len(t, c.Pending(), 1)
}

func TestSNACCache_Peek(t *testing.T) {
	c := NewSNACCache()

	frame := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	c.Add(&frame, statusQuery{screenName: "them"})

	// a SNAC from another food group doesn't match
	_, ok := c.Peek(wire.SNACFrame{FoodGroup: wire.ICBM, RequestID: frame.RequestID})
	assert.False(t, ok)

	req, ok := c.Peek(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: frame.RequestID})
	assert.True(t, ok)
	assert.Equal(t, statusQuery{screenName: "them"}, req.Data)

	// peeking leaves the request in place
	_, ok = c.Take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: frame.RequestID})
	assert.True(t, ok)
}
