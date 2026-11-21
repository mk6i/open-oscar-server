package oscarclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestRequestTracker_trackAndTake(t *testing.T) {
	c := NewRequestTracker()

	first := c.Track(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}, "status of them")
	second := c.Track(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilRequest}, "warning")

	assert.Equal(t, uint32(1), first.RequestID)
	assert.Equal(t, uint32(2), second.RequestID)

	frame, data, ok := c.Take(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: 1})
	assert.True(t, ok)
	assert.Equal(t, first, frame)
	assert.Equal(t, "status of them", data)

	// an entry is removed once taken
	_, _, ok = c.Take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: 1})
	assert.False(t, ok)

	frame, data, ok = c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMErr, RequestID: 2})
	assert.True(t, ok)
	assert.Equal(t, second, frame)
	assert.Equal(t, "warning", data)
}

func TestRequestTracker_remove(t *testing.T) {
	c := NewRequestTracker()

	frame := c.Track(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}, nil)
	c.Remove(frame.RequestID)

	_, _, ok := c.Take(wire.SNACFrame{FoodGroup: wire.Locate, RequestID: frame.RequestID})
	assert.False(t, ok)
}

func TestRequestTracker_sweepsExpiredEntries(t *testing.T) {
	now := time.Now()
	c := NewRequestTracker()
	c.timeNow = func() time.Time { return now }

	old := c.Track(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}, nil)

	now = now.Add(requestTTL + time.Second)
	fresh := c.Track(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}, nil)

	_, _, ok := c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, RequestID: old.RequestID})
	assert.False(t, ok)
	_, _, ok = c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, RequestID: fresh.RequestID})
	assert.True(t, ok)
}

func TestRequestTracker_requestIDWrapsBeforeServerRange(t *testing.T) {
	c := NewRequestTracker()
	c.lastID = wire.ReqIDFromServer - 1

	frame := c.Track(wire.SNACFrame{FoodGroup: wire.ICBM}, nil)

	assert.Equal(t, uint32(1), frame.RequestID)
}

func TestRequestTracker_takeIgnoresServerRequestIDs(t *testing.T) {
	cases := []struct {
		name      string
		requestID uint32
	}{
		{name: "request ID left unset", requestID: 0},
		{name: "server request ID", requestID: wire.ReqIDFromServer},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewRequestTracker()
			frame := c.Track(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}, nil)

			_, _, ok := c.Take(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToClient, RequestID: tc.requestID})
			assert.False(t, ok)

			// the tracked request is still pending
			_, _, ok = c.Take(frame)
			assert.True(t, ok)
		})
	}
}
