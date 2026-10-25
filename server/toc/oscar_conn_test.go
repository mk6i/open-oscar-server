package toc

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestFLAPConn_readsWhileConsumerIsBusy(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	server := wire.NewFlapClient(0, serverEnd, serverEnd)
	conn := newFLAPConn(clientEnd, wire.NewFlapClient(0, clientEnd, clientEnd), slog.Default())
	defer conn.Close()

	// nobody reads conn.Messages() yet, so each send returns only because the
	// connection keeps reading from the pipe
	for i := uint32(1); i <= 100; i++ {
		assert.NoError(t, server.SendSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted, RequestID: i},
			wire.SNAC_0x03_0x0C_BuddyDeparted{}))
	}

	for i := uint32(1); i <= 100; i++ {
		select {
		case msg := <-conn.Messages():
			assert.Equal(t, i, msg.Frame.RequestID)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for SNAC %d", i)
		}
	}
}

// marshalSNAC returns the FLAP payload of a SNAC.
func marshalSNAC(t *testing.T, frame wire.SNACFrame, body any) []byte {
	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(frame, buf))
	assert.NoError(t, wire.MarshalBE(body, buf))
	return buf.Bytes()
}

func TestDecodeSNAC(t *testing.T) {
	cases := []struct {
		name    string
		payload func(t *testing.T) []byte
		want    wire.SNACMessage
		wantErr bool
	}{
		{
			name: "SNAC TOC handles",
			payload: func(t *testing.T) []byte {
				return marshalSNAC(t, wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived, RequestID: 7},
					wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: wire.TLVUserInfo{ScreenName: "them", WarningLevel: 10}})
			},
			want: newSNAC(wire.Buddy, wire.BuddyArrived, 7,
				wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: wire.TLVUserInfo{ScreenName: "them", WarningLevel: 10}}),
		},
		{
			name: "relayed feedbag insert",
			payload: func(t *testing.T) []byte {
				return marshalSNAC(t, wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
					wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{{Name: "them"}}})
			},
			want: newSNAC(wire.Feedbag, wire.FeedbagInsertItem, 0,
				wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{{Name: "them"}}}),
		},
		{
			name: "error in any food group",
			payload: func(t *testing.T) []byte {
				return marshalSNAC(t, wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMErr, RequestID: 3},
					wire.SNACError{Code: wire.ErrorCodeNotLoggedOn})
			},
			want: newSNAC(wire.ICBM, wire.ICBMErr, 3, wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}),
		},
		{
			name: "SNAC TOC doesn't handle has no body",
			payload: func(t *testing.T) []byte {
				return marshalSNAC(t, wire.SNACFrame{FoodGroup: wire.Stats, SubGroup: wire.StatsSetMinReportInterval},
					wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{MinReportInterval: 1})
			},
			want: wire.SNACMessage{Frame: wire.SNACFrame{FoodGroup: wire.Stats, SubGroup: wire.StatsSetMinReportInterval}},
		},
		{
			name: "truncated SNAC frame",
			payload: func(t *testing.T) []byte {
				return []byte{0x00, 0x03}
			},
			wantErr: true,
		},
		{
			name: "truncated SNAC body",
			payload: func(t *testing.T) []byte {
				return marshalSNAC(t, wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived}, []byte{0x05, 't'})
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSNAC(tc.payload(t))
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFLAPConn(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	server := wire.NewFlapClient(0, serverEnd, serverEnd)
	conn := newFLAPConn(clientEnd, wire.NewFlapClient(0, clientEnd, clientEnd), slog.Default())

	// SNACs sent to the server arrive intact
	go func() {
		assert.NoError(t, conn.SendSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyAddBuddies, RequestID: 1},
			wire.SNAC_0x03_0x04_BuddyAddBuddies{}))
	}()
	frame := wire.SNACFrame{}
	assert.NoError(t, server.ReceiveSNAC(&frame, &wire.SNAC_0x03_0x04_BuddyAddBuddies{}))
	assert.Equal(t, wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyAddBuddies, RequestID: 1}, frame)

	// SNACs from the server are decoded and delivered in order
	assert.NoError(t, server.SendSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted},
		wire.SNAC_0x03_0x0C_BuddyDeparted{TLVUserInfo: wire.TLVUserInfo{ScreenName: "first"}}))
	assert.NoError(t, server.SendSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted},
		wire.SNAC_0x03_0x0C_BuddyDeparted{TLVUserInfo: wire.TLVUserInfo{ScreenName: "second"}}))
	for _, want := range []string{"first", "second"} {
		msg := <-conn.Messages()
		assert.Equal(t, want, msg.Body.(wire.SNAC_0x03_0x0C_BuddyDeparted).ScreenName)
	}

	// a signoff from the server closes the connection
	assert.NoError(t, server.NewSignoff(wire.TLVRestBlock{}))
	select {
	case <-conn.Closed():
	case <-time.After(time.Second):
		t.Fatal("connection didn't close after signoff")
	}
	_, err := server.ReceiveFLAP()
	assert.Error(t, err)
}

func TestFLAPConn_closesWhenConsumerFallsBehind(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	server := wire.NewFlapClient(0, serverEnd, serverEnd)
	conn := newFLAPConn(clientEnd, wire.NewFlapClient(0, clientEnd, clientEnd), slog.Default())

	// nobody reads conn.Messages(), so its buffer fills up
	go func() {
		for {
			err := server.SendSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted},
				wire.SNAC_0x03_0x0C_BuddyDeparted{TLVUserInfo: wire.TLVUserInfo{ScreenName: "them"}})
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-conn.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("connection didn't close after its buffer filled up")
	}
}

func TestFLAPConn_Close(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	conn := newFLAPConn(clientEnd, wire.NewFlapClient(0, clientEnd, clientEnd), slog.Default())

	conn.Close()
	conn.Close()

	_, err := wire.NewFlapClient(0, serverEnd, serverEnd).ReceiveFLAP()
	assert.Error(t, err)
	<-conn.Closed()
}
