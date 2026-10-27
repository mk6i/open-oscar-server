package client

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/wire"
)

// fakeService accepts one connection on a local listener, completes the
// service signon handshake and hands the server end to serve.
func fakeService(t *testing.T, serve func(flapc *wire.FlapClient)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = nc.Close() }()
		flapc := wire.NewFlapClient(100, nc, nc)
		if err := flapc.SendSignonFrame(nil); err != nil {
			return
		}
		if _, err := flapc.ReceiveSignonFrame(); err != nil {
			return
		}
		if err := flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
			wire.SNAC_0x01_0x03_OServiceHostOnline{FoodGroups: []uint16{wire.OService}}); err != nil {
			return
		}
		serve(flapc)
	}()
	return ln.Addr().String()
}

func receiveFrame(flapc *wire.FlapClient) (wire.SNACFrame, error) {
	flap, err := flapc.ReceiveFLAP()
	if err != nil {
		return wire.SNACFrame{}, err
	}
	frame := wire.SNACFrame{}
	err = wire.UnmarshalBE(&frame, bytes.NewReader(flap.Payload))
	return frame, err
}

func TestConn_request(t *testing.T) {
	addr := fakeService(t, func(flapc *wire.FlapClient) {
		// user info query: an unrelated server SNAC arrives before the reply
		frame, err := receiveFrame(flapc)
		if err != nil {
			return
		}
		_ = flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted, RequestID: wire.ReqIDFromServer},
			wire.SNAC_0x03_0x0C_BuddyDeparted{TLVUserInfo: wire.TLVUserInfo{ScreenName: "bob"}})
		_ = flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceUserInfoUpdate, RequestID: frame.RequestID},
			wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{UserInfo: []wire.TLVUserInfo{{ScreenName: "Alice"}}})

		// user info lookup: error reply
		frame, err = receiveFrame(flapc)
		if err != nil {
			return
		}
		_ = flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateErr, RequestID: frame.RequestID},
			wire.SNACError{Code: wire.ErrorCodeNotLoggedOn})

		// sign the user off for signing on elsewhere
		block := wire.TLVRestBlock{}
		block.Append(wire.NewTLVBE(0x0009, wire.OServiceDiscErrNewLogin))
		_ = flapc.NewSignoff(block)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := connectService(ctx, addr, []byte("cookie"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	defer c.Close()

	reply, err := c.request(ctx, wire.OService, wire.OServiceUserInfoQuery, struct{}{})
	require.NoError(t, err)
	assert.Equal(t, wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{UserInfo: []wire.TLVUserInfo{{ScreenName: "Alice"}}}, reply.Body)

	select {
	case msg := <-c.Messages():
		assert.Equal(t, "bob", msg.Body.(wire.SNAC_0x03_0x0C_BuddyDeparted).ScreenName)
	case <-ctx.Done():
		t.Fatal("unsolicited SNAC not delivered")
	}

	_, err = c.request(ctx, wire.Locate, wire.LocateUserInfoQuery, wire.SNAC_0x02_0x05_LocateUserInfoQuery{ScreenName: "bob"})
	var snacErr *SNACError
	require.ErrorAs(t, err, &snacErr)
	assert.Equal(t, wire.ErrorCodeNotLoggedOn, snacErr.Code)

	select {
	case <-c.Closed():
	case <-ctx.Done():
		t.Fatal("connection didn't close on signoff")
	}
	var signoff *SignoffError
	require.ErrorAs(t, c.Err(), &signoff)
	assert.Equal(t, uint16(wire.OServiceDiscErrNewLogin), signoff.Code)
}
