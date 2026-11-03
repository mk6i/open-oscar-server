package oscarclient

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
)

// stubServer serves each connection with serve, recording the rate limit
// exemptions it was asked to apply.
type stubServer struct {
	exempt chan []wire.SNACType
	serve  func(conn net.Conn)
}

func (s stubServer) ServeConn(conn net.Conn, _ config.Endpoint, rateLimitExempt []wire.SNACType) {
	defer func() { _ = conn.Close() }()
	s.exempt <- rateLimitExempt
	s.serve(conn)
}

func TestDialer_ConnectService(t *testing.T) {
	exempt := []wire.SNACType{{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}}
	later := make(chan struct{})
	server := stubServer{
		exempt: make(chan []wire.SNACType, 1),
		serve: func(conn net.Conn) {
			flapc := wire.NewFlapClient(100, conn, conn)
			assert.NoError(t, flapc.SendSignonFrame(nil))
			_, err := flapc.ReceiveSignonFrame()
			assert.NoError(t, err)
			assert.NoError(t, flapc.SendSNAC(
				wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
				wire.SNAC_0x01_0x03_OServiceHostOnline{}))

			<-later
			assert.NoError(t, flapc.SendSNAC(
				wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceEvilNotification},
				wire.SNAC_0x01_0x10_OServiceEvilNotification{NewEvil: 1}))
		},
	}
	d := Dialer{Server: server, RateLimitExempt: exempt, Logger: slog.Default()}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conn, err := d.ConnectService(ctx, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}, []byte("cookie"))
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, exempt, <-server.exempt)

	// The handshake's deadline doesn't outlive it.
	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)
	close(later)
	select {
	case msg := <-conn.Messages():
		assert.Equal(t, wire.SNAC_0x01_0x10_OServiceEvilNotification{NewEvil: 1}, msg.Body)
	case <-conn.Closed():
		t.Fatal("the connection closed after the handshake's deadline")
	case <-time.After(time.Second):
		t.Fatal("no SNAC arrived")
	}
}

func TestDialer_ConnectService_handshakeDeadline(t *testing.T) {
	server := stubServer{
		exempt: make(chan []wire.SNACType, 1),
		serve: func(conn net.Conn) {
			// never starts the handshake; returns once the client hangs up
			_, _ = conn.Read(make([]byte, 1))
		},
	}
	d := Dialer{Server: server, Logger: slog.Default()}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := d.ConnectService(ctx, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}, []byte("cookie"))
		errCh <- err
	}()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("ConnectService outlived its deadline")
	}
}
