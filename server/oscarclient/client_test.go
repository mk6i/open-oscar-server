package oscarclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/wire"
)

// stubServer serves each connection with serve on a goroutine of its own, or
// refuses it with refuse if set. It records the rate limit exemptions it was
// asked to apply in exempt, if set.
type stubServer struct {
	serve  func(conn net.Conn)
	refuse error
	exempt chan []wire.SNACType
}

func (s stubServer) ServeConn(conn net.Conn, rateLimitExempt []wire.SNACType) error {
	if s.exempt != nil {
		s.exempt <- rateLimitExempt
	}
	if s.refuse != nil {
		_ = conn.Close()
		return s.refuse
	}
	go func() {
		defer func() { _ = conn.Close() }()
		s.serve(conn)
	}()
	return nil
}

func TestClient_serverRefusesConnection(t *testing.T) {
	refused := errors.New("shutting down")
	c := Client{Server: stubServer{refuse: refused}, Logger: slog.Default()}
	clientAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}

	_, err := c.Login(clientAddr, nil)
	assert.ErrorIs(t, err, refused)

	_, err = c.ConnectService(context.Background(), clientAddr, []byte("cookie"))
	assert.ErrorIs(t, err, refused)
}

func TestClient_ConnectService(t *testing.T) {
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
	c := Client{Server: server, RateLimitExempt: exempt, Logger: slog.Default()}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conn, err := c.ConnectService(ctx, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}, []byte("cookie"))
	require.NoError(t, err)
	defer conn.Close()
	go conn.Run(context.Background())

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

func TestClient_ConnectService_handshakeDeadline(t *testing.T) {
	server := stubServer{
		serve: func(conn net.Conn) {
			// never starts the handshake; returns once the client hangs up
			_, _ = conn.Read(make([]byte, 1))
		},
	}
	c := Client{Server: server, Logger: slog.Default()}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := c.ConnectService(ctx, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}, []byte("cookie"))
		errCh <- err
	}()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("ConnectService outlived its deadline")
	}
}

func TestClient_Login(t *testing.T) {
	clientAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}
	signonTLVs := []wire.TLV{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, "me"),
		wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, []byte("roasted")),
	}

	tests := []struct {
		name string
		// reply answers the signon; nil hangs up without answering
		reply   func(t *testing.T, flapc *wire.FlapClient)
		want    wire.TLVRestBlock
		wantErr string
	}{
		{
			name: "signoff with a login cookie",
			reply: func(t *testing.T, flapc *wire.FlapClient) {
				assert.NoError(t, flapc.NewSignoff(wire.TLVRestBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("cookie")),
				}}))
			},
			want: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("cookie")),
			}},
		},
		{
			name: "signoff with an error code",
			reply: func(t *testing.T, flapc *wire.FlapClient) {
				assert.NoError(t, flapc.NewSignoff(wire.TLVRestBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidPassword),
				}}))
			},
			want: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrInvalidPassword),
			}},
		},
		{
			name: "BUCP login response",
			reply: func(t *testing.T, flapc *wire.FlapClient) {
				assert.NoError(t, flapc.SendSNAC(
					wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPLoginResponse},
					wire.SNAC_0x17_0x03_BUCPLoginResponse{TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrRateLimitExceeded),
					}}}))
			},
			want: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrRateLimitExceeded),
			}},
		},
		{
			name: "SNAC other than a BUCP login response",
			reply: func(t *testing.T, flapc *wire.FlapClient) {
				assert.NoError(t, flapc.SendSNAC(
					wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
					wire.SNAC_0x01_0x03_OServiceHostOnline{}))
			},
			wantErr: "unexpected login reply",
		},
		{
			name: "frame other than signoff or data",
			reply: func(t *testing.T, flapc *wire.FlapClient) {
				assert.NoError(t, flapc.SendKeepAliveFrame())
			},
			wantErr: "unexpected login reply frame type",
		},
		{
			name:    "server hangs up without replying",
			wantErr: "ReceiveFLAP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := stubServer{
				serve: func(conn net.Conn) {
					assert.Equal(t, clientAddr, conn.RemoteAddr())
					flapc := wire.NewFlapClient(100, conn, conn)
					assert.NoError(t, flapc.SendSignonFrame(nil))
					signon, err := flapc.ReceiveSignonFrame()
					assert.NoError(t, err)
					assert.Equal(t, wire.TLVList(signonTLVs), signon.TLVList)
					if tt.reply != nil {
						tt.reply(t, flapc)
					}
				},
			}
			c := Client{Server: server, Logger: slog.Default()}

			got, err := c.Login(clientAddr, signonTLVs)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
