package oscarclient

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
)

// OSCARServer serves OSCAR connections that in-process clients open.
type OSCARServer interface {
	// ServeConn serves conn as if it had been accepted on the listener at
	// endpointCfg, without rate limiting the SNACs in rateLimitExempt, and
	// returns when the connection ends.
	ServeConn(conn net.Conn, endpointCfg config.Endpoint, rateLimitExempt []wire.SNACType)
}

// Dialer opens in-memory connections to the OSCAR server on behalf of a
// client.
type Dialer struct {
	// Server serves the connections.
	Server OSCARServer
	// Endpoint is the OSCAR listener that the connections appear to arrive
	// on.
	Endpoint config.Endpoint
	// RateLimitExempt lists the SNACs that the server doesn't rate limit on
	// the connections.
	RateLimitExempt []wire.SNACType
	Logger          *slog.Logger
}

// clientAddrConn is the server end of an in-memory OSCAR connection. It
// reports the client's address as its remote address, so that the OSCAR
// server sees where the user really connects from.
type clientAddrConn struct {
	net.Conn
	clientAddr net.Addr
}

func (c clientAddrConn) RemoteAddr() net.Addr {
	return c.clientAddr
}

// dial opens an in-memory connection to the OSCAR server on behalf of the
// client at clientAddr.
func (d Dialer) dial(clientAddr net.Addr) net.Conn {
	clientEnd, serverEnd := net.Pipe()
	go d.Server.ServeConn(clientAddrConn{Conn: serverEnd, clientAddr: clientAddr}, d.Endpoint, d.RateLimitExempt)
	return clientEnd
}

// Authenticate signs on to the OSCAR auth service with the given signon TLVs
// and returns the server's reply TLVs, which hold either a login cookie or an
// error code.
func (d Dialer) Authenticate(clientAddr net.Addr, signonTLVs []wire.TLV) (wire.TLVRestBlock, error) {
	conn := d.dial(clientAddr)
	defer func() { _ = conn.Close() }()

	flapc := wire.NewFlapClient(0, conn, conn)
	if _, err := flapc.ReceiveSignonFrame(); err != nil {
		return wire.TLVRestBlock{}, fmt.Errorf("ReceiveSignonFrame: %w", err)
	}
	if err := flapc.SendSignonFrame(signonTLVs); err != nil {
		return wire.TLVRestBlock{}, fmt.Errorf("SendSignonFrame: %w", err)
	}

	frame, err := flapc.ReceiveFLAP()
	if err != nil {
		return wire.TLVRestBlock{}, fmt.Errorf("ReceiveFLAP: %w", err)
	}

	switch frame.FrameType {
	case wire.FLAPFrameSignoff:
		block := wire.TLVRestBlock{}
		if err := wire.UnmarshalBE(&block, bytes.NewReader(frame.Payload)); err != nil {
			return wire.TLVRestBlock{}, fmt.Errorf("UnmarshalBE: %w", err)
		}
		return block, nil
	case wire.FLAPFrameData:
		// the server answers with a BUCP login response when it rate limits
		// an address that recently signed on with BUCP
		msg, err := DecodeSNAC(frame.Payload)
		if err != nil {
			return wire.TLVRestBlock{}, fmt.Errorf("DecodeSNAC: %w", err)
		}
		reply, ok := msg.Body.(wire.SNAC_0x17_0x03_BUCPLoginResponse)
		if !ok {
			return wire.TLVRestBlock{}, fmt.Errorf("unexpected login reply %s",
				wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup))
		}
		return reply.TLVRestBlock, nil
	default:
		return wire.TLVRestBlock{}, fmt.Errorf("unexpected login reply frame type %d", frame.FrameType)
	}
}

// ConnectService connects to the OSCAR service that loginCookie grants access
// to, either BOS or a chat room, and waits for the server to report the
// service online. The deadline of ctx, if it has one, bounds the wait.
func (d Dialer) ConnectService(ctx context.Context, clientAddr net.Addr, loginCookie []byte) (*FLAPConn, error) {
	conn := d.dial(clientAddr)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	flapc := wire.NewFlapClient(0, conn, conn)
	if err := func() error {
		if _, err := flapc.ReceiveSignonFrame(); err != nil {
			return fmt.Errorf("ReceiveSignonFrame: %w", err)
		}
		if err := flapc.SendSignonFrame([]wire.TLV{wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, loginCookie)}); err != nil {
			return fmt.Errorf("SendSignonFrame: %w", err)
		}

		frame, err := flapc.ReceiveFLAP()
		if err != nil {
			return fmt.Errorf("ReceiveFLAP: %w", err)
		}
		if frame.FrameType == wire.FLAPFrameSignoff {
			return ErrSignedOff
		}
		msg, err := DecodeSNAC(frame.Payload)
		if err != nil {
			return fmt.Errorf("DecodeSNAC: %w", err)
		}
		if _, ok := msg.Body.(wire.SNAC_0x01_0x03_OServiceHostOnline); !ok {
			return fmt.Errorf("expected host online, got %s",
				wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup))
		}
		return nil
	}(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	return NewFLAPConn(conn, flapc, d.Logger), nil
}
