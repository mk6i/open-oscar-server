package oscarclient

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// OSCARServer serves OSCAR connections that in-process clients open.
type OSCARServer interface {
	// ServeConn starts serving conn as if it had been accepted on one of
	// the server's listeners. The server owns the goroutine that serves it.
	// It returns an error if the server won't serve the connection.
	ServeConn(conn net.Conn) error
}

// Client signs users on to the OSCAR server over in-memory connections, as
// an ordinary OSCAR client would.
type Client struct {
	// Server serves the connections.
	Server OSCARServer
	// Logger records problems on the connections, such as SNACs that don't
	// decode or a consumer that falls too far behind.
	Logger *slog.Logger
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
func (c Client) dial(clientAddr net.Addr) (net.Conn, error) {
	clientEnd, serverEnd := net.Pipe()
	if err := c.Server.ServeConn(clientAddrConn{Conn: serverEnd, clientAddr: clientAddr}); err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("ServeConn: %w", err)
	}
	return clientEnd, nil
}

// Login signs on to the OSCAR auth service with the given signon TLVs
// and returns the server's reply TLVs, which hold either a login cookie or an
// error code.
func (c Client) Login(clientAddr net.Addr, signonTLVs []wire.TLV) (wire.TLVRestBlock, error) {
	conn, err := c.dial(clientAddr)
	if err != nil {
		return wire.TLVRestBlock{}, err
	}
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
		msg, err := decodeSNAC(frame.Payload)
		if err != nil {
			return wire.TLVRestBlock{}, fmt.Errorf("decodeSNAC: %w", err)
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
// service online. The deadline of ctx, if it has one, bounds the wait. The
// caller must start the returned connection's Run right away.
func (c Client) ConnectService(ctx context.Context, clientAddr net.Addr, loginCookie []byte) (*FLAPConn, error) {
	conn, err := c.dial(clientAddr)
	if err != nil {
		return nil, err
	}
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
		msg, err := decodeSNAC(frame.Payload)
		if err != nil {
			return fmt.Errorf("decodeSNAC: %w", err)
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
	return newFLAPConn(conn, flapc, c.Logger), nil
}
