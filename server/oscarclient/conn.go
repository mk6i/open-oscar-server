// Package oscarclient connects in-process protocol servers, such as TOC, to
// the OSCAR server as ordinary OSCAR clients.
package oscarclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/mk6i/open-oscar-server/wire"
)

// ErrSignedOff indicates that the OSCAR server refused or ended a connection
// with a signoff frame.
var ErrSignedOff = errors.New("signed off by OSCAR server")

// queueLimit is how many received SNACs a connection holds for its consumer,
// the same as an OSCAR session's message queue.
const queueLimit = 1000

// FLAPConn is a client's FLAP connection to an OSCAR service, either BOS or
// a chat room.
type FLAPConn struct {
	conn   net.Conn
	flapc  *wire.FlapClient
	logger *slog.Logger
	// msgs holds SNACs received from the server until the consumer takes
	// them. Run never waits on it, so it keeps reading from the server even
	// while the consumer is busy; otherwise the server's writes would block,
	// and with them its reads of the SNACs the client sends.
	msgs      chan wire.SNACMessage
	closed    chan struct{}
	closeOnce sync.Once
}

// newFLAPConn wraps a FLAP connection that has finished signing on to an
// OSCAR service.
func newFLAPConn(conn net.Conn, flapc *wire.FlapClient, logger *slog.Logger) *FLAPConn {
	return &FLAPConn{
		conn:   conn,
		flapc:  flapc,
		logger: logger,
		msgs:   make(chan wire.SNACMessage, queueLimit),
		closed: make(chan struct{}),
	}
}

// Run reads SNACs from the server into Messages until the connection closes
// from either end or ctx is done, then closes the connection. The consumer
// runs it on a goroutine of its own, from the moment the connection is
// returned: until Run is reading, the server's writes to the connection
// block, and with them its reads of the SNACs the client sends.
func (c *FLAPConn) Run(ctx context.Context) {
	stop := context.AfterFunc(ctx, c.Close)
	defer stop()
	defer c.Close()
	for {
		frame, err := c.flapc.ReceiveFLAP()
		if err != nil {
			return
		}
		switch frame.FrameType {
		case wire.FLAPFrameData:
			msg, err := decodeSNAC(frame.Payload)
			if err != nil {
				c.logger.Debug("unable to decode SNAC from OSCAR server", "err", err.Error())
				continue
			}
			select {
			case c.msgs <- msg:
			default:
				// like the OSCAR server, disconnect a client that falls too far behind
				c.logger.Warn("client isn't keeping up with the OSCAR server, disconnecting")
				return
			}
		case wire.FLAPFrameSignoff:
			return
		}
	}
}

// SendSNAC sends a SNAC to the OSCAR server.
func (c *FLAPConn) SendSNAC(frame wire.SNACFrame, body any) error {
	return c.flapc.SendSNAC(frame, body)
}

// Messages returns the SNACs received from the server in arrival order.
func (c *FLAPConn) Messages() <-chan wire.SNACMessage {
	return c.msgs
}

// Closed returns a channel that is closed when the connection closes.
func (c *FLAPConn) Closed() <-chan struct{} {
	return c.closed
}

// Close closes the connection. It is safe to call more than once.
func (c *FLAPConn) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}
