// Package oscarclient connects in-process protocol servers, such as TOC, to
// the OSCAR server as ordinary OSCAR clients.
package oscarclient

import (
	"errors"
	"log/slog"
	"net"
	"sync"

	"github.com/mk6i/open-oscar-server/wire"
)

// ErrSignedOff indicates that the OSCAR server refused or ended a connection
// with a signoff frame.
var ErrSignedOff = errors.New("signed off by OSCAR server")

// Conn is a client's connection to an OSCAR service, either BOS or a chat
// room.
type Conn interface {
	// SendSNAC sends a SNAC to the OSCAR server.
	SendSNAC(frame wire.SNACFrame, body any) error
	// Messages returns the SNACs received from the server, replies and
	// server-initiated messages alike, in arrival order.
	Messages() <-chan wire.SNACMessage
	// Closed returns a channel that is closed when the connection closes.
	Closed() <-chan struct{}
	// Close closes the connection.
	Close()
}

// QueueLimit is how many received SNACs a connection holds for its consumer,
// the same as an OSCAR session's message queue.
const QueueLimit = 1000

// FLAPConn is a Conn over a FLAP connection to the OSCAR server.
type FLAPConn struct {
	conn   net.Conn
	flapc  *wire.FlapClient
	logger *slog.Logger
	// msgs holds SNACs received from the server until the consumer takes
	// them. read never waits on it, so it keeps reading from the server even
	// while the consumer is busy; otherwise the server's writes would block,
	// and with them its reads of the SNACs the client sends.
	msgs      chan wire.SNACMessage
	closed    chan struct{}
	closeOnce sync.Once
}

// NewFLAPConn wraps a FLAP connection that has finished signing on to an
// OSCAR service and starts reading SNACs from it.
func NewFLAPConn(conn net.Conn, flapc *wire.FlapClient, logger *slog.Logger) *FLAPConn {
	c := &FLAPConn{
		conn:   conn,
		flapc:  flapc,
		logger: logger,
		msgs:   make(chan wire.SNACMessage, QueueLimit),
		closed: make(chan struct{}),
	}
	go c.read()
	return c
}

func (c *FLAPConn) read() {
	defer c.Close()
	for {
		frame, err := c.flapc.ReceiveFLAP()
		if err != nil {
			return
		}
		switch frame.FrameType {
		case wire.FLAPFrameData:
			msg, err := DecodeSNAC(frame.Payload)
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
