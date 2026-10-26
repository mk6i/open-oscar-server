package toc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/mk6i/open-oscar-server/wire"
)

// errSignedOff indicates that the OSCAR server refused or ended a connection
// with a signoff frame.
var errSignedOff = errors.New("signed off by OSCAR server")

// oscarConn is a TOC user's connection to an OSCAR service, either BOS or a
// chat room.
type oscarConn interface {
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

// snacQueueLimit is how many received SNACs a connection holds for the TOC
// consumer, the same as an OSCAR session's message queue.
const snacQueueLimit = 1000

// flapConn is an oscarConn over a FLAP connection to the OSCAR server.
type flapConn struct {
	conn   net.Conn
	flapc  *wire.FlapClient
	logger *slog.Logger
	// msgs holds SNACs received from the server until the TOC consumer takes
	// them. read never waits on it, so it keeps reading from the server even
	// while the consumer is busy; otherwise the server's writes would block,
	// and with them its reads of the SNACs TOC sends.
	msgs      chan wire.SNACMessage
	closed    chan struct{}
	closeOnce sync.Once
}

// newFLAPConn wraps a FLAP connection that has finished signing on to an
// OSCAR service and starts reading SNACs from it.
func newFLAPConn(conn net.Conn, flapc *wire.FlapClient, logger *slog.Logger) *flapConn {
	c := &flapConn{
		conn:   conn,
		flapc:  flapc,
		logger: logger,
		msgs:   make(chan wire.SNACMessage, snacQueueLimit),
		closed: make(chan struct{}),
	}
	go c.read()
	return c
}

func (c *flapConn) read() {
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
				c.logger.Warn("TOC client isn't keeping up with the OSCAR server, disconnecting")
				return
			}
		case wire.FLAPFrameSignoff:
			return
		}
	}
}

func (c *flapConn) SendSNAC(frame wire.SNACFrame, body any) error {
	return c.flapc.SendSNAC(frame, body)
}

func (c *flapConn) Messages() <-chan wire.SNACMessage {
	return c.msgs
}

func (c *flapConn) Closed() <-chan struct{} {
	return c.closed
}

func (c *flapConn) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}

// clientAddrConn is the server end of an in-memory OSCAR connection. It
// reports the TOC client's address as its remote address, so that the OSCAR
// server sees where the user really connects from.
type clientAddrConn struct {
	net.Conn
	clientAddr net.Addr
}

func (c clientAddrConn) RemoteAddr() net.Addr {
	return c.clientAddr
}

// dialOSCAR opens an in-memory connection to the OSCAR server on behalf of
// the TOC client at clientAddr.
func (s OSCARProxy) dialOSCAR(clientAddr net.Addr) net.Conn {
	clientEnd, serverEnd := net.Pipe()
	go s.OSCARServer.ServeConn(clientAddrConn{Conn: serverEnd, clientAddr: clientAddr}, s.OSCAREndpoint)
	return clientEnd
}

// authenticate signs on to the OSCAR auth service with the given signon TLVs
// and returns the server's reply TLVs, which hold either a login cookie or an
// error code.
func (s OSCARProxy) authenticate(clientAddr net.Addr, signonTLVs []wire.TLV) (wire.TLVRestBlock, error) {
	conn := s.dialOSCAR(clientAddr)
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

// connectService connects to the OSCAR service that loginCookie grants access
// to, either BOS or a chat room, and waits for the server to report the
// service online.
func (s OSCARProxy) connectService(clientAddr net.Addr, loginCookie []byte) (*flapConn, error) {
	conn := s.dialOSCAR(clientAddr)

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
			return errSignedOff
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

	return newFLAPConn(conn, flapc, s.Logger), nil
}

// snacDecoders unmarshal the bodies of the SNACs a TOC connection handles,
// keyed by food group and subgroup.
var snacDecoders = map[[2]uint16]func(r io.Reader) (any, error){
	{wire.OService, wire.OServiceHostOnline}:       decodeBody[wire.SNAC_0x01_0x03_OServiceHostOnline],
	{wire.OService, wire.OServiceServiceResponse}:  decodeBody[wire.SNAC_0x01_0x05_OServiceServiceResponse],
	{wire.OService, wire.OServiceRateParamChange}:  decodeBody[wire.SNAC_0x01_0x0A_OServiceRateParamsChange],
	{wire.OService, wire.OServiceUserInfoUpdate}:   decodeBody[wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate],
	{wire.OService, wire.OServiceEvilNotification}: decodeBody[wire.SNAC_0x01_0x10_OServiceEvilNotification],
	{wire.Locate, wire.LocateUserInfoReply}:        decodeBody[wire.SNAC_0x02_0x06_LocateUserInfoReply],
	{wire.Buddy, wire.BuddyArrived}:                decodeBody[wire.SNAC_0x03_0x0B_BuddyArrived],
	{wire.Buddy, wire.BuddyDeparted}:               decodeBody[wire.SNAC_0x03_0x0C_BuddyDeparted],
	{wire.ICBM, wire.ICBMChannelMsgToClient}:       decodeBody[wire.SNAC_0x04_0x07_ICBMChannelMsgToClient],
	{wire.ICBM, wire.ICBMEvilReply}:                decodeBody[wire.SNAC_0x04_0x09_ICBMEvilReply],
	{wire.ICBM, wire.ICBMClientEvent}:              decodeBody[wire.SNAC_0x04_0x14_ICBMClientEvent],
	{wire.Admin, wire.AdminInfoChangeReply}:        decodeBody[wire.SNAC_0x07_0x05_AdminChangeReply],
	{wire.ChatNav, wire.ChatNavNavInfo}:            decodeBody[wire.SNAC_0x0D_0x09_ChatNavNavInfo],
	{wire.Chat, wire.ChatUsersJoined}:              decodeBody[wire.SNAC_0x0E_0x03_ChatUsersJoined],
	{wire.Chat, wire.ChatUsersLeft}:                decodeBody[wire.SNAC_0x0E_0x04_ChatUsersLeft],
	{wire.Chat, wire.ChatChannelMsgToClient}:       decodeBody[wire.SNAC_0x0E_0x06_ChatChannelMsgToClient],
	{wire.Feedbag, wire.FeedbagReply}:              decodeBody[wire.SNAC_0x13_0x06_FeedbagReply],
	{wire.Feedbag, wire.FeedbagInsertItem}:         decodeBody[wire.SNAC_0x13_0x08_FeedbagInsertItem],
	{wire.Feedbag, wire.FeedbagUpdateItem}:         decodeBody[wire.SNAC_0x13_0x09_FeedbagUpdateItem],
	{wire.Feedbag, wire.FeedbagDeleteItem}:         decodeBody[wire.SNAC_0x13_0x0A_FeedbagDeleteItem],
	{wire.Feedbag, wire.FeedbagStatus}:             decodeBody[wire.SNAC_0x13_0x0E_FeedbagStatus],
	{wire.BUCP, wire.BUCPLoginResponse}:            decodeBody[wire.SNAC_0x17_0x03_BUCPLoginResponse],
}

// snacErrorSubGroup is the subgroup of the error SNAC in every food group.
const snacErrorSubGroup = 0x0001

// decodeSNAC unmarshals a SNAC received from the OSCAR server. A SNAC that
// TOC doesn't handle is returned with a nil body.
func decodeSNAC(payload []byte) (wire.SNACMessage, error) {
	r := bytes.NewReader(payload)
	msg := wire.SNACMessage{}
	if err := wire.UnmarshalBE(&msg.Frame, r); err != nil {
		return msg, fmt.Errorf("unmarshal SNAC frame: %w", err)
	}

	decode := snacDecoders[[2]uint16{msg.Frame.FoodGroup, msg.Frame.SubGroup}]
	if msg.Frame.SubGroup == snacErrorSubGroup {
		decode = decodeBody[wire.SNACError]
	}
	if decode == nil {
		return msg, nil
	}

	body, err := decode(r)
	if err != nil {
		return msg, fmt.Errorf("unmarshal %s: %w",
			wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup), err)
	}
	msg.Body = body
	return msg, nil
}

func decodeBody[T any](r io.Reader) (any, error) {
	var body T
	err := wire.UnmarshalBE(&body, r)
	return body, err
}
