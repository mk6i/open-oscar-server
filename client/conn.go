package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// ErrClosed indicates that the connection to the server is closed.
var ErrClosed = errors.New("connection closed")

// keepAliveInterval is how often an idle connection sends a FLAP keepalive.
const keepAliveInterval = time.Minute

// msgQueueLimit is how many unsolicited SNACs a connection holds for its
// consumer before the reader blocks.
const msgQueueLimit = 1000

// SNACError is an error reply from the server to a request.
type SNACError struct {
	FoodGroup uint16
	SubGroup  uint16
	Code      uint16
}

func (e *SNACError) Error() string {
	return fmt.Sprintf("%s failed: %s", wire.SubGroupName(e.FoodGroup, e.SubGroup), errorCodeText(e.Code))
}

// errorCodeText describes a SNAC error code.
func errorCodeText(code uint16) string {
	switch code {
	case wire.ErrorCodeNotLoggedOn:
		return "user is not logged on"
	case wire.ErrorCodeInLocalPermitDeny:
		return "blocked by permit/deny settings"
	case wire.ErrorCodeRequestDenied:
		return "request denied"
	case wire.ErrorCodeRateToHost, wire.ErrorCodeRateToClient:
		return "rate limited"
	case wire.ErrorCodeNotSupportedByHost:
		return "not supported by host"
	case wire.ErrorCodeNoMatch:
		return "no match"
	case wire.ErrorCodeTooEvilSender:
		return "sender warning level too high"
	case wire.ErrorCodeTooEvilReceiver:
		return "recipient warning level too high"
	case wire.ErrorCodeInsufficientRights:
		return "insufficient rights"
	case wire.ErrorCodeServiceUnavailable:
		return "service unavailable"
	default:
		return fmt.Sprintf("error code 0x%02X", code)
	}
}

// SignoffError indicates that the server ended the connection with a signoff
// frame carrying an error code.
type SignoffError struct {
	Code uint16
}

func (e *SignoffError) Error() string {
	switch e.Code {
	case uint16(wire.OServiceDiscErrNewLogin):
		return "signed off: screen name signed on from another location"
	default:
		return fmt.Sprintf("signed off by server (code 0x%04X)", e.Code)
	}
}

// conn is a FLAP connection to an OSCAR service, either BOS or a chat room,
// that has finished signing on.
type conn struct {
	nc     net.Conn
	flapc  *wire.FlapClient
	logger *slog.Logger

	mu      sync.Mutex
	lastID  uint32
	pending map[uint32]pendingReq

	// msgs holds SNACs the server sends that don't answer a pending request.
	msgs chan wire.SNACMessage

	closed    chan struct{}
	closeOnce sync.Once
	err       error
}

// pendingReq is a request awaiting its reply.
type pendingReq struct {
	foodGroup uint16
	subGroup  uint16
	reply     chan wire.SNACMessage
}

// dial opens a TCP connection to addr.
func dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// connectService connects to the OSCAR service at addr that loginCookie
// grants access to and waits for the server to report the service online.
func connectService(ctx context.Context, addr string, loginCookie []byte, logger *slog.Logger) (*conn, error) {
	nc, err := dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	flapc := wire.NewFlapClient(0, nc, nc)
	if err := func() error {
		if deadline, ok := ctx.Deadline(); ok {
			_ = nc.SetDeadline(deadline)
			defer func() { _ = nc.SetDeadline(time.Time{}) }()
		}
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
			return signoffErr(frame.Payload)
		}
		msg, err := decodeSNAC(frame.Payload)
		if err != nil {
			return err
		}
		if _, ok := msg.Body.(wire.SNAC_0x01_0x03_OServiceHostOnline); !ok {
			return fmt.Errorf("expected host online, got %s",
				wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup))
		}
		return nil
	}(); err != nil {
		_ = nc.Close()
		return nil, err
	}

	c := &conn{
		nc:      nc,
		flapc:   flapc,
		logger:  logger,
		pending: make(map[uint32]pendingReq),
		msgs:    make(chan wire.SNACMessage, msgQueueLimit),
		closed:  make(chan struct{}),
	}
	go c.read()
	go c.keepAlive()
	return c, nil
}

// signoffErr builds the error for a signoff frame with the given payload.
func signoffErr(payload []byte) error {
	block := wire.TLVRestBlock{}
	if err := wire.UnmarshalBE(&block, bytes.NewReader(payload)); err == nil {
		// the code is a uint8 or uint16, depending on the reason
		for _, tag := range []uint16{0x0009, wire.LoginTLVTagsErrorSubcode} {
			b, ok := block.Bytes(tag)
			switch {
			case ok && len(b) == 1:
				return &SignoffError{Code: uint16(b[0])}
			case ok && len(b) >= 2:
				return &SignoffError{Code: binary.BigEndian.Uint16(b)}
			}
		}
	}
	return ErrClosed
}

func (c *conn) read() {
	var err error
	defer func() { c.closeWithErr(err) }()

	for {
		var frame wire.FLAPFrame
		frame, err = c.flapc.ReceiveFLAP()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				err = ErrClosed
			}
			return
		}
		switch frame.FrameType {
		case wire.FLAPFrameData:
			msg, decodeErr := decodeSNAC(frame.Payload)
			if decodeErr != nil {
				c.logger.Debug("unable to decode SNAC", "err", decodeErr.Error())
				continue
			}
			c.logger.Debug("received SNAC",
				"snac", wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup),
				"request_id", msg.Frame.RequestID)
			if c.deliverReply(msg) {
				continue
			}
			select {
			case c.msgs <- msg:
			case <-c.closed:
				return
			}
		case wire.FLAPFrameSignoff:
			err = signoffErr(frame.Payload)
			return
		}
	}
}

// deliverReply hands msg to the request it answers, if any.
func (c *conn) deliverReply(msg wire.SNACMessage) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	req, ok := c.pending[msg.Frame.RequestID]
	if !ok || req.foodGroup != msg.Frame.FoodGroup {
		return false
	}
	if msg.Frame.Flags&wire.SNACFlagsMoreToCome == 0 {
		delete(c.pending, msg.Frame.RequestID)
	}
	select {
	case req.reply <- msg:
	default:
		// the requester gave up waiting
	}
	return true
}

func (c *conn) keepAlive() {
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			if err := c.flapc.SendKeepAliveFrame(); err != nil {
				c.closeWithErr(err)
				return
			}
		}
	}
}

// nextID returns the next request ID.
func (c *conn) nextID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastID++
	if c.lastID >= wire.ReqIDFromServer {
		c.lastID = 1
	}
	return c.lastID
}

// send sends a SNAC without waiting for a reply.
func (c *conn) send(foodGroup, subGroup uint16, body any) error {
	frame := wire.SNACFrame{
		FoodGroup: foodGroup,
		SubGroup:  subGroup,
		RequestID: c.nextID(),
	}
	return c.sendFrame(frame, body)
}

func (c *conn) sendFrame(frame wire.SNACFrame, body any) error {
	select {
	case <-c.closed:
		return c.Err()
	default:
	}
	c.logger.Debug("sending SNAC",
		"snac", wire.SubGroupName(frame.FoodGroup, frame.SubGroup),
		"request_id", frame.RequestID)
	if err := c.flapc.SendSNAC(frame, body); err != nil {
		c.closeWithErr(err)
		return fmt.Errorf("SendSNAC(%s): %w", wire.SubGroupName(frame.FoodGroup, frame.SubGroup), err)
	}
	return nil
}

// request sends a SNAC and waits for its reply. An error reply is returned as
// a *SNACError.
func (c *conn) request(ctx context.Context, foodGroup, subGroup uint16, body any) (wire.SNACMessage, error) {
	frame := wire.SNACFrame{
		FoodGroup: foodGroup,
		SubGroup:  subGroup,
		RequestID: c.nextID(),
	}
	reply := make(chan wire.SNACMessage, 1)

	c.mu.Lock()
	c.pending[frame.RequestID] = pendingReq{foodGroup: foodGroup, subGroup: subGroup, reply: reply}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, frame.RequestID)
		c.mu.Unlock()
	}()

	if err := c.sendFrame(frame, body); err != nil {
		return wire.SNACMessage{}, err
	}

	select {
	case msg := <-reply:
		if snacErr, ok := msg.Body.(wire.SNACError); ok {
			return msg, &SNACError{FoodGroup: foodGroup, SubGroup: subGroup, Code: snacErr.Code}
		}
		return msg, nil
	case <-c.closed:
		return wire.SNACMessage{}, c.Err()
	case <-ctx.Done():
		return wire.SNACMessage{}, ctx.Err()
	}
}

// Messages returns the SNACs the server sends that don't answer a request.
func (c *conn) Messages() <-chan wire.SNACMessage {
	return c.msgs
}

// Closed returns a channel that is closed when the connection closes.
func (c *conn) Closed() <-chan struct{} {
	return c.closed
}

// Err returns the reason the connection closed.
func (c *conn) Err() error {
	select {
	case <-c.closed:
		return c.err
	default:
		return nil
	}
}

// Close signs off and closes the connection.
func (c *conn) Close() {
	select {
	case <-c.closed:
		return
	default:
	}
	_ = c.flapc.NewSignoff(wire.TLVRestBlock{})
	c.closeWithErr(ErrClosed)
}

func (c *conn) closeWithErr(err error) {
	c.closeOnce.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		c.err = err
		close(c.closed)
		_ = c.nc.Close()
	})
}

// snacDecoders unmarshal the bodies of the SNACs the client handles, keyed by
// food group and subgroup.
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
	{wire.ICBM, wire.ICBMHostAck}:                  decodeBody[wire.SNAC_0x04_0x0C_ICBMHostAck],
	{wire.ICBM, wire.ICBMClientEvent}:              decodeBody[wire.SNAC_0x04_0x14_ICBMClientEvent],
	{wire.Admin, wire.AdminInfoChangeReply}:        decodeBody[wire.SNAC_0x07_0x05_AdminChangeReply],
	{wire.ChatNav, wire.ChatNavNavInfo}:            decodeBody[wire.SNAC_0x0D_0x09_ChatNavNavInfo],
	{wire.Chat, wire.ChatRoomInfoUpdate}:           decodeBody[wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate],
	{wire.Chat, wire.ChatUsersJoined}:              decodeBody[wire.SNAC_0x0E_0x03_ChatUsersJoined],
	{wire.Chat, wire.ChatUsersLeft}:                decodeBody[wire.SNAC_0x0E_0x04_ChatUsersLeft],
	{wire.Chat, wire.ChatChannelMsgToClient}:       decodeBody[wire.SNAC_0x0E_0x06_ChatChannelMsgToClient],
	{wire.Feedbag, wire.FeedbagReply}:              decodeBody[wire.SNAC_0x13_0x06_FeedbagReply],
	{wire.Feedbag, wire.FeedbagInsertItem}:         decodeBody[wire.SNAC_0x13_0x08_FeedbagInsertItem],
	{wire.Feedbag, wire.FeedbagUpdateItem}:         decodeBody[wire.SNAC_0x13_0x09_FeedbagUpdateItem],
	{wire.Feedbag, wire.FeedbagDeleteItem}:         decodeBody[wire.SNAC_0x13_0x0A_FeedbagDeleteItem],
	{wire.Feedbag, wire.FeedbagStatus}:             decodeBody[wire.SNAC_0x13_0x0E_FeedbagStatus],
	{wire.BUCP, wire.BUCPLoginResponse}:            decodeBody[wire.SNAC_0x17_0x03_BUCPLoginResponse],
	{wire.BUCP, wire.BUCPChallengeResponse}:        decodeBody[wire.SNAC_0x17_0x07_BUCPChallengeResponse],
}

// snacErrorSubGroup is the subgroup of the error SNAC in every food group.
const snacErrorSubGroup = 0x0001

// decodeSNAC unmarshals a SNAC received from the server. A SNAC the client
// doesn't handle is returned with a nil body.
func decodeSNAC(payload []byte) (wire.SNACMessage, error) {
	r := bytes.NewReader(payload)
	msg := wire.SNACMessage{}
	if err := wire.UnmarshalBE(&msg.Frame, r); err != nil {
		return msg, fmt.Errorf("unmarshal SNAC frame: %w", err)
	}
	if msg.Frame.Flags&wire.SNACFlagsExtendedInfo != 0 {
		// skip the extended info block that precedes the body
		var ext struct {
			Data []byte `oscar:"len_prefix=uint16"`
		}
		if err := wire.UnmarshalBE(&ext, r); err != nil {
			return msg, fmt.Errorf("unmarshal SNAC extended info: %w", err)
		}
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
