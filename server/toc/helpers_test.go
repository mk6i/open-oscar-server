package toc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

type userInfoQueryParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery
	msg    wire.SNACMessage
	err    error
}

type dirInfoParams []struct {
	body wire.SNAC_0x02_0x0B_LocateGetDirInfo
	msg  wire.SNACMessage
	err  error
}

type locateParams struct {
	userInfoQueryParams
	dirInfoParams
}

type infoQueryParams []struct {
	inBody wire.SNAC_0x0F_0x02_InfoQuery
	msg    wire.SNACMessage
	err    error
}

type dirSearchParams struct {
	infoQueryParams
}

type setTOCConfigParams []struct {
	user   state.IdentScreenName
	config string
	err    error
}

type retrieveSessionParams []struct {
	screenName      state.IdentScreenName
	returnedSession *state.Session
}

type sessionRetrieverParams struct {
	retrieveSessionParams
}

type tocConfigParams struct {
	setTOCConfigParams
}

type feedBagParams struct {
	feedbagParams
	upsertFeedbagParams
	deleteFeedbagParams
}

// feedbagParams holds the user's feedbag before a command runs.
type feedbagParams []struct {
	results []wire.FeedbagItem
}

// upsertFeedbagParams is the list of feedbag insert or update SNACs a command
// is expected to send, in order. frame holds the expected subgroup, items the
// exact feedbag items, and err the error the connection returns for the send.
type upsertFeedbagParams []struct {
	frame wire.SNACFrame
	items []wire.FeedbagItem
	err   error
}

// deleteFeedbagParams is the list of feedbag delete SNACs a command is
// expected to send, in order, before any upserts.
type deleteFeedbagParams []struct {
	frame  wire.SNACFrame
	inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem
	err    error
}

type mockParams struct {
	cookieBakerParams
	dirSearchParams
	locateParams
	feedBagParams
	sessionRetrieverParams
	tocConfigParams
}

// issueParams holds multiple scenarios for the Issue method.
type issueParams []struct {
	data       []byte
	returnData []byte
	returnErr  error
}

// cookieBakerParams groups the method scenarios for a CookieBaker.
type cookieBakerParams struct {
	issueParams issueParams
}

// fakeOSCARConn is an oscarclient.Conn that records the SNACs sent to it. The nth
// send returns sendErrs[n], if set. Tests feed server SNACs through msgs.
type fakeOSCARConn struct {
	mu        sync.Mutex
	sent      []wire.SNACMessage
	sendErrs  []error
	msgs      chan wire.SNACMessage
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeOSCARConn() *fakeOSCARConn {
	return &fakeOSCARConn{
		msgs:   make(chan wire.SNACMessage),
		closed: make(chan struct{}),
	}
}

func (c *fakeOSCARConn) SendSNAC(frame wire.SNACFrame, body any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.sent)
	c.sent = append(c.sent, wire.SNACMessage{Frame: frame, Body: body})
	if n < len(c.sendErrs) {
		return c.sendErrs[n]
	}
	return nil
}

func (c *fakeOSCARConn) Messages() <-chan wire.SNACMessage {
	return c.msgs
}

func (c *fakeOSCARConn) Closed() <-chan struct{} {
	return c.closed
}

func (c *fakeOSCARConn) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
}

func (c *fakeOSCARConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// sentSNACs returns a copy of the SNACs sent so far.
func (c *fakeOSCARConn) sentSNACs() []wire.SNACMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]wire.SNACMessage(nil), c.sent...)
}

// newTestTOCConn creates a TOC connection for the user of instance whose BOS
// connection is a fakeOSCARConn.
func newTestTOCConn(instance *state.SessionInstance) (*tocConn, *fakeOSCARConn) {
	bos := newFakeOSCARConn()
	me := newTOCConn(bos, instance.IdentScreenName(), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	me.toCh = make(chan []string, 16)
	me.goAsync = func(f func(ctx context.Context) error) { go func() { _ = f(context.Background()) }() }
	return me, bos
}

// newSNAC returns the SNAC message a TOC connection sends as its reqIDth
// request.
func newSNAC(foodGroup uint16, subGroup uint16, reqID uint32, body any) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: foodGroup,
			SubGroup:  subGroup,
			RequestID: reqID,
		},
		Body: body,
	}
}

// feedbagSNACs returns the feedbag SNACs that params expect a command to send.
// A command sends at most one SNAC per subgroup, in the order deletes,
// updates, inserts, so params' items are combined by subgroup in table order.
// It also returns the error for each send. Sends stop at the first error.
func feedbagSNACs(params feedBagParams) ([]wire.SNACMessage, []error) {
	var deletes, updates, inserts []wire.FeedbagItem
	var deleteErr, updateErr, insertErr error
	for _, p := range params.deleteFeedbagParams {
		deletes = append(deletes, p.inBody.Items...)
		deleteErr = errors.Join(deleteErr, p.err)
	}
	for _, p := range params.upsertFeedbagParams {
		if p.frame.SubGroup == wire.FeedbagUpdateItem {
			updates = append(updates, p.items...)
			updateErr = errors.Join(updateErr, p.err)
		} else {
			inserts = append(inserts, p.items...)
			insertErr = errors.Join(insertErr, p.err)
		}
	}

	var want []wire.SNACMessage
	var errs []error
	add := func(subGroup uint16, items []wire.FeedbagItem, body any, err error) bool {
		if len(items) == 0 {
			return true
		}
		want = append(want, newSNAC(wire.Feedbag, subGroup, uint32(len(want)+1), body))
		errs = append(errs, err)
		return err == nil
	}
	if add(wire.FeedbagDeleteItem, deletes, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: deletes}, deleteErr) &&
		add(wire.FeedbagUpdateItem, updates, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: updates}, updateErr) {
		add(wire.FeedbagInsertItem, inserts, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: inserts}, insertErr)
	}
	return want, errs
}

// matchSession matches a mock call based session ident screen name.
func matchSession(mustMatch state.IdentScreenName) interface{} {
	return mock.MatchedBy(func(s *state.SessionInstance) bool {
		return mustMatch == s.IdentScreenName()
	})
}

// newTestSession creates a session object with 0 or more functional options
// applied
func newTestSession(screenName state.DisplayScreenName, options ...func(instance *state.SessionInstance)) *state.SessionInstance {
	s := state.NewSession().AddInstance()
	s.Session().SetIdentScreenName(screenName.IdentScreenName())
	s.Session().SetDisplayScreenName(screenName)
	s.SetSignonComplete()
	s.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses([5]wire.RateClass{
		{
			ID:              1,
			WindowSize:      80,
			ClearLevel:      2500,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 800,
			MaxLevel:        6000,
		},
		{
			ID:              2,
			WindowSize:      80,
			ClearLevel:      3000,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 1000,
			MaxLevel:        6000,
		},
		{
			ID:              3,
			WindowSize:      20,
			ClearLevel:      5100,
			AlertLevel:      5000,
			LimitLevel:      4000,
			DisconnectLevel: 3000,
			MaxLevel:        6000,
		},
		{
			ID:              4,
			WindowSize:      20,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
		{
			ID:              5,
			WindowSize:      10,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
	}))
	for _, op := range options {
		op(s)
	}
	return s
}

// matchContext matches any instance of Context interface.
func matchContext() interface{} {
	return mock.MatchedBy(func(ctx any) bool {
		_, ok := ctx.(context.Context)
		return ok
	})
}

// receivedSNAC is a SNAC that a fake OSCAR service received from TOC, with
// its body still marshaled.
type receivedSNAC struct {
	frame wire.SNACFrame
	body  []byte
}

// newReceivedSNAC returns the receivedSNAC for a SNAC TOC sends as its
// reqIDth request.
func newReceivedSNAC(t *testing.T, foodGroup uint16, subGroup uint16, reqID uint32, body any) receivedSNAC {
	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(body, buf))
	return receivedSNAC{
		frame: wire.SNACFrame{FoodGroup: foodGroup, SubGroup: subGroup, RequestID: reqID},
		body:  buf.Bytes(),
	}
}

// fakeOSCARServer is an oscarclient.OSCARServer that serves each connection TOC opens
// with the next of its handlers, in order.
type fakeOSCARServer struct {
	mu          sync.Mutex
	handlers    []func(conn net.Conn)
	clientAddrs []net.Addr
}

func (s *fakeOSCARServer) ServeConn(conn net.Conn, _ config.Endpoint, _ []wire.SNACType) {
	defer func() { _ = conn.Close() }()

	s.mu.Lock()
	s.clientAddrs = append(s.clientAddrs, conn.RemoteAddr())
	if len(s.handlers) == 0 {
		s.mu.Unlock()
		return
	}
	handler := s.handlers[0]
	s.handlers = s.handlers[1:]
	s.mu.Unlock()

	handler(conn)
}

// fakeAuth returns an auth service handler that records the client's signon
// frame in got and replies with replyTLVs.
func fakeAuth(got *wire.FLAPSignonFrame, replyTLVs ...wire.TLV) func(conn net.Conn) {
	return func(conn net.Conn) {
		flapc := wire.NewFlapClient(100, conn, conn)
		if err := flapc.SendSignonFrame(nil); err != nil {
			return
		}
		frame, err := flapc.ReceiveSignonFrame()
		if err != nil {
			return
		}
		*got = frame
		_ = flapc.NewSignoff(wire.TLVRestBlock{TLVList: replyTLVs})
	}
}

// fakeAuthBUCP returns an auth service handler that records the client's
// signon frame in got and replies with a BUCP login response holding
// replyTLVs, as the OSCAR server does when it rate limits an address that
// recently used BUCP login.
func fakeAuthBUCP(got *wire.FLAPSignonFrame, replyTLVs ...wire.TLV) func(conn net.Conn) {
	return func(conn net.Conn) {
		flapc := wire.NewFlapClient(100, conn, conn)
		if err := flapc.SendSignonFrame(nil); err != nil {
			return
		}
		frame, err := flapc.ReceiveSignonFrame()
		if err != nil {
			return
		}
		*got = frame
		_ = flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPLoginResponse},
			wire.SNAC_0x17_0x03_BUCPLoginResponse{TLVRestBlock: wire.TLVRestBlock{TLVList: replyTLVs}})
	}
}

// fakeService is the server side of a BOS or chat connection opened by TOC. It
// records the login cookie and the SNACs TOC sends, and answers each SNAC with
// reply.
type fakeService struct {
	// refuse makes the service sign the client off instead of going online.
	refuse bool
	// greeting are SNACs sent right after the service goes online.
	greeting []wire.SNACMessage
	// reply returns the SNACs that answer a SNAC from TOC.
	reply func(frame wire.SNACFrame) []wire.SNACMessage
	// ended, if set, is closed once TOC closes the connection.
	ended chan struct{}

	mu     sync.Mutex
	cookie []byte
	snacs  []receivedSNAC
}

func (f *fakeService) handle(conn net.Conn) {
	if f.ended != nil {
		defer close(f.ended)
	}
	flapc := wire.NewFlapClient(100, conn, conn)
	if err := flapc.SendSignonFrame(nil); err != nil {
		return
	}
	signon, err := flapc.ReceiveSignonFrame()
	if err != nil {
		return
	}
	f.mu.Lock()
	f.cookie, _ = signon.Bytes(wire.OServiceTLVTagsLoginCookie)
	f.mu.Unlock()

	if f.refuse {
		_ = flapc.NewSignoff(wire.TLVRestBlock{})
		return
	}
	if err := flapc.SendSNAC(wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
		wire.SNAC_0x01_0x03_OServiceHostOnline{}); err != nil {
		return
	}
	for _, msg := range f.greeting {
		if err := flapc.SendSNAC(msg.Frame, msg.Body); err != nil {
			return
		}
	}

	for {
		flap, err := flapc.ReceiveFLAP()
		if err != nil || flap.FrameType != wire.FLAPFrameData {
			return
		}
		r := bytes.NewReader(flap.Payload)
		frame := wire.SNACFrame{}
		if err := wire.UnmarshalBE(&frame, r); err != nil {
			return
		}
		body, _ := io.ReadAll(r)
		if len(body) == 0 {
			body = nil
		}

		f.mu.Lock()
		f.snacs = append(f.snacs, receivedSNAC{frame: frame, body: body})
		f.mu.Unlock()

		if f.reply == nil {
			continue
		}
		for _, msg := range f.reply(frame) {
			if err := flapc.SendSNAC(msg.Frame, msg.Body); err != nil {
				return
			}
		}
	}
}

// received returns the login cookie and the SNACs received so far.
func (f *fakeService) received() ([]byte, []receivedSNAC) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cookie, append([]receivedSNAC(nil), f.snacs...)
}
