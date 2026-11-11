package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func startServer(t *testing.T, sessionRetriever SessionRetriever, tweak func(*Server)) (string, *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := newTestServer(sessionRetriever, discardLogger())
	if tweak != nil {
		tweak(srv)
	}
	srv.listenWg.Add(1)
	go srv.acceptLoop(ln)
	t.Cleanup(func() {
		_ = ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln.Addr().String(), srv
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func counterOffer(t *testing.T, instance *state.SessionInstance) wire.ICBMCh2Fragment {
	t.Helper()
	select {
	case msg := <-instance.ReceiveMessage():
		body := msg.Body.(wire.SNAC_0x04_0x07_ICBMChannelMsgToClient)
		assert.Equal(t, wire.ICBMChannelRendezvous, body.ChannelID)
		data, _ := body.Bytes(wire.ICBMTLVData)
		frag := wire.ICBMCh2Fragment{}
		require.NoError(t, wire.UnmarshalBE(&frag, bytes.NewReader(data)))
		assert.Equal(t, wire.ICBMRdvMessagePropose, frag.Type)
		seq, _ := frag.Uint16BE(wire.ICBMRdvTLVTagsSeqNum)
		require.Equal(t, uint16(2), seq)
		return frag
	case <-time.After(time.Second):
		t.Fatal("no counter-offer")
	}
	return wire.ICBMCh2Fragment{}
}

func expectBytes(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	b := make([]byte, len(want))
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	assert.Equal(t, want, string(b))
}

func exchange(t *testing.T, a, b net.Conn) {
	t.Helper()
	_, err := a.Write([]byte("ODC2"))
	require.NoError(t, err)
	expectBytes(t, b, "ODC2")
	_, err = b.Write([]byte("OFT2"))
	require.NoError(t, err)
	expectBytes(t, a, "OFT2")
}

func TestServer_serve(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "127.0.0.1")
	signIn(sessionRetriever, "recipient", "127.0.0.1")
	addr, srv := startServer(t, sessionRetriever, nil)
	cookie := [8]byte{1}

	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)

	recipient := dial(t, addr)
	counter := counterOffer(t, offerer)
	assert.Equal(t, cookie, counter.Cookie)
	assertServerAddress(t, counter)

	sender := dial(t, addr)
	exchange(t, recipient, sender)

	// one side closing ends the other
	require.NoError(t, sender.Close())
	_, err := recipient.Read(make([]byte, 1))
	assert.Error(t, err)
}

func TestServer_serve_earlyBytes(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "127.0.0.1")
	signIn(sessionRetriever, "recipient", "127.0.0.1")
	addr, srv := startServer(t, sessionRetriever, nil)
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer([8]byte{2}, wire.CapFileTransfer))
	require.True(t, ok)

	recipient := dial(t, addr)
	counterOffer(t, offerer)
	_, err := recipient.Write([]byte("OFT2"))
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)

	sender := dial(t, addr)
	expectBytes(t, sender, "OFT2")
}

func TestServer_serve_unknownAddress(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	signIn(sessionRetriever, "recipient", "203.0.113.2")
	addr, srv := startServer(t, sessionRetriever, nil)
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer([8]byte{3}, wire.CapDirectICBM))
	require.True(t, ok)

	conn := dial(t, addr)
	_, err := conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
	assert.Empty(t, offerer.ReceiveMessage())
}

func TestServer_serve_firstSideLeaves(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "127.0.0.1")
	signIn(sessionRetriever, "recipient", "127.0.0.1")
	addr, srv := startServer(t, sessionRetriever, nil)
	cookie := [8]byte{4}
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)

	recipient := dial(t, addr)
	counterOffer(t, offerer)
	require.NoError(t, recipient.Close())

	require.Eventually(t, func() bool {
		_, err := srv.registry.lookup(cookie)
		return err != nil
	}, time.Second, 5*time.Millisecond)
}

func TestServer_serve_offererTimeout(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "127.0.0.1")
	signIn(sessionRetriever, "recipient", "127.0.0.1")
	addr, srv := startServer(t, sessionRetriever, func(s *Server) { s.offererTimeout = 20 * time.Millisecond })
	cookie := [8]byte{5}
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)

	recipient := dial(t, addr)
	counterOffer(t, offerer)
	_, err := recipient.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
	_, err = srv.registry.lookup(cookie)
	assert.ErrorIs(t, err, errNoSession)
}

func TestServer_serve_cancel(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "127.0.0.1")
	signIn(sessionRetriever, "recipient", "127.0.0.1")
	addr, srv := startServer(t, sessionRetriever, nil)
	cookie := [8]byte{6}
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)

	recipient := dial(t, addr)
	counterOffer(t, offerer)
	cancel := wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessageCancel, Cookie: cookie, Capability: wire.CapDirectICBM}
	srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), cancel)
	_, err := recipient.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestServer_serve_recipientInstances(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	recipient := signIn(sessionRetriever, "recipient", "203.0.113.2")
	moved := recipient.Session().AddInstance()
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 5190)
	moved.SetRemoteAddr(&addr)
	relayAddr, srv := startServer(t, sessionRetriever, nil)

	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer([8]byte{7}, wire.CapDirectICBM))
	require.True(t, ok)

	dial(t, relayAddr)
	counterOffer(t, offerer)
}

func TestServer_serve_offererInstance(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	elsewhere := signIn(sessionRetriever, "offerer", "203.0.113.2")
	offerer := elsewhere.Session().AddInstance()
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 5190)
	offerer.SetRemoteAddr(&addr)
	signIn(sessionRetriever, "recipient", "127.0.0.1")
	relayAddr, srv := startServer(t, sessionRetriever, nil)

	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer([8]byte{8}, wire.CapDirectICBM))
	require.True(t, ok)
	recipient := dial(t, relayAddr)
	counterOffer(t, offerer)
	assert.Empty(t, elsewhere.ReceiveMessage())

	sender := dial(t, relayAddr)
	exchange(t, recipient, sender)
}

func TestServer_Route(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	recipient := signIn(sessionRetriever, "recipient", "203.0.113.2")
	srv := newTestServer(sessionRetriever, discardLogger())
	expected := &net.TCPAddr{IP: net.ParseIP("203.0.113.2"), Port: 4000}
	other := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000}
	flap := []byte{0x2a, 0x01, 0x00, 0x01}
	cookie := [8]byte{9}

	assert.Nil(t, srv.Route(nil, expected), "no session")
	assert.Nil(t, srv.Route([]byte("OFT2"), expected), "no session")

	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapFileTransfer))
	require.True(t, ok)
	assert.Nil(t, srv.Route(nil, expected), "silent client, not yet accepted, could be OSCAR")
	assert.NotNil(t, srv.Route([]byte("OFT2"), expected), "a file holder can speak before its accept lands")
	assert.Nil(t, srv.Route(flap, expected), "FLAP is OSCAR even before the accept")

	require.True(t, srv.HoldRendezvous(recipient, wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessageAccept, Cookie: cookie}))
	assert.NotNil(t, srv.Route(nil, expected))
	assert.NotNil(t, srv.Route([]byte("OFT2"), expected))
	assert.Nil(t, srv.Route(flap, expected), "FLAP is OSCAR")
	assert.Nil(t, srv.Route(nil, other), "wrong address")
}

// writeSizes records the size of each write.
type writeSizes struct {
	net.Conn
	mu    sync.Mutex
	sizes []int
	data  bytes.Buffer
}

func (w *writeSizes) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(b) > 0 {
		w.sizes = append(w.sizes, len(b))
	}
	return w.data.Write(b)
}

func Test_copyEven(t *testing.T) {
	src, feed := net.Pipe()
	defer func() { _ = src.Close() }()
	dst := &writeSizes{}
	done := make(chan int64)
	go func() {
		n, _ := copyEven(dst, src)
		done <- n
	}()

	for _, chunk := range []string{"abc", "de", "f", "ghi"} {
		_, err := feed.Write([]byte(chunk))
		require.NoError(t, err)
	}
	time.Sleep(2 * evenWriteWait) // a pause gives up the wait for the next byte
	_, err := feed.Write([]byte("jk"))
	require.NoError(t, err)
	require.NoError(t, feed.Close())

	assert.Equal(t, int64(11), <-done)
	assert.Equal(t, "abcdefghijk", dst.data.String())
	for _, size := range dst.sizes[:2] {
		assert.Zero(t, size%2, "sizes %v", dst.sizes)
	}
}

func TestServer_serve_evenFileWrites(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	offerer := signIn(sessionRetriever, "offerer", "127.0.0.1")
	signIn(sessionRetriever, "recipient", "127.0.0.1")
	addr, srv := startServer(t, sessionRetriever, nil)
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer([8]byte{10}, wire.CapFileTransfer))
	require.True(t, ok)

	recipient := dial(t, addr)
	counterOffer(t, offerer)
	sender := dial(t, addr)

	_, err := sender.Write([]byte("odd"))
	require.NoError(t, err)
	expectBytes(t, recipient, "odd") // the last byte gets through once the wait ends
	exchange(t, sender, recipient)
}
