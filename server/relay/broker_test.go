package relay

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// signIn signs name in from ip. The session is real, so messages relayed to
// it can be read back.
func signIn(sessionRetriever *mockSessionRetriever, name, ip string) *state.SessionInstance {
	sess := state.NewSession()
	ident := state.NewIdentScreenName(name)
	sess.SetIdentScreenName(ident)
	instance := sess.AddInstance()
	addr := netip.AddrPortFrom(netip.MustParseAddr(ip), 5190)
	instance.SetRemoteAddr(&addr)
	sessionRetriever.EXPECT().RetrieveSession(ident).Return(sess).Maybe()
	return instance
}

func newTestServer(sessionRetriever SessionRetriever, logger *slog.Logger) *Server {
	return NewServer(nil, netip.MustParseAddr("192.0.2.7"), 5190, logger, sessionRetriever)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// directOffer has the fields AIM 5.9 sends in a direct proposal.
func directOffer(cookie [8]byte, capability [16]byte) wire.ICBMCh2Fragment {
	frag := wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessagePropose, Cookie: cookie, Capability: capability}
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequestHostChk, []byte{}))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRdvIP, []byte{10, 0, 0, 5}))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsIPXOR, []byte{245, 255, 255, 250}))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, []byte{10, 0, 0, 5}))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsPort, uint16(4000)))
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsPortXOR, ^uint16(4000)))
	return frag
}

func assertServerAddress(t *testing.T, frag wire.ICBMCh2Fragment) {
	t.Helper()
	requester, _ := frag.Bytes(wire.ICBMRdvTLVTagsRequesterIP)
	verified, _ := frag.Bytes(wire.ICBMRdvTLVTagsVerifiedIP)
	port, _ := frag.Uint16BE(wire.ICBMRdvTLVTagsPort)
	assert.Equal(t, []byte{192, 0, 2, 7}, requester)
	assert.Equal(t, []byte{192, 0, 2, 7}, verified)
	assert.Equal(t, uint16(5190), port)
	assert.False(t, frag.HasTag(wire.ICBMRdvTLVTagsRdvIP))
	assert.False(t, frag.HasTag(wire.ICBMRdvTLVTagsIPXOR))
	assert.False(t, frag.HasTag(wire.ICBMRdvTLVTagsPortXOR))
	assert.False(t, frag.HasTag(wire.ICBMRdvTLVTagsUseARS))
}

func TestServer_BrokerRendezvous(t *testing.T) {
	tests := []struct {
		name       string
		capability [16]byte
	}{
		{name: "Direct IM", capability: wire.CapDirectICBM},
		{name: "Send File", capability: wire.CapFileTransfer},
		{name: "Get File", capability: wire.CapFileSharing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionRetriever := newMockSessionRetriever(t)
			offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
			signIn(sessionRetriever, "recipient", "203.0.113.2")
			logs := bytes.Buffer{}
			srv := newTestServer(sessionRetriever, slog.New(slog.NewTextHandler(&logs, nil)))
			cookie := [8]byte{1}

			got, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, tt.capability))
			require.True(t, ok)

			assertServerAddress(t, got)
			assert.True(t, got.HasTag(wire.ICBMRdvTLVTagsRequestHostChk))
			seq, _ := got.Uint16BE(wire.ICBMRdvTLVTagsSeqNum)
			assert.Equal(t, uint16(1), seq)
			assert.Contains(t, logs.String(), `tags_in="000a 000f 0002 0016 0003 0005 0017"`)
			assert.Contains(t, logs.String(), `tags_out="000a 000f 0003 0005 0004"`)

			sess, err := srv.registry.lookup(cookie)
			require.NoError(t, err)
			assert.Equal(t, netip.MustParseAddr("203.0.113.1"), sess.offererIP)
			assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.2")}, sess.recipientIPs)
		})
	}
}

func TestServer_BrokerRendezvous_passThrough(t *testing.T) {
	withARS := directOffer([8]byte{2}, wire.CapDirectICBM)
	withARS.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsUseARS, []byte{}))
	secondOffer := directOffer([8]byte{3}, wire.CapDirectICBM)
	secondOffer.Set(wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(2)))
	accept := directOffer([8]byte{4}, wire.CapDirectICBM)
	accept.Type = wire.ICBMRdvMessageAccept

	tests := []struct {
		name string
		frag wire.ICBMCh2Fragment
	}{
		{name: "room invite", frag: directOffer([8]byte{5}, wire.CapChat)},
		{name: "voice", frag: directOffer([8]byte{6}, wire.CapVoiceChat)},
		{name: "an offer that uses the proxy", frag: withARS},
		{name: "a later offer", frag: secondOffer},
		{name: "an accept", frag: accept},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionRetriever := newMockSessionRetriever(t)
			srv := newTestServer(sessionRetriever, discardLogger())
			offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
			_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), tt.frag)
			assert.False(t, ok)
			_, err := srv.registry.lookup(tt.frag.Cookie)
			assert.ErrorIs(t, err, errNoSession)
		})
	}
}

func TestServer_BrokerRendezvous_cookieInUse(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	srv := newTestServer(sessionRetriever, discardLogger())
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	signIn(sessionRetriever, "recipient", "203.0.113.2")
	cookie := [8]byte{7}

	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)
	_, ok = srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	assert.False(t, ok)
}

func TestServer_BrokerRendezvous_cancel(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	srv := newTestServer(sessionRetriever, discardLogger())
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	recipient := signIn(sessionRetriever, "recipient", "203.0.113.2")
	cookie := [8]byte{8}

	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)

	cancel := wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessageCancel, Cookie: cookie, Capability: wire.CapDirectICBM}
	_, ok = srv.BrokerRendezvous(recipient, state.NewIdentScreenName("offerer"), cancel)
	assert.False(t, ok)
	_, err := srv.registry.lookup(cookie)
	assert.ErrorIs(t, err, errNoSession)
}

// AIM 5.9 declines with a client error, code 3, and sends no cancel.
func TestServer_RefuseRendezvous(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	srv := newTestServer(sessionRetriever, discardLogger())
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	signIn(sessionRetriever, "recipient", "203.0.113.2")
	cookie := [8]byte{0x23, 0xc2, 0xab, 0x7a, 0x47, 0x17}

	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)

	srv.RefuseRendezvous(binary.BigEndian.Uint64(cookie[:]))
	_, err := srv.registry.lookup(cookie)
	assert.ErrorIs(t, err, errNoSession)
}

func TestServer_HoldRendezvous(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	srv := newTestServer(sessionRetriever, discardLogger())
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	recipient := signIn(sessionRetriever, "recipient", "203.0.113.2")
	cookie := [8]byte{9}
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer(cookie, wire.CapDirectICBM))
	require.True(t, ok)
	accept := func(cookie [8]byte) wire.ICBMCh2Fragment {
		return wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessageAccept, Cookie: cookie}
	}

	assert.False(t, srv.HoldRendezvous(offerer, accept(cookie)), "only the recipient's accept is held")
	assert.False(t, srv.HoldRendezvous(recipient, accept([8]byte{10})), "no session")
	assert.False(t, srv.HoldRendezvous(recipient, wire.ICBMCh2Fragment{Type: wire.ICBMRdvMessageCancel, Cookie: cookie}))
	assert.True(t, srv.HoldRendezvous(recipient, accept(cookie)))
}

func TestServer_BrokerRendezvous_expiry(t *testing.T) {
	sessionRetriever := newMockSessionRetriever(t)
	srv := newTestServer(sessionRetriever, discardLogger())
	srv.acceptTimeout = 10 * time.Millisecond
	offerer := signIn(sessionRetriever, "offerer", "203.0.113.1")
	sessionRetriever.EXPECT().RetrieveSession(state.NewIdentScreenName("recipient")).Return(nil)
	_, ok := srv.BrokerRendezvous(offerer, state.NewIdentScreenName("recipient"), directOffer([8]byte{11}, wire.CapDirectICBM))
	require.True(t, ok)

	require.Eventually(t, func() bool {
		_, err := srv.registry.lookup([8]byte{11})
		return err != nil
	}, time.Second, 2*time.Millisecond)
}
