package icq_legacy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testV5UIN       = uint32(12345)
	testV5SessionID = uint32(0xBEEF)
	testV5Seq1      = uint16(42)
	testV5Seq2      = uint16(7)
)

var testV5Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

// noopSessionRegistry satisfies SessionRegistry for tests that remove legacy sessions.
type noopSessionRegistry struct{}

func (noopSessionRegistry) RemoveSession(*state.Session) {}

func newTestV5SessionManager() *LegacySessionManager {
	return NewLegacySessionManager(noopSessionRegistry{}, config.ICQLegacyConfig{}, slog.Default())
}

func newTestV5Handler(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V5Handler {
	t.Helper()
	if sessions == nil {
		sessions = newTestV5SessionManager()
	}
	return NewV5Handler(sessions, svc, sender, NewV5PacketBuilder(sessions, nil), slog.Default())
}

func buildPlainV5ClientPacket(pkt V5ClientPacket) []byte {
	size := 24 + len(pkt.Data)
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:2], pkt.Version)
	binary.LittleEndian.PutUint32(buf[2:6], pkt.Zero)
	binary.LittleEndian.PutUint32(buf[6:10], pkt.UIN)
	binary.LittleEndian.PutUint32(buf[10:14], pkt.SessionID)
	binary.LittleEndian.PutUint16(buf[14:16], pkt.Command)
	binary.LittleEndian.PutUint16(buf[16:18], pkt.SeqNum1)
	binary.LittleEndian.PutUint16(buf[18:20], pkt.SeqNum2)
	if len(pkt.Data) > 0 {
		copy(buf[24:], pkt.Data)
	}
	return buf
}

// buildEncryptedV5ClientPacket builds a wire-format V5 client packet for Handle().
// Handle applies DecryptV5Packet, which is an XOR-based involution, so we pre-apply
// DecryptV5Packet to plaintext to produce bytes that decrypt back to the intended fields.
func buildEncryptedV5ClientPacket(t *testing.T, pkt V5ClientPacket) []byte {
	t.Helper()
	buf := buildPlainV5ClientPacket(pkt)
	// Place a valid checkcode at 0x14 (required for decryption key derivation).
	cc := calculateV5CheckCode(buf)
	binary.LittleEndian.PutUint32(buf[20:24], cc)
	DecryptV5Packet(buf, 0)
	// Verify Handle's decrypt path recovers the intended command.
	verify := make([]byte, len(buf))
	copy(verify, buf)
	DecryptV5Packet(verify, 0)
	require.Equal(t, pkt.Command, binary.LittleEndian.Uint16(verify[14:16]),
		"V5 test packet builder failed for command 0x%04X", pkt.Command)
	return buf
}

func v5ServerCommand(packet []byte) uint16 {
	if len(packet) < 9 {
		return 0
	}
	return binary.LittleEndian.Uint16(packet[7:9])
}

func v5ServerPacketData(packet []byte) []byte {
	if len(packet) <= 21 {
		return nil
	}
	return packet[21:]
}

func v5ServerSeq1(packet []byte) uint16 {
	if len(packet) < 11 {
		return 0
	}
	return binary.LittleEndian.Uint16(packet[9:11])
}

func v5ServerSeq2(packet []byte) uint16 {
	if len(packet) < 13 {
		return 0
	}
	return binary.LittleEndian.Uint16(packet[11:13])
}

func newTestV5HandlerWithDispatcher(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V5Handler {
	t.Helper()
	logger := slog.Default()
	v1 := NewV1Handler(sessions, svc, sender, logger)
	v2 := NewV2Handler(sessions, svc, sender, NewV2PacketBuilder(), logger)
	v3 := NewV3Handler(sessions, svc, sender, NewV3PacketBuilder(sessions, nil), logger)
	v4 := NewV4Handler(sessions, svc, sender, NewV4PacketBuilder(sessions, nil), logger)
	v5 := NewV5Handler(sessions, svc, sender, NewV5PacketBuilder(sessions, nil), logger)
	cfg := config.ICQLegacyConfig{SupportedVersions: []int{3, 4, 5}}
	dispatcher := NewProtocolDispatcher(v1, v2, v3, v4, v5, cfg, logger)
	v5.SetDispatcher(dispatcher)
	return v5
}

func sessionWithDirectConn(uin uint32, tcpPort, internalIP uint32, dcType uint8) *LegacySession {
	s := sessionWithInstance(uin)
	s.SetDirectConnectionInfo(tcpPort, internalIP, 5, dcType)
	return s
}

func sessionWithInstance(uin uint32) *LegacySession {
	s := newTestLegacySession(uin, legacySessionOptOSCARSess, func(ls *LegacySession) {
		ls.SessionID = testV5SessionID
		ls.Version = ICQLegacyVersionV5
	})
	return s
}

func expectV5NotConnected(sender *mockPacketSender) {
	sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
		Run(func(_ *net.UDPAddr, p []byte) {
			if got := v5ServerCommand(p); got != ICQLegacySrvNotConnected {
				panic(fmt.Sprintf("got command 0x%04X, want NOT_CONNECTED", got))
			}
		}).Return(nil).Once()
}

func registerSession(mgr *LegacySessionManager, session *LegacySession) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.sessions[session.UIN] = session
	if session.Addr != nil {
		mgr.addrIndex[session.Addr.String()] = session
	}
}

func defaultV5Pkt(command uint16, data []byte) V5ClientPacket {
	return V5ClientPacket{
		Version:   ICQLegacyVersionV5,
		UIN:       testV5UIN,
		SessionID: testV5SessionID,
		Command:   command,
		SeqNum1:   testV5Seq1,
		SeqNum2:   testV5Seq2,
		Data:      data,
	}
}

func v5LPString(s string) []byte {
	buf := new(bytes.Buffer)
	writeLegacyString(buf, s)
	return buf.Bytes()
}

func v5GetDepsData(uin uint32, password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+2+len(pwd))
	binary.LittleEndian.PutUint32(buf[0:4], uin)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(pwd)))
	copy(buf[6:], pwd)
	return buf
}

func v5LoginData(password string, minimal bool) []byte {
	pwd := []byte(password)
	if minimal {
		buf := make([]byte, 4+4+2+len(pwd))
		binary.LittleEndian.PutUint32(buf[4:8], 4000)
		binary.LittleEndian.PutUint16(buf[8:10], uint16(len(pwd)))
		copy(buf[10:], pwd)
		return buf
	}
	buf := make([]byte, 4+4+2+len(pwd)+4+4+1+4+4+28)
	off := 0
	off += 4 // time
	binary.LittleEndian.PutUint32(buf[off:], 4000)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], uint16(len(pwd)))
	off += 2
	copy(buf[off:], pwd)
	off += len(pwd)
	binary.LittleEndian.PutUint32(buf[off:], 0x98)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 0x7F000001)
	off += 4
	buf[off] = 0
	off++
	binary.LittleEndian.PutUint32(buf[off:], 0)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 0)
	return buf
}

func v5ContactListData(uins []uint32) []byte {
	buf := make([]byte, 1+4*len(uins))
	buf[0] = byte(len(uins))
	for i, u := range uins {
		binary.LittleEndian.PutUint32(buf[1+4*i:], u)
	}
	return buf
}

func v5MessageData(toUIN uint32, msgType uint16, message string) []byte {
	msg := []byte(message)
	buf := make([]byte, 4+2+2+len(msg))
	binary.LittleEndian.PutUint32(buf[0:4], toUIN)
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(len(msg)))
	copy(buf[8:], msg)
	return buf
}

func v5MetaUserData(subCmd uint16, subData []byte) []byte {
	buf := make([]byte, 2+len(subData))
	binary.LittleEndian.PutUint16(buf[0:2], subCmd)
	copy(buf[2:], subData)
	return buf
}

func metaUserPkt(subCmd uint16, subData []byte) V5ClientPacket {
	return defaultV5Pkt(ICQLegacyCmdMetaUser, v5MetaUserData(subCmd, subData))
}

func v5MetaWireMarshal(t *testing.T, body any) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, wire.MarshalLE(body, &buf))
	return buf.Bytes()
}

func v5MetaSetBasicData() []byte {
	buf := new(bytes.Buffer)
	for _, s := range []string{
		"nick", "first", "last", "a@b.com", "", "", "city", "ST",
		"phone", "fax", "addr", "cell", "zip",
	} {
		writeLegacyString(buf, s)
	}
	tail := []byte{0x01, 0x00, 0, 1} // country=1, gmt=0, publish=1
	return append(buf.Bytes(), tail...)
}

func v5MetaUnregisterData(uin uint32, password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+2+len(pwd))
	binary.LittleEndian.PutUint32(buf[0:4], uin)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(pwd)))
	copy(buf[6:], pwd)
	return buf
}

func v5MetaSetPassData(password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 2+len(pwd))
	binary.LittleEndian.PutUint16(buf[0:2], uint16(len(pwd)))
	copy(buf[2:], pwd)
	return buf
}

func v5MetaSetHPCatData(enabled bool, index uint16, desc string) []byte {
	d := []byte(desc)
	buf := make([]byte, 5+len(d))
	if enabled {
		buf[0] = 1
	}
	binary.LittleEndian.PutUint16(buf[1:3], index)
	binary.LittleEndian.PutUint16(buf[3:5], uint16(len(d)))
	copy(buf[5:], d)
	return buf
}

func v5MetaSearchNameData() []byte {
	return append(append(v5LPString("nick"), v5LPString("first")...), v5LPString("last")...)
}

func v5MetaSearchEmailData(email string) []byte {
	return v5LPString(email)
}

func v5MetaInterestsWireData(t *testing.T) []byte {
	t.Helper()
	return v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests{
		Interests: []struct {
			Code    uint16
			Keyword string `oscar:"len_prefix=uint16,nullterm"`
		}{
			{Code: 1, Keyword: "kw1"},
			{Code: 2, Keyword: "kw2"},
			{Code: 3, Keyword: "kw3"},
			{Code: 4, Keyword: "kw4"},
		},
	})
}

func v5MetaAffiliationsWireData(t *testing.T) []byte {
	t.Helper()
	return v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
		PastAffiliations: []struct {
			Code    uint16
			Keyword string `oscar:"len_prefix=uint16,nullterm"`
		}{
			{Code: 1, Keyword: "p1"},
			{Code: 2, Keyword: "p2"},
			{Code: 3, Keyword: "p3"},
		},
		Affiliations: []struct {
			Code    uint16
			Keyword string `oscar:"len_prefix=uint16,nullterm"`
		}{
			{Code: 4, Keyword: "c1"},
			{Code: 5, Keyword: "c2"},
			{Code: 6, Keyword: "c3"},
		},
	})
}

func v5TargetUINData(target uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, target)
	return buf
}

func testAuthSuccessInstance() *state.SessionInstance {
	return newTestOSCARInstance(state.DisplayScreenName(strconv.FormatUint(uint64(testV5UIN), 10)))
}

func testMinimalUser() *state.User {
	u := &state.User{}
	u.ICQInfo.Basic.Nickname = "nick"
	u.ICQInfo.Basic.FirstName = "first"
	u.ICQInfo.Basic.LastName = "last"
	return u
}

// v5HandleEnv groups per-case dependencies for runV5HandleCases.
type v5HandleEnv struct {
	T        *testing.T
	Sender   *mockPacketSender
	Service  *mockLegacyService
	Sessions *LegacySessionManager
	Session  *LegacySession // same pointer passed to Handle
}

// v5HandleCase is one row in a table-driven V5Handler.Handle test.
type v5HandleCase struct {
	name    string
	session *LegacySession
	pkt     V5ClientPacket
	// packet, when set, supplies wire bytes instead of encrypting pkt.
	packet func(t *testing.T) []byte
	// setup configures mocks and session manager before Handle; the returned
	// function validates the Handle result (and optional post-conditions).
	setup func(v5HandleEnv) func(error)
}

// v5CaseSetup runs pre-Handle wiring and returns the post-Handle check.
// If after is nil, Handle is expected to return nil.
func v5CaseSetup(pre func(v5HandleEnv), after func(e v5HandleEnv, err error)) func(v5HandleEnv) func(error) {
	return func(e v5HandleEnv) func(error) {
		if pre != nil {
			pre(e)
		}
		return func(err error) {
			if after != nil {
				after(e, err)
				return
			}
			assert.NoError(e.T, err)
		}
	}
}

func runV5HandleCases(t *testing.T, cases []v5HandleCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			svc := newMockLegacyService(t)
			sessions := newTestV5SessionManager()
			e := v5HandleEnv{
				T:        t,
				Sender:   sender,
				Service:  svc,
				Sessions: sessions,
				Session:  tt.session,
			}
			var check func(error)
			if tt.setup != nil {
				check = tt.setup(e)
			} else {
				check = func(err error) { assert.NoError(t, err) }
			}
			h := newTestV5Handler(t, sender, svc, sessions)
			var wire []byte
			if tt.packet != nil {
				wire = tt.packet(t)
			} else {
				wire = buildEncryptedV5ClientPacket(t, tt.pkt)
			}
			check(h.Handle(tt.session, testV5Addr, wire))
		})
	}
}

func TestV5Handler_Handle(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:   "packet too short",
			packet: func(_ *testing.T) []byte { return []byte{0x01, 0x02, 0x03} },
			setup: v5CaseSetup(nil, func(e v5HandleEnv, err error) {
				require.Error(e.T, err)
				assert.Contains(e.T, err.Error(), "V5 packet too short")
			}),
		},
		{
			name:    "nil session disallowed command",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v5CaseSetup(func(e v5HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(t, ICQLegacySrvNotConnected, v5ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "nil session ACK allowed",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdAck, nil),
		},
		{
			name:    "session state updated",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdAck, nil),
			setup: v5CaseSetup(nil, func(e v5HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(t, testV5Seq1, e.Session.SeqNumClient)
				assert.WithinDuration(e.T, time.Now(), e.Session.GetLastActivity(), time.Second)
			}),
		},
		{
			name:    "unknown command",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(0xFFFF, nil),
			setup: v5CaseSetup(func(e v5HandleEnv) {
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(t, ICQLegacySrvAck, v5ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "inline ACK command",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdAck, nil),
		},
	})
}

func TestV5Handler_HandleFirstLogin(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "with session_id2 in data",
			session: nil,
			pkt: defaultV5Pkt(ICQLegacyCmdFirstLogin, func() []byte {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 0xCAFEBABE)
				return b
			}()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvAck, v5ServerCommand(p))
							assert.GreaterOrEqual(t, len(p), 28)
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "empty data",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdFirstLogin, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvAck, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleGetDeps(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "valid credentials",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdGetDeps, v5GetDepsData(testV5UIN, "secret")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ValidateCredentials(mock.Anything, testV5UIN, "secret").Return(true, nil).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "invalid credentials",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdGetDeps, v5GetDepsData(testV5UIN, "wrong")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ValidateCredentials(mock.Anything, testV5UIN, "wrong").Return(false, nil).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvWrongPasswd, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdGetDeps, v5GetDepsData(testV5UIN, "secret")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ValidateCredentials(mock.Anything, testV5UIN, "secret").
						Return(false, errors.New("db down")).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvWrongPasswd, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "packet too short",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdGetDeps, []byte{0x01}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvWrongPasswd, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleLogin(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "auth success",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdLogin, v5LoginData("secret", true)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.MatchedBy(func(req AuthRequest) bool {
						return req.UIN == testV5UIN && req.Password == "secret"
					})).Return(&AuthResult{Success: true, oscarSession: testAuthSuccessInstance()}, nil).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).
						Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.NotNil(t, e.Sessions.GetSession(testV5UIN))
				},
			),
		},
		{
			name:    "bad password",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdLogin, v5LoginData("wrong", true)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
						Return(&AuthResult{Success: false, ErrorCode: 0x0001}, nil).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvWrongPasswd, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "auth service error",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdLogin, v5LoginData("secret", true)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
						Return(nil, errors.New("auth failed")).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvWrongPasswd, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "packet too short",
			session: nil,
			pkt:     defaultV5Pkt(ICQLegacyCmdLogin, []byte{0, 0, 0}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once() // login ACK
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvWrongPasswd, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "truncated password field",
			session: nil,
			pkt: defaultV5Pkt(ICQLegacyCmdLogin, func() []byte {
				buf := make([]byte, 12)
				binary.LittleEndian.PutUint32(buf[4:8], 4000)
				binary.LittleEndian.PutUint16(buf[8:10], 20) // claims 20 bytes but only 2 available
				return buf
			}()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvWrongPasswd, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleContactList(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "valid contact list",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdContactList, v5ContactListData([]uint32{99999})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ProcessContactList(mock.Anything, mock.Anything, mock.Anything).
						Return(&ContactListResult{}, nil).Once()
					e.Service.EXPECT().NotifyUserOnline(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvUserListDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdContactList, v5ContactListData(nil)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvNotConnected, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "parse error empty data",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdContactList, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvUserListDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdContactList, v5ContactListData(nil)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ProcessContactList(mock.Anything, mock.Anything, mock.Anything).
						Return(nil, errors.New("fail")).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvUserListDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandlePing(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "keep alive",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvAck, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "keep alive 2",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdKeepAlive2, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvAck, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(testV5Addr, mock.AnythingOfType("[]uint8")).
						Run(func(_ *net.UDPAddr, p []byte) {
							assert.Equal(t, ICQLegacySrvNotConnected, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleLogoff(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "active session",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdLogoff, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					registerSession(e.Sessions, e.Session)
					e.Service.EXPECT().NotifyUserOffline(mock.Anything, testV5UIN).Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.Nil(t, e.Sessions.GetSession(testV5UIN))
				},
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdLogoff, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleSetStatus(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "valid status change",
			session: sessionWithInstance(testV5UIN),
			pkt: defaultV5Pkt(ICQLegacyCmdSetStatus, func() []byte {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 0x00000001)
				return b
			}()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
						Return(&StatusChangeResult{}, nil).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.Equal(t, uint32(0x00000001), e.Session.GetStatus())
				},
			),
		},
		{
			name: "nil session",
			pkt: defaultV5Pkt(ICQLegacyCmdSetStatus, func() []byte {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 1)
				return b
			}()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSetStatus, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMessage(t *testing.T) {
	target := sessionWithInstance(99999)
	target.Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4001}

	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "online target",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdThruServer, v5MessageData(99999, 0x0001, "hi")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					registerSession(e.Sessions, target)
					e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
						Return(&MessageResult{TargetOnline: true}, nil).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).
						Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "offline stored",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdThruServer, v5MessageData(99999, 0x0001, "hi")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
						Return(&MessageResult{StoredOffline: true}, nil).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdThruServer, v5MessageData(99999, 0x0001, "hi")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdThruServer, []byte{1, 2, 3}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdThruServer, v5MessageData(99999, 0x0001, "hi")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
						Return(nil, errors.New("fail")).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleUserAdd(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "success",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdUserAdd, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
						Return(&UserAddResult{}, nil).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.Contains(t, e.Session.GetContactList(), uint32(99999))
				},
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdUserAdd, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdUserAdd, []byte{1, 2}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdUserAdd, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
						Return(nil, errors.New("fail")).Once()
					e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_sendV5UserOnline(t *testing.T) {
	const (
		onlineUIN  = uint32(67890)
		tcpPort    = uint32(5190)
		internalIP = uint32(0x7F000001)
		dcType     = uint8(2)
		userStatus = uint32(0x00000010)
	)

	t.Run("V5 peer includes connection info", func(t *testing.T) {
		sender := newMockPacketSender(t)
		svc := newMockLegacyService(t)
		sessions := newTestV5SessionManager()

		onlineSess := sessionWithDirectConn(onlineUIN, tcpPort, internalIP, dcType)
		registerSession(sessions, onlineSess)

		recipient := sessionWithInstance(testV5UIN)
		wantExtIP := onlineSess.GetExternalIP()

		sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
			if v5ServerCommand(p) != ICQLegacySrvUserOnline {
				return false
			}
			data := v5ServerPacketData(p)
			return len(data) >= 17 &&
				binary.LittleEndian.Uint32(data[0:4]) == onlineUIN &&
				binary.LittleEndian.Uint32(data[4:8]) == wantExtIP &&
				binary.LittleEndian.Uint32(data[8:12]) == tcpPort &&
				binary.LittleEndian.Uint32(data[12:16]) == internalIP &&
				data[16] == dcType
		})).Return(nil).Once()

		h := newTestV5Handler(t, sender, svc, sessions)
		assert.NoError(t, h.sendV5UserOnline(recipient, onlineUIN, userStatus))
	})

	t.Run("non-V5 online user zeros connection info", func(t *testing.T) {
		sender := newMockPacketSender(t)
		svc := newMockLegacyService(t)
		sessions := newTestV5SessionManager()

		onlineSess := newTestLegacySession(onlineUIN, legacySessionOptVersion(ICQLegacyVersionV3))
		onlineSess.SetDirectConnectionInfo(tcpPort, internalIP, 5, dcType)
		registerSession(sessions, onlineSess)

		recipient := sessionWithInstance(testV5UIN)

		sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
			data := v5ServerPacketData(p)
			return v5ServerCommand(p) == ICQLegacySrvUserOnline &&
				len(data) >= 17 &&
				binary.LittleEndian.Uint32(data[4:8]) == 0 &&
				binary.LittleEndian.Uint32(data[8:12]) == 0
		})).Return(nil).Once()

		h := newTestV5Handler(t, sender, svc, sessions)
		assert.NoError(t, h.sendV5UserOnline(recipient, onlineUIN, userStatus))
	})
}

func TestV5Handler_sendV5AckToAddr(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	h := newTestV5Handler(t, sender, svc, newTestV5SessionManager())

	sender.EXPECT().SendPacket(testV5Addr, mock.MatchedBy(func(p []byte) bool {
		return v5ServerCommand(p) == ICQLegacySrvAck &&
			v5ServerSeq1(p) == testV5Seq1 &&
			v5ServerSeq2(p) == testV5Seq2 &&
			binary.LittleEndian.Uint32(p[3:7]) == testV5SessionID &&
			binary.LittleEndian.Uint32(p[13:17]) == testV5UIN &&
			len(v5ServerPacketData(p)) == 0
	})).Return(nil).Once()

	assert.NoError(t, h.sendV5AckToAddr(testV5Addr, testV5SessionID, testV5UIN, testV5Seq1, testV5Seq2))
}

func TestV5Handler_sendV5UserOffline(t *testing.T) {
	const offlineUIN = uint32(88888)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := sessionWithInstance(testV5UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v5ServerPacketData(p)
		return v5ServerCommand(p) == ICQLegacySrvUserOffline &&
			len(data) == 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == offlineUIN
	})).Return(nil).Once()

	h := newTestV5Handler(t, sender, svc, newTestV5SessionManager())
	assert.NoError(t, h.sendV5UserOffline(recipient, offlineUIN))
}

func TestV5Handler_sendV5UserStatus(t *testing.T) {
	const (
		changedUIN = uint32(88888)
		status     = uint32(0x00010002) // estat=1, status=2
	)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := sessionWithInstance(testV5UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v5ServerPacketData(p)
		return v5ServerCommand(p) == ICQLegacySrvUserStatus &&
			len(data) == 8 &&
			binary.LittleEndian.Uint32(data[0:4]) == changedUIN &&
			binary.LittleEndian.Uint16(data[4:6]) == uint16(status&0xFFFF) &&
			binary.LittleEndian.Uint16(data[6:8]) == uint16(status>>16)
	})).Return(nil).Once()

	h := newTestV5Handler(t, sender, svc, newTestV5SessionManager())
	assert.NoError(t, h.sendV5UserStatus(recipient, changedUIN, status))
}

func TestV5Handler_HandleLogoff_notifiesContacts(t *testing.T) {
	const contactUIN = uint32(88888)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestV5SessionManager()

	loggingOff := sessionWithInstance(testV5UIN)
	loggingOff.SetContactList([]uint32{contactUIN})
	contact := sessionWithInstance(contactUIN)
	contact.SetContactList([]uint32{testV5UIN})
	registerSession(sessions, loggingOff)
	registerSession(sessions, contact)

	svc.EXPECT().NotifyUserOffline(mock.Anything, testV5UIN).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		data := v5ServerPacketData(p)
		return v5ServerCommand(p) == ICQLegacySrvUserOffline &&
			len(data) == 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == testV5UIN
	})).Return(nil).Once()

	h := newTestV5HandlerWithDispatcher(t, sender, svc, sessions)
	pkt := buildEncryptedV5ClientPacket(t, defaultV5Pkt(ICQLegacyCmdLogoff, nil))
	assert.NoError(t, h.Handle(loggingOff, testV5Addr, pkt))
	assert.Nil(t, sessions.GetSession(testV5UIN))
}

func TestV5Handler_HandleSetStatus_notifiesContacts(t *testing.T) {
	const (
		contactUIN = uint32(88888)
		newStatus  = uint32(0x00010002)
	)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestV5SessionManager()

	changer := sessionWithInstance(testV5UIN)
	contact := sessionWithInstance(contactUIN)
	registerSession(sessions, changer)
	registerSession(sessions, contact)

	svc.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
		Return(&StatusChangeResult{
			NotifyTargets: []NotifyTarget{{UIN: contactUIN}},
		}, nil).Once()

	sender.EXPECT().SendPacket(changer.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		data := v5ServerPacketData(p)
		return v5ServerCommand(p) == ICQLegacySrvUserStatus &&
			len(data) == 8 &&
			binary.LittleEndian.Uint32(data[0:4]) == testV5UIN &&
			binary.LittleEndian.Uint16(data[4:6]) == uint16(newStatus&0xFFFF) &&
			binary.LittleEndian.Uint16(data[6:8]) == uint16(newStatus>>16)
	})).Return(nil).Once()

	h := newTestV5HandlerWithDispatcher(t, sender, svc, sessions)
	pkt := buildEncryptedV5ClientPacket(t, defaultV5Pkt(ICQLegacyCmdSetStatus, func() []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, newStatus)
		return b
	}()))
	assert.NoError(t, h.Handle(changer, testV5Addr, pkt))
	assert.Equal(t, newStatus, changer.GetStatus())
}

func TestV5Handler_HandleUserAdd_notifyTarget(t *testing.T) {
	const targetUIN = uint32(99999)

	userAddResult := &UserAddResult{
		TargetOnline:     true,
		TargetStatus:     0x00000010,
		SendYouWereAdded: true,
	}

	t.Run("without dispatcher uses packet builder", func(t *testing.T) {
		sender := newMockPacketSender(t)
		svc := newMockLegacyService(t)
		sessions := newTestV5SessionManager()

		adder := sessionWithDirectConn(testV5UIN, 5191, 0x7F000002, 1)
		adder.SetStatus(0x00000020)
		target := sessionWithInstance(targetUIN)
		registerSession(sessions, adder)
		registerSession(sessions, target)

		svc.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
			Return(userAddResult, nil).Once()

		sender.EXPECT().SendPacket(adder.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
		sender.EXPECT().SendToSession(adder, mock.MatchedBy(func(p []byte) bool {
			return v5ServerCommand(p) == ICQLegacySrvUserOnline &&
				len(v5ServerPacketData(p)) >= 4 &&
				binary.LittleEndian.Uint32(v5ServerPacketData(p)[0:4]) == targetUIN
		})).Return(nil).Once()
		sender.EXPECT().SendToSession(target, mock.MatchedBy(func(p []byte) bool {
			if v5ServerCommand(p) != ICQLegacySrvSysMsgOnline {
				return false
			}
			data := v5ServerPacketData(p)
			return len(data) >= 8 &&
				binary.LittleEndian.Uint32(data[0:4]) == testV5UIN &&
				binary.LittleEndian.Uint16(data[4:6]) == ICQLegacyMsgAdded
		})).Return(nil).Once()
		sender.EXPECT().SendToSession(target, mock.MatchedBy(func(p []byte) bool {
			data := v5ServerPacketData(p)
			return v5ServerCommand(p) == ICQLegacySrvUserOnline &&
				len(data) >= 4 &&
				binary.LittleEndian.Uint32(data[0:4]) == testV5UIN
		})).Return(nil).Once()

		h := newTestV5Handler(t, sender, svc, sessions)
		pkt := buildEncryptedV5ClientPacket(t, defaultV5Pkt(ICQLegacyCmdUserAdd, v5TargetUINData(targetUIN)))
		assert.NoError(t, h.Handle(adder, testV5Addr, pkt))
		assert.Contains(t, adder.GetContactList(), targetUIN)
	})

	t.Run("with dispatcher sends user online via sendV5UserOnline", func(t *testing.T) {
		sender := newMockPacketSender(t)
		svc := newMockLegacyService(t)
		sessions := newTestV5SessionManager()

		adder := sessionWithDirectConn(testV5UIN, 5191, 0x7F000002, 1)
		adder.SetStatus(0x00000020)
		target := sessionWithInstance(targetUIN)
		registerSession(sessions, adder)
		registerSession(sessions, target)

		svc.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
			Return(userAddResult, nil).Once()

		sender.EXPECT().SendPacket(adder.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
		sender.EXPECT().SendToSession(adder, mock.MatchedBy(func(p []byte) bool {
			return v5ServerCommand(p) == ICQLegacySrvUserOnline
		})).Return(nil).Once()
		sender.EXPECT().SendToSession(target, mock.MatchedBy(func(p []byte) bool {
			return v5ServerCommand(p) == ICQLegacySrvSysMsgOnline
		})).Return(nil).Once()
		sender.EXPECT().SendToSession(target, mock.MatchedBy(func(p []byte) bool {
			data := v5ServerPacketData(p)
			return v5ServerCommand(p) == ICQLegacySrvUserOnline &&
				len(data) >= 17 &&
				binary.LittleEndian.Uint32(data[0:4]) == testV5UIN &&
				binary.LittleEndian.Uint32(data[8:12]) == 5191 &&
				data[16] == 1
		})).Return(nil).Once()

		h := newTestV5HandlerWithDispatcher(t, sender, svc, sessions)
		pkt := buildEncryptedV5ClientPacket(t, defaultV5Pkt(ICQLegacyCmdUserAdd, v5TargetUINData(targetUIN)))
		assert.NoError(t, h.Handle(adder, testV5Addr, pkt))
	})

	t.Run("SendYouWereAdded false skips target notifications", func(t *testing.T) {
		sender := newMockPacketSender(t)
		svc := newMockLegacyService(t)
		sessions := newTestV5SessionManager()

		adder := sessionWithInstance(testV5UIN)
		target := sessionWithInstance(targetUIN)
		registerSession(sessions, adder)
		registerSession(sessions, target)

		svc.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
			Return(&UserAddResult{
				TargetOnline:     true,
				TargetStatus:     0x10,
				SendYouWereAdded: false,
			}, nil).Once()

		sender.EXPECT().SendPacket(adder.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
		sender.EXPECT().SendToSession(adder, mock.AnythingOfType("[]uint8")).Return(nil).Once()

		h := newTestV5Handler(t, sender, svc, sessions)
		pkt := buildEncryptedV5ClientPacket(t, defaultV5Pkt(ICQLegacyCmdUserAdd, v5TargetUINData(targetUIN)))
		assert.NoError(t, h.Handle(adder, testV5Addr, pkt))
	})
}

func TestV5Handler_HandleOfflineMsgReq(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "no messages",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSysMsgReq, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetOfflineMessages(mock.Anything, testV5UIN).
						Return([]LegacyOfflineMessage{}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once() // ack
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvSysMsgDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "with messages",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSysMsgReq, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetOfflineMessages(mock.Anything, testV5UIN).
						Return([]LegacyOfflineMessage{{FromUIN: 99999, ToUIN: testV5UIN, MsgType: 1, Message: "hi"}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(3) // ack + msg + done
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdSysMsgReq, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSysMsgReq, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetOfflineMessages(mock.Anything, testV5UIN).
						Return(nil, errors.New("fail")).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once() // ack
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvSysMsgDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleOfflineMsgAck(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "success",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSysMsgDoneAck, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().AckOfflineMessages(mock.Anything, testV5UIN).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdSysMsgDoneAck, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSysMsgDoneAck, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().AckOfflineMessages(mock.Anything, testV5UIN).
						Return(errors.New("fail")).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMetaUser(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "login info found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdMetaUser, v5MetaUserData(0x04CE, v5TargetUINData(testV5UIN))),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV5UIN).Return(testMinimalUser(), nil).Once()
					e.Service.EXPECT().GetUserInfo(mock.Anything, testV5UIN).
						Return(&LegacyUserSearchResult{UIN: testV5UIN}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(8)
				},
				nil,
			),
		},
		{
			name:    "login info not found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdMetaUser, v5MetaUserData(0x04CE, v5TargetUINData(testV5UIN))),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV5UIN).Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2) // meta ack + fail
				},
				nil,
			),
		},
		{
			name:    "packet too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdMetaUser, []byte{0x01}),
			setup: v5CaseSetup(nil, func(e v5HandleEnv, err error) {
				require.Error(e.T, err)
				assert.Contains(e.T, err.Error(), "META_USER packet too short")
			}),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdMetaUser, v5MetaUserData(0x04CE, v5TargetUINData(testV5UIN))),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMetaUser_Login(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "meta login reply",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaLogin, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "meta login empty subData",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaLogin, []byte{}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMetaUser_GetInfo(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "login info alt opcode",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaLoginInfo2, v5TargetUINData(testV5UIN)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV5UIN).Return(testMinimalUser(), nil).Once()
					e.Service.EXPECT().GetUserInfo(mock.Anything, testV5UIN).
						Return(&LegacyUserSearchResult{UIN: testV5UIN}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(8)
				},
				nil,
			),
		},
		{
			name:    "user full info found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserFullInfo, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(testMinimalUser(), nil).Once()
					e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
						Return(&LegacyUserSearchResult{UIN: 99999}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(8)
				},
				nil,
			),
		},
		{
			name:    "user full info data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserFullInfo, []byte{0x01, 0x02, 0x03}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "user full info2 found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserFullInfo2, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(testMinimalUser(), nil).Once()
					e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
						Return(&LegacyUserSearchResult{UIN: 99999}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(8)
				},
				nil,
			),
		},
		{
			name:    "user full info2 not found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserFullInfo2, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "user info found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserInfo, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
						Return(&LegacyUserSearchResult{UIN: 99999, Nickname: "nick"}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "user info not found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserInfo, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMetaUser_SetProfile(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "set basic success",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetBasic2, v5MetaSetBasicData()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set basic service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetBasic2, v5MetaSetBasicData()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV5UIN, mock.Anything).
						Return(errors.New("fail")).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set work success",
			session: sessionWithInstance(testV5UIN),
			pkt: metaUserPkt(ICQLegacyMetaSetWork2, v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{
				Company: "co",
			})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().UpdateWorkInfo(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set work parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetWork2, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set more success",
			session: sessionWithInstance(testV5UIN),
			pkt: metaUserPkt(ICQLegacyMetaSetMore2, v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{
				Gender: 1,
			})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().UpdateMoreInfo(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set more parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetMore2, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set about success",
			session: sessionWithInstance(testV5UIN),
			pkt: metaUserPkt(ICQLegacyMetaSetAbout, v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{
				Notes: "about me",
			})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SetNotes(mock.Anything, testV5UIN, "about me").Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set about parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetAbout, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set interests success",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetInterests, v5MetaInterestsWireData(t)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SetInterests(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set interests wrong count",
			session: sessionWithInstance(testV5UIN),
			pkt: metaUserPkt(ICQLegacyMetaSetInterests, v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests{
				Interests: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{{Code: 1, Keyword: "only"}},
			})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set affiliations success",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetAffiliations, v5MetaAffiliationsWireData(t)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SetAffiliations(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set affiliations wrong count",
			session: sessionWithInstance(testV5UIN),
			pkt: metaUserPkt(ICQLegacyMetaSetAffiliations, v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
				PastAffiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{{Code: 1, Keyword: "p1"}},
				Affiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{{Code: 2, Keyword: "c1"}},
			})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set security success",
			session: sessionWithInstance(testV5UIN),
			pkt: metaUserPkt(ICQLegacyMetaSetSecurity, v5MetaWireMarshal(t, wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions{
				Authorization: 0,
				WebAware:      1,
			})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().UpdatePermissions(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set security parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetSecurity, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set password success",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetPass, v5MetaSetPassData("newpass")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SetPassword(mock.Anything, testV5UIN, "", "newpass").Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set password truncated",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetPass, []byte{0x01}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set hpcat success",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetHPCat, v5MetaSetHPCatData(true, 1, "home")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SetHomepageCategory(mock.Anything, testV5UIN, mock.Anything).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "set hpcat data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSetHPCat, []byte{0x01, 0x02}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMetaUser_Search(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "search name found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchName, v5MetaSearchNameData()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "nick", "first", "last", "").
						Return([]LegacyUserSearchResult{{UIN: 99999}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search name empty",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchName, v5MetaSearchNameData()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "nick", "first", "last", "").
						Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search uin found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchUIN, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetUserInfoForProtocol(mock.Anything, uint32(99999)).
						Return(&UserInfoResult{UIN: 99999}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search uin data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchUIN, []byte{0x01, 0x02, 0x03}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search email found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchEmail, v5MetaSearchEmailData("a@b.com")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "", "", "", "a@b.com").
						Return([]LegacyUserSearchResult{{UIN: 99999}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search email empty",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchEmail, v5MetaSearchEmailData("a@b.com")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "", "", "", "a@b.com").
						Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search white found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchWhite, v5LPString("alice")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().WhitePagesSearch(mock.Anything, mock.Anything).
						Return([]LegacyUserSearchResult{{UIN: 99999}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search white no criteria",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchWhite, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search white2 found",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchWhite2, v5LPString("alice")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "", "alice", "", "").
						Return([]LegacyUserSearchResult{{UIN: 99999}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "search white2 empty",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaSearchWhite2, v5LPString("alice")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "", "alice", "", "").
						Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMetaUser_Unregister(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "unregister success",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserUnreg, v5MetaUnregisterData(testV5UIN, "secret")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().DeleteUser(mock.Anything, testV5UIN, "secret").Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name:    "unregister data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(ICQLegacyMetaUserUnreg, []byte{0x01, 0x02, 0x03, 0x04, 0x05}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleMetaUser_Default(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "unknown sub-command",
			session: sessionWithInstance(testV5UIN),
			pkt:     metaUserPkt(0xFFFF, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleVisibleList(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "valid list",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdVisibleList, v5ContactListData([]uint32{11111})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvAck, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.True(t, e.Session.IsOnVisibleList(11111))
				},
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdVisibleList, v5ContactListData([]uint32{11111})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdVisibleList, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.False(t, e.Session.IsOnVisibleList(11111))
				},
			),
		},
	})
}

func TestV5Handler_HandleInvisibleList(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "valid list",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdInvisibleList, v5ContactListData([]uint32{22222})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.True(t, e.Session.IsOnInvisibleList(22222))
				},
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdInvisibleList, v5ContactListData([]uint32{22222})),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "parse error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdInvisibleList, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				func(e v5HandleEnv, err error) {
					assert.NoError(e.T, err)
					assert.False(t, e.Session.IsOnInvisibleList(22222))
				},
			),
		},
	})
}

func TestV5Handler_HandleChangeVILists(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "valid action",
			session: sessionWithInstance(testV5UIN),
			pkt: defaultV5Pkt(ICQLegacyCmdChangeVILists, func() []byte {
				b := make([]byte, 5)
				b[0] = 1
				binary.LittleEndian.PutUint32(b[1:], 33333)
				return b
			}()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt: defaultV5Pkt(ICQLegacyCmdChangeVILists, func() []byte {
				b := make([]byte, 5)
				b[0] = 1
				binary.LittleEndian.PutUint32(b[1:], 33333)
				return b
			}()),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
		{
			name:    "data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdChangeVILists, []byte{1}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleOldSearchUIN(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "user found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSearchUIN, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
						Return(&LegacyUserSearchResult{UIN: 99999}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once() // ack
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once() // found
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvSearchDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "user not found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSearchUIN, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once() // ack
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvSearchDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSearchUIN, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
						Return(nil, errors.New("fail")).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvSearchDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSearchUIN, []byte{1, 2}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvSearchDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdSearchUIN, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleOldSearch(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "any data",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdSearchUser, []byte{0x01}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvSearchDone, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdSearchUser, []byte{0x01}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleOldInfoReq(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "user found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
						Return(&LegacyUserSearchResult{UIN: 99999}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once() // ack
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvInfoReply, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "user not found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvInvalidUIN, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
						Return(nil, errors.New("fail")).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvInvalidUIN, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdInfoReq, []byte{1, 2}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleOldExtInfoReq(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "user found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdExtInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(testMinimalUser(), nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvExtInfoReply, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "user not found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdExtInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvInvalidUIN, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "service error",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdExtInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).
						Return(nil, errors.New("fail")).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvInvalidUIN, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name:    "data too short",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdExtInfoReq, []byte{1}),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdExtInfoReq, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleAckNewUIN(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "with session",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(ICQLegacyCmdRegNewUser, nil),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
						Run(func(_ *LegacySession, p []byte) {
							assert.Equal(t, ICQLegacySrvAck, v5ServerCommand(p))
						}).Return(nil).Once()
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(ICQLegacyCmdRegNewUser, nil),
		},
	})
}

func TestV5Handler_HandleDirectWhiteSearch(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "results found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(0x0532, v5LPString("alice")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().WhitePagesSearch(mock.Anything, mock.Anything).
						Return([]LegacyUserSearchResult{{UIN: 99999}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2) // ack + result
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(0x0532, v5LPString("alice")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleDirectNameSearch(t *testing.T) {
	nameData := append(append(v5LPString("nick"), v5LPString("first")...), v5LPString("last")...)

	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "results found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(0x0514, nameData),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "nick", "first", "last", "").
						Return([]LegacyUserSearchResult{{UIN: 99999}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(3)
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(0x0514, nameData),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleDirectUINSearch(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "user found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(0x051F, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
						Return(&LegacyUserSearchResult{UIN: 99999}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(3)
				},
				nil,
			),
		},
		{
			name:    "user not found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(0x051F, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).Return(nil, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(0x051F, v5TargetUINData(99999)),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}

func TestV5Handler_HandleDirectEmailSearch(t *testing.T) {
	runV5HandleCases(t, []v5HandleCase{
		{
			name:    "results found",
			session: sessionWithInstance(testV5UIN),
			pkt:     defaultV5Pkt(0x0528, v5LPString("a@b.com")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					e.Service.EXPECT().SearchByName(mock.Anything, "", "", "", "a@b.com").
						Return([]LegacyUserSearchResult{{UIN: 99999}}, nil).Once()
					e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(3)
				},
				nil,
			),
		},
		{
			name: "nil session",
			pkt:  defaultV5Pkt(0x0528, v5LPString("a@b.com")),
			setup: v5CaseSetup(
				func(e v5HandleEnv) {
					expectV5NotConnected(e.Sender)
				},
				nil,
			),
		},
	})
}
