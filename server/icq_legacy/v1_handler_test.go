package icq_legacy

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testV1UIN = uint32(12345)
	testV1Seq = uint16(42)
)

var testV1Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

type v1HandleEnv struct {
	T        *testing.T
	Sender   *mockPacketSender
	Service  *mockLegacyService
	Sessions *LegacySessionManager
	Session  *LegacySession
}

type v1HandleCase struct {
	name    string
	session *LegacySession
	pkt     []byte
	setup   func(v1HandleEnv) func(error)
}

func v1CaseSetup(pre func(v1HandleEnv), after func(e v1HandleEnv, err error)) func(v1HandleEnv) func(error) {
	return func(e v1HandleEnv) func(error) {
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

func runV1HandleCases(t *testing.T, cases []v1HandleCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			svc := newMockLegacyService(t)
			sessions := newTestLegacySessionManager()
			e := v1HandleEnv{
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
			h := newTestV1Handler(t, sender, svc, sessions)
			check(h.Handle(tt.session, testV1Addr, tt.pkt))
		})
	}
}

func newTestV1Handler(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V1Handler {
	t.Helper()
	if sessions == nil {
		sessions = newTestLegacySessionManager()
	}
	return NewV1Handler(sessions, svc, sender, slog.Default())
}

func buildV1LoginPacket(uin uint32, seq uint16, password string, status uint32) []byte {
	pwd := []byte(password)
	data := make([]byte, 2+len(pwd)+4)
	binary.LittleEndian.PutUint16(data[0:2], uint16(len(pwd)))
	copy(data[2:], pwd)
	binary.LittleEndian.PutUint32(data[2+len(pwd):], status)
	buf := make([]byte, 10+len(data))
	binary.LittleEndian.PutUint16(buf[0:2], ICQLegacyVersionV1)
	binary.LittleEndian.PutUint16(buf[2:4], ICQLegacyCmdGetDeps)
	binary.LittleEndian.PutUint16(buf[4:6], seq)
	binary.LittleEndian.PutUint32(buf[6:10], uin)
	copy(buf[10:], data)
	return buf
}

func TestV1Handler_Handle_V1Login(t *testing.T) {
	runV1HandleCases(t, []v1HandleCase{
		{
			name: "auth success",
			pkt:  buildV1LoginPacket(testV1UIN, testV1Seq, "secret", 0),
			setup: v1CaseSetup(func(e v1HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.MatchedBy(func(req AuthRequest) bool {
					return req.UIN == testV1UIN && req.Password == "secret" && req.Version == ICQLegacyVersionV1
				})).Return(&AuthResult{Success: true, oscarSession: testAuthSuccessInstance()}, nil).Once()
				e.Service.EXPECT().NotifyStatusChange(mock.Anything, testV1UIN, uint32(0)).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).Return(nil).Twice()
			}, func(e v1HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.NotNil(e.T, e.Sessions.GetSession(testV1UIN))
			}),
		},
		{
			name: "bad password",
			pkt:  buildV1LoginPacket(testV1UIN, testV1Seq, "wrong", 0),
			setup: v1CaseSetup(func(e v1HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
					Return(&AuthResult{Success: false}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV1Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name: "packet too short",
			pkt:  []byte{0x01, 0x00, 0xF2, 0x03, 0x2A, 0x00},
			setup: v1CaseSetup(nil, func(e v1HandleEnv, err error) {
				assert.NoError(e.T, err)
			}),
		},
		{
			name: "auth service error",
			pkt:  buildV1LoginPacket(testV1UIN, testV1Seq, "secret", 0),
			setup: v1CaseSetup(func(e v1HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
					Return(nil, errors.New("auth failed")).Once()
				e.Sender.EXPECT().SendPacket(testV1Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV1Handler_Handle_delegatesToV2(t *testing.T) {
	sess := v2Session(testV1UIN)
	sess.Version = ICQLegacyVersionV1
	runV1HandleCases(t, []v1HandleCase{
		{
			name:    "keep alive uses V2 handler",
			session: sess,
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdKeepAlive, nil)),
			setup: v1CaseSetup(func(e v1HandleEnv) {
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV1Handler_Handle_GetDeps_notIntercepted(t *testing.T) {
	// V1 always routes 0x03F2 to handleV1Login; it never calls V2 ValidateCredentials (getdeps).
	pwd := []byte("secret")
	data := make([]byte, 2+len(pwd)+4)
	binary.LittleEndian.PutUint16(data[0:2], uint16(len(pwd)))
	copy(data[2:], pwd)
	pkt := make([]byte, 10+len(data))
	binary.LittleEndian.PutUint16(pkt[0:2], ICQLegacyVersionV1)
	binary.LittleEndian.PutUint16(pkt[2:4], ICQLegacyCmdGetDeps)
	binary.LittleEndian.PutUint16(pkt[4:6], testV1Seq)
	binary.LittleEndian.PutUint32(pkt[6:10], testV1UIN)
	copy(pkt[10:], data)
	runV1HandleCases(t, []v1HandleCase{
		{
			name: "0x03F2 on V1 uses login not V2 getdeps",
			pkt:  pkt,
			setup: v1CaseSetup(func(e v1HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.MatchedBy(func(req AuthRequest) bool {
					return req.UIN == testV1UIN && req.Password == "secret"
				})).Return(&AuthResult{Success: false}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV1Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV1Handler_Handle_sessionCreateFailure(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()
	svc.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
		Return(&AuthResult{Success: true, oscarSession: nil}, nil).Once()
	sender.EXPECT().SendPacket(testV1Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
	h := newTestV1Handler(t, sender, svc, sessions)
	pkt := buildV1LoginPacket(testV1UIN, testV1Seq, "secret", 0)
	require.NoError(t, h.Handle(nil, testV1Addr, pkt))
}
