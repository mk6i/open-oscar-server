package icq_legacy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testV4UIN  = uint32(12345)
	testV4Seq  = uint16(42)
	testV4Seq2 = uint16(7)
)

var testV4Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

type v4HandleEnv struct {
	T        *testing.T
	Sender   *mockPacketSender
	Service  *mockLegacyService
	Sessions *LegacySessionManager
	Session  *LegacySession
}

type v4HandleCase struct {
	name    string
	session *LegacySession
	pkt     []byte
	wire    func(t *testing.T) []byte
	setup   func(v4HandleEnv) func(error)
}

func v4CaseSetup(pre func(v4HandleEnv), after func(e v4HandleEnv, err error)) func(v4HandleEnv) func(error) {
	return func(e v4HandleEnv) func(error) {
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

func runV4HandleCases(t *testing.T, cases []v4HandleCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			svc := newMockLegacyService(t)
			sessions := newTestLegacySessionManager()
			e := v4HandleEnv{
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
			h := newTestV4Handler(t, sender, svc, sessions)
			var wire []byte
			switch {
			case tt.wire != nil:
				wire = tt.wire(t)
			case tt.pkt != nil:
				wire = tt.pkt
			default:
				t.Fatal("case must set pkt or wire")
			}
			check(h.Handle(tt.session, testV4Addr, wire))
		})
	}
}

func newTestV4Handler(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V4Handler {
	t.Helper()
	if sessions == nil {
		sessions = newTestLegacySessionManager()
	}
	return NewV4Handler(sessions, svc, sender, NewV4PacketBuilder(sessions, nil), slog.Default())
}

func v4Session(uin uint32) *LegacySession {
	s := newTestLegacySession(uin, legacySessionOptOSCARSess, func(ls *LegacySession) {
		ls.Version = ICQLegacyVersionV4
		ls.SeqNumClient = testV4Seq
	})
	return s
}

// v4SrvCommand reads the command from outbound V3-format server packets (V4 wire uses
// ICQLegacyVersionV3 headers with checkcode for server→client replies).
func v4SrvCommand(packet []byte) uint16 {
	return v3ServerCommand(packet)
}

func expectV4NotConnected(sender *mockPacketSender) {
	sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
		Run(func(_ *net.UDPAddr, p []byte) {
			if got := v3ServerCommand(p); got != ICQLegacySrvNotConnected {
				panic(fmt.Sprintf("got command 0x%04X, want NOT_CONNECTED", got))
			}
		}).Return(nil).Once()
}

func transformV4Packet(packet []byte) error {
	if len(packet) < v4HeaderSize {
		return fmt.Errorf("packet too short for V4 transform")
	}
	checkcode := binary.LittleEndian.Uint32(packet[v4OffsetCheckcode:])
	packetLen := len(packet)
	key := uint32(packetLen)*0x66756B65 + checkcode
	count := ((packetLen+3)/4 + 3) / 4
	for i := 0; i < count; i++ {
		pos := i * 4
		if i == 4 {
			continue
		}
		if pos >= packetLen {
			break
		}
		tableIdx := pos & 0xFF
		xorVal := key + uint32(V4Table[tableIdx])
		for j := 0; j < 4 && pos+j < packetLen; j++ {
			packet[pos+j] ^= byte(xorVal >> (j * 8))
		}
	}
	packet[0] = 0x04
	packet[1] = 0x00
	return nil
}

func buildV4ClientPacket(t *testing.T, command, seq1, seq2 uint16, uin uint32, data []byte) []byte {
	t.Helper()
	buf := make([]byte, v4HeaderSize+len(data))
	binary.LittleEndian.PutUint16(buf[v4OffsetVersion:], ICQLegacyVersionV4)
	binary.LittleEndian.PutUint16(buf[v4OffsetRandom:], 0x1234)
	binary.LittleEndian.PutUint16(buf[v4OffsetZero:], 0)
	binary.LittleEndian.PutUint16(buf[v4OffsetCommand:], command)
	binary.LittleEndian.PutUint16(buf[v4OffsetSeq1:], seq1)
	binary.LittleEndian.PutUint16(buf[v4OffsetSeq2:], seq2)
	binary.LittleEndian.PutUint32(buf[v4OffsetUIN:], uin)
	binary.LittleEndian.PutUint32(buf[v4OffsetCheckcode:], 0)
	copy(buf[v4HeaderSize:], data)
	require.NoError(t, transformV4Packet(buf))
	verify := make([]byte, len(buf))
	copy(verify, buf)
	require.NoError(t, transformV4Packet(verify))
	require.Equal(t, command, binary.LittleEndian.Uint16(verify[v4OffsetCommand:]))
	require.Equal(t, uin, binary.LittleEndian.Uint32(verify[v4OffsetUIN:]))
	return buf
}

func defaultV4Pkt(command uint16, data []byte) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		return buildV4ClientPacket(t, command, testV4Seq, testV4Seq2, testV4UIN, data)
	}
}

func v4GetDepsPayload(uin uint32, password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+2+len(pwd))
	binary.LittleEndian.PutUint32(buf[0:4], uin)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(pwd)))
	copy(buf[6:], pwd)
	return buf
}

func v4LoginData(password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+4+2+len(pwd))
	binary.LittleEndian.PutUint32(buf[0:4], 0)
	binary.LittleEndian.PutUint32(buf[4:8], 4000)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(pwd)))
	copy(buf[10:], pwd)
	return buf
}

func v4ContactListData(uins []uint32) []byte {
	buf := make([]byte, 1+4*len(uins))
	buf[0] = byte(len(uins))
	for i, u := range uins {
		binary.LittleEndian.PutUint32(buf[1+4*i:], u)
	}
	return buf
}

func v4MessageData(toUIN uint32, msgType uint16, message string) []byte {
	msg := []byte(message)
	buf := make([]byte, 4+2+2+len(msg))
	binary.LittleEndian.PutUint32(buf[0:4], toUIN)
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(len(msg)))
	copy(buf[8:], msg)
	return buf
}

func v4TargetUINData(target uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, target)
	return buf
}

func v4WriteBufLE(buf *bytes.Buffer, v any) {
	_ = binary.Write(buf, binary.LittleEndian, v)
}

func TestBuildV4ClientPacket_roundTrip(t *testing.T) {
	wire := buildV4ClientPacket(t, ICQLegacyCmdKeepAlive, testV4Seq, testV4Seq2, testV4UIN, nil)
	plain := make([]byte, len(wire))
	copy(plain, wire)
	require.NoError(t, transformV4Packet(plain))
	require.Equal(t, ICQLegacyCmdKeepAlive, binary.LittleEndian.Uint16(plain[v4OffsetCommand:]))
	require.Equal(t, testV4UIN, binary.LittleEndian.Uint32(plain[v4OffsetUIN:]))
}

func v4SrvData(packet []byte) []byte {
	if len(packet) <= 16 {
		return nil
	}
	return packet[16:]
}

func v4UpdateBasicData() []byte {
	buf := new(bytes.Buffer)
	writeLegacyString(buf, "nick")
	writeLegacyString(buf, "first")
	writeLegacyString(buf, "last")
	writeLegacyString(buf, "a@b.com")
	buf.WriteByte(0)
	return buf.Bytes()
}

func v4UpdateDetailData() []byte {
	buf := new(bytes.Buffer)
	writeLegacyString(buf, "city")
	v4WriteBufLE(buf, uint16(840))
	buf.WriteByte(0)
	writeLegacyString(buf, "CA")
	v4WriteBufLE(buf, uint16(25))
	buf.WriteByte(1)
	writeLegacyString(buf, "555")
	writeLegacyString(buf, "http://example.com")
	writeLegacyString(buf, "about me")
	v4WriteBufLE(buf, uint32(0))
	return buf.Bytes()
}

func v4RegNewUserData(nick, first, last, email string) []byte {
	buf := new(bytes.Buffer)
	v4WriteBufLE(buf, uint16(0))
	writeLegacyString(buf, nick)
	writeLegacyString(buf, first)
	writeLegacyString(buf, last)
	writeLegacyString(buf, email)
	return buf.Bytes()
}

func TestV4Handler_Handle(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name: "packet too short",
			pkt:  []byte{0x01, 0x02},
			setup: v4CaseSetup(nil, func(e v4HandleEnv, err error) {
				require.Error(e.T, err)
				assert.Contains(e.T, err.Error(), "V4 packet too short")
			}),
		},
		{
			name: "header too short for decrypt",
			pkt:  make([]byte, v4HeaderSize-1),
			setup: v4CaseSetup(nil, func(e v4HandleEnv, err error) {
				require.Error(e.T, err)
				assert.Contains(e.T, err.Error(), "too short")
			}),
		},
		{
			name:    "nil session disallowed command",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				expectV4NotConnected(e.Sender)
			}, nil),
		},
		{
			name:    "nil session ACK allowed",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdAck, nil),
		},
		{
			name:    "session state updated",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdAck, nil),
			setup: v4CaseSetup(nil, func(e v4HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(e.T, testV4Seq, e.Session.SeqNumClient)
				assert.WithinDuration(e.T, time.Now(), e.Session.GetLastActivity(), time.Second)
			}),
		},
		{
			name:    "unknown command with session",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(0xFFFF, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "SysMsgDoneAck no-op",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdSysMsgDoneAck, nil),
		},
	})
}

func TestV4Handler_HandleFirstLogin(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "first login",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdFirstLogin, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v4SrvCommand(p))
					}).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvRegisterInfo, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleRegRequestInfo(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "registration info request",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdRegRequestInfo, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvRegisterInfo, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleRegNewUserInfo(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "success",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdRegNewUserInfo, v4RegNewUserData("nick", "first", "last", "a@b.com")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().RegisterNewUser(mock.Anything, "nick", "first", "last", "a@b.com", mock.AnythingOfType("string")).
					Return(uint32(100001), nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvNewUIN, v4SrvCommand(p))
						assert.Equal(e.T, uint32(100001), binary.LittleEndian.Uint32(p[8:12]))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "data too short",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdRegNewUserInfo, []byte{0, 0}),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				expectV4NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV4Handler_HandleGetDeps(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "valid credentials",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdGetDeps, v4GetDepsPayload(testV4UIN, "secret")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV4UIN, "secret").Return(true, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvUserDepsList, v4SrvCommand(p))
					}).Return(nil).Once()
			}, func(e v4HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.NotNil(e.T, e.Sessions.GetSession(testV4UIN))
			}),
		},
		{
			name:    "invalid credentials",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdGetDeps, v4GetDepsPayload(testV4UIN, "wrong")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV4UIN, "wrong").Return(false, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "service error",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdGetDeps, v4GetDepsPayload(testV4UIN, "secret")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV4UIN, "secret").
					Return(false, errors.New("db down")).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "packet too short",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdGetDeps, []byte{0x01}),
			setup: v4CaseSetup(nil, func(e v4HandleEnv, err error) {
				assert.NoError(e.T, err)
			}),
		},
	})
}

func TestV4Handler_HandleLogin(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "auth success direct login",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdLogin, v4LoginData("secret")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.MatchedBy(func(req AuthRequest) bool {
					return req.UIN == testV4UIN && req.Password == "secret" && req.Version == ICQLegacyVersionV4
				})).Return(&AuthResult{Success: true, oscarSession: testAuthSuccessInstance()}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v4HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.NotNil(e.T, e.Sessions.GetSession(testV4UIN))
			}),
		},
		{
			name:    "bad password",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdLogin, v4LoginData("wrong")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
					Return(&AuthResult{Success: false, ErrorCode: 0x0001}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "parse error",
			session: nil,
			wire:    defaultV4Pkt(ICQLegacyCmdLogin, []byte{0, 0, 0}),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleContactList(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "valid contact list",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdContactList, v4ContactListData([]uint32{99999})),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ProcessContactList(mock.Anything, mock.Anything, mock.Anything).
					Return(&ContactListResult{}, nil).Once()
				e.Service.EXPECT().NotifyUserOnline(mock.Anything, testV4UIN, mock.Anything).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvUserListDone, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			wire: defaultV4Pkt(ICQLegacyCmdContactList, v4ContactListData(nil)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				expectV4NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV4Handler_HandlePing(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "keep alive",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "keep alive2",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdKeepAlive2, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			wire: defaultV4Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				expectV4NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV4Handler_HandleLogoff(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "active session",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdLogoff, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				registerSession(e.Sessions, e.Session)
				e.Service.EXPECT().NotifyUserOffline(mock.Anything, testV4UIN).Return(nil).Once()
			}, func(e v4HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Nil(e.T, e.Sessions.GetSession(testV4UIN))
			}),
		},
		{
			name: "nil session",
			wire: defaultV4Pkt(ICQLegacyCmdLogoff, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				expectV4NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV4Handler_HandleSetStatus(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "valid status",
			session: v4Session(testV4UIN),
			wire: defaultV4Pkt(ICQLegacyCmdSetStatus, func() []byte {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 0x00000001)
				return b
			}()),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
					Return(&StatusChangeResult{}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v4HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(e.T, uint32(0x00000001), e.Session.GetStatus())
			}),
		},
		{
			name: "nil session",
			wire: defaultV4Pkt(ICQLegacyCmdSetStatus, func() []byte {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 1)
				return b
			}()),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				expectV4NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV4Handler_HandleMessage(t *testing.T) {
	target := v4Session(99999)
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "offline stored",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdThruServer, v4MessageData(99999, 0x0001, "hi")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{StoredOffline: true}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name:    "online target",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdThruServer, v4MessageData(99999, 0x0001, "hi")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				registerSession(e.Sessions, target)
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{TargetOnline: true}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			wire: defaultV4Pkt(ICQLegacyCmdThruServer, v4MessageData(99999, 0x0001, "hi")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				expectV4NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV4Handler_HandleAuthorize(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "authorize message",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdAuthorize, v4MessageData(99999, 0x0001, "auth")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{StoredOffline: true}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleUserAdd(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "success",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdUserAdd, v4TargetUINData(99999)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
					Return(&UserAddResult{}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v4HandleEnv, err error) {
				assert.Contains(e.T, e.Session.GetContactList(), uint32(99999))
			}),
		},
		{
			name: "nil session",
			wire: defaultV4Pkt(ICQLegacyCmdUserAdd, v4TargetUINData(99999)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				expectV4NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV4Handler_HandleOfflineMsgReq(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "no messages",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdSysMsgReq, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().GetOfflineMessages(mock.Anything, testV4UIN).
					Return([]LegacyOfflineMessage{}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvSysMsgDone, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleGetInfo(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "get info",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdUserGetInfo, v4TargetUINData(99999)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvInfoReply, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleInfoReq(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "get info",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdInfoReq, v4TargetUINData(99999)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
					Return(&LegacyUserSearchResult{UIN: 99999, Nickname: "nick"}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvInfoReply, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleExtInfoReq(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "get ext info",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdExtInfoReq, v4TargetUINData(99999)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(testMinimalUser(), nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvExtInfoReply, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleUpdateBasic(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "success",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdSetBasicInfo, v4UpdateBasicData()),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV4UIN, mock.Anything).Return(nil).Once()
				e.Service.EXPECT().SetAuthMode(mock.Anything, testV4UIN, false).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvUpdatedBasicV4, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleUpdateDetail(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "success",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdUpdateDetail, v4UpdateDetailData()),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV4UIN).Return(testMinimalUser(), nil).Once()
				e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV4UIN, mock.Anything).Return(nil).Once()
				e.Service.EXPECT().UpdateMoreInfo(mock.Anything, testV4UIN, mock.Anything).Return(nil).Once()
				e.Service.EXPECT().SetNotes(mock.Anything, testV4UIN, "about me").Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvUpdatedDetail, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleSearchByUIN(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "found",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdSearchUIN, v4TargetUINData(99999)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
					Return(&LegacyUserSearchResult{UIN: 99999}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
		{
			name:    "not found",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdSearchUIN, v4TargetUINData(99999)),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
					Return(&LegacyUserSearchResult{}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV4Handler_HandleSearchByName(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "stub ends search",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdSearchUser, v2SearchUserData(1, "alice")),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvSearchDone, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleSearchStart(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "stub ACK",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdSearchStart, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v4SrvCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_HandleVisibleInvisibleMeta(t *testing.T) {
	runV4HandleCases(t, []v4HandleCase{
		{
			name:    "visible list stub",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdVisibleList, v4ContactListData([]uint32{11111})),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name:    "invisible list stub",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdInvisibleList, v4ContactListData([]uint32{22222})),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name:    "meta user stub",
			session: v4Session(testV4UIN),
			wire:    defaultV4Pkt(ICQLegacyCmdMetaUser, nil),
			setup: v4CaseSetup(func(e v4HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV4Handler_sendUserOnline(t *testing.T) {
	const (
		onlineUIN  = uint32(67890)
		userStatus = uint32(0x00000010)
	)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v4Session(testV4UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		if v4SrvCommand(p) != ICQLegacySrvUserOnline {
			return false
		}
		data := v4SrvData(p)
		return len(data) >= 25 &&
			binary.LittleEndian.Uint32(data[0:4]) == onlineUIN
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendUserOnline(recipient, onlineUIN, userStatus))
}

func TestV4Handler_sendUserOffline(t *testing.T) {
	const offlineUIN = uint32(88888)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v4Session(testV4UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v4SrvData(p)
		return v4SrvCommand(p) == ICQLegacySrvUserOffline &&
			len(data) == 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == offlineUIN
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendUserOffline(recipient, offlineUIN))
}

func TestV4Handler_sendUserStatus(t *testing.T) {
	const (
		changedUIN = uint32(88888)
		status     = uint32(0x00010002)
	)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v4Session(testV4UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v4SrvData(p)
		return v4SrvCommand(p) == ICQLegacySrvUserStatus &&
			len(data) == 8 &&
			binary.LittleEndian.Uint32(data[0:4]) == changedUIN &&
			binary.LittleEndian.Uint32(data[4:8]) == status
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendUserStatus(recipient, changedUIN, status))
}

func TestV4Handler_sendOnlineMessage(t *testing.T) {
	const fromUIN = uint32(55555)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v4Session(testV4UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v4SrvData(p)
		return v4SrvCommand(p) == ICQLegacySrvSysMsgOnline &&
			len(data) >= 8 &&
			binary.LittleEndian.Uint32(data[0:4]) == fromUIN
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendOnlineMessage(recipient, fromUIN, 0x0001, "hello", testV4Seq2))
}

func TestV4Handler_sendSearchFoundAndEnd(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sess := v4Session(testV4UIN)

	sender.EXPECT().SendToSession(sess, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvSearchFound
	})).Return(nil).Once()
	sender.EXPECT().SendToSession(sess, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvSearchDone
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	result := &LegacyUserSearchResult{UIN: 99999, Nickname: "alice"}
	assert.NoError(t, h.sendSearchFound(sess, testV4Seq2, result))
	assert.NoError(t, h.sendSearchEnd(sess, testV4Seq2, false))
}

func TestV4Handler_sendBasicInfo(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sess := v4Session(testV4UIN)

	sender.EXPECT().SendToSession(sess, mock.MatchedBy(func(p []byte) bool {
		data := v4SrvData(p)
		return v4SrvCommand(p) == ICQLegacySrvInfoReply &&
			len(data) >= 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == uint32(99999)
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendBasicInfo(sess, testV4Seq2, 99999))
}

func TestV4Handler_sendBasicInfoResponse(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sess := v4Session(testV4UIN)

	svc.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
		Return(&LegacyUserSearchResult{UIN: 99999, Nickname: "nick"}, nil).Once()
	sender.EXPECT().SendToSession(sess, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvInfoReply
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendBasicInfoResponse(sess, testV4Seq2, 99999))
}

func TestV4Handler_sendExtInfoResponse(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sess := v4Session(testV4UIN)

	svc.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(testMinimalUser(), nil).Once()
	sender.EXPECT().SendToSession(sess, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvExtInfoReply
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendExtInfoResponse(sess, testV4Seq2, 99999))
}

func TestV4Handler_sendDeptsListWithCheckcode(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sess := v4Session(testV4UIN)

	sender.EXPECT().SendToSession(sess, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvUserDepsList && len(p) == 28
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendDeptsListWithCheckcode(sess, testV4Seq2))
}

func TestV4Handler_sendRegisterInfo(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)

	sender.EXPECT().SendPacket(testV4Addr, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvRegisterInfo
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendRegisterInfo(testV4Addr, testV4Seq2, testV4UIN))
}

func TestV4Handler_sendRegistrationOK(t *testing.T) {
	const newUIN = uint32(100001)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)

	sender.EXPECT().SendPacket(testV4Addr, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvNewUIN &&
			binary.LittleEndian.Uint32(p[8:12]) == newUIN
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, newTestLegacySessionManager())
	assert.NoError(t, h.sendRegistrationOK(testV4Addr, testV4Seq2, newUIN, "pass"))
}

func TestV4Handler_HandleLogoff_notifiesContacts(t *testing.T) {
	const contactUIN = uint32(88888)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()

	loggingOff := v4Session(testV4UIN)
	loggingOff.SetContactList([]uint32{contactUIN})
	contact := v4Session(contactUIN)
	contact.SetContactList([]uint32{testV4UIN})
	registerSession(sessions, loggingOff)
	registerSession(sessions, contact)

	svc.EXPECT().NotifyUserOffline(mock.Anything, testV4UIN).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		data := v4SrvData(p)
		return v4SrvCommand(p) == ICQLegacySrvUserOffline &&
			len(data) == 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == testV4UIN
	})).Return(nil).Once()

	h := newTestV4HandlerWithDispatcher(t, sender, svc, sessions)
	pkt := buildV4ClientPacket(t, ICQLegacyCmdLogoff, testV4Seq, testV4Seq2, testV4UIN, nil)
	assert.NoError(t, h.Handle(loggingOff, testV4Addr, pkt))
	assert.Nil(t, sessions.GetSession(testV4UIN))
}

func TestV4Handler_HandleSetStatus_notifiesContacts(t *testing.T) {
	const (
		contactUIN = uint32(88888)
		newStatus  = uint32(0x00010002)
	)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()

	changer := v4Session(testV4UIN)
	contact := v4Session(contactUIN)
	registerSession(sessions, changer)
	registerSession(sessions, contact)

	svc.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
		Return(&StatusChangeResult{
			NotifyTargets: []NotifyTarget{{UIN: contactUIN}},
		}, nil).Once()

	sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		data := v4SrvData(p)
		return v4SrvCommand(p) == ICQLegacySrvUserStatus &&
			len(data) == 8 &&
			binary.LittleEndian.Uint32(data[0:4]) == testV4UIN &&
			binary.LittleEndian.Uint32(data[4:8]) == newStatus
	})).Return(nil).Once()

	h := newTestV4HandlerWithDispatcher(t, sender, svc, sessions)
	statusData := make([]byte, 4)
	binary.LittleEndian.PutUint32(statusData, newStatus)
	pkt := buildV4ClientPacket(t, ICQLegacyCmdSetStatus, testV4Seq, testV4Seq2, testV4UIN, statusData)
	assert.NoError(t, h.Handle(changer, testV4Addr, pkt))
	assert.Equal(t, newStatus, changer.GetStatus())
}

func TestV4Handler_HandleUserAdd_notifyTarget(t *testing.T) {
	const targetUIN = uint32(99999)

	adder := v4Session(testV4UIN)
	target := v4Session(targetUIN)
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()
	registerSession(sessions, adder)
	registerSession(sessions, target)

	svc.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).Return(&UserAddResult{}, nil).Once()
	sender.EXPECT().SendPacket(testV4Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
	sender.EXPECT().SendToSession(adder, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvUserOnline
	})).Return(nil).Once()
	sender.EXPECT().SendToSession(target, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvSysMsgOnline
	})).Return(nil).Once()
	sender.EXPECT().SendToSession(target, mock.MatchedBy(func(p []byte) bool {
		return v4SrvCommand(p) == ICQLegacySrvUserOnline
	})).Return(nil).Once()

	h := newTestV4Handler(t, sender, svc, sessions)
	pkt := buildV4ClientPacket(t, ICQLegacyCmdUserAdd, testV4Seq, testV4Seq2, testV4UIN, v4TargetUINData(targetUIN))
	assert.NoError(t, h.Handle(adder, testV4Addr, pkt))
	assert.Contains(t, adder.GetContactList(), targetUIN)
}

func newTestV4HandlerWithDispatcher(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V4Handler {
	t.Helper()
	logger := slog.Default()
	if sessions == nil {
		sessions = newTestLegacySessionManager()
	}
	v1 := NewV1Handler(sessions, svc, sender, logger)
	v2 := NewV2Handler(sessions, svc, sender, NewV2PacketBuilder(), logger)
	v3 := NewV3Handler(sessions, svc, sender, NewV3PacketBuilder(sessions, nil), logger)
	v4 := NewV4Handler(sessions, svc, sender, NewV4PacketBuilder(sessions, nil), logger)
	v5 := NewV5Handler(sessions, svc, sender, NewV5PacketBuilder(sessions, nil), logger)
	cfg := config.ICQLegacyConfig{SupportedVersions: []int{1, 2, 3, 4, 5}}
	dispatcher := NewProtocolDispatcher(v1, v2, v3, v4, v5, cfg, logger)
	v4.SetDispatcher(dispatcher)
	return v4
}
