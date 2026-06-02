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
	testV3UIN  = uint32(12345)
	testV3Seq  = uint16(42)
	testV3Seq2 = uint16(7)
)

var testV3Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

type v3HandleEnv struct {
	T        *testing.T
	Sender   *mockPacketSender
	Service  *mockLegacyService
	Sessions *LegacySessionManager
	Session  *LegacySession
}

type v3HandleCase struct {
	name    string
	session *LegacySession
	pkt     []byte
	wire    func(t *testing.T) []byte
	setup   func(v3HandleEnv) func(error)
}

func v3CaseSetup(pre func(v3HandleEnv), after func(e v3HandleEnv, err error)) func(v3HandleEnv) func(error) {
	return func(e v3HandleEnv) func(error) {
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

func runV3HandleCases(t *testing.T, cases []v3HandleCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			svc := newMockLegacyService(t)
			sessions := newTestLegacySessionManager()
			e := v3HandleEnv{
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
			h := newTestV3Handler(t, sender, svc, sessions)
			var wire []byte
			switch {
			case tt.wire != nil:
				wire = tt.wire(t)
			case tt.pkt != nil:
				wire = tt.pkt
			default:
				t.Fatal("case must set pkt or wire")
			}
			check(h.Handle(tt.session, testV3Addr, wire))
		})
	}
}

func newTestV3Handler(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V3Handler {
	t.Helper()
	if sessions == nil {
		sessions = newTestLegacySessionManager()
	}
	return NewV3Handler(sessions, svc, sender, NewV3PacketBuilder(sessions, nil), slog.Default())
}

func newTestV3HandlerWithDispatcher(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V3Handler {
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
	v3.SetDispatcher(dispatcher)
	return v3
}

func v3Session(uin uint32) *LegacySession {
	s := newTestLegacySession(uin, legacySessionOptOSCARSess, func(ls *LegacySession) {
		ls.Version = ICQLegacyVersionV3
		ls.SeqNumClient = testV3Seq
	})
	return s
}

func v3ServerCommand(packet []byte) uint16 {
	if len(packet) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint16(packet[2:4])
}

func expectV3NotConnected(sender *mockPacketSender) {
	sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
		Run(func(_ *net.UDPAddr, p []byte) {
			if got := v3ServerCommand(p); got != ICQLegacySrvNotConnected {
				panic(fmt.Sprintf("got command 0x%04X, want NOT_CONNECTED", got))
			}
		}).Return(nil).Once()
}

func buildV3ClientPacket(command, seq1, seq2 uint16, uin uint32, data []byte) []byte {
	buf := make([]byte, 12+len(data))
	binary.LittleEndian.PutUint16(buf[0:2], ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(buf[2:4], command)
	binary.LittleEndian.PutUint16(buf[4:6], seq1)
	binary.LittleEndian.PutUint16(buf[6:8], seq2)
	binary.LittleEndian.PutUint32(buf[8:12], uin)
	copy(buf[12:], data)
	return buf
}

func defaultV3Pkt(command uint16, data []byte) []byte {
	return buildV3ClientPacket(command, testV3Seq, testV3Seq2, testV3UIN, data)
}

func v3LoginData(password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+4+2+len(pwd))
	binary.LittleEndian.PutUint32(buf[0:4], 0)
	binary.LittleEndian.PutUint32(buf[4:8], 4000)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(pwd)))
	copy(buf[10:], pwd)
	return buf
}

func v3GetDepsPayload(uin uint32, password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+2+len(pwd))
	binary.LittleEndian.PutUint32(buf[0:4], uin)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(pwd)))
	copy(buf[6:], pwd)
	return buf
}

func v3GetDepsData(uin uint32, password string) []byte {
	return append(make([]byte, 4), v3GetDepsPayload(uin, password)...)
}

func v3TimestampPrefix(payload []byte) []byte {
	return append(make([]byte, 4), payload...)
}

func v3LPString(s string) []byte {
	buf := new(bytes.Buffer)
	writeLegacyString(buf, s)
	return buf.Bytes()
}

func v3ContactListPayload(uins []uint32) []byte {
	buf := make([]byte, 1+4*len(uins))
	buf[0] = byte(len(uins))
	for i, u := range uins {
		binary.LittleEndian.PutUint32(buf[1+4*i:], u)
	}
	return buf
}

func v3ContactListData(uins []uint32) []byte {
	return v3TimestampPrefix(v3ContactListPayload(uins))
}

func v3MessagePayload(toUIN uint32, msgType uint16, message string) []byte {
	msg := []byte(message)
	buf := make([]byte, 4+2+2+len(msg))
	binary.LittleEndian.PutUint32(buf[0:4], toUIN)
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(len(msg)))
	copy(buf[8:], msg)
	return buf
}

func v3MessageData(toUIN uint32, msgType uint16, message string) []byte {
	return v3TimestampPrefix(v3MessagePayload(toUIN, msgType, message))
}

func v3TargetUINPayload(target uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, target)
	return buf
}

func v3TargetUINData(target uint32) []byte {
	return v3TimestampPrefix(v3TargetUINPayload(target))
}

func v3SetStatusData(status uint32) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[4:8], status)
	return buf
}

func v3SearchUINData(targetUIN uint32) []byte {
	uinStr := fmt.Sprintf("%d", targetUIN)
	buf := make([]byte, 4+2+2+2+len(uinStr)+1)
	off := 4
	binary.LittleEndian.PutUint16(buf[off:], 0x00FF)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], 0x0002)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], uint16(len(uinStr)+1))
	off += 2
	copy(buf[off:], uinStr)
	return buf
}

func v3SetBasicInfoData(nick, first, last, email string) []byte {
	buf := new(bytes.Buffer)
	buf.Write(make([]byte, 4))
	writeLegacyString(buf, nick)
	writeLegacyString(buf, first)
	writeLegacyString(buf, last)
	writeLegacyString(buf, email)
	return buf.Bytes()
}

func v3SetNotesData(notes string) []byte {
	n := []byte(notes)
	buf := make([]byte, 4+2+len(n))
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(n)))
	copy(buf[6:], n)
	return buf
}

func v3SetPasswordData(password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+2+len(pwd))
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(pwd)))
	copy(buf[6:], pwd)
	return buf
}

func v3SetAuthData(authRequired bool) []byte {
	buf := make([]byte, 5)
	if authRequired {
		buf[4] = 1
	}
	return buf
}

func v3SetStateData(status, estatus uint32) []byte {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[4:8], status)
	binary.LittleEndian.PutUint32(buf[8:12], estatus)
	return buf
}

func v3ServerPacketData(p []byte) []byte {
	if len(p) < 16 {
		return nil
	}
	return p[16:]
}

func TestV3Handler_Handle(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name: "packet too short",
			pkt:  []byte{0x01, 0x02},
			setup: v3CaseSetup(nil, func(e v3HandleEnv, err error) {
				require.Error(e.T, err)
				assert.Contains(e.T, err.Error(), "packet too short")
			}),
		},
		{
			name:    "nil session disallowed command",
			session: nil,
			pkt:     defaultV3Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				expectV3NotConnected(e.Sender)
			}, nil),
		},
		{
			name:    "nil session ACK allowed",
			session: nil,
			pkt:     defaultV3Pkt(ICQLegacyCmdAck, nil),
		},
		{
			name:    "session state updated",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdAck, nil),
			setup: v3CaseSetup(nil, func(e v3HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(e.T, testV3Seq, e.Session.SeqNumClient)
				assert.WithinDuration(e.T, time.Now(), e.Session.GetLastActivity(), time.Second)
			}),
		},
		{
			name:    "unknown command with session",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0xFFFF, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleFirstLogin(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "first login",
			session: nil,
			pkt:     defaultV3Pkt(ICQLegacyCmdFirstLogin, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleGetDeps(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name: "valid credentials",
			pkt:  defaultV3Pkt(ICQLegacyCmdGetDeps, v3GetDepsData(testV3UIN, "secret")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV3UIN, "secret").Return(true, nil).Once()
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
		{
			name: "invalid credentials",
			pkt:  defaultV3Pkt(ICQLegacyCmdGetDeps, v3GetDepsData(testV3UIN, "wrong")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV3UIN, "wrong").Return(false, nil).Once()
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name: "service error",
			pkt:  defaultV3Pkt(ICQLegacyCmdGetDeps, v3GetDepsData(testV3UIN, "secret")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV3UIN, "secret").
					Return(false, errors.New("db down")).Once()
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleLogin(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "auth success",
			session: nil,
			pkt:     defaultV3Pkt(ICQLegacyCmdLogin, v3LoginData("secret")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.MatchedBy(func(req AuthRequest) bool {
					return req.UIN == testV3UIN && req.Password == "secret"
				})).Return(&AuthResult{Success: true, oscarSession: testAuthSuccessInstance()}, nil).Once()
				e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v3HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.NotNil(e.T, e.Sessions.GetSession(testV3UIN))
			}),
		},
		{
			name:    "bad password",
			session: nil,
			pkt:     defaultV3Pkt(ICQLegacyCmdLogin, v3LoginData("wrong")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
					Return(&AuthResult{Success: false, ErrorCode: 0x0001}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "parse error",
			session: nil,
			pkt:     defaultV3Pkt(ICQLegacyCmdLogin, []byte{0, 0, 0}),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleContactList(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "valid contact list",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdContactList, v3ContactListData([]uint32{99999})),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ProcessContactList(mock.Anything, mock.Anything, mock.Anything).
					Return(&ContactListResult{}, nil).Once()
				e.Service.EXPECT().NotifyUserOnline(mock.Anything, testV3UIN, mock.Anything).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			pkt:  defaultV3Pkt(ICQLegacyCmdContactList, v3ContactListData(nil)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				expectV3NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV3Handler_HandlePing(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "keep alive",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "keep alive 2",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdKeepAlive2, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV3Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v3ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			pkt:  defaultV3Pkt(ICQLegacyCmdKeepAlive, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				expectV3NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV3Handler_HandleLogoff(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "active session",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdLogoff, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				registerSession(e.Sessions, e.Session)
				e.Service.EXPECT().NotifyUserOffline(mock.Anything, testV3UIN).Return(nil).Once()
			}, func(e v3HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Nil(e.T, e.Sessions.GetSession(testV3UIN))
			}),
		},
		{
			name: "nil session",
			pkt:  defaultV3Pkt(ICQLegacyCmdLogoff, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				expectV3NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetStatus(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "valid status",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSetStatus, v3SetStatusData(0x00000001)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
					Return(&StatusChangeResult{}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v3HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(e.T, uint32(0x00000001), e.Session.GetStatus())
			}),
		},
		{
			name: "nil session",
			pkt:  defaultV3Pkt(ICQLegacyCmdSetStatus, v3SetStatusData(1)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				expectV3NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV3Handler_HandleMessage(t *testing.T) {
	target := v3Session(99999)
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "offline stored",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdThruServer, v3MessageData(99999, 0x0001, "hi")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{StoredOffline: true}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name:    "online target",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdThruServer, v3MessageData(99999, 0x0001, "hi")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				registerSession(e.Sessions, target)
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{TargetOnline: true}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(target, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			pkt:  defaultV3Pkt(ICQLegacyCmdThruServer, v3MessageData(99999, 0x0001, "hi")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				expectV3NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV3Handler_HandleAuthorize(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "authorize message",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdAuthorize, v3MessageData(99999, 0x0001, "auth")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{StoredOffline: true}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleUserAdd(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "success",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdUserAdd, v3TargetUINData(99999)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
					Return(&UserAddResult{}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v3HandleEnv, err error) {
				assert.Contains(e.T, e.Session.GetContactList(), uint32(99999))
			}),
		},
		{
			name: "nil session",
			pkt:  defaultV3Pkt(ICQLegacyCmdUserAdd, v3TargetUINData(99999)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				expectV3NotConnected(e.Sender)
			}, nil),
		},
	})
}

func TestV3Handler_HandleOfflineMsgReq(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "no messages",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSysMsgReq, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().GetOfflineMessages(mock.Anything, testV3UIN).
					Return([]LegacyOfflineMessage{}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetBasicInfo(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "success",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSetBasicInfo, v3SetBasicInfoData("nick", "first", "last", "a@b.com")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV3UIN, mock.Anything).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetHomeInfo(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "data too short",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x0582, []byte{0, 0, 0}),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name:    "updates profile",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x0582, v3SetBasicInfoData("addr", "city", "CA", "555")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV3UIN).Return(testMinimalUser(), nil).Once()
				e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV3UIN, mock.Anything).Return(nil).Once()
				e.Service.EXPECT().SetAuthMode(mock.Anything, testV3UIN, true).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetHomeWeb(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "success",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x058C, append(make([]byte, 4), 0, 0, 0, 2, 0, 'h', 'p')),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().UpdateMoreInfo(mock.Anything, testV3UIN, mock.Anything).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetWorkInfo(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "data too short",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x0578, []byte{0, 0, 0}),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetWorkWeb(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "success",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x05BE, v3TimestampPrefix(v3LPString("http://work.example"))),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV3UIN).Return(testMinimalUser(), nil).Once()
				e.Service.EXPECT().UpdateWorkInfo(mock.Anything, testV3UIN, mock.Anything).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleUnknownDep(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "acks request",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x0604, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleVisibleList(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "acks list",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x06AE, v3ContactListData([]uint32{11111})),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleInvisibleList(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "acks list",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x06A4, v3ContactListData([]uint32{22222})),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSearchStart(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "found",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSearchStart, v3SearchUINData(99999)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
					Return(&LegacyUserSearchResult{UIN: 99999, Nickname: "nick"}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
		{
			name:    "not found",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSearchStart, v3SearchUINData(99999)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
					Return(nil, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleGetDeps1(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "sends deps list",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdGetDeps1, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.MatchedBy(func(p []byte) bool {
					return v3ServerCommand(p) == ICQLegacySrvUserDepsList1
				})).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleGetNotes(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "success",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x05AA, v3TargetUINData(testV3UIN)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().GetNotes(mock.Anything, testV3UIN).Return("hello notes", nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetNotes(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "success",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x0596, v3SetNotesData("about me")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().SetNotes(mock.Anything, testV3UIN, "about me").Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetPassword(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "success",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSetPassword, v3SetPasswordData("newsecret")),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().SetPassword(mock.Anything, testV3UIN, "", "newsecret").Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetAuth(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "auth required",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSetAuth, v3SetAuthData(true)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().SetAuthMode(mock.Anything, testV3UIN, true).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSetState(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "updates status",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x0528, v3SetStateData(2, 1)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v3HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(e.T, uint32(2|1<<16), e.Session.GetStatus())
			}),
		},
	})
}

func TestV3Handler_HandleUsageStats(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "acks stats",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(0x0532, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleGetExternals(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "empty externals",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdGetExternals, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleSysAck(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "acks offline messages",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdSysMsgDoneAck, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().AckOfflineMessages(mock.Anything, testV3UIN).Return(nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleOnlineInfo(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "reconnect",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdReconnect, nil),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleGetInfo1(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "basic info only",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdInfoReq, v3TargetUINData(99999)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().GetUserInfoForProtocol(mock.Anything, uint32(99999)).
					Return(&UserInfoResult{UIN: 99999, Nickname: "nick"}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV3Handler_HandleGetInfo(t *testing.T) {
	runV3HandleCases(t, []v3HandleCase{
		{
			name:    "full info",
			session: v3Session(testV3UIN),
			pkt:     defaultV3Pkt(ICQLegacyCmdUserGetInfo, v3TargetUINData(99999)),
			setup: v3CaseSetup(func(e v3HandleEnv) {
				e.Service.EXPECT().GetUserInfoForProtocol(mock.Anything, uint32(99999)).
					Return(&UserInfoResult{UIN: 99999, Nickname: "nick"}, nil).Once()
				e.Sender.EXPECT().SendPacket(e.Session.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(5)
			}, nil),
		},
	})
}

func TestV3Handler_sendUserOnline(t *testing.T) {
	const onlineUIN = uint32(67890)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v3Session(testV3UIN)
	status := uint32(0x00000010)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v3ServerPacketData(p)
		return v3ServerCommand(p) == ICQLegacySrvUserOnline &&
			len(data) >= 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == onlineUIN
	})).Return(nil).Once()

	h := newTestV3Handler(t, sender, svc, newTestLegacySessionManager())
	require.NoError(t, h.sendUserOnline(recipient, onlineUIN, status))
}

func TestV3Handler_sendUserOffline(t *testing.T) {
	const offlineUIN = uint32(88888)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v3Session(testV3UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v3ServerPacketData(p)
		return v3ServerCommand(p) == ICQLegacySrvUserOffline &&
			len(data) == 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == offlineUIN
	})).Return(nil).Once()

	h := newTestV3Handler(t, sender, svc, newTestLegacySessionManager())
	require.NoError(t, h.sendUserOffline(recipient, offlineUIN))
}

func TestV3Handler_sendUserStatus(t *testing.T) {
	const (
		changedUIN = uint32(88888)
		status     = uint32(0x00010002)
	)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v3Session(testV3UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v3ServerPacketData(p)
		return v3ServerCommand(p) == ICQLegacySrvUserStatus &&
			len(data) == 8 &&
			binary.LittleEndian.Uint32(data[0:4]) == changedUIN &&
			binary.LittleEndian.Uint16(data[4:6]) == uint16(status&0xFFFF) &&
			binary.LittleEndian.Uint16(data[6:8]) == uint16(status>>16)
	})).Return(nil).Once()

	h := newTestV3Handler(t, sender, svc, newTestLegacySessionManager())
	require.NoError(t, h.sendUserStatus(recipient, changedUIN, status))
}

func TestV3Handler_sendOnlineMessage(t *testing.T) {
	const fromUIN = uint32(55555)

	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	recipient := v3Session(testV3UIN)

	sender.EXPECT().SendToSession(recipient, mock.MatchedBy(func(p []byte) bool {
		data := v3ServerPacketData(p)
		return v3ServerCommand(p) == ICQLegacySrvSysMsgOnline &&
			len(data) >= 8 &&
			binary.LittleEndian.Uint32(data[0:4]) == fromUIN
	})).Return(nil).Once()

	h := newTestV3Handler(t, sender, svc, newTestLegacySessionManager())
	require.NoError(t, h.sendOnlineMessage(recipient, fromUIN, 0x0001, "hello", testV3Seq2))
}

func TestV3Handler_sendSearchFound(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	session := v3Session(testV3UIN)

	sender.EXPECT().SendToSession(session, mock.MatchedBy(func(p []byte) bool {
		data := v3ServerPacketData(p)
		return v3ServerCommand(p) == 0x008C &&
			len(data) >= 4 &&
			binary.LittleEndian.Uint32(data[0:4]) == uint32(99999)
	})).Return(nil).Once()

	h := newTestV3Handler(t, sender, svc, newTestLegacySessionManager())
	require.NoError(t, h.sendSearchFound(session, testV3Seq2, 99999, "nick", "first", "last", "a@b.com", 0))
}

func TestV3Handler_sendSearchDone(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	session := v3Session(testV3UIN)

	sender.EXPECT().SendToSession(session, mock.MatchedBy(func(p []byte) bool {
		return v3ServerCommand(p) == 0x00A0 && len(p) == 17
	})).Return(nil).Once()

	h := newTestV3Handler(t, sender, svc, newTestLegacySessionManager())
	require.NoError(t, h.sendSearchDone(session, testV3Seq2))
}

func TestV3Handler_sendDeptsList1(t *testing.T) {
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	session := v3Session(testV3UIN)

	sender.EXPECT().SendToSession(session, mock.MatchedBy(func(p []byte) bool {
		return v3ServerCommand(p) == ICQLegacySrvUserDepsList1
	})).Return(nil).Once()

	h := newTestV3Handler(t, sender, svc, newTestLegacySessionManager())
	require.NoError(t, h.sendDeptsList1(session, testV3Seq2))
}

func TestV3Handler_HandleSetStatus_notifiesContacts(t *testing.T) {
	const contactUIN = uint32(88888)
	changer := v3Session(testV3UIN)
	contact := v3Session(contactUIN)
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()
	registerSession(sessions, changer)
	registerSession(sessions, contact)
	svc.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
		Return(&StatusChangeResult{NotifyTargets: []NotifyTarget{{UIN: contactUIN}}}, nil).Once()
	sender.EXPECT().SendPacket(changer.Addr, mock.AnythingOfType("[]uint8")).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		return v3ServerCommand(p) == ICQLegacySrvUserStatus
	})).Return(nil).Once()
	h := newTestV3Handler(t, sender, svc, sessions)
	pkt := defaultV3Pkt(ICQLegacyCmdSetStatus, v3SetStatusData(0x00000002))
	require.NoError(t, h.Handle(changer, testV3Addr, pkt))
}

func TestV3Handler_HandleLogoff_notifiesContacts(t *testing.T) {
	const contactUIN = uint32(88888)
	loggingOff := v3Session(testV3UIN)
	contact := v3Session(contactUIN)
	contact.SetContactList([]uint32{testV3UIN})
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()
	registerSession(sessions, loggingOff)
	registerSession(sessions, contact)
	svc.EXPECT().NotifyUserOffline(mock.Anything, testV3UIN).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		return v3ServerCommand(p) == ICQLegacySrvUserOffline
	})).Return(nil).Once()
	h := newTestV3HandlerWithDispatcher(t, sender, svc, sessions)
	pkt := defaultV3Pkt(ICQLegacyCmdLogoff, nil)
	require.NoError(t, h.Handle(loggingOff, testV3Addr, pkt))
}
