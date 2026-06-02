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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testV2UIN  = uint32(12345)
	testV2Seq  = uint16(42)
	testV2Seq2 = uint16(7)
)

var testV2Addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

type v2HandleEnv struct {
	T        *testing.T
	Sender   *mockPacketSender
	Service  *mockLegacyService
	Sessions *LegacySessionManager
	Session  *LegacySession
}

type v2HandleCase struct {
	name    string
	session *LegacySession
	pkt     []byte
	wire    func(t *testing.T) []byte
	setup   func(v2HandleEnv) func(error)
}

func v2CaseSetup(pre func(v2HandleEnv), after func(e v2HandleEnv, err error)) func(v2HandleEnv) func(error) {
	return func(e v2HandleEnv) func(error) {
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

func runV2HandleCases(t *testing.T, cases []v2HandleCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			svc := newMockLegacyService(t)
			sessions := newTestLegacySessionManager()
			e := v2HandleEnv{
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
			h := newTestV2Handler(t, sender, svc, sessions)
			var wire []byte
			switch {
			case tt.wire != nil:
				wire = tt.wire(t)
			case tt.pkt != nil:
				wire = tt.pkt
			default:
				t.Fatal("case must set pkt or wire")
			}
			check(h.Handle(tt.session, testV2Addr, wire))
		})
	}
}

func newTestV2Handler(t *testing.T, sender PacketSender, svc LegacyService, sessions *LegacySessionManager) *V2Handler {
	t.Helper()
	if sessions == nil {
		sessions = newTestLegacySessionManager()
	}
	return NewV2Handler(sessions, svc, sender, NewV2PacketBuilder(), slog.Default())
}

func v2Session(uin uint32) *LegacySession {
	s := newTestLegacySession(uin, legacySessionOptOSCARSess, func(ls *LegacySession) {
		ls.Version = ICQLegacyVersionV2
		ls.SeqNumClient = testV2Seq
	})
	return s
}

func v2ServerCommand(packet []byte) uint16 {
	if len(packet) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint16(packet[2:4])
}

func expectV2NotConnected(sender *mockPacketSender, seq uint16) {
	sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).
		Run(func(_ *net.UDPAddr, p []byte) {
			if got := v2ServerCommand(p); got != ICQLegacySrvNotConnected {
				panic(fmt.Sprintf("got command 0x%04X, want NOT_CONNECTED", got))
			}
			if len(p) >= 6 && binary.LittleEndian.Uint16(p[4:6]) != seq {
				panic(fmt.Sprintf("seq %d want %d", binary.LittleEndian.Uint16(p[4:6]), seq))
			}
		}).Return(nil).Once()
}

func buildV2ClientPacket(pkt V2ClientPacket) []byte {
	isPreV2 := pkt.Command == ICQLegacyCmdFirstLogin ||
		pkt.Command == ICQLegacyCmdGetDeps ||
		pkt.Command == ICQLegacyCmdRegNewUser
	if isPreV2 {
		buf := make([]byte, 6+len(pkt.Data))
		binary.LittleEndian.PutUint16(buf[0:2], pkt.Version)
		binary.LittleEndian.PutUint16(buf[2:4], pkt.Command)
		binary.LittleEndian.PutUint16(buf[4:6], pkt.SeqNum)
		copy(buf[6:], pkt.Data)
		return buf
	}
	buf := make([]byte, 10+len(pkt.Data))
	binary.LittleEndian.PutUint16(buf[0:2], pkt.Version)
	binary.LittleEndian.PutUint16(buf[2:4], pkt.Command)
	binary.LittleEndian.PutUint16(buf[4:6], pkt.SeqNum)
	binary.LittleEndian.PutUint32(buf[6:10], pkt.UIN)
	copy(buf[10:], pkt.Data)
	return buf
}

func defaultV2Pkt(command uint16, data []byte) V2ClientPacket {
	return V2ClientPacket{
		Version: ICQLegacyVersionV2,
		Command: command,
		SeqNum:  testV2Seq,
		UIN:     testV2UIN,
		Data:    data,
	}
}

func buildV2GetDepsWire(uin uint32, password string) []byte {
	pwd := []byte(password)
	data := make([]byte, 2+len(pwd)+4)
	binary.LittleEndian.PutUint16(data[0:2], uint16(len(pwd)))
	copy(data[2:], pwd)
	buf := make([]byte, 12+len(data))
	binary.LittleEndian.PutUint16(buf[0:2], ICQLegacyVersionV3)
	binary.LittleEndian.PutUint16(buf[2:4], ICQLegacyCmdGetDeps)
	binary.LittleEndian.PutUint16(buf[4:6], testV2Seq)
	binary.LittleEndian.PutUint16(buf[6:8], testV2Seq2)
	binary.LittleEndian.PutUint32(buf[8:12], uin)
	copy(buf[12:], data)
	return buf
}

func v2WriteBufLE(buf *bytes.Buffer, v any) {
	_ = binary.Write(buf, binary.LittleEndian, v)
}

func v2LoginData(password string) []byte {
	pwd := []byte(password)
	buf := make([]byte, 4+2+len(pwd)+4+4+1+2+2+12)
	off := 0
	binary.LittleEndian.PutUint32(buf[off:], 4000)
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], uint16(len(pwd)))
	off += 2
	copy(buf[off:], pwd)
	off += len(pwd)
	binary.LittleEndian.PutUint32(buf[off:], 0x00040072)
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 0x7F000001)
	off += 4
	buf[off] = 0x04
	off++
	binary.LittleEndian.PutUint16(buf[off:], 0)
	off += 2
	binary.LittleEndian.PutUint16(buf[off:], 0)
	return buf
}

func v2ContactListData(uins []uint32) []byte {
	buf := make([]byte, 1+4*len(uins))
	buf[0] = byte(len(uins))
	for i, u := range uins {
		binary.LittleEndian.PutUint32(buf[1+4*i:], u)
	}
	return buf
}

func v2MessageData(toUIN uint32, msgType uint16, message string) []byte {
	msg := []byte(message)
	buf := make([]byte, 4+2+2+len(msg))
	binary.LittleEndian.PutUint32(buf[0:4], toUIN)
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(len(msg)))
	copy(buf[8:], msg)
	return buf
}

func v2TargetUINData(target uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, target)
	return buf
}

func v2SearchUINData(clientSubSeq uint16, target uint32) []byte {
	buf := make([]byte, 6)
	binary.LittleEndian.PutUint16(buf[0:2], clientSubSeq)
	binary.LittleEndian.PutUint32(buf[2:6], target)
	return buf
}

func v2SearchUserData(clientSubSeq uint16, nick string) []byte {
	buf := new(bytes.Buffer)
	v2WriteBufLE(buf, clientSubSeq)
	writeLegacyString(buf, nick)
	writeLegacyString(buf, "")
	writeLegacyString(buf, "")
	writeLegacyString(buf, "")
	return buf.Bytes()
}

func v2UpdateDetailData(updateSeq uint16) []byte {
	buf := new(bytes.Buffer)
	v2WriteBufLE(buf, updateSeq)
	writeLegacyString(buf, "city")
	v2WriteBufLE(buf, uint16(840))
	buf.WriteByte(0)
	writeLegacyString(buf, "CA")
	v2WriteBufLE(buf, uint16(25))
	buf.WriteByte(1)
	writeLegacyString(buf, "555")
	writeLegacyString(buf, "http://example.com")
	writeLegacyString(buf, "about me")
	return buf.Bytes()
}

func v2RegNewUserData(password string) []byte {
	pwd := append([]byte(password), 0)
	buf := make([]byte, 2+2+len(pwd))
	binary.LittleEndian.PutUint16(buf[0:2], 0)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(pwd)))
	copy(buf[4:], pwd)
	return buf
}

func TestV2Handler_Handle(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name: "packet too short",
			pkt:  []byte{0x01, 0x02},
			setup: v2CaseSetup(nil, func(e v2HandleEnv, err error) {
				require.Error(e.T, err)
				assert.Contains(e.T, err.Error(), "packet too short")
			}),
		},
		{
			name:    "nil session disallowed command",
			session: nil,
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdKeepAlive, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				expectV2NotConnected(e.Sender, testV2Seq)
			}, nil),
		},
		{
			name:    "nil session ACK allowed",
			session: nil,
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdAck, nil)),
		},
		{
			name:    "session state updated",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdAck, nil)),
			setup: v2CaseSetup(nil, func(e v2HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(e.T, testV2Seq, e.Session.SeqNumClient)
				assert.WithinDuration(e.T, time.Now(), e.Session.GetLastActivity(), time.Second)
			}),
		},
		{
			name:    "unknown command with session",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(0xFFFF, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV2Handler_HandleFirstLogin(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "first login",
			session: nil,
			pkt: buildV2ClientPacket(V2ClientPacket{
				Version: ICQLegacyVersionV2,
				Command: ICQLegacyCmdFirstLogin,
				SeqNum:  testV2Seq,
				Data: func() []byte {
					b := make([]byte, 4)
					binary.LittleEndian.PutUint32(b, 0xCAFEBABE)
					return b
				}(),
			}),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV2Handler_HandleGetDeps(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name: "valid credentials",
			pkt:  buildV2GetDepsWire(testV2UIN, "secret"),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV2UIN, "secret").Return(true, nil).Once()
				e.Sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
		{
			name: "invalid credentials",
			pkt:  buildV2GetDepsWire(testV2UIN, "wrong"),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV2UIN, "wrong").Return(false, nil).Once()
				e.Sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name: "service error",
			pkt:  buildV2GetDepsWire(testV2UIN, "secret"),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ValidateCredentials(mock.Anything, testV2UIN, "secret").
					Return(false, errors.New("db down")).Once()
				e.Sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV2Handler_HandleLogin(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "auth success",
			session: nil,
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdLogin, v2LoginData("secret"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.MatchedBy(func(req AuthRequest) bool {
					return req.UIN == testV2UIN && req.Password == "secret"
				})).Return(&AuthResult{Success: true, oscarSession: testAuthSuccessInstance()}, nil).Once()
				e.Service.EXPECT().NotifyStatusChange(mock.Anything, testV2UIN, mock.Anything).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).Return(nil).Twice()
			}, func(e v2HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.NotNil(e.T, e.Sessions.GetSession(testV2UIN))
			}),
		},
		{
			name:    "bad password",
			session: nil,
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdLogin, v2LoginData("wrong"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().AuthenticateUser(mock.Anything, mock.Anything).
					Return(&AuthResult{Success: false, ErrorCode: 0x0001}, nil).Once()
				e.Sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name:    "parse error",
			session: nil,
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdLogin, []byte{0, 0, 0})),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvWrongPasswd, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV2Handler_HandleContactList(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "valid contact list",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdContactList, v2ContactListData([]uint32{99999}))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ProcessContactList(mock.Anything, mock.Anything, mock.Anything).
					Return(&ContactListResult{}, nil).Once()
				e.Service.EXPECT().NotifyUserOnline(mock.Anything, testV2UIN, mock.Anything).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvUserListDone, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			pkt:  buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdContactList, v2ContactListData(nil))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				expectV2NotConnected(e.Sender, testV2Seq)
			}, nil),
		},
	})
}

func TestV2Handler_HandlePing(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "keep alive",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdKeepAlive, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			pkt:  buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdKeepAlive, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				expectV2NotConnected(e.Sender, testV2Seq)
			}, nil),
		},
	})
}

func TestV2Handler_HandleLogoff(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "active session",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdLogoff, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				registerSession(e.Sessions, e.Session)
				e.Service.EXPECT().NotifyUserOffline(mock.Anything, testV2UIN).Return(nil).Once()
			}, func(e v2HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Nil(e.T, e.Sessions.GetSession(testV2UIN))
			}),
		},
		{
			name: "nil session",
			pkt:  buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdLogoff, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				expectV2NotConnected(e.Sender, testV2Seq)
			}, nil),
		},
	})
}

func TestV2Handler_HandleSetStatus(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "valid status",
			session: v2Session(testV2UIN),
			pkt: buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSetStatus, func() []byte {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 0x00000001)
				return b
			}())),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
					Return(&StatusChangeResult{}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v2HandleEnv, err error) {
				assert.NoError(e.T, err)
				assert.Equal(e.T, uint32(0x00000001), e.Session.GetStatus())
			}),
		},
		{
			name: "nil session",
			pkt: buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSetStatus, func() []byte {
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 1)
				return b
			}())),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				expectV2NotConnected(e.Sender, testV2Seq)
			}, nil),
		},
	})
}

func TestV2Handler_HandleMessage(t *testing.T) {
	target := v2Session(99999)
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "offline stored",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdThruServer, v2MessageData(99999, 0x0001, "hi"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{StoredOffline: true}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name:    "online target",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdThruServer, v2MessageData(99999, 0x0001, "hi"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				registerSession(e.Sessions, target)
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{TargetOnline: true}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(mock.AnythingOfType("*icq_legacy.LegacySession"), mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
		{
			name: "nil session",
			pkt:  buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdThruServer, v2MessageData(99999, 0x0001, "hi"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				expectV2NotConnected(e.Sender, testV2Seq)
			}, nil),
		},
	})
}

func TestV2Handler_HandleUserAdd(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "success",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdUserAdd, v2TargetUINData(99999))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).
					Return(&UserAddResult{}, nil).Once()
				e.Service.EXPECT().GetUserInfoForProtocol(mock.Anything, uint32(99999)).Return(nil, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v2HandleEnv, err error) {
				assert.Contains(e.T, e.Session.GetContactList(), uint32(99999))
			}),
		},
		{
			name: "nil session",
			pkt:  buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdUserAdd, v2TargetUINData(99999))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				expectV2NotConnected(e.Sender, testV2Seq)
			}, nil),
		},
	})
}

func TestV2Handler_HandleSearchUIN(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "found",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSearchUIN, v2SearchUINData(1, 99999))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
					Return(&LegacyUserSearchResult{UIN: 99999}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(3)
			}, nil),
		},
		{
			name:    "not found",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSearchUIN, v2SearchUINData(1, 99999))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().SearchByUIN(mock.Anything, uint32(99999)).
					Return(&LegacyUserSearchResult{}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV2Handler_HandleVisibleList(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "valid list",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdVisibleList, v2ContactListData([]uint32{11111}))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).
					Run(func(_ *LegacySession, p []byte) {
						assert.Equal(e.T, ICQLegacySrvAck, v2ServerCommand(p))
					}).Return(nil).Once()
			}, func(e v2HandleEnv, err error) {
				assert.True(e.T, e.Session.IsOnVisibleList(11111))
			}),
		},
	})
}

func TestV2Handler_HandleInvisibleList(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "valid list",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdInvisibleList, v2ContactListData([]uint32{22222}))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, func(e v2HandleEnv, err error) {
				assert.True(e.T, e.Session.IsOnInvisibleList(22222))
			}),
		},
	})
}

func TestV2Handler_HandleOfflineMsgReq(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "no messages",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSysMsgReq, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().GetOfflineMessages(mock.Anything, testV2UIN).
					Return([]LegacyOfflineMessage{}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV2Handler_HandleOfflineMsgAck(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "ack",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSysMsgDoneAck, nil)),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().AckOfflineMessages(mock.Anything, testV2UIN).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func v2InfoReqData(targetUIN uint32) []byte {
	buf := make([]byte, 6)
	binary.LittleEndian.PutUint16(buf[0:2], testV2Seq)
	binary.LittleEndian.PutUint32(buf[2:6], targetUIN)
	return buf
}

func TestV2Handler_HandleInfoReq(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "get info",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdInfoReq, v2InfoReqData(99999))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().GetUserInfo(mock.Anything, uint32(99999)).
					Return(&LegacyUserSearchResult{UIN: 99999, Nickname: "nick"}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV2Handler_HandleExtInfoReq(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "get ext info",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdExtInfoReq, v2InfoReqData(99999))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().GetFullUserInfo(mock.Anything, uint32(99999)).Return(testMinimalUser(), nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV2Handler_HandleUpdateBasic(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "success",
			session: v2Session(testV2UIN),
			pkt: buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdUpdateBasic, func() []byte {
				buf := new(bytes.Buffer)
				v2WriteBufLE(buf, testV2Seq)
				writeLegacyString(buf, "nick")
				writeLegacyString(buf, "first")
				writeLegacyString(buf, "last")
				writeLegacyString(buf, "a@b.com")
				buf.WriteByte(0) // auth
				return buf.Bytes()
			}())),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV2UIN).Return(testMinimalUser(), nil).Once()
				e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV2UIN, mock.Anything).Return(nil).Once()
				e.Service.EXPECT().SetAuthMode(mock.Anything, testV2UIN, false).Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV2Handler_HandleSearchUser(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "found",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSearchUser, v2SearchUserData(1, "alice"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().SearchByName(mock.Anything, "alice", "", "", "").
					Return([]LegacyUserSearchResult{{UIN: 99999, Nickname: "alice"}}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(3)
			}, nil),
		},
		{
			name:    "not found",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSearchUser, v2SearchUserData(1, "nobody"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().SearchByName(mock.Anything, "nobody", "", "", "").
					Return(nil, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV2Handler_HandleAuthorize(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "authorize message",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdAuthorize, v2MessageData(99999, 0x0001, "auth"))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().ProcessMessage(mock.Anything, mock.Anything, mock.Anything).
					Return(&MessageResult{StoredOffline: true}, nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV2Handler_HandleUpdateDetail(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name:    "success",
			session: v2Session(testV2UIN),
			pkt:     buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdUpdateDetail, v2UpdateDetailData(3))),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().GetFullUserInfo(mock.Anything, testV2UIN).Return(testMinimalUser(), nil).Once()
				e.Service.EXPECT().UpdateBasicInfo(mock.Anything, testV2UIN, mock.Anything).Return(nil).Once()
				e.Service.EXPECT().UpdateMoreInfo(mock.Anything, testV2UIN, mock.Anything).Return(nil).Once()
				e.Service.EXPECT().SetNotes(mock.Anything, testV2UIN, "about me").Return(nil).Once()
				e.Sender.EXPECT().SendToSession(e.Session, mock.AnythingOfType("[]uint8")).Return(nil).Times(2)
			}, nil),
		},
	})
}

func TestV2Handler_HandleRegNewUser(t *testing.T) {
	runV2HandleCases(t, []v2HandleCase{
		{
			name: "success",
			pkt: buildV2ClientPacket(V2ClientPacket{
				Version: ICQLegacyVersionV2,
				Command: ICQLegacyCmdRegNewUser,
				SeqNum:  testV2Seq,
				Data:    v2RegNewUserData("newpass"),
			}),
			setup: v2CaseSetup(func(e v2HandleEnv) {
				e.Service.EXPECT().RegisterNewUser(mock.Anything, "", "", "", "", "newpass").
					Return(uint32(100001), nil).Once()
				e.Sender.EXPECT().SendPacket(testV2Addr, mock.AnythingOfType("[]uint8")).
					Run(func(_ *net.UDPAddr, p []byte) {
						assert.Equal(e.T, ICQLegacySrvNewUIN, v2ServerCommand(p))
					}).Return(nil).Once()
			}, nil),
		},
	})
}

func TestV2Handler_HandleSetStatus_notifiesContacts(t *testing.T) {
	const contactUIN = uint32(88888)
	changer := v2Session(testV2UIN)
	contact := v2Session(contactUIN)
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()
	registerSession(sessions, changer)
	registerSession(sessions, contact)
	svc.EXPECT().ProcessStatusChange(mock.Anything, mock.Anything).
		Return(&StatusChangeResult{NotifyTargets: []NotifyTarget{{UIN: contactUIN}}}, nil).Once()
	sender.EXPECT().SendToSession(changer, mock.AnythingOfType("[]uint8")).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		return v2ServerCommand(p) == ICQLegacySrvUserStatus
	})).Return(nil).Once()
	h := newTestV2Handler(t, sender, svc, sessions)
	pkt := buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdSetStatus, func() []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, 0x00000002)
		return b
	}()))
	require.NoError(t, h.Handle(changer, testV2Addr, pkt))
}

func TestV2Handler_HandleUserAdd_notifyTarget(t *testing.T) {
	const targetUIN = uint32(99999)
	adder := v2Session(testV2UIN)
	target := v2Session(targetUIN)
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()
	registerSession(sessions, adder)
	registerSession(sessions, target)
	svc.EXPECT().ProcessUserAdd(mock.Anything, mock.Anything, mock.Anything).Return(&UserAddResult{}, nil).Once()
	sender.EXPECT().SendToSession(adder, mock.AnythingOfType("[]uint8")).Return(nil).Once()
	sender.EXPECT().SendToSession(adder, mock.MatchedBy(func(p []byte) bool {
		return v2ServerCommand(p) == ICQLegacySrvUserOnline
	})).Return(nil).Once()
	sender.EXPECT().SendToSession(target, mock.MatchedBy(func(p []byte) bool {
		return v2ServerCommand(p) == ICQLegacySrvUserOnline
	})).Return(nil).Once()
	h := newTestV2Handler(t, sender, svc, sessions)
	pkt := buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdUserAdd, v2TargetUINData(targetUIN)))
	require.NoError(t, h.Handle(adder, testV2Addr, pkt))
	assert.Contains(t, adder.GetContactList(), targetUIN)
}

func TestV2Handler_HandleLogoff_notifiesContacts(t *testing.T) {
	const contactUIN = uint32(88888)
	loggingOff := v2Session(testV2UIN)
	loggingOff.SetContactList([]uint32{contactUIN})
	contact := v2Session(contactUIN)
	sender := newMockPacketSender(t)
	svc := newMockLegacyService(t)
	sessions := newTestLegacySessionManager()
	registerSession(sessions, loggingOff)
	registerSession(sessions, contact)
	svc.EXPECT().NotifyUserOffline(mock.Anything, testV2UIN).Return(nil).Once()
	sender.EXPECT().SendToSession(contact, mock.MatchedBy(func(p []byte) bool {
		return v2ServerCommand(p) == ICQLegacySrvUserOffline
	})).Return(nil).Once()
	h := newTestV2Handler(t, sender, svc, sessions)
	pkt := buildV2ClientPacket(defaultV2Pkt(ICQLegacyCmdLogoff, nil))
	require.NoError(t, h.Handle(loggingOff, testV2Addr, pkt))
}
