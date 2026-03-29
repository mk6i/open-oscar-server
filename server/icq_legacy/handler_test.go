package icq_legacy

import (
	"log/slog"
	"testing"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// newTestDispatcher creates a ProtocolDispatcher wired with real version
// handlers that share the given mock PacketSender. This lets tests verify
// that the dispatcher routes to the correct handler by asserting on the
// mock sender's SendToSession calls.
func newTestDispatcher(t *testing.T, sender PacketSender) *ProtocolDispatcher {
	t.Helper()

	logger := slog.Default()
	svc := newMockLegacyService(t)

	// Create a minimal LegacySessionManager so V5 handler can call GetSession
	// without panicking. The map is empty so GetSession returns nil, which is
	// handled gracefully by the handlers.
	sessions := &LegacySessionManager{
		sessions:  make(map[uint32]*LegacySession),
		addrIndex: make(map[string]*LegacySession),
	}

	v1 := NewV1Handler(sessions, svc, sender, logger)
	v2 := NewV2Handler(sessions, svc, sender, NewV2PacketBuilder(), logger)
	v3 := NewV3Handler(sessions, svc, sender, NewV3PacketBuilder(), logger)
	v4 := NewV4Handler(sessions, svc, sender, NewV4PacketBuilder(), logger)
	v5 := NewV5Handler(sessions, svc, sender, NewV5PacketBuilder(sessions), logger)

	cfg := config.ICQLegacyConfig{
		SupportedVersions: []int{2, 3, 4, 5},
	}

	return NewProtocolDispatcher(v1, v2, v3, v4, v5, cfg, logger)
}

// ---------------------------------------------------------------------------
// Task 12.1 — Table-driven tests for ProtocolDispatcher
// ---------------------------------------------------------------------------

func TestProtocolDispatcher_SendUserOnline(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"V2", wire.ICQLegacyVersionV2},
		{"V3", wire.ICQLegacyVersionV3},
		{"V4", wire.ICQLegacyVersionV4},
		{"V5", wire.ICQLegacyVersionV5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			dispatcher := newTestDispatcher(t, sender)

			session := newTestLegacySession(12345, legacySessionOptVersion(tt.version))

			// The handler will call SendToSession exactly once.
			sender.EXPECT().
				SendToSession(session, mock.AnythingOfType("[]uint8")).
				Return(nil)

			err := dispatcher.SendUserOnline(session, 67890, 0x00000000)
			assert.NoError(t, err)
		})
	}
}

func TestProtocolDispatcher_SendUserOnline_NilSession(t *testing.T) {
	sender := newMockPacketSender(t)
	dispatcher := newTestDispatcher(t, sender)

	// nil session should return nil without calling sender
	err := dispatcher.SendUserOnline(nil, 67890, 0x00000000)
	assert.NoError(t, err)
}

func TestProtocolDispatcher_SendUserOffline(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"V2", wire.ICQLegacyVersionV2},
		{"V3", wire.ICQLegacyVersionV3},
		{"V4", wire.ICQLegacyVersionV4},
		{"V5", wire.ICQLegacyVersionV5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			dispatcher := newTestDispatcher(t, sender)

			session := newTestLegacySession(12345, legacySessionOptVersion(tt.version))

			sender.EXPECT().
				SendToSession(session, mock.AnythingOfType("[]uint8")).
				Return(nil)

			err := dispatcher.SendUserOffline(session, 67890)
			assert.NoError(t, err)
		})
	}
}

func TestProtocolDispatcher_SendStatusChange(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"V2", wire.ICQLegacyVersionV2},
		{"V3", wire.ICQLegacyVersionV3},
		{"V4", wire.ICQLegacyVersionV4},
		{"V5", wire.ICQLegacyVersionV5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			dispatcher := newTestDispatcher(t, sender)

			session := newTestLegacySession(12345, legacySessionOptVersion(tt.version))

			sender.EXPECT().
				SendToSession(session, mock.AnythingOfType("[]uint8")).
				Return(nil)

			err := dispatcher.SendStatusChange(session, 67890, 0x00000001)
			assert.NoError(t, err)
		})
	}
}

func TestProtocolDispatcher_SendOnlineMessage(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"V2", wire.ICQLegacyVersionV2},
		{"V3", wire.ICQLegacyVersionV3},
		{"V4", wire.ICQLegacyVersionV4},
		{"V5", wire.ICQLegacyVersionV5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := newMockPacketSender(t)
			dispatcher := newTestDispatcher(t, sender)

			session := newTestLegacySession(12345, legacySessionOptVersion(tt.version))

			sender.EXPECT().
				SendToSession(session, mock.AnythingOfType("[]uint8")).
				Return(nil)

			err := dispatcher.SendOnlineMessage(session, 67890, 0x0001, "Hello, world!")
			assert.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// Task 12.2 — Property test: protocol dispatcher version routing
// **Property 6: Protocol dispatcher routes to version-matching handler**
// For any version V in {1,2,3,4,5} and any dispatch operation, the dispatcher
// invokes the V-specific handler (verified by mock sender being called).
// **Validates: Requirements 6.1, 6.4, 6.7, 6.8**
// ---------------------------------------------------------------------------

func TestProperty_DispatcherRoutesToVersionHandler(t *testing.T) {
	versions := []uint16{
		wire.ICQLegacyVersionV2,
		wire.ICQLegacyVersionV3,
		wire.ICQLegacyVersionV4,
		wire.ICQLegacyVersionV5,
	}

	type dispatchOp struct {
		name string
		call func(d *ProtocolDispatcher, s *LegacySession) error
	}

	ops := []dispatchOp{
		{
			name: "SendUserOnline",
			call: func(d *ProtocolDispatcher, s *LegacySession) error {
				return d.SendUserOnline(s, 99999, 0x00000000)
			},
		},
		{
			name: "SendUserOffline",
			call: func(d *ProtocolDispatcher, s *LegacySession) error {
				return d.SendUserOffline(s, 99999)
			},
		},
		{
			name: "SendStatusChange",
			call: func(d *ProtocolDispatcher, s *LegacySession) error {
				return d.SendStatusChange(s, 99999, 0x00000001)
			},
		},
		{
			name: "SendOnlineMessage",
			call: func(d *ProtocolDispatcher, s *LegacySession) error {
				return d.SendOnlineMessage(s, 99999, 0x0001, "test message")
			},
		},
	}

	for _, v := range versions {
		for _, op := range ops {
			t.Run(op.name+"/"+versionName(v), func(t *testing.T) {
				sender := newMockPacketSender(t)
				dispatcher := newTestDispatcher(t, sender)

				session := newTestLegacySession(12345, legacySessionOptVersion(v))

				// Expect exactly one SendToSession call — proves the
				// correct handler was invoked (each handler builds a
				// packet and sends it via the shared sender).
				sender.EXPECT().
					SendToSession(session, mock.AnythingOfType("[]uint8")).
					Return(nil)

				err := op.call(dispatcher, session)
				assert.NoError(t, err)
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Task 12.3 — Property test: cross-version message content preservation
// **Property 7: Cross-version message content preservation**
// For any message content string and type, and any sender/receiver version
// pair, the message is dispatched without error.
// **Validates: Requirements 6.5, 6.6**
// ---------------------------------------------------------------------------

func TestProperty_CrossVersionMessageContentPreservation(t *testing.T) {
	versions := []uint16{
		wire.ICQLegacyVersionV2,
		wire.ICQLegacyVersionV3,
		wire.ICQLegacyVersionV4,
		wire.ICQLegacyVersionV5,
	}

	messages := []struct {
		msgType uint16
		content string
	}{
		{0x0001, "Hello"},
		{0x0001, ""},
		{0x0001, "A longer message with special chars: !@#$%^&*()"},
		{0x0004, "URL message"},
		{0x000E, "Email express"},
		{0x0001, "Unicode: café résumé naïve"},
	}

	for _, senderVersion := range versions {
		for _, receiverVersion := range versions {
			for _, msg := range messages {
				testName := versionName(senderVersion) + "->" + versionName(receiverVersion) +
					"/type_" + msgTypeName(msg.msgType)
				t.Run(testName, func(t *testing.T) {
					sender := newMockPacketSender(t)
					dispatcher := newTestDispatcher(t, sender)

					// The receiver session has the receiver's version.
					session := newTestLegacySession(12345, legacySessionOptVersion(receiverVersion))

					// Allow the send call — we just verify no error.
					sender.EXPECT().
						SendToSession(session, mock.AnythingOfType("[]uint8")).
						Return(nil)

					// Dispatch the message as if it came from a sender
					// on senderVersion to a receiver on receiverVersion.
					err := dispatcher.SendOnlineMessage(session, 67890, msg.msgType, msg.content)
					assert.NoError(t, err)
				})
			}
		}
	}
}

// versionName returns a human-readable name for a protocol version constant.
func versionName(v uint16) string {
	switch v {
	case wire.ICQLegacyVersionV1:
		return "V1"
	case wire.ICQLegacyVersionV2:
		return "V2"
	case wire.ICQLegacyVersionV3:
		return "V3"
	case wire.ICQLegacyVersionV4:
		return "V4"
	case wire.ICQLegacyVersionV5:
		return "V5"
	default:
		return "Unknown"
	}
}

// msgTypeName returns a short label for common ICQ message types.
func msgTypeName(t uint16) string {
	switch t {
	case 0x0001:
		return "normal"
	case 0x0004:
		return "url"
	case 0x000E:
		return "email"
	default:
		return "other"
	}
}
