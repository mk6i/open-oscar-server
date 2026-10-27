package oscar

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// noopRateLimitUpdater satisfies RateLimitUpdater without running the monitor.
type noopRateLimitUpdater struct{}

func (noopRateLimitUpdater) MonitorRateLimits(context.Context, *state.Session) {}

// recordingRateLimitUpdater reports which sessions the monitor was started for.
type recordingRateLimitUpdater struct {
	monitored chan *state.Session
}

func newRecordingRateLimitUpdater() recordingRateLimitUpdater {
	return recordingRateLimitUpdater{monitored: make(chan *state.Session, 1)}
}

func (r recordingRateLimitUpdater) MonitorRateLimits(_ context.Context, session *state.Session) {
	select {
	case r.monitored <- session:
	default:
	}
}

func TestServer_ListenAndServeAndShutdown(t *testing.T) {
	var mu sync.Mutex
	var received []string

	var msgWg sync.WaitGroup

	// the second group terminates SSL, so it binds :15001 and :15002
	groups := []config.ListenerGroup{
		{
			BOSListenAddress:       ":15000",
			BOSAdvertisedHostPlain: "localhost",
		},
		{
			BOSListenAddress:       ":15001",
			BOSListenAddressSSL:    ":15002",
			BOSAdvertisedHostPlain: "localhost",
			BOSAdvertisedHostSSL:   "localhost",
		},
	}
	var endpoints []config.Endpoint
	for _, g := range groups {
		endpoints = append(endpoints, g.Endpoints()...)
	}
	responses := []string{"hello1", "hello2", "hello3"}

	server := NewServer(
		nil,
		nil,
		nil,
		nil,
		slog.Default(),
		nil,
		nil,
		nil,
		wire.DefaultSNACRateLimits(),
		nil,
		groups,
		func(ctx context.Context, instance *state.SessionInstance) error { return nil },
		func(ctx context.Context, instance *state.SessionInstance) {},
	)

	server.handler = func(ctx context.Context, conn net.Conn, endpointCfg config.Endpoint, rateLimitExempt []wire.SNACType) error {
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()
		for {
			r := bufio.NewReader(conn)
			line, err := r.ReadString('\n')
			if err != nil {
				break
			}
			mu.Lock()
			received = append(received, strings.TrimSpace(line))
			mu.Unlock()
			msgWg.Done()
		}
		return nil
	}
	server.shutdownCtx, server.shutdownCancel = context.WithCancel(context.Background())

	shutdownCh := make(chan struct{})

	go func() {
		defer close(shutdownCh)
		assert.NoError(t, server.ListenAndServe())
	}()

	// Wait for server to be ready by checking if ports are listening
	for i := 0; i < len(endpoints); i++ {
		maxRetries := 10
		backoff := 5 * time.Millisecond

		for attempt := 0; attempt < maxRetries; attempt++ {
			conn, err := net.Dial("tcp", "localhost"+endpoints[i].ListenAddress)
			if err == nil {
				_ = conn.Close()
				break
			}
			if attempt == maxRetries-1 {
				t.Fatalf("Server not ready after %d attempts: %v", maxRetries, err)
			}
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	for i := 0; i < len(endpoints); i++ {
		msgWg.Add(1)
		// Connect and send message
		conn, err := net.Dial("tcp", "localhost"+endpoints[i].ListenAddress)
		assert.NoError(t, err)

		_, err = conn.Write([]byte(responses[i] + "\n"))
		assert.NoError(t, err)
	}

	msgWg.Wait()

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := server.Shutdown(ctx)
	assert.NoError(t, err)

	<-shutdownCh

	// Check what was received
	mu.Lock()
	defer mu.Unlock()
	assert.ElementsMatch(t, received, responses)
}

type fakeConn struct {
	net.Conn // embed the real connection
	local    net.Addr
	remote   net.Addr
}

func (f fakeConn) RemoteAddr() net.Addr { return f.remote }

func TestOscarServer_RouteConnection_Auth_BUCP(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)

	clientFake := fakeConn{
		Conn:   serverConn,
		local:  addr,
		remote: addr,
	}

	go func() {
		defer func() {
			_ = clientConn.Close()
		}()

		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flapSignonFrame, bytes.NewBuffer(flap.Payload)))

		// > send FLAPSignonFrame
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		buf := &bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker: 42,
			FrameType:   wire.FLAPFrameSignon,
			Payload:     buf.Bytes(),
		}
		assert.NoError(t, wire.MarshalBE(flap, clientConn))

		// > send SNAC_0x17_0x06_BUCPChallengeRequest
		flapc := wire.NewFlapClient(0, clientConn, clientConn)
		frame := wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPChallengeRequest,
			RequestID: 4,
		}
		bodyIn := wire.SNAC_0x17_0x06_BUCPChallengeRequest{}
		assert.NoError(t, flapc.SendSNAC(frame, bodyIn))

		// < receive SNAC_0x17_0x07_BUCPChallengeResponse
		frame = wire.SNACFrame{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &wire.SNAC_0x17_0x07_BUCPChallengeResponse{}))
		assert.Equal(t, wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPChallengeResponse, RequestID: 4}, frame)

		// > send keep alive frame (like BSFlite does mid-login)
		assert.NoError(t, flapc.SendKeepAliveFrame())

		// > send SNAC_0x17_0x02_BUCPLoginRequest
		frame = wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPLoginRequest,
			RequestID: 5,
		}
		assert.NoError(t, flapc.SendSNAC(frame, wire.SNAC_0x17_0x02_BUCPLoginRequest{}))

		// < receive SNAC_0x17_0x03_BUCPLoginResponse
		frame = wire.SNACFrame{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &wire.SNAC_0x17_0x03_BUCPLoginResponse{}))
		assert.Equal(t, wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPLoginResponse, RequestID: 5}, frame)

		// < receive FLAPSignoffFrame (server sends this after SNAC for Kopete compatibility)
		flap = wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		assert.Equal(t, wire.FLAPFrameSignoff, flap.FrameType)
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		BUCPChallenge(matchContext(), mock.Anything, mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.BUCP,
				SubGroup:  wire.BUCPChallengeResponse,
			},
			Body: wire.SNAC_0x17_0x07_BUCPChallengeResponse{},
		}, nil)
	authService.EXPECT().
		BUCPLogin(matchContext(), mock.Anything, config.Endpoint{Group: config.ListenerGroup{BOSAdvertisedHostPlain: "localhost:5190"}}).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.BUCP,
				SubGroup:  wire.BUCPLoginResponse,
			},
			Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{},
		}, nil)

	rt := oscarServer{
		rateLimitUpdater: noopRateLimitUpdater{},
		authService:      authService,
		logger:           slog.Default(),
		ipRateLimiter:    NewIPRateLimiter(rate.Every(1*time.Minute), 10, 1*time.Minute),
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Endpoint{Group: config.ListenerGroup{BOSAdvertisedHostPlain: "localhost:5190"}}, nil))

	wg.Wait()
}

func TestOscarServer_RouteConnection_Auth_FLAP(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)

	clientFake := fakeConn{
		Conn:   serverConn,
		local:  addr,
		remote: addr,
	}

	go func() {
		defer func() {
			_ = clientConn.Close()
		}()

		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flapSignonFrame, bytes.NewBuffer(flap.Payload)))

		// > send FLAPSignonFrame with screen name TLV (indicates FLAP auth)
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		// Add screen name TLV to indicate FLAP authentication
		flapSignonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, "testuser"))
		// Add password hash TLV for authentication
		flapSignonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, []byte("password_hash")))
		// Add client identity TLV
		flapSignonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, "ICQ 2000b"))

		buf := &bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker: 42,
			FrameType:   wire.FLAPFrameSignon,
			Payload:     buf.Bytes(),
		}
		assert.NoError(t, wire.MarshalBE(flap, clientConn))

		// < receive FLAPSignoffFrame with authentication result
		flap = wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		assert.Equal(t, wire.FLAPFrameSignoff, flap.FrameType)

		// Parse the signoff frame payload to verify authentication response
		signoffTLVs := wire.TLVRestBlock{}
		assert.NoError(t, wire.UnmarshalBE(&signoffTLVs, bytes.NewBuffer(flap.Payload)))
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		FLAPLogin(matchContext(), mock.Anything, config.Endpoint{Group: config.ListenerGroup{BOSAdvertisedHostPlain: "localhost:5190"}}).
		Return(wire.TLVRestBlock{
			TLVList: []wire.TLV{
				wire.NewTLVBE(wire.LoginTLVTagsScreenName, "testuser"),
				wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "localhost:5190"),
				wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("auth-cookie")),
			},
		}, nil)

	rt := oscarServer{
		rateLimitUpdater: noopRateLimitUpdater{},
		authService:      authService,
		logger:           slog.Default(),
		ipRateLimiter:    NewIPRateLimiter(rate.Every(1*time.Minute), 10, 1*time.Minute),
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Endpoint{Group: config.ListenerGroup{BOSAdvertisedHostPlain: "localhost:5190"}}, nil))

	wg.Wait()
}

func TestOscarServer_RouteConnection_BOS(t *testing.T) {
	instance := state.NewSession().AddInstance()

	clientConn, serverConn := net.Pipe()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)

	clientFake := fakeConn{
		Conn:   serverConn,
		local:  addr,
		remote: addr,
	}

	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flapSignonFrame, bytes.NewBuffer(flap.Payload)))

		// > send FLAPSignonFrame
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		flapSignonFrame.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf := &bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker: 42,
			FrameType:   wire.FLAPFrameSignon,
			Payload:     buf.Bytes(),
		}
		assert.NoError(t, wire.MarshalBE(flap, clientConn))

		flapc := wire.NewFlapClient(0, clientConn, clientConn)

		// < receive SNAC_0x01_0x03_OServiceHostOnline
		frame := wire.SNACFrame{}
		body := wire.SNAC_0x01_0x03_OServiceHostOnline{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &body))

		// send the first request that should get relayed to BOSRouter.Handle
		frame = wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceClientOnline,
		}
		assert.NoError(t, flapc.SendSNAC(frame, struct{}{}))
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterBOSSession(mock.Anything, state.ServerCookie{Service: wire.BOS}, mock.Anything).
		Run(func(ctx context.Context, cookie state.ServerCookie, conf func(*state.Session)) {
			if conf != nil {
				conf(instance.Session())
			}
		}).
		Return(instance, nil)
	wg.Add(1)
	authService.EXPECT().
		Signout(mock.Anything, instance.Session()).
		Run(func(ctx context.Context, s *state.Session) {
			defer wg.Done()
		})

	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.BOS}, time.Now().Add(time.Minute), nil)

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline(mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	buddyListRegistry := newMockBuddyListRegistry(t)
	buddyListRegistry.EXPECT().
		RegisterBuddyList(mock.Anything, mock.Anything).
		Return(nil)
	buddyListRegistry.EXPECT().
		UnregisterBuddyList(mock.Anything, mock.Anything).
		Return(nil)

	departureNotifier := newMockDepartureNotifier(t)
	departureNotifier.EXPECT().
		BroadcastBuddyDeparted(mock.Anything, mock.Anything).
		Return(nil)

	chatSessionManager := newMockChatSessionManager(t)
	chatSessionManager.EXPECT().
		RemoveUserFromAllChats(mock.Anything)

	wg.Add(2)
	handler := func(ctx context.Context, serverType uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, endpointCfg config.Endpoint) error {
		defer wg.Done()
		assert.NoError(t, clientConn.Close())
		return nil
	}

	rt := oscarServer{
		rateLimitUpdater:   noopRateLimitUpdater{},
		authService:        authService,
		snacHandler:        handler,
		logger:             slog.Default(),
		onlineNotifier:     onlineNotifier,
		buddyListRegistry:  buddyListRegistry,
		chatSessionManager: chatSessionManager,
		departureNotifier:  departureNotifier,
		recalcWarning: func(ctx context.Context, instance *state.SessionInstance) error {
			return nil
		},
		lowerWarnLevel: func(ctx context.Context, instance *state.SessionInstance) {
			defer wg.Done()
		},
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Endpoint{}, nil))

	wg.Wait()
}

// Set up a multi-instance session and connect as the second instance.
//   - Ensure that disconnecting second instance does not sign out the session.
func TestOscarServer_RouteConnection_BOS_MultiSessionSignoff(t *testing.T) {
	instance := state.NewSession().AddInstance()
	instance.Session().AddInstance()

	clientConn, serverConn := net.Pipe()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)

	clientFake := fakeConn{
		Conn:   serverConn,
		local:  addr,
		remote: addr,
	}

	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flapSignonFrame, bytes.NewBuffer(flap.Payload)))

		// > send FLAPSignonFrame
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		flapSignonFrame.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf := &bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker: 42,
			FrameType:   wire.FLAPFrameSignon,
			Payload:     buf.Bytes(),
		}
		assert.NoError(t, wire.MarshalBE(flap, clientConn))

		flapc := wire.NewFlapClient(0, clientConn, clientConn)

		// < receive SNAC_0x01_0x03_OServiceHostOnline
		frame := wire.SNACFrame{}
		body := wire.SNAC_0x01_0x03_OServiceHostOnline{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &body))

		// send the first request that should get relayed to BOSRouter.Handle
		frame = wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceClientOnline,
		}
		assert.NoError(t, flapc.SendSNAC(frame, struct{}{}))
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterBOSSession(mock.Anything, state.ServerCookie{Service: wire.BOS}, mock.Anything).
		Return(instance, nil)

	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.BOS}, time.Now().Add(time.Minute), nil)

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline(mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	buddyListRegistry := newMockBuddyListRegistry(t)
	buddyListRegistry.EXPECT().
		RegisterBuddyList(mock.Anything, mock.Anything).
		Return(nil)

	departureNotifier := newMockDepartureNotifier(t)
	departureNotifier.EXPECT().
		BroadcastBuddyArrived(mock.Anything, mock.Anything, mock.Anything).
		Return(nil)

	chatSessionManager := newMockChatSessionManager(t)

	wg.Add(2)
	handler := func(ctx context.Context, serverType uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, endpointCfg config.Endpoint) error {
		defer wg.Done()
		assert.NoError(t, clientConn.Close())
		return nil
	}

	rt := oscarServer{
		rateLimitUpdater:   noopRateLimitUpdater{},
		authService:        authService,
		snacHandler:        handler,
		logger:             slog.Default(),
		onlineNotifier:     onlineNotifier,
		buddyListRegistry:  buddyListRegistry,
		chatSessionManager: chatSessionManager,
		departureNotifier:  departureNotifier,
		recalcWarning: func(ctx context.Context, instance *state.SessionInstance) error {
			return nil
		},
		lowerWarnLevel: func(ctx context.Context, instance *state.SessionInstance) {
			defer wg.Done()
		},
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Endpoint{}, nil))

	wg.Wait()
}

// Ensure client disconnection if session hits max concurrent sessions limit.
func TestOscarServer_RouteConnection_BOS_MaxConcurrentSessionsReached(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)

	clientFake := fakeConn{
		Conn:   serverConn,
		local:  addr,
		remote: addr,
	}

	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flapSignonFrame, bytes.NewBuffer(flap.Payload)))

		// > send FLAPSignonFrame
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		flapSignonFrame.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf := &bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker: 42,
			FrameType:   wire.FLAPFrameSignon,
			Payload:     buf.Bytes(),
		}
		assert.NoError(t, wire.MarshalBE(flap, clientConn))

		flapc := wire.NewFlapClient(0, clientConn, clientConn)

		// < receive SNAC_0x01_0x03_OServiceHostOnline
		flap, err = flapc.ReceiveFLAP()
		assert.NoError(t, err)

		assert.NoError(t, clientConn.Close())
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterBOSSession(mock.Anything, state.ServerCookie{Service: wire.BOS}, mock.Anything).
		Return(nil, state.ErrMaxConcurrentSessionsReached)

	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.BOS}, time.Now().Add(time.Minute), nil)

	rt := oscarServer{
		rateLimitUpdater: noopRateLimitUpdater{},
		authService:      authService,
		logger:           slog.Default(),
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Endpoint{}, nil))

	wg.Wait()
}

func TestOscarServer_RouteConnection_Chat(t *testing.T) {
	instance := state.NewSession().AddInstance()

	// Without a monitor of its own, a chat client that subscribes over this
	// connection is never told its rate limit status changed.
	rateLimitUpdater := newRecordingRateLimitUpdater()

	clientConn, serverConn := net.Pipe()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)

	clientFake := fakeConn{
		Conn:   serverConn,
		local:  addr,
		remote: addr,
	}

	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flapSignonFrame, bytes.NewBuffer(flap.Payload)))

		// > send FLAPSignonFrame
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		flapSignonFrame.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf := &bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker: 42,
			FrameType:   wire.FLAPFrameSignon,
			Payload:     buf.Bytes(),
		}
		assert.NoError(t, wire.MarshalBE(flap, clientConn))

		flapc := wire.NewFlapClient(0, clientConn, clientConn)

		// < receive SNAC_0x01_0x03_OServiceHostOnline
		frame := wire.SNACFrame{}
		body := wire.SNAC_0x01_0x03_OServiceHostOnline{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &body))

		// send the first request that should get relayed to BOSRouter.Handle
		frame = wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceClientOnline,
		}
		assert.NoError(t, flapc.SendSNAC(frame, struct{}{}))
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterChatSession(mock.Anything, state.ServerCookie{Service: wire.Chat}, mock.Anything).
		Run(func(_ context.Context, _ state.ServerCookie, cfg func(*state.Session)) {
			if cfg != nil {
				cfg(instance.Session())
			}
		}).
		Return(instance, nil)
	wg.Add(1)
	authService.EXPECT().
		SignoutChat(mock.Anything, instance.Session()).
		Run(func(ctx context.Context, s *state.Session) {
			defer wg.Done()
		})

	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.Chat}, time.Now().Add(time.Minute), nil)

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline(mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	buddyListRegistry := newMockBuddyListRegistry(t)
	departureNotifier := newMockDepartureNotifier(t)
	chatSessionManager := newMockChatSessionManager(t)

	wg.Add(1)
	handler := func(ctx context.Context, serverType uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, endpointCfg config.Endpoint) error {
		defer wg.Done()
		assert.NoError(t, clientConn.Close())
		return nil
	}

	rt := oscarServer{
		rateLimitUpdater:   rateLimitUpdater,
		authService:        authService,
		snacHandler:        handler,
		logger:             slog.Default(),
		onlineNotifier:     onlineNotifier,
		buddyListRegistry:  buddyListRegistry,
		chatSessionManager: chatSessionManager,
		departureNotifier:  departureNotifier,
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Endpoint{}, nil))

	wg.Wait()

	select {
	case monitored := <-rateLimitUpdater.monitored:
		assert.Same(t, instance.Session(), monitored, "the monitor must run against the chat session")
	case <-time.After(2 * time.Second):
		t.Fatal("no rate limit monitor was started for the chat session")
	}
}

func TestOscarServer_RouteConnection_Admin(t *testing.T) {
	instance := state.NewSession().AddInstance()

	clientConn, serverConn := net.Pipe()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)

	clientFake := fakeConn{
		Conn:   serverConn,
		local:  addr,
		remote: addr,
	}

	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flap, clientConn))
		flapSignonFrame := wire.FLAPSignonFrame{}
		assert.NoError(t, wire.UnmarshalBE(&flapSignonFrame, bytes.NewBuffer(flap.Payload)))

		// > send FLAPSignonFrame
		flapSignonFrame = wire.FLAPSignonFrame{
			FLAPVersion: 1,
		}
		flapSignonFrame.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf := &bytes.Buffer{}
		assert.NoError(t, wire.MarshalBE(flapSignonFrame, buf))
		flap = wire.FLAPFrame{
			StartMarker: 42,
			FrameType:   wire.FLAPFrameSignon,
			Payload:     buf.Bytes(),
		}
		assert.NoError(t, wire.MarshalBE(flap, clientConn))

		flapc := wire.NewFlapClient(0, clientConn, clientConn)

		// < receive SNAC_0x01_0x03_OServiceHostOnline
		frame := wire.SNACFrame{}
		body := wire.SNAC_0x01_0x03_OServiceHostOnline{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &body))

		// send the first request that should get relayed to BOSRouter.Handle
		frame = wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceClientOnline,
		}
		assert.NoError(t, flapc.SendSNAC(frame, struct{}{}))
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.Admin}, time.Now().Add(time.Minute), nil)
	authService.EXPECT().
		RetrieveBOSSession(mock.Anything, state.ServerCookie{Service: wire.Admin}).
		Return(instance, nil)

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline(mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	buddyListRegistry := newMockBuddyListRegistry(t)
	departureNotifier := newMockDepartureNotifier(t)
	chatSessionManager := newMockChatSessionManager(t)

	wg.Add(1)
	handler := func(ctx context.Context, serverType uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, endpointCfg config.Endpoint) error {
		defer wg.Done()
		assert.NoError(t, clientConn.Close())
		return nil
	}

	rt := oscarServer{
		rateLimitUpdater:   noopRateLimitUpdater{},
		authService:        authService,
		snacHandler:        handler,
		logger:             slog.Default(),
		onlineNotifier:     onlineNotifier,
		buddyListRegistry:  buddyListRegistry,
		chatSessionManager: chatSessionManager,
		departureNotifier:  departureNotifier,
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Endpoint{}, nil))

	wg.Wait()
}

// Make sure the client receives signoff FLAP when the server shuts down via
// context cancellation.
func Test_oscarServer_dispatchIncomingMessages_shutdownSignoff(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := oscarServer{
			rateLimitUpdater: noopRateLimitUpdater{},
			logger:           slog.Default(),
		}
		instance := state.NewSession().AddInstance()
		instance.SetMultiConnFlag(wire.MultiConnFlagsRecentClient)
		flapc := wire.NewFlapClient(0, serverConn, serverConn)
		err := srv.dispatchIncomingMessages(ctx, wire.BOS, instance, flapc, serverConn, config.Endpoint{}, nil)
		assert.NoError(t, err)
	}()

	cancel()
	flapc := wire.NewFlapClient(0, clientConn, clientConn)
	frame, err := flapc.ReceiveFLAP()
	assert.NoError(t, err)
	assert.Equal(t, wire.FLAPFrameSignoff, frame.FrameType)

	wg.Wait()
}

// Make sure the client (which doesn't support multi-conn) receives
// disconnection signoff FLAP when the session gets logged off by a new session.
func Test_oscarServer_dispatchIncomingMessages_disconnect_old_client(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	ctx := context.Background()
	instance := state.NewSession().AddInstance()
	instance.SetMultiConnFlag(wire.MultiConnFlagsOldClient)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := oscarServer{
			rateLimitUpdater: noopRateLimitUpdater{},
			logger:           slog.Default(),
		}
		flapc := wire.NewFlapClient(0, serverConn, serverConn)
		err := srv.dispatchIncomingMessages(ctx, wire.BOS, instance, flapc, serverConn, config.Endpoint{}, nil)
		assert.NoError(t, err)
	}()

	instance.CloseInstance()

	frame := wire.FLAPFrameDisconnect{}
	assert.NoError(t, wire.UnmarshalBE(&frame, clientConn))
	assert.Equal(t, wire.FLAPFrameSignoff, frame.FrameType)

	wg.Wait()
}

// Make sure the client (which supports multi-conn) receives disconnection
// signoff FLAP when the session gets logged off by a new session.
func Test_oscarServer_dispatchIncomingMessages_disconnect_new_client(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	ctx := context.Background()
	instance := state.NewSession().AddInstance()
	instance.SetMultiConnFlag(wire.MultiConnFlagsRecentClient)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := oscarServer{
			rateLimitUpdater: noopRateLimitUpdater{},
			logger:           slog.Default(),
		}
		flapc := wire.NewFlapClient(0, serverConn, serverConn)
		err := srv.dispatchIncomingMessages(ctx, wire.BOS, instance, flapc, serverConn, config.Endpoint{}, nil)
		assert.NoError(t, err)
	}()

	instance.CloseInstance()

	flapc := wire.NewFlapClient(0, clientConn, clientConn)
	frame, err := flapc.ReceiveFLAP()
	assert.NoError(t, err)
	assert.Equal(t, wire.FLAPFrameSignoff, frame.FrameType)

	wg.Wait()
}

// SNACs exempt from rate limiting on a connection are neither dropped nor
// charged, while the connection's other SNACs still are.
func Test_oscarServer_dispatchIncomingMessages_rateLimitExempt(t *testing.T) {
	exempt := wire.SNACType{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
	charged := wire.SNACType{FoodGroup: wire.Locate, SubGroup: wire.LocateSetInfo}
	rateLimits := wire.DefaultSNACRateLimits()
	exemptClass, ok := rateLimits.RateClassLookup(exempt.FoodGroup, exempt.SubGroup)
	require.True(t, ok)
	chargedClass, ok := rateLimits.RateClassLookup(charged.FoodGroup, charged.SubGroup)
	require.True(t, ok)

	// From MaxLevel 200, each back-to-back SNAC halves the moving average,
	// so the second one in a class is limited.
	var classes [5]wire.RateClass
	for i := range classes {
		classes[i] = wire.RateClass{
			ID:              wire.RateLimitClassID(i + 1),
			WindowSize:      2,
			ClearLevel:      100,
			AlertLevel:      80,
			LimitLevel:      70,
			DisconnectLevel: 2,
			MaxLevel:        200,
		}
	}
	instance := state.NewSession().AddInstance()
	instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))
	before := instance.Session().RateLimitStates()

	var mu sync.Mutex
	handled := map[wire.SNACType]int{}
	srv := oscarServer{
		rateLimitUpdater: noopRateLimitUpdater{},
		rateLimits:       rateLimits,
		logger:           slog.Default(),
		snacHandler: func(_ context.Context, _ uint16, _ *state.SessionInstance, inFrame wire.SNACFrame, _ io.Reader, _ ResponseWriter, _ config.Endpoint) error {
			mu.Lock()
			defer mu.Unlock()
			handled[wire.SNACType{FoodGroup: inFrame.FoodGroup, SubGroup: inFrame.SubGroup}]++
			return nil
		},
	}

	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		flapc := wire.NewFlapClient(0, nil, io.Discard)
		err := srv.dispatchIncomingMessages(context.Background(), wire.BOS, instance, flapc, pr, config.Endpoint{}, []wire.SNACType{exempt})
		assert.NoError(t, err)
	}()

	send := func(snacType wire.SNACType) {
		snac := bytes.Buffer{}
		require.NoError(t, wire.MarshalBE(wire.SNACFrame{FoodGroup: snacType.FoodGroup, SubGroup: snacType.SubGroup}, &snac))
		frame := wire.FLAPFrame{StartMarker: 42, FrameType: wire.FLAPFrameData, Payload: snac.Bytes()}
		require.NoError(t, wire.MarshalBE(frame, pw))
	}
	for range 5 {
		send(exempt)
	}
	for range 5 {
		send(charged)
	}
	require.NoError(t, pw.Close())
	<-done

	assert.Equal(t, 5, handled[exempt], "an exempt SNAC is never dropped")
	assert.Equal(t, 1, handled[charged], "the charged SNACs after the first are limited")

	after := instance.Session().RateLimitStates()
	require.NotEqual(t, exemptClass, chargedClass)
	assert.Equal(t, before[exemptClass-1].CurrentLevel, after[exemptClass-1].CurrentLevel, "an exempt SNAC is not charged")
	assert.Less(t, after[chargedClass-1].CurrentLevel, before[chargedClass-1].CurrentLevel)
}

// Make sure the frame reader exits when the dispatch loop ends with frames
// still in flight.
func Test_oscarServer_dispatchIncomingMessages_readerExits(t *testing.T) {
	const fn = "dispatchIncomingMessages"
	before := blockedSends(fn)

	pr, pw := io.Pipe()
	release := make(chan struct{})
	srv := oscarServer{
		rateLimitUpdater: noopRateLimitUpdater{},
		logger:           slog.Default(),
		snacHandler: func(context.Context, uint16, *state.SessionInstance, wire.SNACFrame, io.Reader, ResponseWriter, config.Endpoint) error {
			<-release
			return errors.New("handler failed")
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		instance := state.NewSession().AddInstance()
		flapc := wire.NewFlapClient(0, nil, io.Discard)
		err := srv.dispatchIncomingMessages(context.Background(), wire.BOS, instance, flapc, pr, config.Endpoint{}, nil)
		assert.Error(t, err)
	}()

	// the handler holds the first frame, the channel buffers the second, and
	// the reader holds the third
	snac := bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost}, &snac))
	for range 3 {
		frame := wire.FLAPFrame{StartMarker: 42, FrameType: wire.FLAPFrameData, Payload: snac.Bytes()}
		assert.NoError(t, wire.MarshalBE(frame, pw))
	}

	close(release)
	<-done
	assert.NoError(t, pw.Close())

	assert.Eventually(t, func() bool {
		return blockedSends(fn) == before
	}, time.Second, 10*time.Millisecond)
}

// blockedSends counts the goroutines blocked sending on a channel in fn.
func blockedSends(fn string) int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(stack, "[chan send") && strings.Contains(stack, fn) {
			n++
		}
	}
	return n
}

func Test_oscarServer_receiveSessMessages_BOS_integration(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	// Prepare session and mocks so we can exercise through routeConnection
	instance := state.NewSession().AddInstance()
	instance.SetSignonComplete()

	authService := newMockAuthService(t)
	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.BOS}, time.Now().Add(time.Minute), nil)
	authService.EXPECT().
		RegisterBOSSession(mock.Anything, state.ServerCookie{Service: wire.BOS}, mock.Anything).
		Run(func(ctx context.Context, cookie state.ServerCookie, conf func(*state.Session)) {
			if conf != nil {
				conf(instance.Session())
			}
		}).
		Return(instance, nil)

	var signoutWG sync.WaitGroup
	signoutWG.Add(1)
	authService.EXPECT().
		Signout(mock.Anything, instance.Session()).
		Run(func(ctx context.Context, s *state.Session) { signoutWG.Done() })

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline(mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
			Body:  wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	buddyListRegistry := newMockBuddyListRegistry(t)
	buddyListRegistry.EXPECT().RegisterBuddyList(mock.Anything, mock.Anything).Return(nil)
	buddyListRegistry.EXPECT().UnregisterBuddyList(mock.Anything, mock.Anything).Return(nil)

	departureNotifier := newMockDepartureNotifier(t)
	departureNotifier.EXPECT().BroadcastBuddyDeparted(mock.Anything, mock.Anything).Return(nil)

	chatSessionManager := newMockChatSessionManager(t)
	chatSessionManager.EXPECT().RemoveUserFromAllChats(mock.Anything)

	server := oscarServer{
		rateLimitUpdater:   noopRateLimitUpdater{},
		authService:        authService,
		buddyListRegistry:  buddyListRegistry,
		chatSessionManager: chatSessionManager,
		departureNotifier:  departureNotifier,
		onlineNotifier:     onlineNotifier,
		logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		recalcWarning:      func(ctx context.Context, instance *state.SessionInstance) error { return nil },
		lowerWarnLevel:     func(ctx context.Context, instance *state.SessionInstance) {},
	}

	// Fake client connection with address
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)
	clientFake := fakeConn{Conn: serverConn, local: addr, remote: addr}

	// Coordinate when the server has finished login and sent HostOnline
	ready := make(chan struct{})

	// Client goroutine: perform handshake and then read forwarded messages
	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		_ = wire.UnmarshalBE(&flap, clientConn)
		flapSignon := wire.FLAPSignonFrame{}
		_ = wire.UnmarshalBE(&flapSignon, bytes.NewBuffer(flap.Payload))

		// > send FLAPSignonFrame with login cookie
		flapSignon = wire.FLAPSignonFrame{FLAPVersion: 1}
		flapSignon.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf := &bytes.Buffer{}
		_ = wire.MarshalBE(flapSignon, buf)
		_ = wire.MarshalBE(wire.FLAPFrame{StartMarker: 42, FrameType: wire.FLAPFrameSignon, Payload: buf.Bytes()}, clientConn)

		// Expect HostOnline
		flapcClient := wire.NewFlapClient(0, clientConn, clientConn)
		fr := wire.SNACFrame{}
		body := wire.SNAC_0x01_0x03_OServiceHostOnline{}
		_ = flapcClient.ReceiveSNAC(&fr, &body)
		close(ready)
	}()

	// Run the server handler in background so we can drive the session
	doneServer := make(chan error, 1)
	go func() { doneServer <- server.routeConnection(context.Background(), clientFake, config.Endpoint{}, nil) }()

	// Wait for HostOnline to be received so session is ready
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not complete login in time")
	}

	// Now send messages via the session and verify client receives them
	messages := []wire.SNACMessage{
		{
			Frame: wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived},
			Body:  wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: wire.TLVUserInfo{ScreenName: "user1"}},
		},
		{
			Frame: wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted},
			Body:  wire.SNAC_0x03_0x0C_BuddyDeparted{TLVUserInfo: wire.TLVUserInfo{ScreenName: "user2"}},
		},
		{
			Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: 0x07},
			Body:  wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{Cookie: 12345, ChannelID: 1, TLVUserInfo: wire.TLVUserInfo{ScreenName: "sender"}},
		},
	}

	for i, msg := range messages {
		status := instance.RelayMessageToInstance(msg)
		assert.Equal(t, state.SessSendOK, status, "Message %d should be sent successfully", i)
	}

	// Read and verify all messages from client side
	for i, expected := range messages {
		flapFrame := wire.FLAPFrame{}
		err := wire.UnmarshalBE(&flapFrame, clientConn)
		assert.NoError(t, err, "read FLAP frame %d", i)
		assert.Equal(t, uint8(42), flapFrame.StartMarker)
		assert.Equal(t, wire.FLAPFrameData, flapFrame.FrameType)

		snac := wire.SNACFrame{}
		buf := bytes.NewBuffer(flapFrame.Payload)
		err = wire.UnmarshalBE(&snac, buf)
		assert.NoError(t, err, "unmarshal SNAC %d", i)
		assert.Equal(t, expected.Frame.FoodGroup, snac.FoodGroup)
		assert.Equal(t, expected.Frame.SubGroup, snac.SubGroup)
	}

	// CloseSession client to let server exit cleanly
	_ = clientConn.Close()

	// Wait for server handler to return
	select {
	case err := <-doneServer:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("routeConnection did not exit in time")
	}

	// Ensure signout ran
	signoutWG.Wait()
}

func Test_oscarServer_receiveSessMessages_Chat_integration(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	// Prepare session and mocks so we can exercise through routeConnection
	instance := state.NewSession().AddInstance()
	instance.SetSignonComplete()

	authService := newMockAuthService(t)
	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.Chat}, time.Now().Add(time.Minute), nil)
	authService.EXPECT().
		RegisterChatSession(mock.Anything, state.ServerCookie{Service: wire.Chat}, mock.Anything).
		Run(func(_ context.Context, _ state.ServerCookie, cfg func(*state.Session)) {
			if cfg != nil {
				cfg(instance.Session())
			}
		}).
		Return(instance, nil)

	var signoutWG sync.WaitGroup
	signoutWG.Add(1)
	authService.EXPECT().
		SignoutChat(mock.Anything, instance.Session()).
		Run(func(ctx context.Context, s *state.Session) { signoutWG.Done() })

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline(mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
			Body:  wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	server := oscarServer{
		rateLimitUpdater: noopRateLimitUpdater{},
		authService:      authService,
		onlineNotifier:   onlineNotifier,
		logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Fake client connection with address
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	assert.NoError(t, err)
	clientFake := fakeConn{Conn: serverConn, local: addr, remote: addr}

	ready := make(chan struct{})

	// Client goroutine: perform handshake and then read forwarded messages
	go func() {
		// < receive FLAPSignonFrame
		flap := wire.FLAPFrame{}
		_ = wire.UnmarshalBE(&flap, clientConn)
		flapSignon := wire.FLAPSignonFrame{}
		_ = wire.UnmarshalBE(&flapSignon, bytes.NewBuffer(flap.Payload))

		// > send FLAPSignonFrame with login cookie
		flapSignon = wire.FLAPSignonFrame{FLAPVersion: 1}
		flapSignon.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")))
		buf := &bytes.Buffer{}
		_ = wire.MarshalBE(flapSignon, buf)
		_ = wire.MarshalBE(wire.FLAPFrame{StartMarker: 42, FrameType: wire.FLAPFrameSignon, Payload: buf.Bytes()}, clientConn)

		// Expect HostOnline
		flapcClient := wire.NewFlapClient(0, clientConn, clientConn)
		fr := wire.SNACFrame{}
		body := wire.SNAC_0x01_0x03_OServiceHostOnline{}
		_ = flapcClient.ReceiveSNAC(&fr, &body)
		close(ready)
	}()

	// Run the server handler in background so we can drive the session
	doneServer := make(chan error, 1)
	go func() { doneServer <- server.routeConnection(context.Background(), clientFake, config.Endpoint{}, nil) }()

	// Wait for HostOnline to be received so session is ready
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not complete login in time")
	}

	messages := []wire.SNACMessage{
		{
			Frame: wire.SNACFrame{FoodGroup: wire.Chat, SubGroup: wire.ChatUsersJoined},
			Body:  wire.SNAC_0x0E_0x03_ChatUsersJoined{Users: []wire.TLVUserInfo{{ScreenName: "user1"}}},
		},
		{
			Frame: wire.SNACFrame{FoodGroup: wire.Chat, SubGroup: wire.ChatUsersLeft},
			Body:  wire.SNAC_0x0E_0x04_ChatUsersLeft{Users: []wire.TLVUserInfo{{ScreenName: "user2"}}},
		},
		{
			Frame: wire.SNACFrame{FoodGroup: wire.Chat, SubGroup: wire.ChatChannelMsgToClient},
			Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
				Cookie: 12345, Channel: 1,
				TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ChatTLVSenderInformation, wire.TLVUserInfo{ScreenName: "sender"}),
					wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{TLVList: wire.TLVList{
						wire.NewTLVBE(wire.ChatTLVMessageInfoText, "Hello chat!"),
					}}),
				}},
			},
		},
	}

	for i, msg := range messages {
		status := instance.RelayMessageToInstance(msg)
		assert.Equal(t, state.SessSendOK, status, "Message %d should be sent successfully", i)
	}

	for i, expected := range messages {
		flapFrame := wire.FLAPFrame{}
		err := wire.UnmarshalBE(&flapFrame, clientConn)
		assert.NoError(t, err, "read FLAP frame %d", i)
		assert.Equal(t, uint8(42), flapFrame.StartMarker)
		assert.Equal(t, wire.FLAPFrameData, flapFrame.FrameType)

		snac := wire.SNACFrame{}
		buf := bytes.NewBuffer(flapFrame.Payload)
		err = wire.UnmarshalBE(&snac, buf)
		assert.NoError(t, err, "unmarshal SNAC %d", i)
		assert.Equal(t, expected.Frame.FoodGroup, snac.FoodGroup)
		assert.Equal(t, expected.Frame.SubGroup, snac.SubGroup)
	}

	_ = clientConn.Close()

	select {
	case err := <-doneServer:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("routeConnection did not exit in time")
	}

	signoutWG.Wait()
}

func newServeConnTestServer() *Server {
	return NewServer(
		nil,
		nil,
		nil,
		nil,
		slog.Default(),
		nil,
		nil,
		nil,
		wire.DefaultSNACRateLimits(),
		nil,
		nil,
		func(ctx context.Context, instance *state.SessionInstance) error { return nil },
		func(ctx context.Context, instance *state.SessionInstance) {},
	)
}

func TestServer_ServeConn(t *testing.T) {
	server := newServeConnTestServer()

	var gotEndpoint config.Endpoint
	var gotRemote net.Addr
	var gotExempt []wire.SNACType
	server.handler = func(ctx context.Context, conn net.Conn, endpointCfg config.Endpoint, rateLimitExempt []wire.SNACType) error {
		gotEndpoint = endpointCfg
		gotRemote = conn.RemoteAddr()
		gotExempt = rateLimitExempt
		return nil
	}

	serverEnd, clientEnd := net.Pipe()
	clientAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4321}
	endpoint := config.Endpoint{ListenAddress: ":5190", Group: config.ListenerGroup{Name: "LOCAL"}}
	exempt := []wire.SNACType{{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}}

	server.ServeConn(fakeConn{Conn: serverEnd, remote: clientAddr}, endpoint, exempt)

	assert.Equal(t, endpoint, gotEndpoint)
	assert.Equal(t, clientAddr, gotRemote)
	assert.Equal(t, exempt, gotExempt)

	// the connection is closed once served
	_, err := clientEnd.Read(make([]byte, 1))
	assert.Error(t, err)
	assert.Empty(t, server.conns)
}

func TestServer_ServeConn_afterShutdown(t *testing.T) {
	server := newServeConnTestServer()

	called := false
	server.handler = func(ctx context.Context, conn net.Conn, endpointCfg config.Endpoint, rateLimitExempt []wire.SNACType) error {
		called = true
		return nil
	}
	assert.NoError(t, server.Shutdown(context.Background()))

	serverEnd, clientEnd := net.Pipe()
	server.ServeConn(serverEnd, config.Endpoint{}, nil)

	assert.False(t, called)
	_, err := clientEnd.Read(make([]byte, 1))
	assert.Error(t, err)
}
