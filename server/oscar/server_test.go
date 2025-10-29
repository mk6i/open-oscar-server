package oscar

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/time/rate"

	"github.com/mk6i/retro-aim-server/config"
	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

func TestServer_ListenAndServeAndShutdown(t *testing.T) {
	var mu sync.Mutex
	var received []string

	var msgWg sync.WaitGroup

	cfg := []config.Listener{
		{
			BOSListenAddress:       ":15000",
			BOSAdvertisedHostPlain: "localhost",
		},
		{
			BOSListenAddress:       ":15001",
			BOSAdvertisedHostPlain: "localhost",
		},
		{
			BOSListenAddress:       ":15002",
			BOSAdvertisedHostPlain: "localhost",
		},
	}
	responses := []string{"hello1", "hello2", "hello2"}

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
		cfg,
		func(ctx context.Context, sess *state.Session) error { return nil },
		func(ctx context.Context, sess *state.Session) {},
	)

	server.handler = func(ctx context.Context, conn net.Conn, listener config.Listener) error {
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
	for i := 0; i < len(cfg); i++ {
		maxRetries := 10
		backoff := 5 * time.Millisecond

		for attempt := 0; attempt < maxRetries; attempt++ {
			conn, err := net.Dial("tcp", "localhost"+cfg[i].BOSListenAddress)
			if err == nil {
				conn.Close()
				break
			}
			if attempt == maxRetries-1 {
				t.Fatalf("Server not ready after %d attempts: %v", maxRetries, err)
			}
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	for i := 0; i < len(cfg); i++ {
		msgWg.Add(1)
		// Connect and send message
		conn, err := net.Dial("tcp", "localhost"+cfg[i].BOSListenAddress)
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
		}
		bodyIn := wire.SNAC_0x17_0x06_BUCPChallengeRequest{}
		assert.NoError(t, flapc.SendSNAC(frame, bodyIn))

		// < receive SNAC_0x17_0x07_BUCPChallengeResponse
		frame = wire.SNACFrame{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &wire.SNAC_0x17_0x07_BUCPChallengeResponse{}))
		assert.Equal(t, wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPChallengeResponse}, frame)

		// > send keep alive frame (like BSFlite does mid-login)
		assert.NoError(t, flapc.SendKeepAliveFrame())

		// > send SNAC_0x17_0x02_BUCPLoginRequest
		frame = wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPLoginRequest,
		}
		assert.NoError(t, flapc.SendSNAC(frame, wire.SNAC_0x17_0x02_BUCPLoginRequest{}))

		// < receive SNAC_0x17_0x03_BUCPLoginResponse
		frame = wire.SNACFrame{}
		assert.NoError(t, flapc.ReceiveSNAC(&frame, &wire.SNAC_0x17_0x03_BUCPLoginResponse{}))
		assert.Equal(t, wire.SNACFrame{FoodGroup: wire.BUCP, SubGroup: wire.BUCPLoginResponse}, frame)
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
		BUCPLogin(matchContext(), mock.Anything, mock.Anything, "localhost:5190").
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.BUCP,
				SubGroup:  wire.BUCPLoginResponse,
			},
			Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{},
		}, nil)

	rt := oscarServer{
		AuthService:   authService,
		Logger:        slog.Default(),
		IPRateLimiter: NewIPRateLimiter(rate.Every(1*time.Minute), 10, 1*time.Minute),
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Listener{BOSAdvertisedHostPlain: "localhost:5190"}))

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
		FLAPLogin(matchContext(), mock.Anything, mock.Anything, "localhost:5190").
		Return(wire.TLVRestBlock{
			TLVList: []wire.TLV{
				wire.NewTLVBE(wire.LoginTLVTagsScreenName, "testuser"),
				wire.NewTLVBE(wire.LoginTLVTagsReconnectHere, "localhost:5190"),
				wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, []byte("auth-cookie")),
			},
		}, nil)

	rt := oscarServer{
		AuthService:   authService,
		Logger:        slog.Default(),
		IPRateLimiter: NewIPRateLimiter(rate.Every(1*time.Minute), 10, 1*time.Minute),
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Listener{BOSAdvertisedHostPlain: "localhost:5190"}))

	wg.Wait()
}

func TestOscarServer_RouteConnection_BOS(t *testing.T) {
	sess := state.NewSession()

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
		assert.NoError(t, clientConn.Close())
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterBOSSession(mock.Anything, state.ServerCookie{Service: wire.BOS}).
		Return(sess, nil)
	wg.Add(1)
	authService.EXPECT().
		Signout(mock.Anything, sess).
		Run(func(ctx context.Context, s *state.Session) {
			defer wg.Done()
		})

	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.BOS}, nil)

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
	handler := func(ctx context.Context, serverType uint16, sess *state.Session, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error {
		defer wg.Done()
		return nil
	}

	rt := oscarServer{
		AuthService:        authService,
		SNACHandler:        handler,
		Logger:             slog.Default(),
		OnlineNotifier:     onlineNotifier,
		BuddyListRegistry:  buddyListRegistry,
		ChatSessionManager: chatSessionManager,
		DepartureNotifier:  departureNotifier,
		recalcWarning: func(ctx context.Context, sess *state.Session) error {
			return nil
		},
		lowerWarnLevel: func(ctx context.Context, sess *state.Session) {
			defer wg.Done()
		},
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Listener{}))

	wg.Wait()
}

// Set up a multi-instance session and connect as the second instance.
//   - Ensure that disconnecting second instance does not sign out the session.
func TestOscarServer_RouteConnection_BOS_MultiSessionSignoff(t *testing.T) {
	sess := state.NewSession()
	sess.AddInstance(state.NewInstance(sess.SessionGroup))

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
		assert.NoError(t, clientConn.Close())
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterBOSSession(mock.Anything, state.ServerCookie{Service: wire.BOS}).
		Return(sess, nil)

	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.BOS}, nil)

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
	chatSessionManager := newMockChatSessionManager(t)

	wg.Add(2)
	handler := func(ctx context.Context, serverType uint16, sess *state.Session, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error {
		defer wg.Done()
		return nil
	}

	rt := oscarServer{
		AuthService:        authService,
		SNACHandler:        handler,
		Logger:             slog.Default(),
		OnlineNotifier:     onlineNotifier,
		BuddyListRegistry:  buddyListRegistry,
		ChatSessionManager: chatSessionManager,
		DepartureNotifier:  departureNotifier,
		recalcWarning: func(ctx context.Context, sess *state.Session) error {
			return nil
		},
		lowerWarnLevel: func(ctx context.Context, sess *state.Session) {
			defer wg.Done()
		},
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Listener{}))

	wg.Wait()
}

func TestOscarServer_RouteConnection_Chat(t *testing.T) {
	sess := state.NewSession()

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
		assert.NoError(t, clientConn.Close())
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		RegisterChatSession(mock.Anything, state.ServerCookie{Service: wire.Chat}).
		Return(sess, nil)
	wg.Add(1)
	authService.EXPECT().
		SignoutChat(mock.Anything, sess).
		Run(func(ctx context.Context, s *state.Session) {
			defer wg.Done()
		})

	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.Chat}, nil)

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
	handler := func(ctx context.Context, serverType uint16, sess *state.Session, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error {
		defer wg.Done()
		return nil
	}

	rt := oscarServer{
		AuthService:        authService,
		SNACHandler:        handler,
		Logger:             slog.Default(),
		OnlineNotifier:     onlineNotifier,
		BuddyListRegistry:  buddyListRegistry,
		ChatSessionManager: chatSessionManager,
		DepartureNotifier:  departureNotifier,
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Listener{}))

	wg.Wait()
}

func TestOscarServer_RouteConnection_Admin(t *testing.T) {
	sess := state.NewSession()

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
		assert.NoError(t, clientConn.Close())
	}()

	wg := &sync.WaitGroup{}

	authService := newMockAuthService(t)
	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.Admin}, nil)
	authService.EXPECT().
		RetrieveBOSSession(mock.Anything, state.ServerCookie{Service: wire.Admin}).
		Return(sess, nil)

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
	handler := func(ctx context.Context, serverType uint16, sess *state.Session, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error {
		defer wg.Done()
		return nil
	}

	rt := oscarServer{
		AuthService:        authService,
		SNACHandler:        handler,
		Logger:             slog.Default(),
		OnlineNotifier:     onlineNotifier,
		BuddyListRegistry:  buddyListRegistry,
		ChatSessionManager: chatSessionManager,
		DepartureNotifier:  departureNotifier,
	}
	assert.NoError(t, rt.routeConnection(context.Background(), clientFake, config.Listener{}))

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
			Logger: slog.Default(),
		}
		sess := state.NewSession()
		sess.SetMultiConnFlag(wire.MultiConnFlagsRecentClient)
		flapc := wire.NewFlapClient(0, serverConn, serverConn)
		err := srv.dispatchIncomingMessages(ctx, wire.BOS, sess, flapc, serverConn, config.Listener{})
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
	sess := state.NewSession()
	sess.SetMultiConnFlag(wire.MultiConnFlagsOldClient)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := oscarServer{
			Logger: slog.Default(),
		}
		flapc := wire.NewFlapClient(0, serverConn, serverConn)
		err := srv.dispatchIncomingMessages(ctx, wire.BOS, sess, flapc, serverConn, config.Listener{})
		assert.NoError(t, err)
	}()

	sess.Close()

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
	sess := state.NewSession()
	sess.SetMultiConnFlag(wire.MultiConnFlagsRecentClient)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv := oscarServer{
			Logger: slog.Default(),
		}
		flapc := wire.NewFlapClient(0, serverConn, serverConn)
		err := srv.dispatchIncomingMessages(ctx, wire.BOS, sess, flapc, serverConn, config.Listener{})
		assert.NoError(t, err)
	}()

	sess.Close()

	flapc := wire.NewFlapClient(0, clientConn, clientConn)
	frame, err := flapc.ReceiveFLAP()
	assert.NoError(t, err)
	assert.Equal(t, wire.FLAPFrameSignoff, frame.FrameType)

	wg.Wait()
}

func Test_oscarServer_receiveSessMessages_BOS_integration(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Prepare session and mocks so we can exercise through routeConnection
	sess := state.NewSession()

	authService := newMockAuthService(t)
	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.BOS}, nil)
	authService.EXPECT().
		RegisterBOSSession(mock.Anything, state.ServerCookie{Service: wire.BOS}).
		Return(sess, nil)

	var signoutWG sync.WaitGroup
	signoutWG.Add(1)
	authService.EXPECT().
		Signout(mock.Anything, sess).
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
		AuthService:        authService,
		BuddyListRegistry:  buddyListRegistry,
		ChatSessionManager: chatSessionManager,
		DepartureNotifier:  departureNotifier,
		OnlineNotifier:     onlineNotifier,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		recalcWarning:      func(ctx context.Context, sess *state.Session) error { return nil },
		lowerWarnLevel:     func(ctx context.Context, sess *state.Session) {},
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
	go func() { doneServer <- server.routeConnection(context.Background(), clientFake, config.Listener{}) }()

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
		status := sess.RelayMessage(msg)
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

	// Close client to let server exit cleanly
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
	defer serverConn.Close()
	defer clientConn.Close()

	// Prepare session and mocks so we can exercise through routeConnection
	sess := state.NewSession()

	authService := newMockAuthService(t)
	authService.EXPECT().
		CrackCookie(mock.Anything).
		Return(state.ServerCookie{Service: wire.Chat}, nil)
	authService.EXPECT().
		RegisterChatSession(mock.Anything, state.ServerCookie{Service: wire.Chat}).
		Return(sess, nil)

	var signoutWG sync.WaitGroup
	signoutWG.Add(1)
	authService.EXPECT().
		SignoutChat(mock.Anything, sess).
		Run(func(ctx context.Context, s *state.Session) { signoutWG.Done() })

	onlineNotifier := newMockOnlineNotifier(t)
	onlineNotifier.EXPECT().
		HostOnline(mock.Anything).
		Return(wire.SNACMessage{
			Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
			Body:  wire.SNAC_0x01_0x03_OServiceHostOnline{},
		})

	server := oscarServer{
		AuthService:    authService,
		OnlineNotifier: onlineNotifier,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	go func() { doneServer <- server.routeConnection(context.Background(), clientFake, config.Listener{}) }()

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
		status := sess.RelayMessage(msg)
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
