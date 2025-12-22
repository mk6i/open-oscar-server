package oscar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/oscar/middleware"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func NewServer(
	authService AuthService,
	buddyListRegistry BuddyListRegistry,
	chatSessionManager *state.InMemoryChatSessionManager,
	departureNotifier DepartureNotifier,
	logger *slog.Logger,
	onlineNotifier OnlineNotifier,
	SNACHandler func(ctx context.Context, serverType uint16, sess *state.Session, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error,
	rateLimitUpdater RateLimitUpdater,
	limits wire.SNACRateLimits,
	limiter *IPRateLimiter,
	listenerCfg []config.Listener,
	recalcWarning func(ctx context.Context, sess *state.Session) error,
	lowerWarnLevel func(ctx context.Context, sess *state.Session),
) *Server {
	oscarSvc := oscarServer{
		AuthService:        authService,
		BuddyListRegistry:  buddyListRegistry,
		ChatSessionManager: chatSessionManager,
		DepartureNotifier:  departureNotifier,
		Logger:             logger,
		OnlineNotifier:     onlineNotifier,
		SNACHandler:        SNACHandler,
		RateLimitUpdater:   rateLimitUpdater,
		SNACRateLimits:     limits,
		IPRateLimiter:      limiter,
		recalcWarning:      recalcWarning,
		lowerWarnLevel:     lowerWarnLevel,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		closed:         make(chan struct{}),
		conns:          make(map[net.Conn]struct{}),
		handler:        oscarSvc.routeConnection,
		listenerCfg:    listenerCfg,
		logger:         logger,
		shutdownCancel: cancel,
		shutdownCtx:    ctx,
	}
}

type Server struct {
	logger *slog.Logger

	listenerCfg []config.Listener
	listeners   []net.Listener

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	connWg   sync.WaitGroup
	listenWg sync.WaitGroup

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	closed         chan struct{}

	handler func(ctx context.Context, conn net.Conn, listener config.Listener) error
}

func (s *Server) ListenAndServe() error {
	for _, listenCfg := range s.listenerCfg {
		ln, err := net.Listen("tcp", listenCfg.BOSListenAddress)
		if err != nil {
			s.cleanupListeners()
			s.shutdownCancel()
			return fmt.Errorf("failed to listen on %s: %w", listenCfg.BOSListenAddress, err)
		}

		args := []any{
			"listen_address", listenCfg.BOSListenAddress,
			"advertised_host_plain", listenCfg.BOSAdvertisedHostPlain,
		}
		if listenCfg.HasSSL {
			args = append(args, "advertised_host_ssl", listenCfg.BOSAdvertisedHostSSL)
		}
		s.logger.Info("starting server", args...)

		s.listeners = append(s.listeners, ln)
		s.listenWg.Add(1)
		go s.acceptLoop(ln, listenCfg)
	}

	<-s.closed // block until Shutdown is called
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Debug("Initiating graceful shutdown...")
	s.shutdownCancel()
	s.cleanupListeners()

	// Wait for handlers to complete
	done := make(chan struct{})
	go func() {
		s.connWg.Wait()
		s.listenWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("shutdown complete")
	case <-ctx.Done():
		s.logger.Info("shutdown complete, but connections didn't close cleanly")
	}

	close(s.closed)

	return nil
}

func (s *Server) acceptLoop(ln net.Listener, listener config.Listener) {
	defer s.listenWg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("accept error", "err", err.Error())
			continue
		}

		// track connection
		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.connMu.Unlock()

		s.connWg.Add(1)
		go s.handleConnection(s.shutdownCtx, conn, listener)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn, listener config.Listener) {
	defer func() {
		// untrack connections
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()

		_ = conn.Close()
		s.connWg.Done()
	}()
	if err := s.handler(ctx, conn, listener); err != nil {
		s.logger.InfoContext(ctx, "user session failed", "err", err.Error())
	}
}

func (s *Server) cleanupListeners() {
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
}

type oscarServer struct {
	AuthService
	BuddyListRegistry
	ChatSessionManager
	DepartureNotifier
	Logger *slog.Logger
	OnlineNotifier
	SNACHandler func(ctx context.Context, serverType uint16, sess *state.Session, inFrame wire.SNACFrame, r io.Reader, rw ResponseWriter, listener config.Listener) error
	RateLimitUpdater
	wire.SNACRateLimits
	*IPRateLimiter
	recalcWarning  func(ctx context.Context, sess *state.Session) error
	lowerWarnLevel func(ctx context.Context, sess *state.Session)
}

func (s oscarServer) routeConnection(ctx context.Context, conn net.Conn, listener config.Listener) error {
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		s.Logger.Error("failed to parse remote address", "err", err.Error())
		return err
	}

	flapc := wire.NewFlapClient(100, conn, conn)

	if err := flapc.SendSignonFrame(nil); err != nil {
		return err
	}
	flap, err := flapc.ReceiveSignonFrame()
	if err != nil {
		return err
	}

	if flap.HasTag(wire.OServiceTLVTagsLoginCookie) {
		return s.connectToOSCARService(ctx, flap, flapc, conn, listener)
	}

	return s.authenticate(ctx, flap, ip, conn, flapc, listener.BOSAdvertisedHostPlain)
}

func (s oscarServer) connectToOSCARService(
	ctx context.Context,
	flap wire.FLAPSignonFrame,
	flapc *wire.FlapClient,
	conn net.Conn,
	listener config.Listener,
) error {
	authCookie, ok := flap.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !ok {
		return errors.New("unable to get session id from payload")
	}

	cookie, err := s.CrackCookie(authCookie)
	if err != nil {
		return err
	}

	s.Logger.Debug("connecting to service", "service", wire.FoodGroupName(cookie.Service))

	var sess *state.Session
	switch cookie.Service {
	case wire.BOS:
		sess, err = s.AuthService.RegisterBOSSession(ctx, cookie)
		if err != nil {
			return err
		}
		if sess == nil {
			return errors.New("session not found")
		}

		if err := s.BuddyListRegistry.RegisterBuddyList(ctx, sess.IdentScreenName()); err != nil {
			return fmt.Errorf("unable to init buddy list: %w", err)
		}

		defer func() {
			sess.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := s.DepartureNotifier.BroadcastBuddyDeparted(ctx, sess); err != nil {
				s.Logger.ErrorContext(ctx, "error sending buddy departure notifications", "err", err.Error())
			}
			// buddy list must be cleared before session is closed, otherwise
			// there will be a race condition that could cause the buddy list
			// be prematurely deleted.
			if err := s.BuddyListRegistry.UnregisterBuddyList(ctx, sess.IdentScreenName()); err != nil {
				s.Logger.ErrorContext(ctx, "error removing buddy list entry", "err", err.Error())
			}
			s.ChatSessionManager.RemoveUserFromAllChats(sess.IdentScreenName())
			s.Signout(ctx, sess)
		}()
		remoteAddr, ok := ctx.Value("ip").(string)
		if ok {
			ip, err := netip.ParseAddrPort(remoteAddr)
			if err != nil {
				return errors.New("unable to parse ip addr")
			}
			sess.SetRemoteAddr(&ip)
		}

		if err := s.recalcWarning(ctx, sess); err != nil {
			return fmt.Errorf("failed to recalculate warning level: %w", err)
		}
		go s.lowerWarnLevel(ctx, sess)
		go s.receiveSessMessages(ctx, sess, flapc)

	case wire.Chat:
		sess, err = s.AuthService.RegisterChatSession(ctx, cookie)
		if err != nil {
			return err
		}
		if sess == nil {
			return errors.New("session not found")
		}

		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s.SignoutChat(ctx, sess)
		}()

		go s.receiveSessMessages(ctx, sess, flapc)
	default:
		sess, err = s.AuthService.RetrieveBOSSession(ctx, cookie)
		if err != nil {
			return err
		}
		if sess == nil {
			return errors.New("session not found")
		}
	}

	ctx = context.WithValue(ctx, "screenName", sess.IdentScreenName())

	msg := s.OnlineNotifier.HostOnline(cookie.Service)
	if err := flapc.SendSNAC(msg.Frame, msg.Body); err != nil {
		return err
	}

	return s.dispatchIncomingMessages(ctx, cookie.Service, sess, flapc, conn, listener)
}

func (s oscarServer) receiveSessMessages(ctx context.Context, sess *state.Session, flapc *wire.FlapClient) {
	for {
		select {
		case <-sess.Closed():
			return
		case <-ctx.Done():
			return
		case m := <-sess.ReceiveMessage():
			// forward a notification sent from another client to this client
			if err := flapc.SendSNAC(m.Frame, m.Body); err != nil {
				middleware.LogRequestError(ctx, s.Logger, m.Frame, err)
			} else {
				middleware.LogRequest(ctx, s.Logger, m.Frame, m.Body)
			}
		}
	}
}

func (s oscarServer) authenticate(
	ctx context.Context,
	flap wire.FLAPSignonFrame,
	ip string,
	conn net.Conn,
	flapc *wire.FlapClient,
	advertisedHost string,
) error {
	if ok, isBUCP := s.Allow(ip); !ok {
		s.Logger.Error("user rate limited at login", "remote", ip)
		tlv := wire.TLVRestBlock{
			TLVList: []wire.TLV{
				wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, wire.LoginErrRateLimitExceeded),
			},
		}
		// gives wrong response if you quickly switch between BUCP/FLAP clients
		if isBUCP {
			return flapc.SendSNAC(
				wire.SNACFrame{
					FoodGroup: wire.BUCP,
					SubGroup:  wire.BUCPLoginResponse,
				},
				wire.SNAC_0x17_0x03_BUCPLoginResponse{
					TLVRestBlock: tlv,
				},
			)
		} else {
			return flapc.NewSignoff(tlv)
		}
	}

	// auth must complete within the next 30 seconds
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return fmt.Errorf("failed to set deadline: %w", err)
	}

	// decide whether the client is using BUCP or FLAP authentication based on
	// the presence of the screen name TLV. this block used to check for the
	// presence of the roasted password TLV, however that proved an unreliable
	// indicator of FLAP-auth because older ICQ clients appear to omit the
	// roasted password TLV when the password is not stored client-side.
	if _, hasScreenName := flap.Uint16BE(wire.LoginTLVTagsScreenName); hasScreenName {
		return s.processFLAPAuth(ctx, flap, flapc, advertisedHost)
	}

	s.SetBUCP(ip)

	return s.processBUCPAuth(ctx, flapc, advertisedHost)
}

func (s oscarServer) processFLAPAuth(
	ctx context.Context,
	signonFrame wire.FLAPSignonFrame,
	flapc *wire.FlapClient,
	advertisedHost string,
) error {
	tlv, err := s.AuthService.FLAPLogin(ctx, signonFrame, state.NewStubUser, advertisedHost)
	if err != nil {
		return err
	}
	return flapc.NewSignoff(tlv)
}

func (s oscarServer) processBUCPAuth(ctx context.Context, flapc *wire.FlapClient, advertisedHost string) error {
	frames := 0

	for {
		frame, err := flapc.ReceiveFLAP()
		if err != nil {
			return err
		}

		if frames > 10 {
			// a lot of frames received, the client is misbehaving
			return fmt.Errorf("too many auth flap packets received")
		}
		frames++

		switch frame.FrameType {
		case wire.FLAPFrameSignoff:
			s.Logger.Debug("signed off mid-login")
			return io.EOF // client disconnected
		case wire.FLAPFrameKeepAlive:
			s.Logger.Debug("received flap keepalive frame")
		case wire.FLAPFrameData:
			buf := bytes.NewReader(frame.Payload)
			fr := wire.SNACFrame{}
			if err := wire.UnmarshalBE(&fr, buf); err != nil {
				return err
			}
			switch {
			case fr.FoodGroup == wire.BUCP && fr.SubGroup == wire.BUCPChallengeRequest:
				challengeRequest := wire.SNAC_0x17_0x06_BUCPChallengeRequest{}
				if err := wire.UnmarshalBE(&challengeRequest, buf); err != nil {
					return err
				}
				outSNAC, err := s.BUCPChallenge(ctx, challengeRequest, uuid.New)
				if err != nil {
					return err
				}
				if err := flapc.SendSNAC(outSNAC.Frame, outSNAC.Body); err != nil {
					return err
				}

				if outSNAC.Frame.SubGroup == wire.BUCPLoginResponse {
					screenName, _ := challengeRequest.String(wire.LoginTLVTagsScreenName)
					s.Logger.Debug("failed BUCP challenge: user does not exist", "screen_name", screenName)
					return nil // account does not exist
				}
			case fr.FoodGroup == wire.BUCP && fr.SubGroup == wire.BUCPLoginRequest:
				loginRequest := wire.SNAC_0x17_0x02_BUCPLoginRequest{}
				if err := wire.UnmarshalBE(&loginRequest, buf); err != nil {
					return err
				}
				outSNAC, err := s.BUCPLogin(ctx, loginRequest, state.NewStubUser, advertisedHost)
				if err != nil {
					return err
				}

				return flapc.SendSNAC(outSNAC.Frame, outSNAC.Body)
			default:
				s.Logger.Debug("unexpected SNAC received during login",
					"foodgroup", wire.FoodGroupName(fr.FoodGroup),
					"subgroup", wire.SubGroupName(fr.FoodGroup, fr.SubGroup))
				return io.EOF
			}
		default:
			s.Logger.Debug("unexpected frame type received during login", "type", frame.FrameType)
			return io.EOF
		}
	}
}

func sendInvalidSNACErr(frameIn wire.SNACFrame, rw ResponseWriter) error {
	frameOut := wire.SNACFrame{
		FoodGroup: frameIn.FoodGroup,
		SubGroup:  0x01, // error subgroup for all SNACs
		RequestID: frameIn.RequestID,
	}
	bodyOut := wire.SNACError{
		Code: wire.ErrorCodeInvalidSnac,
	}
	return rw.SendSNAC(frameOut, bodyOut)
}

// dispatchIncomingMessages receives incoming messages and sends them to the
// appropriate message handler. Messages from the client are sent to the
// router. Messages relayed from the user session are forwarded to the client.
// This function ensures that the same sequence number is incremented for both
// types of messages. The function terminates upon receiving a connection error
// or when the session closes.
func (s oscarServer) dispatchIncomingMessages(
	ctx context.Context,
	fg uint16,
	sess *state.Session,
	flapc *wire.FlapClient,
	r io.ReadCloser,
	listener config.Listener,
) error {
	defer func() {
		s.Logger.InfoContext(ctx, "user disconnected")
	}()

	// buffered so that the go routine has room to exit
	msgCh := make(chan wire.FLAPFrame, 1)
	errCh := make(chan error, 1)

	// consume flap frames
	go func() {
		defer close(msgCh)
		defer close(errCh)

		for {
			frame := wire.FLAPFrame{}
			if err := wire.UnmarshalBE(&frame, r); err != nil {
				errCh <- err
				return
			}
			msgCh <- frame
		}
	}()

	for {
		select {
		case flap, ok := <-msgCh:
			if !ok {
				return nil
			}
			switch flap.FrameType {
			case wire.FLAPFrameData:
				flapBuf := bytes.NewBuffer(flap.Payload)

				inFrame := wire.SNACFrame{}
				if err := wire.UnmarshalBE(&inFrame, flapBuf); err != nil {
					return err
				}

				rateClassID, ok := s.SNACRateLimits.RateClassLookup(inFrame.FoodGroup, inFrame.SubGroup)
				if ok {
					if status := sess.EvaluateRateLimit(time.Now(), rateClassID); status == wire.RateLimitStatusLimited {
						s.Logger.DebugContext(ctx, "rate limit exceeded, dropping SNAC",
							"foodgroup", wire.FoodGroupName(inFrame.FoodGroup),
							"subgroup", wire.SubGroupName(inFrame.FoodGroup, inFrame.SubGroup))
						break
					}
				} else {
					s.Logger.ErrorContext(ctx, "rate limit not found, allowing request through")
				}

				// route a client request to the appropriate service handler. the
				// handler may write a response to the client connection.
				if err := s.SNACHandler(ctx, fg, sess, inFrame, flapBuf, flapc, listener); err != nil {
					middleware.LogRequestError(ctx, s.Logger, inFrame, err)
					if errors.Is(err, ErrRouteNotFound) {
						if err1 := sendInvalidSNACErr(inFrame, flapc); err1 != nil {
							return errors.Join(err1, err)
						}
						break
					}
					return err
				}
			case wire.FLAPFrameSignon:
				return fmt.Errorf("shouldn't get FLAPFrameSignon. flap: %v", flap)
			case wire.FLAPFrameError:
				return fmt.Errorf("got FLAPFrameError. flap: %v", flap)
			case wire.FLAPFrameSignoff:
				s.Logger.InfoContext(ctx, "got FLAPFrameSignoff", "flap", flap)
				return nil
			case wire.FLAPFrameKeepAlive:
				s.Logger.DebugContext(ctx, "keepalive heartbeat")
			default:
				return fmt.Errorf("got unknown FLAP frame type. flap: %v", flap)
			}
		case <-time.After(1 * time.Second):
			updates := s.RateLimitUpdater.RateLimitUpdates(ctx, sess, time.Now())
			for _, update := range updates {
				if err := flapc.SendSNAC(update.Frame, update.Body); err != nil {
					middleware.LogRequestError(ctx, s.Logger, update.Frame, err)
					return err
				}
			}
		case <-sess.Closed():
			// add logoff reason to clients that support multi-conn
			if sess.MultiConnFlag() == wire.MultiConnFlagsOldClient {
				if err := flapc.OldSignoff(); err != nil {
					return fmt.Errorf("unable to gracefully disconnect user. %w", err)
				}
			} else {
				block := wire.TLVRestBlock{}
				// error code indicating user signed in a different location
				block.Append(wire.NewTLVBE(0x0009, wire.OServiceDiscErrNewLogin))
				// "more info" button
				block.Append(wire.NewTLVBE(0x000b, "https://github.com/mk6i/open-oscar-server"))
				if err := flapc.NewSignoff(block); err != nil {
					return fmt.Errorf("unable to gracefully disconnect user. %w", err)
				}
			}
			return nil
		case <-ctx.Done():
			if sess.MultiConnFlag() == wire.MultiConnFlagsOldClient {
				if err := flapc.OldSignoff(); err != nil {
					return fmt.Errorf("unable to gracefully disconnect user. %w", err)
				}
			} else {
				if err := flapc.NewSignoff(wire.TLVRestBlock{}); err != nil {
					return fmt.Errorf("unable to gracefully disconnect user. %w", err)
				}
			}
			return nil
		case err := <-errCh:
			if !errors.Is(io.EOF, err) {
				s.Logger.ErrorContext(ctx, "client disconnected with error", "err", err)
			}
			return nil
		}
	}
}

// IPRateLimiter enforces a per-IP rate limit using a token bucket algorithm.
// It caches individual rate limiters by IP address and supports tagging requests
// as originating from the BUCP or FLAP auth.
//
// The limiter uses an in-memory cache with TTL expiration, so rate limits reset
// after the TTL if no activity is observed for a given IP.
type IPRateLimiter struct {
	cache *cache.Cache // In-memory cache mapping IPs to rate limiters with optional BUCP tag
	rate  rate.Limit   // Requests allowed per second
	burst int          // Maximum burst size allowed
}

type rateLimitEntry struct {
	isBUCP  bool
	limiter *rate.Limiter
}

// NewIPRateLimiter initializes a new IPRateLimiter with the specified rate,
// burst size, and TTL for each IP's limiter. Entries expire after 2×TTL.
func NewIPRateLimiter(rate rate.Limit, burst int, ttl time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		cache: cache.New(ttl, 2*ttl),
		rate:  rate,
		burst: burst,
	}
}

// SetBUCP marks the rate limiter for the given IP as originating from BUCP auth
// (default FLAP auth).
func (l *IPRateLimiter) SetBUCP(ip string) {
	limiter, found := l.cache.Get(ip)
	if !found {
		limiter = &rateLimitEntry{
			isBUCP:  true,
			limiter: rate.NewLimiter(l.rate, l.burst),
		}
		l.cache.Set(ip, limiter, cache.DefaultExpiration)
	}
	limiter.(*rateLimitEntry).isBUCP = true
}

// Allow checks if a request from the given IP is allowed under its rate limit.
// It returns whether the request is allowed and whether the connection uses
// BUCP auth.
func (l *IPRateLimiter) Allow(ip string) (allowed bool, isBUCP bool) {
	limiter, found := l.cache.Get(ip)
	if !found {
		limiter = &rateLimitEntry{
			limiter: rate.NewLimiter(l.rate, l.burst),
		}
		l.cache.Set(ip, limiter, cache.DefaultExpiration)
	}
	entry := limiter.(*rateLimitEntry)
	return entry.limiter.Allow(), entry.isBUCP
}
