package toc

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// errClientReq indicates that an error occurred while reading a client request
	errClientReq = errors.New("failed to read client request")

	// errServerWrite indicates that an error occurred while writing a server response
	errServerWrite = errors.New("failed to send server response")

	// errTOCProcessing indicates that an error occurred in the TOC handler
	errTOCProcessing = errors.New("failed to process TOC request")
)

// bufferedConn is a wrapper around net.Conn that allows peeking into the
// incoming connection without consuming data. It is useful for multiplexing
// TOC/HTTP and TOC/FLAP connections.
//
// It embeds net.Conn, so all standard connection methods remain available.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

// newBufferedConn wraps a net.Conn with buffered reading capabilities.
func newBufferedConn(c net.Conn) bufferedConn {
	return bufferedConn{bufio.NewReader(c), c}
}

// Peek returns the next n bytes from the buffer without advancing the reader.
// If fewer than n bytes are available, it returns an error.
func (b bufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

// Read reads data into p from the buffered connection.
// It prioritizes buffered data before reading from the underlying connection.
func (b bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// channelListener is an implementation of net.Listener that accepts connections
// from a channel instead of a network socket. It is useful for attaching an
// HTTP service to a connection on the fly.
type channelListener struct {
	ch  chan net.Conn // Channel used to receive connections.
	ctx context.Context
}

// Accept waits for and returns the next connection from the channel.
// If the channel is closed, it returns io.EOF to indicate no more connections.
func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, io.EOF
	case ch := <-l.ch:
		return ch, nil
	}
}

// Close closes the listener. Since channelListener does not manage an actual
// network connection, this is a no-op and always returns nil.
func (l *channelListener) Close() error {
	return nil
}

// Addr returns the network address of the listener.
// Since channelListener is not bound to a real network address, it returns nil.
func (l *channelListener) Addr() net.Addr {
	return nil
}

// IPRateLimiter provides per-IP rate limiting using a token bucket algorithm.
// It caches individual rate limiters per IP address with automatic TTL expiration.
type IPRateLimiter struct {
	cache *cache.Cache // In-memory cache of rate limiters keyed by IP
	rate  rate.Limit   // Allowed request rate (events per second)
	burst int          // Maximum burst size
}

// NewIPRateLimiter returns a new IPRateLimiter that limits each IP to the specified
// rate and burst, with limiter state expiring after the given TTL.
// Entries are retained for up to 2×TTL to reduce churn under frequent lookups.
func NewIPRateLimiter(rate rate.Limit, burst int, ttl time.Duration) *IPRateLimiter {
	return &IPRateLimiter{
		cache: cache.New(ttl, 2*ttl),
		rate:  rate,
		burst: burst,
	}
}

// Allow returns true if the request from the given IP is allowed under its rate limit.
// If no limiter exists for the IP, one is created and tracked in the cache.
func (l *IPRateLimiter) Allow(ip string) (allowed bool) {
	limiter, found := l.cache.Get(ip)
	if !found {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.cache.Set(ip, limiter, cache.DefaultExpiration)
	}
	return limiter.(*rate.Limiter).Allow()
}

func NewServer(
	listenerCfg []string,
	logger *slog.Logger,
	BOSProxy OSCARProxy,
	ipRateLimiter *IPRateLimiter,
	recalcWarning func(ctx context.Context, instance *state.SessionInstance) error,
	lowerWarnLevel func(ctx context.Context, instance *state.SessionInstance),
) *Server {

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		bosProxy:           BOSProxy,
		conns:              make(map[net.Conn]struct{}),
		listenerCfg:        listenerCfg,
		logger:             logger,
		loginIPRateLimiter: ipRateLimiter,
		recalcWarning:      recalcWarning,
		lowerWarnLevel:     lowerWarnLevel,
		servers:            make([]*http.Server, 0, len(listenerCfg)),
		shutdownCancel:     cancel,
		shutdownCtx:        ctx,
	}

	for range listenerCfg {
		s.servers = append(s.servers, &http.Server{
			Handler: BOSProxy.NewServeMux(),
			BaseContext: func(net.Listener) context.Context {
				return s.shutdownCtx
			},
		})
	}

	return s
}

// Server implements a TOC protocol server that multiplexes TOC/HTTP and
// TOC/FLAP requests. It acts as a gateway, forwarding all TOC requests
// to the OSCAR server for processing.
type Server struct {
	bosProxy           OSCARProxy
	logger             *slog.Logger
	loginIPRateLimiter *IPRateLimiter
	recalcWarning      func(ctx context.Context, instance *state.SessionInstance) error
	lowerWarnLevel     func(ctx context.Context, instance *state.SessionInstance)

	listenerCfg []string
	listeners   []net.Listener
	servers     []*http.Server

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	connWg   sync.WaitGroup
	listenWg sync.WaitGroup

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func (s *Server) ListenAndServe() error {
	g, ctx := errgroup.WithContext(s.shutdownCtx)

	for i, cfg := range s.listenerCfg {
		ln, err := net.Listen("tcp", cfg)
		if err != nil {
			s.cleanupListeners()
			s.shutdownCancel()
			return fmt.Errorf("unable to start TOC server: %w", err)
		}

		s.logger.InfoContext(ctx, "starting server", "listen_host", cfg)

		s.listeners = append(s.listeners, ln)
		s.listenWg.Add(1)

		httpCh := make(chan net.Conn)

		g.Go(func() error {
			cl := &channelListener{
				ch:  httpCh,
				ctx: s.shutdownCtx,
			}
			if err := s.servers[i].Serve(cl); !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, io.EOF) {
				s.shutdownCancel()
				return err
			}
			return nil
		})

		g.Go(func() error {
			s.acceptLoop(ctx, ln, httpCh)
			return nil
		})
	}

	return g.Wait()
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

	for _, srv := range s.servers {
		_ = srv.Shutdown(ctx)
	}

	select {
	case <-done:
		s.logger.Info("shutdown complete")
	case <-ctx.Done():
		s.logger.Info("shutdown complete, but connections didn't close cleanly")
	}

	return nil
}

func (s *Server) cleanupListeners() {
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, httpCh chan net.Conn) {
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

		go func() {
			if err := s.handleConnection(conn, ctx, httpCh); err != nil {
				s.logger.InfoContext(ctx, "user session failed", "err", err.Error())
			}
		}()
	}
}

// handleConnection inspects and routes an incoming connection. If the connection
// starts with "FLAP", handle as TOC/FLAP; otherwise, dispatch for HTTP
// processing.
func (s *Server) handleConnection(conn net.Conn, ctx context.Context, httpCh chan net.Conn) error {
	bufCon := newBufferedConn(conn)

	doFlap := "FLAP"
	buf, err := bufCon.Peek(len(doFlap))
	if err != nil {
		return fmt.Errorf("bufCon.Peek: %w", err)
	}

	// handle TOC/FLAP
	if string(buf) == doFlap {
		defer func() {
			// untrack connections
			s.connMu.Lock()
			delete(s.conns, conn)
			s.connMu.Unlock()

			_ = conn.Close()
			s.connWg.Done()
		}()

		// track connection
		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.connMu.Unlock()

		s.connWg.Add(1)

		if err = s.dispatchFLAP(ctx, bufCon); err != nil {
			switch {
			case errors.Is(err, io.EOF):
			case errors.Is(err, net.ErrClosed):
			case errors.Is(err, syscall.ECONNRESET):
				return nil
			default:
				return fmt.Errorf("s.dispatchFLAP: %w", err)
			}
		}
		return nil
	}

	// handle TOC/HTTP
	select {
	case httpCh <- bufCon:
		return nil
	case <-ctx.Done():
		return nil
	}
}

func (s *Server) dispatchFLAP(ctx context.Context, conn net.Conn) error {
	var once sync.Once

	closeConn := func() {
		once.Do(func() {
			_ = conn.Close()
		})
	}
	defer closeConn()

	ctx = context.WithValue(ctx, "ip", conn.RemoteAddr().String())

	clientFlap, err := s.initFLAP(conn)
	if err != nil {
		return err
	}

	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		s.logger.Error("failed to parse remote address", "err", err.Error())
		return err
	}

	if ok := s.loginIPRateLimiter.Allow(ip); !ok {
		if err := clientFlap.SendDataFrame([]byte("ERROR:983")); err != nil {
			return fmt.Errorf("clientFlap.SendDataFrame: %w", err)
		}
		return nil
	}

	sessBOS, err := s.login(ctx, clientFlap)
	if err != nil {
		return fmt.Errorf("s.login: %w", err)
	}
	if sessBOS == nil {
		return nil // user not found
	}

	ctx = context.WithValue(ctx, "screenName", sessBOS.IdentScreenName())

	remoteAddr, ok := ctx.Value("ip").(string)
	if ok {
		ip, err := netip.ParseAddrPort(remoteAddr)
		if err != nil {
			return errors.New("unable to parse ip addr")
		}
		sessBOS.SetRemoteAddr(&ip)
	}

	chatRegistry := NewChatRegistry()

	return s.handleTOCRequest(ctx, closeConn, sessBOS, chatRegistry, clientFlap)
}

// handleTOCRequest processes incoming TOC requests and coordinates their handling.
// It reads client requests, processes TOC commands, and sends responses back to the client.
//
// Returns:
//   - errClientReq if an error occurs while reading the TOC request. wraps
//     io.EOF if the client disconnected.
//   - errTOCProcessing if an error occurs while processing the TOC command.
//   - errServerWrite if an error occurs while sending the TOC response.
func (s *Server) handleTOCRequest(
	ctx context.Context,
	closeConn func(),
	sessBOS *state.SessionInstance,
	chatRegistry *ChatRegistry,
	clientFlap *wire.FlapClient,
) error {
	if err := s.recalcWarning(ctx, sessBOS); err != nil {
		return fmt.Errorf("failed to recalculate warning level: %w", err)
	}

	// TOC response queue
	msgCh := make(chan []byte, 1)

	g, ctx := errgroup.WithContext(ctx)

	// process TOC client requests and enqueue TOC server responses
	g.Go(func() error {
		err := s.runClientCommands(ctx, g.Go, sessBOS, chatRegistry, clientFlap, msgCh)
		return errors.Join(err, errClientReq)
	})

	// translate OSCAR server responses to TOC responses and enqueue them
	g.Go(func() error {
		err := s.bosProxy.RecvBOS(ctx, sessBOS, chatRegistry, msgCh)
		closeConn() // unblock runClientCommands
		return errors.Join(err, errTOCProcessing)
	})

	// send TOC server responses to the client
	g.Go(func() error {
		err := s.sendToClient(ctx, msgCh, clientFlap)
		closeConn() // unblock runClientCommands
		return errors.Join(err, errServerWrite)
	})

	// process warning limits
	g.Go(func() error {
		s.lowerWarnLevel(ctx, sessBOS)
		return nil
	})

	return g.Wait()
}

func (s *Server) runClientCommands(ctx context.Context, doAsync func(f func() error), sessBOS *state.SessionInstance, chatRegistry *ChatRegistry, clientFlap *wire.FlapClient, toCh chan<- []byte) error {
	for {
		clientFrame, err := clientFlap.ReceiveFLAP()
		if err != nil {
			return err
		}
		switch clientFrame.FrameType {
		case wire.FLAPFrameSignoff:
			return io.EOF // client disconnected
		case wire.FLAPFrameKeepAlive:
			// keep alive heartbeat, do nothing for now.
			// todo set connection deadline to future time
		case wire.FLAPFrameData:
			clientFrame.Payload = bytes.TrimRight(clientFrame.Payload, "\x00") // trim null terminator

			if len(clientFrame.Payload) == 0 {
				return errors.New("TOC command is empty")
			}
			if len(clientFrame.Payload) > 2048 {
				return errors.New("TOC command exceeds maximum length (2048)")
			}

			msg := s.bosProxy.RecvClientCmd(ctx, sessBOS, chatRegistry, clientFrame.Payload, toCh, doAsync)
			if len(msg) > 0 {
				select {
				case toCh <- []byte(msg):
				case <-ctx.Done():
					return nil
				}
			}
		default:
			return fmt.Errorf("unexpected clientFlap clientFrame type %d", clientFrame.FrameType)
		}
	}
}

func (s *Server) sendToClient(ctx context.Context, toClient <-chan []byte, clientFlap *wire.FlapClient) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg := <-toClient:
			if err := clientFlap.SendDataFrame(msg); err != nil {
				return fmt.Errorf("clientFlap.SendDataFrame: %w", err)
			}
			if s.logger.Enabled(ctx, slog.LevelDebug) {
				s.logger.DebugContext(ctx, "server response", "command", msg)
			} else {
				// just log the command, omit params
				idx := len(msg)
				if col := bytes.IndexByte(msg, ':'); col > -1 {
					idx = col
				}
				s.logger.InfoContext(ctx, "server response", "command", msg[0:idx])
			}
		}
	}
}

func (s *Server) login(ctx context.Context, clientFlap *wire.FlapClient) (*state.SessionInstance, error) {
	clientFrame, err := clientFlap.ReceiveFLAP()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("clientFlap.ReceiveFLAP: %w", err)
	}

	cmd := clientFrame.Payload
	var args []byte

	if idx := bytes.IndexByte(clientFrame.Payload, ' '); idx > -1 {
		cmd, args = clientFrame.Payload[:idx], clientFrame.Payload[idx:]
	}
	if string(cmd) != "toc_signon" {
		return nil, errors.New("expected toc_signon")
	}

	sessBOS, reply := s.bosProxy.Signon(ctx, args)
	for _, m := range reply {
		if err := clientFlap.SendDataFrame([]byte(m)); err != nil {
			return nil, fmt.Errorf("clientFlap.SendDataFrame: %w", err)
		}
	}

	return sessBOS, nil
}

// initFLAP sets up a new FLAP connection. It returns a flap client if the
// connection successfully initialized.
func (s *Server) initFLAP(rw io.ReadWriter) (*wire.FlapClient, error) {
	expected := "FLAPON\r\n\r\n"
	buf := make([]byte, len(expected))

	_, err := io.ReadFull(rw, buf)
	if err != nil {
		return nil, fmt.Errorf("io.ReadFull: %w", err)
	}
	if expected != string(buf) {
		return nil, fmt.Errorf("expected FLAPON, got %s", buf)
	}

	clientFlap := wire.NewFlapClient(0, rw, rw)

	if err := clientFlap.SendSignonFrame(nil); err != nil {
		return nil, fmt.Errorf("clientFlap.SendSignonFrame: %w", err)
	}
	if _, err := clientFlap.ReceiveSignonFrame(); err != nil {
		return nil, fmt.Errorf("clientFlap.ReceiveSignonFrame: %w", err)
	}

	return clientFlap, nil
}
