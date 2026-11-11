// Package relay carries Direct IM and file transfers through the server, for
// clients that can't reach each other directly.
package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

const (
	// acceptTimeout bounds the wait for the recipient. Its user may be
	// looking at an accept prompt.
	acceptTimeout = 5 * time.Minute
	// offererTimeout bounds the wait for an offerer sent a counter-offer. It
	// dials without asking anyone.
	offererTimeout = 30 * time.Second
	// evenWriteWait bounds how long copyEven holds a byte back waiting for the
	// next one.
	evenWriteWait = 100 * time.Millisecond
	// flapStartMarker is the first byte of every FLAP frame.
	flapStartMarker = 0x2A
)

// NewServer creates a relay server that listens on endpointCfg and writes
// advertisedIP and advertisedPort into the offers it relays.
func NewServer(
	endpointCfg []string,
	advertisedIP netip.Addr,
	advertisedPort uint16,
	logger *slog.Logger,
	sessionRetriever SessionRetriever,
) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		acceptTimeout:    acceptTimeout,
		advertisedIP:     advertisedIP,
		advertisedPort:   advertisedPort,
		closed:           make(chan struct{}),
		conns:            make(map[net.Conn]struct{}),
		endpointCfg:      endpointCfg,
		logger:           logger,
		offererTimeout:   offererTimeout,
		registry:         newRegistry(),
		sessionRetriever: sessionRetriever,
		shutdownCancel:   cancel,
		shutdownCtx:      ctx,
	}
}

type Server struct {
	acceptTimeout    time.Duration
	advertisedIP     netip.Addr
	advertisedPort   uint16
	endpointCfg      []string
	logger           *slog.Logger
	offererTimeout   time.Duration
	registry         *registry
	sessionRetriever SessionRetriever

	listeners []net.Listener

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	connWg   sync.WaitGroup
	listenWg sync.WaitGroup

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	closed         chan struct{}
}

func (s *Server) ListenAndServe() error {
	for _, addr := range s.endpointCfg {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			s.cleanupListeners()
			s.shutdownCancel()
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
		s.logger.Info("starting server",
			"listen_address", addr,
			"advertised_ip", s.advertisedIP.String(),
			"advertised_port", s.advertisedPort)
		s.listeners = append(s.listeners, ln)
		s.listenWg.Add(1)
		go s.acceptLoop(ln)
	}

	<-s.closed // block until Shutdown is called
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.connMu.Lock()
	s.shutdownCancel()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.connMu.Unlock()
	s.cleanupListeners()

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

// Route returns the relay for a connection on the OSCAR port that the server
// expects from that address, or nil to leave it to OSCAR. OSCAR clients wait
// for a hello, so silence only counts once the client was told to dial.
func (s *Server) Route(first []byte, remote net.Addr) func(conn net.Conn) {
	if len(first) > 0 && first[0] == flapStartMarker {
		return nil
	}
	ip, ok := remoteIP(remote)
	if !ok || s.registry.find(ip, len(first) == 0) == nil {
		return nil
	}
	return func(conn net.Conn) {
		if !s.trackConn(conn) {
			_ = conn.Close()
			return
		}
		s.handleConnection(conn)
	}
}

func remoteIP(addr net.Addr) (netip.Addr, bool) {
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return addrPort.Addr().Unmap(), true
}

func (s *Server) cleanupListeners() {
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
}

func (s *Server) acceptLoop(ln net.Listener) {
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
		if !s.trackConn(conn) {
			_ = conn.Close()
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) trackConn(conn net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.shutdownCtx.Err() != nil {
		return false
	}
	s.conns[conn] = struct{}{}
	s.connWg.Add(1)
	return true
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()

		_ = conn.Close()
		s.connWg.Done()
	}()

	logger := s.logger.With("remote", conn.RemoteAddr().String(), "local", conn.LocalAddr().String())
	logger.Info("relay connection opened")
	if err := s.serve(conn, logger); err != nil {
		logger.Info("relay connection ended", "err", err.Error())
	}
}

// peerConn is a client's connection. Bytes it sends before the other side
// arrives stay buffered for the relay.
type peerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c peerConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// serve pairs a connection with the session waiting for it, by the address
// it signed in from.
func (s *Server) serve(conn net.Conn, logger *slog.Logger) error {
	ip, ok := remoteIP(conn.RemoteAddr())
	if !ok {
		return fmt.Errorf("unusable address %s", conn.RemoteAddr())
	}
	sess := s.registry.find(ip, false)
	if sess == nil {
		return errNoSession
	}
	logger = logger.With("cookie", fmt.Sprintf("%x", sess.cookie))
	logger.Info("client paired")
	return s.meet(sess, peerConn{Conn: conn, r: bufio.NewReader(conn)}, logger)
}

// meet waits for the other side of the session, then relays until one side
// closes. The recipient arrives first and waits; the offerer opens the pipe.
func (s *Server) meet(sess *session, conn peerConn, logger *slog.Logger) error {
	defer s.registry.remove(sess.cookie)

	first, err := sess.claim(conn)
	if err != nil {
		return err
	}
	if first {
		s.counterOffer(sess, logger)
		return s.awaitPeer(sess, conn, logger)
	}

	<-sess.released
	defer close(sess.finished)
	logger.Info("relay open")
	started := time.Now()
	ab, ba := relay(sess.first, conn, sess.capability != wire.CapDirectICBM)
	logger.Info("relay closed", "first_to_second", ab, "second_to_first", ba, "elapsed", time.Since(started).String())
	return nil
}

// awaitPeer holds the first side until the second arrives, the first side
// leaves, or time runs out.
func (s *Server) awaitPeer(sess *session, conn peerConn, logger *slog.Logger) error {
	left := make(chan struct{})
	stop := make(chan struct{})
	var stopOnce sync.Once
	defer stopOnce.Do(func() { close(stop) })
	go func() {
		defer close(left)
		// a client may speak now, and keeps its bytes
		if _, err := conn.r.Peek(1); err == nil {
			<-stop
		}
	}()

	timeout := time.NewTimer(s.offererTimeout)
	defer timeout.Stop()

	select {
	case <-sess.arrived:
		stopOnce.Do(func() { close(stop) })
		_ = conn.SetReadDeadline(time.Now())
		<-left
		_ = conn.SetReadDeadline(time.Time{})
		close(sess.released)
		<-sess.finished
		return nil
	case <-left:
		sess.abandon()
		return errors.New("client left before the other side arrived")
	case <-sess.cancelled:
		sess.abandon()
		return errors.New("the rendezvous was cancelled")
	case <-timeout.C:
		sess.abandon()
		return errors.New("the other side never arrived")
	case <-s.shutdownCtx.Done():
		sess.abandon()
		return s.shutdownCtx.Err()
	}
}

// copyEven copies src to dst in even-sized writes. AIM 5.1 gets a received
// file's checksum wrong when its reads end on odd offsets, so a byte left over
// waits for the next read, or for evenWriteWait if the sender has paused.
func copyEven(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	write := func(b []byte) error {
		n, err := dst.Write(b)
		written += int64(n)
		return err
	}
	held := 0
	for {
		if held > 0 {
			_ = src.SetReadDeadline(time.Now().Add(evenWriteWait))
		} else {
			_ = src.SetReadDeadline(time.Time{})
		}
		n, readErr := src.Read(buf[held:])
		n += held
		even := n &^ 1
		if err := write(buf[:even]); err != nil {
			return written, err
		}
		held = n - even
		if held > 0 {
			buf[0] = buf[even]
		}
		if readErr == nil {
			continue
		}
		if held > 0 {
			if err := write(buf[:held]); err != nil {
				return written, err
			}
			held = 0
		}
		if !errors.Is(readErr, os.ErrDeadlineExceeded) {
			return written, readErr
		}
	}
}

// relay copies between two connections until either closes, then closes both.
// Files go in even-sized writes.
func relay(a, b net.Conn, files bool) (ab, ba int64) {
	transfer := func(dst, src net.Conn) int64 {
		if files {
			n, _ := copyEven(dst, src)
			return n
		}
		n, _ := io.Copy(dst, src)
		return n
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ab = transfer(b, a)
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		defer wg.Done()
		ba = transfer(a, b)
		_ = a.Close()
		_ = b.Close()
	}()
	wg.Wait()
	return ab, ba
}
