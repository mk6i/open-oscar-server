package icq_legacy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
)

const (
	// MaxPacketSize is the maximum UDP packet size we'll accept
	MaxPacketSize = 8192

	// ReadBufferSize is the UDP socket read buffer size
	ReadBufferSize = 65536
)

var (
	ErrServerClosed     = errors.New("server closed")
	ErrUnsupportedProto = errors.New("unsupported protocol version")
)

// LegacyServer handles legacy ICQ protocol connections over UDP
type LegacyServer struct {
	conn       *net.UDPConn
	config     config.ICQLegacyConfig
	sessions   *LegacySessionManager
	dispatcher *ProtocolDispatcher
	logger     *slog.Logger

	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	running  bool
}

// NewLegacyServer creates a new legacy ICQ server
func NewLegacyServer(
	cfg config.ICQLegacyConfig,
	sessions *LegacySessionManager,
	dispatcher *ProtocolDispatcher,
	logger *slog.Logger,
) *LegacyServer {
	return &LegacyServer{
		config:     cfg,
		sessions:   sessions,
		dispatcher: dispatcher,
		logger:     logger,
		stopChan:   make(chan struct{}),
	}
}

// Start begins listening for legacy ICQ connections
func (s *LegacyServer) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("legacy ICQ server disabled")
		return nil
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.running = true
	s.mu.Unlock()

	// Parse listen address
	addr, err := net.ResolveUDPAddr("udp", s.config.UDPListener)
	if err != nil {
		return fmt.Errorf("invalid UDP listener address: %w", err)
	}

	// Create UDP socket
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	// Set socket options
	if err := conn.SetReadBuffer(ReadBufferSize); err != nil {
		s.logger.Warn("failed to set read buffer size", "err", err)
	}

	s.conn = conn

	s.logger.Info("legacy ICQ server started",
		"address", s.config.UDPListener,
		"versions", s.config.SupportedVersions,
	)

	// Start session cleanup routine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sessions.StartCleanupRoutine(s.config.SessionTimeout/2, s.stopChan)
	}()

	// Start packet receive loop
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.receiveLoop(ctx)
	}()

	return nil
}

// Stop gracefully shuts down the server
func (s *LegacyServer) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	// Signal all goroutines to stop
	close(s.stopChan)

	// Close the UDP socket to unblock the receive loop
	if s.conn != nil {
		s.conn.Close()
	}

	// Wait for all goroutines to finish
	s.wg.Wait()

	s.logger.Info("legacy ICQ server stopped")
	return nil
}

// receiveLoop handles incoming UDP packets
func (s *LegacyServer) receiveLoop(ctx context.Context) {
	buf := make([]byte, MaxPacketSize)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		// Set read deadline to allow periodic checking of stop signal
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			// Check if it's a timeout (expected)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			// Check if server is stopping
			select {
			case <-s.stopChan:
				return
			default:
			}

			s.logger.Error("UDP read error", "err", err)
			continue
		}

		if n < 2 {
			s.logger.Debug("packet too short", "size", n, "addr", addr)
			continue
		}

		// Copy packet data to avoid buffer reuse issues
		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Handle packet in goroutine to not block receive loop
		go s.handlePacket(addr, packet)
	}
}

// handlePacket processes a single incoming packet
func (s *LegacyServer) handlePacket(addr *net.UDPAddr, packet []byte) {
	// Detect protocol version
	version, err := wire.DetectProtocolVersion(packet)
	if err != nil {
		s.logger.Debug("failed to detect protocol version",
			"err", err,
			"addr", addr,
		)
		return
	}

	// Check if version is supported
	if !s.config.SupportsVersion(int(version)) {
		s.logger.Debug("unsupported protocol version",
			"version", version,
			"addr", addr,
		)
		return
	}

	// Get or create session
	session := s.sessions.GetSessionByAddr(addr)

	// Dispatch to appropriate handler
	if err := s.dispatcher.Dispatch(session, addr, packet); err != nil {
		s.logger.Debug("packet dispatch error",
			"err", err,
			"addr", addr,
			"version", version,
		)
	}
}

// SendPacket sends a packet to a specific address
func (s *LegacyServer) SendPacket(addr *net.UDPAddr, packet []byte) error {
	s.mu.RLock()
	if !s.running || s.conn == nil {
		s.mu.RUnlock()
		return ErrServerClosed
	}
	conn := s.conn
	s.mu.RUnlock()

	s.logger.Debug("sending packet",
		"to", addr.String(),
		"size", len(packet),
		"hex", fmt.Sprintf("%X", packet),
	)

	_, err := conn.WriteToUDP(packet, addr)
	if err != nil {
		s.logger.Debug("failed to send packet",
			"err", err,
			"addr", addr,
			"size", len(packet),
		)
		return err
	}

	return nil
}

// SendToSession sends a packet to a session
func (s *LegacyServer) SendToSession(session *LegacySession, packet []byte) error {
	if session == nil || session.Addr == nil {
		return errors.New("invalid session")
	}
	return s.SendPacket(session.Addr, packet)
}

// BroadcastToAll sends a packet to all connected sessions
func (s *LegacyServer) BroadcastToAll(packet []byte) {
	sessions := s.sessions.GetAllSessions()
	for _, session := range sessions {
		if err := s.SendToSession(session, packet); err != nil {
			s.logger.Debug("broadcast send failed",
				"uin", session.UIN,
				"err", err,
			)
		}
	}
}

// IsRunning returns whether the server is currently running
func (s *LegacyServer) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// SessionCount returns the number of active sessions
func (s *LegacyServer) SessionCount() int {
	return s.sessions.Count()
}

// ListenAndServe starts the server and blocks until it's stopped.
// This method matches the interface used by other servers in the project.
func (s *LegacyServer) ListenAndServe() error {
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		return err
	}

	// Block until server is stopped
	<-s.stopChan
	return nil
}

// Shutdown gracefully shuts down the server.
// This method matches the interface used by other servers in the project.
func (s *LegacyServer) Shutdown(ctx context.Context) error {
	return s.Stop()
}
