package relay

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/state"
)

var (
	errNoSession   = errors.New("no session for cookie")
	errSessionFull = errors.New("session already has two sides")
)

// session is one relayed connection, identified by the rendezvous cookie.
type session struct {
	cookie [8]byte

	mu        sync.Mutex
	first     net.Conn
	paired    bool
	abandoned bool
	accepted  bool

	// arrived closes when the second side turns up.
	arrived chan struct{}
	// released closes when the waiting side has stopped watching its
	// connection, so the second side can use it.
	released chan struct{}
	// finished closes when the relay ends.
	finished chan struct{}
	// cancelled closes when a client cancels the rendezvous.
	cancelled chan struct{}

	offerer   *state.SessionInstance
	offererIP netip.Addr
	recipient state.IdentScreenName
	// recipientIPs holds the address of each of the recipient's instances,
	// since any of them can accept.
	recipientIPs []netip.Addr
	capability   [16]byte
	expiry       *time.Timer
	created      time.Time
}

// awaits reports whether the next side to arrive dials from ip. With ready
// set, it also has to have been told to dial: the recipient by accepting, the
// offerer by the counter-offer that follows the recipient arriving.
func (s *session) awaits(ip netip.Addr, ready bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.abandoned || s.paired:
		return false
	case s.first == nil:
		return slices.Contains(s.recipientIPs, ip) && (s.accepted || !ready)
	}
	return s.offererIP == ip
}

func (s *session) markAccepted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accepted = true
}

// claim records a side arriving. It reports whether this side is the first.
func (s *session) claim(conn net.Conn) (first bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.abandoned:
		return false, errNoSession
	case s.first == nil:
		s.first = conn
		return true, nil
	case !s.paired:
		s.paired = true
		close(s.arrived)
		return false, nil
	}
	return false, errSessionFull
}

// abandon records that the first side has gone. A second side already paired
// is released, and its first write fails.
func (s *session) abandon() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abandoned = true
	if s.paired {
		close(s.released)
	}
}

// registry holds the sessions waiting for or running a relay.
type registry struct {
	mu       sync.Mutex
	sessions map[[8]byte]*session
}

func newRegistry() *registry {
	return &registry{sessions: make(map[[8]byte]*session)}
}

// reserve opens a session for an offer. It returns false if the cookie is
// already in use.
func (r *registry) reserve(sess *session, ttl time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[sess.cookie]; ok {
		return false
	}
	sess.arrived = make(chan struct{})
	sess.released = make(chan struct{})
	sess.finished = make(chan struct{})
	sess.cancelled = make(chan struct{})
	sess.created = time.Now()
	sess.expiry = time.AfterFunc(ttl, func() { r.expire(sess) })
	r.sessions[sess.cookie] = sess
	return true
}

// find returns the oldest session whose next side dials from ip.
func (r *registry) find(ip netip.Addr, ready bool) *session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found *session
	for _, sess := range r.sessions {
		if sess.awaits(ip, ready) && (found == nil || sess.created.Before(found.created)) {
			found = sess
		}
	}
	return found
}

func (r *registry) expire(sess *session) {
	sess.mu.Lock()
	reached := sess.first != nil
	sess.mu.Unlock()
	if !reached {
		r.remove(sess.cookie)
	}
}

// cancel ends a session the clients have called off. It reports whether there
// was one.
func (r *registry) cancel(cookie [8]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.sessions[cookie]
	if !ok {
		return false
	}
	delete(r.sessions, cookie)
	close(sess.cancelled)
	sess.expiry.Stop()
	return true
}

func (r *registry) lookup(cookie [8]byte) (*session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.sessions[cookie]
	if !ok {
		return nil, errNoSession
	}
	return sess, nil
}

func (r *registry) remove(cookie [8]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess, ok := r.sessions[cookie]; ok {
		sess.expiry.Stop()
	}
	delete(r.sessions, cookie)
}
