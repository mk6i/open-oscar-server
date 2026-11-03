package webapi

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// feedbagQuery tracks a session's outstanding feedbag query. The OSCAR server
// relays other locations' feedbag changes and answers the query from different
// goroutines, so a change can arrive before a reply that doesn't include it.
// The changes that arrive while the query is outstanding are applied again on
// top of its reply.
type feedbagQuery struct {
	mu     sync.Mutex
	active bool
	// marker marks the changes the session sent before the query.
	marker uint64
	remote []remoteFeedbagChange
}

// remoteFeedbagChange is a feedbag change made at another of the owner's
// locations.
type remoteFeedbagChange struct {
	del   bool
	items []wire.FeedbagItem
}

// Feedbag returns the owner's feedbag, including the change the session is
// waiting on.
func (s *Session) Feedbag() []wire.FeedbagItem {
	return s.feedbag.Snapshot()
}

// Aliases returns this session owner's private buddy aliases, keyed by
// normalized screen name. Buddies without an alias are absent.
func (s *Session) Aliases() map[string]string {
	aliases := make(map[string]string)
	for _, item := range s.Feedbag() {
		if item.ClassID != wire.FeedbagClassIdBuddy || item.Name == "" {
			continue
		}
		if alias, ok := item.String(wire.FeedbagAttributesAlias); ok && alias != "" {
			aliases[state.NewIdentScreenName(item.Name).String()] = alias
		}
	}
	return aliases
}

// aliasFor returns this session owner's private alias for buddy, or "" when none is
// set. The web client deletes the alias it holds whenever it merges a user map, so
// every event naming a buddy has to repeat it.
func (s *Session) aliasFor(buddy state.IdentScreenName) string {
	return s.Aliases()[buddy.String()]
}

// lockFeedbag waits for the session's other feedbag changes to finish and
// returns the feedbag to diff a change against, reloading it first if it's
// stale. On success the caller holds the feedbag lock until unlockFeedbag.
func (s *Session) lockFeedbag(ctx context.Context) ([]wire.FeedbagItem, error) {
	s.feedbagMu.Lock()
	if s.feedbagStale.Load() {
		if err := s.loadFeedbag(ctx); err != nil {
			s.feedbagMu.Unlock()
			return nil, err
		}
	}
	return s.feedbag.Snapshot(), nil
}

// unlockFeedbag releases the lock that lockFeedbag took.
func (s *Session) unlockFeedbag() {
	s.feedbagMu.Unlock()
}

// changeFeedbag sends a feedbag insert, update or delete of items and waits
// for the FeedbagStatus that answers it, returning the result for each item.
// The caller holds the feedbag lock. A change that isn't confirmed is
// discarded and marks the feedbag stale.
func (s *Session) changeFeedbag(ctx context.Context, subGroup uint16, items []wire.FeedbagItem) ([]uint16, error) {
	var body any
	switch subGroup {
	case wire.FeedbagInsertItem:
		body = wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: items}
	case wire.FeedbagUpdateItem:
		body = wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: items}
	case wire.FeedbagDeleteItem:
		body = wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: items}
	default:
		return nil, fmt.Errorf("unsupported feedbag change %s", wire.SubGroupName(wire.Feedbag, subGroup))
	}

	var requestID uint32
	reply, err := s.requestWith(ctx, wire.Feedbag, subGroup, body, func(id uint32) {
		requestID = id
		s.feedbag.Sent(id, subGroup == wire.FeedbagDeleteItem, items)
	}, wire.FeedbagStatus)
	if err == nil {
		if status, ok := reply.Body.(wire.SNAC_0x13_0x0E_FeedbagStatus); ok {
			return status.Results, nil
		}
		err = snacError(reply)
	}
	if requestID != 0 {
		s.feedbag.Discard(requestID)
		s.feedbagStale.Store(true)
	}
	return nil, fmt.Errorf("%s: %w", wire.SubGroupName(wire.Feedbag, subGroup), err)
}

// loadFeedbag replaces the mirror with the OSCAR server's feedbag. The
// caller holds the feedbag lock.
func (s *Session) loadFeedbag(ctx context.Context) error {
	s.feedbagQuery.start(s.feedbag.Mark())
	reply, err := s.request(ctx, wire.Feedbag, wire.FeedbagQuery, struct{}{}, wire.FeedbagReply)
	if err == nil {
		if _, ok := reply.Body.(wire.SNAC_0x13_0x06_FeedbagReply); ok {
			s.feedbagStale.Store(false)
			return nil
		}
		err = fmt.Errorf("FeedbagQuery: %w", snacError(reply))
	}
	s.feedbagQuery.abandon()
	s.feedbagStale.Store(true)
	return err
}

// reloadStaleFeedbag reloads the feedbag if a change or reload failed.
func (s *Session) reloadStaleFeedbag(ctx context.Context) {
	if !s.feedbagStale.Load() {
		return
	}
	s.feedbagMu.Lock()
	defer s.feedbagMu.Unlock()
	if !s.feedbagStale.Load() {
		return
	}
	if err := s.loadFeedbag(ctx); err != nil {
		s.logger.Error("failed to reload feedbag", "err", err)
	}
}

// start begins a query sent after the changes up to marker.
func (q *feedbagQuery) start(marker uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.active = true
	q.marker = marker
	q.remote = nil
}

// abandon ends a query whose reply never came.
func (q *feedbagQuery) abandon() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.active = false
	q.remote = nil
}

// applyFeedbagReply reloads the mirror from the reply to the outstanding
// feedbag query.
func (s *Session) applyFeedbagReply(items []wire.FeedbagItem) {
	q := &s.feedbagQuery
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.active {
		return
	}
	s.feedbag.Reload(q.marker, items)
	for _, change := range q.remote {
		s.feedbag.ApplyRemote(change.del, change.items)
	}
	q.active = false
	q.remote = nil
}

// applyRemoteFeedbag applies a change made at another of the owner's
// locations.
func (s *Session) applyRemoteFeedbag(del bool, items []wire.FeedbagItem) {
	q := &s.feedbagQuery
	q.mu.Lock()
	defer q.mu.Unlock()
	s.feedbag.ApplyRemote(del, items)
	if q.active {
		q.remote = append(q.remote, remoteFeedbagChange{del: del, items: state.CloneFeedbagItems(items)})
	}
}

// applyFeedbagStatus confirms the items of the session's feedbag change
// requestID that the server accepted.
func (s *Session) applyFeedbagStatus(requestID uint32, results []uint16) {
	s.feedbag.Confirm(requestID, results)
	// A buddy declined for authorization is not stored, and is simply absent
	// from the refreshed roster.
	if slices.Contains(results, feedbagResultAuthRequired) {
		s.logger.Info("feedbag item declined pending authorization")
	}
	s.refreshBuddyList()
}

// snacError describes a reply that is an error SNAC.
func snacError(reply wire.SNACMessage) error {
	if body, ok := reply.Body.(wire.SNACError); ok {
		return fmt.Errorf("error code %d", body.Code)
	}
	return fmt.Errorf("unexpected reply %s", wire.SubGroupName(reply.Frame.FoodGroup, reply.Frame.SubGroup))
}
