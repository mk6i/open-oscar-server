package webapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// defaultRequestTimeout bounds how long a request waits for the OSCAR
// server's reply. The server drops a rate-limited SNAC without replying.
const defaultRequestTimeout = 5 * time.Second

// snacErrorSubGroup is the subgroup of the error SNAC in every food group.
const snacErrorSubGroup = 0x0001

var (
	// errRateLimited indicates that a request's rate class is limited, so the
	// request was held back or dropped by the OSCAR server.
	errRateLimited = errors.New("rate limited")
	// errNoReply indicates that the OSCAR server didn't answer a request in
	// time.
	errNoReply = errors.New("no reply from OSCAR server")
	// errOSCARClosed indicates that the session's OSCAR connection closed.
	errOSCARClosed = errors.New("OSCAR connection closed")
)

// rateLimitError is errRateLimited along with how long the client should wait
// before retrying.
type rateLimitError struct {
	retryAfter time.Duration
}

func (e *rateLimitError) Error() string {
	return errRateLimited.Error()
}

func (e *rateLimitError) Is(target error) bool {
	return target == errRateLimited
}

// RateLimitExempt lists the SNACs that the OSCAR server doesn't rate limit on
// Web API connections: the read-only lookups that a single Web API request
// makes for many users at once.
var RateLimitExempt = []wire.SNACType{
	{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery},
	{FoodGroup: wire.Locate, SubGroup: wire.LocateGetDirInfo},
	{FoodGroup: wire.ODir, SubGroup: wire.ODirInfoQuery},
}

// replyWaiter is cached with a request whose reply a caller waits for.
type replyWaiter struct {
	ch        chan wire.SNACMessage
	subGroups []uint16
}

// accepts reports whether a SNAC in subGroup can answer the request.
func (w *replyWaiter) accepts(subGroup uint16) bool {
	return subGroup == snacErrorSubGroup || slices.Contains(w.subGroups, subGroup)
}

// request sends a SNAC to the OSCAR server and waits for its reply: a SNAC in
// the same food group with one of replySubGroups, or an error SNAC. A SNAC
// whose rate class the server has announced as limited isn't sent.
//
// The session's inbound loop delivers the reply, so request must never be
// called from that loop.
func (s *Session) request(ctx context.Context, foodGroup, subGroup uint16, body any, replySubGroups ...uint16) (wire.SNACMessage, error) {
	return s.requestWith(ctx, foodGroup, subGroup, body, nil, replySubGroups...)
}

// requestWith is request, calling sending, when it's not nil, with the
// request ID just before the SNAC goes out.
func (s *Session) requestWith(ctx context.Context, foodGroup, subGroup uint16, body any, sending func(requestID uint32), replySubGroups ...uint16) (wire.SNACMessage, error) {
	class, gated := s.rateClass(foodGroup, subGroup)
	if gated {
		if retryAfter, limited := s.rates.limited(class, time.Now()); limited {
			return wire.SNACMessage{}, &rateLimitError{retryAfter: retryAfter}
		}
	}

	waiter := &replyWaiter{ch: make(chan wire.SNACMessage, 1), subGroups: replySubGroups}
	frame := wire.SNACFrame{FoodGroup: foodGroup, SubGroup: subGroup}
	s.cache.Add(&frame, waiter)
	defer s.cache.Remove(frame.RequestID)

	if sending != nil {
		sending(frame.RequestID)
	}
	if err := s.bos.SendSNAC(frame, body); err != nil {
		return wire.SNACMessage{}, fmt.Errorf("SendSNAC(%s): %w", wire.SubGroupName(foodGroup, subGroup), err)
	}

	timer := time.NewTimer(s.requestTimeout)
	defer timer.Stop()

	select {
	case reply := <-waiter.ch:
		return reply, nil
	case <-s.bos.Closed():
		select {
		case reply := <-waiter.ch:
			return reply, nil
		default:
			return wire.SNACMessage{}, errOSCARClosed
		}
	case <-ctx.Done():
		return wire.SNACMessage{}, ctx.Err()
	case <-timer.C:
		if gated {
			if retryAfter, limited := s.rates.timedOut(class, time.Now()); limited {
				return wire.SNACMessage{}, &rateLimitError{retryAfter: retryAfter}
			}
		}
		return wire.SNACMessage{}, errNoReply
	}
}

// send sends a SNAC to the OSCAR server without waiting for a reply. A SNAC
// whose rate class the server has announced as limited isn't sent.
func (s *Session) send(foodGroup, subGroup uint16, body any) error {
	class, gated := s.rateClass(foodGroup, subGroup)
	if gated {
		if retryAfter, limited := s.rates.limited(class, time.Now()); limited {
			return &rateLimitError{retryAfter: retryAfter}
		}
	}

	frame := wire.SNACFrame{FoodGroup: foodGroup, SubGroup: subGroup}
	s.cache.Add(&frame, nil)
	if err := s.bos.SendSNAC(frame, body); err != nil {
		s.cache.Remove(frame.RequestID)
		return fmt.Errorf("SendSNAC(%s): %w", wire.SubGroupName(foodGroup, subGroup), err)
	}
	return nil
}

// rateClass returns the rate class of a SNAC, and whether the session holds
// it back while the class is limited. Exempt SNACs are never limited.
func (s *Session) rateClass(foodGroup, subGroup uint16) (wire.RateLimitClassID, bool) {
	if slices.Contains(RateLimitExempt, wire.SNACType{FoodGroup: foodGroup, SubGroup: subGroup}) {
		return 0, false
	}
	return s.snacRateLimits.RateClassLookup(foodGroup, subGroup)
}

// takeReply hands msg to the request it answers and reports whether it did.
// A relayed SNAC can carry another user's request ID, but it never has the
// subgroup of a reply the request waits for.
func (s *Session) takeReply(msg wire.SNACMessage) bool {
	req, ok := s.cache.Peek(msg.Frame)
	if !ok {
		return false
	}
	waiter, isWaiter := req.Data.(*replyWaiter)
	switch {
	case isWaiter && waiter.accepts(msg.Frame.SubGroup):
		s.cache.Remove(msg.Frame.RequestID)
		s.applyReply(req.Frame, msg)
		select {
		case waiter.ch <- msg:
		default:
		}
		return true
	case !isWaiter && msg.Frame.SubGroup == snacErrorSubGroup:
		s.cache.Remove(msg.Frame.RequestID)
		if body, ok := msg.Body.(wire.SNACError); ok {
			s.logger.Debug("OSCAR server rejected request",
				"request", wire.SubGroupName(req.Frame.FoodGroup, req.Frame.SubGroup), "code", body.Code)
		}
		return true
	}
	return false
}

// applyReply updates the session from a reply before its waiter sees it.
func (s *Session) applyReply(req wire.SNACFrame, msg wire.SNACMessage) {
	switch body := msg.Body.(type) {
	case wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate:
		if len(body.UserInfo) > 0 {
			s.self.setReply(body.UserInfo[0])
		}
	case wire.SNAC_0x01_0x07_OServiceRateParamsReply:
		s.rates.seed(body.RateClasses, time.Now())
	case wire.SNAC_0x13_0x06_FeedbagReply:
		s.applyFeedbagReply(body.Items)
	case wire.SNAC_0x13_0x0E_FeedbagStatus:
		s.applyFeedbagStatus(req.RequestID, body.Results)
	}
}

// recvBOS translates the SNACs that arrive on the session's BOS connection
// into events until ctx is done or the connection closes. It never waits for
// a reply, since it is the only goroutine that delivers them.
func (s *Session) recvBOS(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			s.bos.Close()
			return nil
		case <-s.bos.Closed():
			// A teardown this session started closed the queue first, so
			// only an unexpected disconnect reaches the client.
			s.PushEvent(EventTypeSessionEnded, struct{}{})
			return errOSCARClosed
		case msg := <-s.bos.Messages():
			if !s.takeReply(msg) {
				s.handleSNACMessage(msg)
			}
		}
	}
}

// rateLimitState holds the rate limit status that the OSCAR server last
// announced for each rate class.
type rateLimitState struct {
	mu      sync.Mutex
	classes map[wire.RateLimitClassID]*announcedRate
}

// announcedRate is a rate class's last announced status.
type announcedRate struct {
	limited bool
	params  wire.RateParamsSNAC
	// until is when the session stops holding SNACs back, in case the
	// server's clear announcement never arrives.
	until time.Time
}

// rateParamsChange codes the OSCAR server sends when a rate class becomes
// limited or clears.
const (
	rateParamsChangeLimited uint16 = 3
	rateParamsChangeClear   uint16 = 4
)

// announce records a rate class status change from the OSCAR server.
func (r *rateLimitState) announce(code uint16, params wire.RateParamsSNAC, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.classes == nil {
		r.classes = make(map[wire.RateLimitClassID]*announcedRate)
	}
	class := wire.RateLimitClassID(params.ID)
	switch code {
	case rateParamsChangeLimited:
		r.classes[class] = &announcedRate{limited: true, params: params, until: now.Add(retryAfter(params))}
	case rateParamsChangeClear:
		r.classes[class] = &announcedRate{params: params}
	}
}

// seed records the rate classes that the OSCAR server reports as dropping
// SNACs. A class it has announced since is left as announced.
func (r *rateLimitState) seed(classes []wire.RateParamsSNAC, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.classes == nil {
		r.classes = make(map[wire.RateLimitClassID]*announcedRate)
	}
	for _, params := range classes {
		class := wire.RateLimitClassID(params.ID)
		if _, announced := r.classes[class]; announced {
			continue
		}
		if params.V2Params != nil && params.V2Params.DroppingSNACs == 1 {
			r.classes[class] = &announcedRate{limited: true, params: params, until: now.Add(retryAfter(params))}
		}
	}
}

// limited reports how long to wait before sending SNACs of class, and whether
// the class is limited now.
func (r *rateLimitState) limited(class wire.RateLimitClassID, now time.Time) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rate := r.classes[class]
	if rate == nil || !rate.limited || !now.Before(rate.until) {
		return 0, false
	}
	return max(rate.until.Sub(now), minRetryAfter), true
}

// timedOut handles a request of class that the server didn't answer. If the
// class is limited, the server most likely dropped the request, so the
// session holds SNACs back again and timedOut reports how long to wait.
func (r *rateLimitState) timedOut(class wire.RateLimitClassID, now time.Time) (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rate := r.classes[class]
	if rate == nil || !rate.limited {
		return 0, false
	}
	wait := retryAfter(rate.params)
	rate.until = now.Add(wait)
	return wait, true
}

// selfInfo is the session owner's user info as the OSCAR server last
// reported it, and the away message the session last set.
type selfInfo struct {
	mu      sync.Mutex
	info    wire.TLVUserInfo
	relayed bool
	awayMsg string
}

// setReply records user info from the reply to a user info query. A
// server-initiated update that arrived first is newer, so it is kept.
func (i *selfInfo) setReply(info wire.TLVUserInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.relayed {
		i.info = info
	}
}

// setRelayed records user info from a server-initiated update.
func (i *selfInfo) setRelayed(info wire.TLVUserInfo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.info = info
	i.relayed = true
}

// userInfo returns the owner's user info.
func (i *selfInfo) userInfo() wire.TLVUserInfo {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.info
}

// setAwayMessage records the away message the session set.
func (i *selfInfo) setAwayMessage(msg string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.awayMsg = msg
}

// awayMessage returns the away message the session last set.
func (i *selfInfo) awayMessage() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.awayMsg
}

// signOn completes the OSCAR sign-on of a session whose inbound loop is
// running: it subscribes to rate limit changes, starts using the feedbag,
// advertises the Web API's capabilities, reads which rate classes are
// limited, reads the owner's user info and feedbag, and goes online, waiting
// for the server to finish.
func (s *Session) signOn(ctx context.Context) error {
	subscribe := wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{ClassIDs: []uint16{1, 2, 3, 4, 5}}
	if err := s.send(wire.OService, wire.OServiceRateParamsSubAdd, subscribe); err != nil {
		return err
	}
	if err := s.send(wire.Feedbag, wire.FeedbagUse, struct{}{}); err != nil {
		return err
	}
	// sent before going online, so that the arrival broadcast carries them
	caps := wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, webAPICaps),
			},
		},
	}
	if err := s.send(wire.Locate, wire.LocateSetInfo, caps); err != nil {
		return err
	}

	// OService version 3 makes the rate params reply report whether each
	// class is dropping SNACs.
	versions := wire.SNAC_0x01_0x17_OServiceClientVersions{Versions: []uint16{wire.OService, 3}}
	if err := s.send(wire.OService, wire.OServiceClientVersions, versions); err != nil {
		return err
	}
	if _, err := s.request(ctx, wire.OService, wire.OServiceRateParamsQuery, struct{}{}, wire.OServiceRateParamsReply); err != nil {
		return fmt.Errorf("rate params query: %w", err)
	}

	reply, err := s.request(ctx, wire.OService, wire.OServiceUserInfoQuery, struct{}{}, wire.OServiceUserInfoUpdate)
	if err != nil {
		return fmt.Errorf("user info query: %w", err)
	}
	if body, ok := reply.Body.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate); !ok || len(body.UserInfo) == 0 {
		return fmt.Errorf("unexpected user info reply %s", wire.SubGroupName(reply.Frame.FoodGroup, reply.Frame.SubGroup))
	}

	// loaded before going online, so that buddy arrivals carry aliases
	s.feedbagMu.Lock()
	err = s.loadFeedbag(ctx)
	s.feedbagMu.Unlock()
	if err != nil {
		return fmt.Errorf("feedbag query: %w", err)
	}

	if err := s.send(wire.OService, wire.OServiceClientOnline, wire.SNAC_0x01_0x02_OServiceClientOnline{}); err != nil {
		return err
	}

	// waited for, so that the presence view holds the owner's online buddies
	// before the client is sent the buddy list
	timer := time.NewTimer(s.requestTimeout)
	defer timer.Stop()
	select {
	case <-s.online:
		return nil
	case <-s.bos.Closed():
		return errOSCARClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("client online: %w", errNoReply)
	}
}
