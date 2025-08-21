package state

import (
	"net/netip"
	"sync"
	"time"

	"github.com/mk6i/retro-aim-server/wire"
)

// SessSendStatus is the result of sending a message to a user.
type SessSendStatus int

// RateClassState tracks the rate limiting state for a specific rate class
// within a user's session.
//
// It embeds the static wire.RateClass configuration and maintains dynamic,
// per-session state used to evaluate rate limits in real time.
type RateClassState struct {
	// static rate limit configuration for this class
	wire.RateClass
	// CurrentLevel is the current exponential moving average for this rate
	// class.
	CurrentLevel int32
	// LastTime represents the last time a SNAC message was sent for this rate
	// class.
	LastTime time.Time
	// CurrentStatus is the last recorded rate limit status for this rate class.
	CurrentStatus wire.RateLimitStatus
	// Subscribed indicates whether the user wants to receive rate limit
	// parameter updates for this rate class.
	Subscribed bool
	// LimitedNow indicates whether the user is currently rate limited for this
	// rate class; the user is blocked from sending SNACs in this rate class
	// until the clear threshold is met.
	LimitedNow bool
}

const (
	// SessSendOK indicates message was sent to recipient
	SessSendOK SessSendStatus = iota
	// SessSendClosed indicates send did not complete because session is closed
	SessSendClosed
	// SessQueueFull indicates send failed due to full queue -- client is likely
	// dead
	SessQueueFull
)

// Session represents a user's current session. Unless stated otherwise, all
// methods may be safely accessed by multiple goroutines.
type Session struct {
	awayMessage         string
	caps                [][16]byte
	chatRoomCookie      string
	closed              bool
	displayScreenName   DisplayScreenName
	identScreenName     IdentScreenName
	idle                bool
	idleTime            time.Time
	msgCh               chan wire.SNACMessage
	mutex               sync.RWMutex
	nowFn               func() time.Time
	signonComplete      bool
	signonTime          time.Time
	stopCh              chan struct{}
	uin                 uint32
	warning             uint16
	userInfoBitmask     uint16
	userStatusBitmask   uint32
	clientID            string
	remoteAddr          *netip.AddrPort
	lastObservedStates  [5]RateClassState
	rateByClassID       [5]RateClassState
	foodGroupVersions   [wire.MDir + 1]uint16
	typingEventsEnabled bool
}

// NewSession returns a new instance of Session. By default, the user may have
// up to 1000 pending messages before blocking.
func NewSession() *Session {
	now := time.Now()
	return &Session{
		msgCh:             make(chan wire.SNACMessage, 1000),
		nowFn:             time.Now,
		stopCh:            make(chan struct{}),
		signonTime:        now,
		caps:              make([][16]byte, 0),
		userInfoBitmask:   wire.OServiceUserFlagOSCARFree,
		userStatusBitmask: wire.OServiceUserStatusAvailable,
		foodGroupVersions: func() [wire.MDir + 1]uint16 {
			// initialize default food groups versions to 1.0
			vals := [wire.MDir + 1]uint16{}
			vals[wire.OService] = 1
			vals[wire.Locate] = 1
			vals[wire.Buddy] = 1
			vals[wire.ICBM] = 1
			vals[wire.Advert] = 1
			vals[wire.Invite] = 1
			vals[wire.Admin] = 1
			vals[wire.Popup] = 1
			vals[wire.PermitDeny] = 1
			vals[wire.UserLookup] = 1
			vals[wire.Stats] = 1
			vals[wire.Translate] = 1
			vals[wire.ChatNav] = 1
			vals[wire.Chat] = 1
			vals[wire.ODir] = 1
			vals[wire.BART] = 1
			vals[wire.Feedbag] = 1
			vals[wire.ICQ] = 1
			vals[wire.BUCP] = 1
			vals[wire.Alert] = 1
			vals[wire.Plugin] = 1
			vals[wire.UnnamedFG24] = 1
			vals[wire.MDir] = 1
			return vals
		}(),
	}
}

func (s *Session) SetRateClasses(now time.Time, classes wire.RateLimitClasses) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var newStates [5]RateClassState
	for i, class := range classes.All() {
		newStates[i] = RateClassState{
			CurrentLevel:  class.MaxLevel,
			CurrentStatus: wire.RateLimitStatusClear,
			LastTime:      now,
			RateClass:     class,
			Subscribed:    s.lastObservedStates[i].Subscribed,
		}
	}

	if s.lastObservedStates[0].ID == 0 {
		s.lastObservedStates = newStates
	} else {
		s.lastObservedStates = s.rateByClassID
	}

	s.rateByClassID = newStates
}

// SetRemoteAddr sets the user's remote IP address
func (s *Session) SetRemoteAddr(remoteAddr *netip.AddrPort) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.remoteAddr = remoteAddr
}

// RemoteAddrs returns user's remote IP address
func (s *Session) RemoteAddr() (remoteAddr *netip.AddrPort) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.remoteAddr
}

// SetUserInfoFlag sets a flag to and returns UserInfoBitmask
func (s *Session) SetUserInfoFlag(flag uint16) (flags uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.userInfoBitmask |= flag
	return s.userInfoBitmask
}

// ClearUserInfoFlag clear a flag from and returns UserInfoBitmask
func (s *Session) ClearUserInfoFlag(flag uint16) (flags uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.userInfoBitmask &^= flag
	return s.userInfoBitmask
}

// UserInfoBitmask returns UserInfoBitmask
func (s *Session) UserInfoBitmask() (flags uint16) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userInfoBitmask
}

// SetUserStatusBitmask sets the user status bitmask from the client.
func (s *Session) SetUserStatusBitmask(bitmask uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.userStatusBitmask = bitmask
}

// IncrementWarning increments the user's warning level. To decrease, pass a
// negative increment value.
func (s *Session) IncrementWarning(incr uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.warning += incr
}

// Invisible returns true if the user is idle.
func (s *Session) Invisible() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userStatusBitmask&wire.OServiceUserStatusInvisible == wire.OServiceUserStatusInvisible
}

// SetIdentScreenName sets the user's screen name.
func (s *Session) SetIdentScreenName(screenName IdentScreenName) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.identScreenName = screenName
}

// IdentScreenName returns the user's screen name.
func (s *Session) IdentScreenName() IdentScreenName {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.identScreenName
}

// SetDisplayScreenName sets the user's screen name.
func (s *Session) SetDisplayScreenName(displayScreenName DisplayScreenName) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.displayScreenName = displayScreenName
}

// DisplayScreenName returns the user's screen name.
func (s *Session) DisplayScreenName() DisplayScreenName {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.displayScreenName
}

// SetSignonTime sets the user's sign-ontime.
func (s *Session) SetSignonTime(t time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.signonTime = t
}

// SignonTime reports when the user signed on
func (s *Session) SignonTime() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.signonTime
}

// Idle reports the user's idle state.
func (s *Session) Idle() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.idle
}

// IdleTime reports when the user went idle
func (s *Session) IdleTime() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.idleTime
}

// SetIdle sets the user's idle state.
func (s *Session) SetIdle(dur time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idle = true
	// set the time the user became idle
	s.idleTime = s.nowFn().Add(-dur)
}

// UnsetIdle removes the user's idle state.
func (s *Session) UnsetIdle() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idle = false
}

// SetAwayMessage sets the user's away message.
func (s *Session) SetAwayMessage(awayMessage string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.awayMessage = awayMessage
}

// AwayMessage returns the user's away message.
func (s *Session) AwayMessage() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.awayMessage
}

// SetChatRoomCookie sets the chatRoomCookie for the chat room the user is currently in.
func (s *Session) SetChatRoomCookie(cookie string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.chatRoomCookie = cookie
}

// ChatRoomCookie gets the chatRoomCookie for the chat room the user is currently in.
func (s *Session) ChatRoomCookie() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.chatRoomCookie
}

// SignonComplete indicates whether the client has completed the sign-on sequence.
func (s *Session) SignonComplete() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.signonComplete
}

// SetSignonComplete indicates that the client has completed the sign-on sequence.
func (s *Session) SetSignonComplete() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.signonComplete = true
}

// UIN returns the user's ICQ number.
func (s *Session) UIN() uint32 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.uin
}

// SetUIN sets the user's ICQ number.
func (s *Session) SetUIN(uin uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.uin = uin
}

// TLVUserInfo returns a TLV list containing session information required by
// multiple SNAC message types that convey user information.
func (s *Session) TLVUserInfo() wire.TLVUserInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return wire.TLVUserInfo{
		ScreenName:   string(s.displayScreenName),
		WarningLevel: s.warning,
		TLVBlock: wire.TLVBlock{
			TLVList: s.userInfo(),
		},
	}
}

func (s *Session) userInfo() wire.TLVList {
	tlvs := wire.TLVList{}

	// sign-in timestamp
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(s.signonTime.Unix())))

	// user info flags
	uFlags := s.userInfoBitmask
	if s.awayMessage != "" {
		uFlags |= wire.OServiceUserFlagUnavailable
	}
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uFlags))

	// user status flags
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, s.userStatusBitmask))

	// idle status
	if s.idle {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(s.nowFn().Sub(s.idleTime).Minutes())))
	}

	// ICQ direct-connect info. The TLV is required for buddy arrival events to
	// work in ICQ, even if the values are set to default.
	if s.userInfoBitmask&wire.OServiceUserFlagICQ == wire.OServiceUserFlagICQ {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoICQDC, wire.ICQDCInfo{}))
	}

	// capabilities (buddy icon, chat, etc...)
	if len(s.caps) > 0 {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, s.caps))
	}

	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)))

	return tlvs
}

// SetCaps sets capability UUIDs that represent the features the client
// supports. If set, capability metadata appears in the user info TLV list.
func (s *Session) SetCaps(caps [][16]byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.caps = caps
}

// Caps retrieves user capabilities.
func (s *Session) Caps() [][16]byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.caps
}

func (s *Session) Warning() uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var w uint16
	w = s.warning
	return w
}

// ReceiveMessage returns a channel of messages relayed via this session. It
// may only be read by one consumer. The channel never closes; call this method
// in a select block along with Closed in order to detect session closure.
func (s *Session) ReceiveMessage() chan wire.SNACMessage {
	return s.msgCh
}

// RelayMessage receives a SNAC message from a user and passes it on
// asynchronously to the consumer of this session's messages. It returns
// SessSendStatus to indicate whether the message was successfully sent or
// not. This method is non-blocking.
func (s *Session) RelayMessage(msg wire.SNACMessage) SessSendStatus {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.closed {
		return SessSendClosed
	}
	select {
	case s.msgCh <- msg:
		return SessSendOK
	case <-s.stopCh:
		return SessSendClosed
	default:
		return SessQueueFull
	}
}

// Close shuts down the session's ability to relay messages. Once invoked,
// RelayMessage returns SessQueueFull and Closed returns a closed channel.
// It is not possible to re-open message relaying once closed. It is safe to
// call from multiple go routines.
func (s *Session) Close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.close()
}

func (s *Session) close() {
	if s.closed {
		return
	}
	close(s.stopCh)
	s.closed = true
}

// Closed blocks until the session is closed.
func (s *Session) Closed() <-chan struct{} {
	return s.stopCh
}

// SetClientID sets the client ID.
func (s *Session) SetClientID(clientID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.clientID = clientID
}

// ClientID retrieves the client ID.
func (s *Session) ClientID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.clientID
}

// SubscribeRateLimits subscribes the Session to updates for the specified
// rate limit classes. Future calls to ObserveRateChanges will report changes
// for these classes.
func (s *Session) SubscribeRateLimits(classes []wire.RateLimitClassID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, classID := range classes {
		s.rateByClassID[classID-1].Subscribed = true
	}
}

// ObserveRateChanges updates rate limit states for all known classes and returns
// any classes and class states that have changed since the previous observation.
func (s *Session) ObserveRateChanges(now time.Time) (classDelta []RateClassState, stateDelta []RateClassState) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for i, params := range s.rateByClassID {
		if !params.Subscribed {
			continue
		}

		state, level := wire.CheckRateLimit(params.LastTime, now, params.RateClass, params.CurrentLevel, params.LimitedNow)
		s.rateByClassID[i].CurrentStatus = state

		// clear limited now flag if passing from limited state to clear state
		if s.rateByClassID[i].LimitedNow && state == wire.RateLimitStatusClear {
			s.rateByClassID[i].LimitedNow = false
			s.rateByClassID[i].CurrentLevel = level
		}

		// did rate class change?
		if params.RateClass != s.lastObservedStates[i].RateClass {
			classDelta = append(classDelta, s.rateByClassID[i])
		}

		// did rate limit status change?
		if s.lastObservedStates[i].CurrentStatus != s.rateByClassID[i].CurrentStatus {
			stateDelta = append(stateDelta, s.rateByClassID[i])
		}

		// save it for next time
		s.lastObservedStates[i] = s.rateByClassID[i]
	}

	return classDelta, stateDelta
}

// EvaluateRateLimit checks and updates the session’s rate limit state
// for the given rate class ID. If the rate status reaches 'disconnect',
// the session is closed. Rate limits are not enforced if the user is a bot
// (has wire.OServiceUserFlagBot set in their user info bitmask).
func (s *Session) EvaluateRateLimit(now time.Time, rateClassID wire.RateLimitClassID) wire.RateLimitStatus {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.userInfoBitmask&wire.OServiceUserFlagBot == wire.OServiceUserFlagBot {
		return wire.RateLimitStatusClear // don't rate limit bots
	}

	rateClass := &s.rateByClassID[rateClassID-1]

	status, newLevel := wire.CheckRateLimit(rateClass.LastTime, now, rateClass.RateClass, rateClass.CurrentLevel, rateClass.LimitedNow)
	rateClass.CurrentLevel = newLevel
	rateClass.CurrentStatus = status
	rateClass.LastTime = now
	rateClass.LimitedNow = status == wire.RateLimitStatusLimited

	if status == wire.RateLimitStatusDisconnect {
		s.close()
	}

	return status
}

// SetFoodGroupVersions sets the client's supported food group versions
func (s *Session) SetFoodGroupVersions(versions [wire.MDir + 1]uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.foodGroupVersions = versions
}

// FoodGroupVersions retrieves the client's supported food group versions.
func (s *Session) FoodGroupVersions() [wire.MDir + 1]uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.foodGroupVersions
}

// TypingEventsEnabled indicates whether the client wants to send and receive
// typing events.
func (s *Session) TypingEventsEnabled() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.typingEventsEnabled
}

// SetTypingEventsEnabled sets whether the client wants to send and receive
// typing events.
func (s *Session) SetTypingEventsEnabled(enabled bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.typingEventsEnabled = enabled
}
