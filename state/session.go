package state

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
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

// Session represents shared user-level state that persists across all concurrent
// connections for a single user account.
//
// Session maintains client identity information, preferences, rate limiting state,
// and other shared data that should be consistent across all of a user's active
// connections. Individual connection-specific state (like remote address, sign-on
// status, or per-connection capabilities) is stored in SessionInstance instead.
//
// All methods on Session are safe for concurrent use.
type Session struct {
	mutex sync.RWMutex

	// User identity (shared across all sessions)
	displayScreenName DisplayScreenName
	identScreenName   IdentScreenName
	uin               uint32
	memberSince       time.Time
	signonTime        time.Time

	// User-level settings and profile (shared)
	warning             uint16
	warningCh           chan uint16
	offlineMsgCount     int
	chatRoomCookie      string
	buddyIcon           wire.BARTID
	typingEventsEnabled bool

	// Rate limiting (shared across all sessions per user)
	rateLimitStates         [5]RateClassState
	rateLimitStatesOriginal [5]RateClassState
	lastObservedStates      [5]RateClassState

	instances        map[uint8]*SessionInstance
	instancesOrdered []*SessionInstance

	initOnce      sync.Once
	onSessCloseFn func()
	nowFn         func() time.Time
}

// NewSession creates a new Session for a user.
func NewSession() *Session {
	return &Session{
		warningCh:        make(chan uint16, 1),
		instances:        make(map[uint8]*SessionInstance),
		instancesOrdered: make([]*SessionInstance, 0),
		onSessCloseFn:    func() {},
		nowFn:            time.Now,
	}
}

//
// Instance Management
//

// AddInstance creates and adds a new connection instance to the session.
// Returns the newly created SessionInstance with a unique instance number.
func (s *Session) AddInstance() *SessionInstance {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	instance := &SessionInstance{
		session:           s,
		instanceNum:       s.generateInstanceNum(),
		msgCh:             make(chan wire.SNACMessage, 1000),
		stopCh:            make(chan struct{}),
		capabilities:      make([][16]byte, 0),
		foodGroupVersions: defaultFoodGroupVersions(),
		userInfoBitmask:   wire.OServiceUserFlagOSCARFree,
		userStatusBitmask: wire.OServiceUserStatusAvailable,
		onInstanceCloseFn: func() {},
	}

	s.instances[instance.instanceNum] = instance
	s.instancesOrdered = append(s.instancesOrdered, instance)

	return instance
}

// HasLiveInstances returns true if the session has at least one live instance.
// A live instance is one that is not closed and has completed the sign-on sequence.
func (s *Session) HasLiveInstances() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, instance := range s.instances {
		if instance.live() {
			return true
		}
	}
	return false
}

// InstanceCount returns the number of total instances in the session group.
func (s *Session) InstanceCount() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.instances)
}

// Instances returns all instances in the order they were added.
func (s *Session) Instances() []*SessionInstance {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	instances := make([]*SessionInstance, len(s.instancesOrdered))
	copy(instances, s.instancesOrdered)
	return instances
}

// RemoveInstance removes an instance from the session group.
func (s *Session) RemoveInstance(instance *SessionInstance) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.instances, instance.instanceNum)
	for i, inst := range s.instancesOrdered {
		if inst == instance {
			s.instancesOrdered = append(s.instancesOrdered[:i], s.instancesOrdered[i+1:]...)
			break
		}
	}
}

// generateInstanceNum generates the next available instance number for this session group.
// It finds the next number that is not currently in use by iterating over the possible key range.
func (s *Session) generateInstanceNum() uint8 {
	// if num reaches 0, all number have been taken
	for num := uint8(1); num != 0; num++ {
		if _, exists := s.instances[num]; !exists {
			return num
		}
	}

	// the caller should ensure there are no more than 255 instances per session
	panic("all instance numbers are taken (max 255 instances per session)")
}

// defaultFoodGroupVersions returns default version numbers for all food groups.
func defaultFoodGroupVersions() [wire.MDir + 1]uint16 {
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
}

//
// Identity
//

// ChatRoomCookie returns the chat room cookie.
func (s *Session) ChatRoomCookie() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.chatRoomCookie
}

// DisplayScreenName returns the user's display screen name.
func (s *Session) DisplayScreenName() DisplayScreenName {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.displayScreenName
}

// IdentScreenName returns the user's identity screen name.
func (s *Session) IdentScreenName() IdentScreenName {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.identScreenName
}

// SetDisplayScreenName sets the user's display screen name (shared across all sessions).
func (s *Session) SetDisplayScreenName(displayScreenName DisplayScreenName) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.displayScreenName = displayScreenName
}

// SetIdentScreenName sets the user's identity screen name (shared across all sessions).
func (s *Session) SetIdentScreenName(screenName IdentScreenName) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.identScreenName = screenName
}

// SetUIN sets the user's ICQ number (shared across all sessions).
func (s *Session) SetUIN(uin uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.uin = uin
}

// UIN returns the user's ICQ number.
func (s *Session) UIN() uint32 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.uin
}

//
// Status / Availability
//

// Away returns true if all instances are away.
func (s *Session) Away() bool {
	instances := s.Instances()

	if len(instances) == 0 {
		return false
	}

	for _, instance := range instances {
		if instance.UserInfoBitmask()&wire.OServiceUserFlagUnavailable == 0 &&
			instance.UserStatusBitmask()&wire.OServiceUserStatusAway == 0 {
			return false
		}
	}

	return true
}

// AwayMessage returns the away message from the last instance to set an away message.
func (s *Session) AwayMessage() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var latest *SessionInstance
	var latestTime time.Time

	for _, instance := range s.instances {
		// Only consider instances that are away
		if !instance.Away() {
			continue
		}

		_, awayTime := instance.AwayMessage()
		if latest == nil || awayTime.After(latestTime) {
			latest = instance
			latestTime = awayTime
		}
	}

	if latest == nil {
		return ""
	}
	awayMsg, _ := latest.AwayMessage()
	return awayMsg
}

// Idle returns true if all instances are idle.
func (s *Session) Idle() bool {
	instances := s.Instances()
	if len(instances) == 0 {
		return false
	}

	for _, instance := range instances {
		if !instance.Idle() {
			return false
		}
	}

	return true
}

// IdleTime returns the latest idle time if all instances are idle. If not all
// instances are idle, it returns a zero time.
func (s *Session) IdleTime() time.Time {
	if !s.Idle() {
		return time.Time{}
	}
	return s.mostRecentIdleTime()
}

// Inactive returns true if all instances are not active.
func (s *Session) Inactive() bool {
	for _, instance := range s.Instances() {
		if instance.active() {
			return false
		}
	}

	return true
}

// Instance returns the SessionInstance with the given instance number, or nil if not found.
func (s *Session) Instance(num uint8) *SessionInstance {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.instances[num]
}

// Invisible returns true if all instances are invisible.
func (s *Session) Invisible() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, instance := range s.instances {
		if !instance.Invisible() {
			return false
		}
	}

	return true
}

// mostRecentIdleTime returns the most recent idle time from all instances.
func (s *Session) mostRecentIdleTime() time.Time {
	var mostRecent time.Time
	for _, instance := range s.Instances() {
		if mostRecent.IsZero() || (instance.Idle() && instance.IdleTime().After(mostRecent)) {
			mostRecent = instance.IdleTime()
		}
	}

	return mostRecent
}

//
// Rate Limiting / Warning
//

// EvaluateRateLimit checks and updates the rate limit state.
func (s *Session) EvaluateRateLimit(now time.Time, rateClassID wire.RateLimitClassID) wire.RateLimitStatus {
	if s.AllUserInfoBitmask(wire.OServiceUserFlagBot) {
		return wire.RateLimitStatusClear // don't rate limit bots
	}

	s.mutex.Lock()
	rateClass := &s.rateLimitStates[rateClassID-1]

	status, newLevel := wire.CheckRateLimit(rateClass.LastTime, now, rateClass.RateClass, rateClass.CurrentLevel, rateClass.LimitedNow)
	rateClass.CurrentLevel = newLevel
	rateClass.CurrentStatus = status
	rateClass.LastTime = now
	rateClass.LimitedNow = status == wire.RateLimitStatusLimited
	s.mutex.Unlock()

	if status == wire.RateLimitStatusDisconnect {
		s.CloseSession()
	}

	return status
}

// ObserveRateChanges updates rate limit states and returns changes.
func (s *Session) ObserveRateChanges(now time.Time) (classDelta []RateClassState, stateDelta []RateClassState) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for i, params := range s.rateLimitStates {
		if !params.Subscribed {
			continue
		}

		state, level := wire.CheckRateLimit(params.LastTime, now, params.RateClass, params.CurrentLevel, params.LimitedNow)
		s.rateLimitStates[i].CurrentStatus = state

		// clear limited now flag if passing from limited state to clear state
		if s.rateLimitStates[i].LimitedNow && state == wire.RateLimitStatusClear {
			s.rateLimitStates[i].LimitedNow = false
			s.rateLimitStates[i].CurrentLevel = level
		}

		// did rate class change?
		if params.RateClass != s.lastObservedStates[i].RateClass {
			classDelta = append(classDelta, s.rateLimitStates[i])
		}

		// did rate limit status change?
		if s.lastObservedStates[i].CurrentStatus != s.rateLimitStates[i].CurrentStatus {
			stateDelta = append(stateDelta, s.rateLimitStates[i])
		}

		// save it for next time
		s.lastObservedStates[i] = s.rateLimitStates[i]
	}

	return classDelta, stateDelta
}

// RateLimitStates returns the current rate limit states (shared across all sessions).
func (s *Session) RateLimitStates() [5]RateClassState {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.rateLimitStates
}

// SetRateClasses sets the rate limit classes (shared across all sessions).
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
		s.lastObservedStates = s.rateLimitStates
	}

	s.rateLimitStates = newStates
	s.rateLimitStatesOriginal = newStates
}

// SetWarning sets the user's warning level (shared across all sessions).
func (s *Session) SetWarning(warning uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.warning = warning
}

// ScaleWarningAndRateLimit increments the user's warning level and scales rate limits.
func (s *Session) ScaleWarningAndRateLimit(incr int16, classID wire.RateLimitClassID) (bool, uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Handle warning level increment
	newWarning := int32(s.warning) + int32(incr)
	if newWarning > 1000 {
		return false, 0
	}
	if newWarning < 0 {
		s.warning = 0 // clamp min at 0
	} else {
		s.warning = uint16(newWarning)
	}

	pct := float32(incr) / 1000.0

	// create reference variables for better readability
	rateClass := &s.rateLimitStates[classID-1]
	originalRateClass := &s.rateLimitStatesOriginal[classID-1]

	// clamp function to constrain values between min and max
	clamp := func(value, min, max int32) int32 {
		if value < min {
			return min
		}
		if value > max {
			return max
		}
		return value
	}

	// Apply a buffer to limit/clear/alert levels so that they never approach
	// too close to the maximum level. Otherwise, AIM 4.8 exhibits instability
	// (client crashes, IM window glitches) when the warning level reaches 90-100%.
	maxLevel := originalRateClass.MaxLevel - 150

	// scale the rate limit parameters
	newLimitLevel := rateClass.LimitLevel + int32(float32(maxLevel-originalRateClass.LimitLevel)*pct)
	rateClass.LimitLevel = clamp(newLimitLevel, originalRateClass.LimitLevel, originalRateClass.MaxLevel)

	newLimitLevel = rateClass.ClearLevel + int32(float32(maxLevel-originalRateClass.ClearLevel)*pct)
	rateClass.ClearLevel = clamp(newLimitLevel, originalRateClass.ClearLevel, originalRateClass.MaxLevel)

	newLimitLevel = rateClass.AlertLevel + int32(float32(maxLevel-originalRateClass.AlertLevel)*pct)
	rateClass.AlertLevel = clamp(newLimitLevel, originalRateClass.AlertLevel, originalRateClass.MaxLevel)

	s.warningCh <- s.warning

	return true, s.warning
}

// SubscribeRateLimits subscribes to rate limit updates.
func (s *Session) SubscribeRateLimits(classes []wire.RateLimitClassID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, classID := range classes {
		s.rateLimitStates[classID-1].Subscribed = true
	}
}

// Warning returns the user's current warning level.
func (s *Session) Warning() uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.warning
}

// WarningCh returns the warning notification channel.
func (s *Session) WarningCh() chan uint16 {
	return s.warningCh
}

//
// Lifecycle
//

// CloseSession closes all instances in the session.
func (s *Session) CloseSession() {
	s.mutex.RLock()
	instances := make([]*SessionInstance, 0, len(s.instances))
	for _, instance := range s.instances {
		instances = append(instances, instance)
	}
	s.mutex.RUnlock()

	for _, instance := range instances {
		instance.closeOnly()
	}
}

// OnSessionClose registers a function to be called once all instances have closed.
func (s *Session) OnSessionClose(fn func()) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.onSessCloseFn = fn
}

// RunOnce executes the given function once across all invocations. Used to
// run arbitrary code that must only run once when the first session instance
// connects. The function must not block.
func (s *Session) RunOnce(fn func() error) error {
	var err error
	s.initOnce.Do(func() {
		err = fn()
	})
	return err
}

// SetNowFn sets the function used to get the current time. This is useful for testing.
func (s *Session) SetNowFn(fn func() time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.nowFn = fn
}

//
// User Settings / Attributes
//

// AllUserInfoBitmask returns whether all instances have user info flag set.
func (s *Session) AllUserInfoBitmask(flag uint16) bool {
	for _, instance := range s.Instances() {
		if instance.UserInfoBitmask()&flag != flag {
			return false
		}
	}
	return true
}

// AllUserStatusBitmask returns whether all instances have user status flag set.
func (s *Session) AllUserStatusBitmask(flag uint32) bool {
	for _, instance := range s.Instances() {
		if instance.UserStatusBitmask()&flag != flag {
			return false
		}
	}
	return true
}

// BuddyIcon returns the session's buddy icon metadata and reports whether it
// has been set.
func (s *Session) BuddyIcon() (wire.BARTID, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	icon := s.buddyIcon
	return icon, icon.Type != 0
}

// Caps returns the union of all capability UUIDs from all instances in the session.
func (s *Session) Caps() [][16]byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	caps := make(map[[16]byte]bool)

	for _, instance := range s.instances {
		for _, c := range instance.caps() {
			caps[c] = true
		}
	}

	ret := make([][16]byte, 0, len(caps))

	for c := range caps {
		ret = append(ret, c)
	}

	// Sort capabilities to ensure deterministic order
	slices.SortFunc(ret, func(a, b [16]byte) int {
		for i := 0; i < 16; i++ {
			if a[i] != b[i] {
				return int(a[i]) - int(b[i])
			}
		}
		return 0
	})

	return ret
}

// HasCap returns true if any instance in the session has the given capability UUID.
func (s *Session) HasCap(cap [16]byte) bool {
	for _, c := range s.Caps() {
		if c == cap {
			return true
		}
	}
	return false
}

// MemberSince reports when the user became a member.
func (s *Session) MemberSince() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.memberSince
}

// OfflineMsgCount returns the offline message count.
func (s *Session) OfflineMsgCount() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.offlineMsgCount
}

// Profile returns the most recently updated non-empty profile from all instances.
func (s *Session) Profile() UserProfile {
	var latest UserProfile

	for _, instance := range s.Instances() {
		profile := instance.Profile()
		if profile.IsEmpty() {
			continue
		}

		if latest.IsEmpty() || profile.UpdateTime.After(latest.UpdateTime) {
			latest = profile
		}
	}

	return latest
}

// SetBuddyIcon stores the session's buddy icon metadata.
func (s *Session) SetBuddyIcon(icon wire.BARTID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.buddyIcon = icon
}

// SetChatRoomCookie sets the chat room cookie.
func (s *Session) SetChatRoomCookie(cookie string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.chatRoomCookie = cookie
}

// SetMemberSince sets the member since timestamp.
func (s *Session) SetMemberSince(t time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.memberSince = t
}

// SetOfflineMsgCount sets the offline message count.
func (s *Session) SetOfflineMsgCount(count int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.offlineMsgCount = count
}

// SetSignonTime sets the session's sign-on time.
func (s *Session) SetSignonTime(t time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.signonTime = t
}

// SetTypingEventsEnabled sets whether the session wants to send and receive typing events.
func (s *Session) SetTypingEventsEnabled(enabled bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.typingEventsEnabled = enabled
}

// SignonTime returns the session's sign-on time.
func (s *Session) SignonTime() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.signonTime
}

// TLVUserInfo returns a TLV list containing session information aggregated from all instances.
func (s *Session) TLVUserInfo() wire.TLVUserInfo {
	return wire.TLVUserInfo{
		ScreenName:   s.DisplayScreenName().String(),
		WarningLevel: s.Warning(),
		TLVBlock: wire.TLVBlock{
			TLVList: s.userInfo(),
		},
	}
}

// TypingEventsEnabled indicates whether the session wants to send and receive typing events.
func (s *Session) TypingEventsEnabled() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.typingEventsEnabled
}

func (s *Session) userInfo() wire.TLVList {
	tlvs := wire.TLVList{}

	// sign-in timestamp
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(s.SignonTime().Unix())))

	instances := s.Instances()

	// Use the first instance as a template for user flags. Most flags are static
	// and should be consistent across all instances; only the "away" flag may vary.
	// If instances differ in protocol type (ICQ vs AIM), that indicates an error.
	var baseUserFlags uint16
	if len(instances) > 0 {
		baseUserFlags = instances[0].UserInfoBitmask()
	}

	if s.Away() {
		baseUserFlags |= wire.OServiceUserFlagUnavailable
	} else {
		baseUserFlags &^= wire.OServiceUserFlagUnavailable
	}

	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, baseUserFlags))

	// user status flags - user-level (shared)
	var statusBitmask uint32
	if len(instances) > 0 {
		statusBitmask = instances[0].UserStatusBitmask()
		for _, instance := range instances {
			statusBitmask &= instance.UserStatusBitmask()
		}
	}

	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, statusBitmask))

	// idle status - use most recent idle time if all instances are idle
	if s.Idle() {
		mostRecentIdleTime := s.mostRecentIdleTime()
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(s.nowFn().Sub(mostRecentIdleTime).Minutes())))
	}

	// set buddy icon metadata, if user has buddy icon
	if icon, hasIcon := s.BuddyIcon(); hasIcon {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, icon))
	}

	// ICQ direct-connect info. The TLV is required for buddy arrival events to
	// work in ICQ, even if the values are set to default.
	if baseUserFlags&wire.OServiceUserFlagICQ == wire.OServiceUserFlagICQ {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoICQDC, wire.ICQDCInfo{}))
	}

	caps := s.Caps()
	if len(caps) > 0 {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, caps))
	}

	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)))

	return tlvs
}

// SessionInstance represents a single client connection instance within a user's
// session. Multiple SessionInstance objects can belong to the same Session,
// allowing a user to maintain concurrent connections from different clients or
// devices.
//
// SessionInstance stores connection-specific state such as the remote address,
// sign-on completion status, client capabilities, idle state, and per-connection
// profile data. It holds a reference to its parent Session to access shared
// user-level data like identity, warning levels, and rate limiting state.
//
// All methods on SessionInstance are safe for concurrent use.
type SessionInstance struct {
	session *Session

	mutex sync.RWMutex

	// Unique instance identifier
	instanceNum uint8

	// Per-session connection state
	remoteAddr     *netip.AddrPort
	signonComplete bool
	closed         bool
	stopCh         chan struct{}
	msgCh          chan wire.SNACMessage
	kerberosAuth   bool

	// Per-session client information
	clientID          string
	capabilities      [][16]byte
	foodGroupVersions [wire.MDir + 1]uint16
	multiConnFlag     wire.MultiConnFlag

	// Per-session state
	idle              bool
	idleTime          time.Time
	awayMsg           string
	userInfoBitmask   uint16
	userStatusBitmask uint32

	// Per-session profile
	profile           UserProfile
	awayTime          time.Time
	onInstanceCloseFn func()
}

// Session returns the parent Session for this instance.
func (s *SessionInstance) Session() *Session {
	return s.session
}

//
// Identity
//

// ChatRoomCookie returns the chat room cookie from the parent session.
func (s *SessionInstance) ChatRoomCookie() string {
	return s.session.ChatRoomCookie()
}

// ClientID retrieves the instance's client ID.
func (s *SessionInstance) ClientID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.clientID
}

// DisplayScreenName returns the user's display screen name.
func (s *SessionInstance) DisplayScreenName() DisplayScreenName {
	return s.session.DisplayScreenName()
}

// IdentScreenName returns the user's identity screen name.
func (s *SessionInstance) IdentScreenName() IdentScreenName {
	return s.session.IdentScreenName()
}

// Num returns the unique instance identifier.
func (s *SessionInstance) Num() uint8 {
	return s.instanceNum
}

// UIN returns the user's ICQ number.
func (s *SessionInstance) UIN() uint32 {
	return s.session.UIN()
}

// SetClientID sets the instance's client ID.
func (s *SessionInstance) SetClientID(clientID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.clientID = clientID
}

//
// Status / Availability
//

// Away returns true if the instance is away.
func (s *SessionInstance) Away() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.away()
}

// AwayMessage returns the instance's away message and the time it was set.
func (s *SessionInstance) AwayMessage() (string, time.Time) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.awayMsg, s.awayTime
}

// Idle reports the instance's idle state.
func (s *SessionInstance) Idle() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.idle
}

// IdleTime reports when the instance went idle.
func (s *SessionInstance) IdleTime() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.idleTime
}

// Invisible returns true if the user is invisible.
func (s *SessionInstance) Invisible() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userStatusBitmask&wire.OServiceUserStatusInvisible == wire.OServiceUserStatusInvisible
}

// SetIdle sets the instance's idle state.
func (s *SessionInstance) SetIdle(dur time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idle = true
	// set the time the instance became idle
	s.idleTime = s.session.nowFn().Add(-dur)
}

// SetSignonComplete indicates that the instance has completed the sign-on sequence.
func (s *SessionInstance) SetSignonComplete() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.signonComplete = true
}

// SignonComplete indicates whether the instance has completed the sign-on sequence.
func (s *SessionInstance) SignonComplete() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.signonComplete
}

// UnsetIdle removes the instance's idle state.
func (s *SessionInstance) UnsetIdle() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idle = false
}

// active returns true if the instance is active. An instance is considered active if:
// - it is not closed
// - it has completed the sign-on sequence
// - it is not idle
// - it is not away
func (s *SessionInstance) active() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return !s.closed && s.signonComplete && !s.idle && !s.away()
}

// away checks if the instance is away based on bitmask flags.
// This method must be called while holding the mutex lock.
func (s *SessionInstance) away() bool {
	return s.userInfoBitmask&wire.OServiceUserFlagUnavailable != 0 ||
		s.userStatusBitmask&wire.OServiceUserStatusAway != 0
}

// live returns whether the instance is ready to receive messages.
func (s *SessionInstance) live() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return !s.closed && s.signonComplete
}

//
// Rate Limiting / Warning
//

// RateLimitStates returns the current rate limit states.
func (s *SessionInstance) RateLimitStates() [5]RateClassState {
	return s.session.RateLimitStates()
}

// Warning returns the user's current warning level.
func (s *SessionInstance) Warning() uint16 {
	return s.session.Warning()
}

// WarningCh returns the warning notification channel.
func (s *SessionInstance) WarningCh() chan uint16 {
	return s.session.WarningCh()
}

//
// Lifecycle
//

// Closed blocks until the instance is closed.
func (s *SessionInstance) Closed() <-chan struct{} {
	return s.stopCh
}

// CloseInstance shuts down the instance's ability to relay messages and removes it from the session.
func (s *SessionInstance) CloseInstance() {
	s.mutex.Lock()

	if s.closed {
		s.mutex.Unlock()
		return
	}
	close(s.stopCh)
	s.closed = true
	onInstanceCloseFn := s.onInstanceCloseFn
	s.mutex.Unlock()

	s.session.RemoveInstance(s)

	count := s.session.InstanceCount()
	if count == 0 {
		s.session.mutex.RLock()
		onSessCloseFn := s.session.onSessCloseFn
		s.session.mutex.RUnlock()
		onSessCloseFn()
	} else {
		onInstanceCloseFn()
	}
}

// OnClose registers a function to be called when the instance closes,
// but only if other instances remain in the session. If this is the last instance
// to close, OnSessionClose will be called instead.
func (s *SessionInstance) OnClose(fn func()) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.onInstanceCloseFn = fn
}

// CloseInstance shuts down the instance's ability to relay messages.
func (s *SessionInstance) closeOnly() {
	s.mutex.Lock()

	if s.closed {
		s.mutex.Unlock()
		return
	}
	close(s.stopCh)
	s.closed = true
	s.mutex.Unlock()

	s.session.RemoveInstance(s)
	if s.session.InstanceCount() == 0 {
		s.session.mutex.RLock()
		onSessCloseFn := s.session.onSessCloseFn
		s.session.mutex.RUnlock()
		onSessCloseFn()
	}
}

//
// User Settings / Attributes
//

// ClearUserInfoFlag clears a flag from the user info bitmask.
func (s *SessionInstance) ClearUserInfoFlag(flag uint16) (flags uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.userInfoBitmask &^= flag
	return s.userInfoBitmask
}

// FoodGroupVersions retrieves the instance's supported food group versions.
func (s *SessionInstance) FoodGroupVersions() [wire.MDir + 1]uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.foodGroupVersions
}

// KerberosAuth indicates whether Kerberos authentication was used for this instance.
func (s *SessionInstance) KerberosAuth() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.kerberosAuth
}

// MultiConnFlag retrieves the multi-connection flag for this instance.
func (s *SessionInstance) MultiConnFlag() wire.MultiConnFlag {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.multiConnFlag
}

// OfflineMsgCount returns the offline message count.
func (s *SessionInstance) OfflineMsgCount() int {
	return s.session.OfflineMsgCount()
}

// Profile returns the user's profile information.
func (s *SessionInstance) Profile() UserProfile {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.profile
}

// RemoteAddr returns the instance's remote IP address.
func (s *SessionInstance) RemoteAddr() (remoteAddr *netip.AddrPort) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.remoteAddr
}

// SetAwayMessage sets the instance's away message.
func (s *SessionInstance) SetAwayMessage(awayMessage string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.awayMsg = awayMessage
}

// SetCaps sets capability UUIDs for the instance.
func (s *SessionInstance) SetCaps(caps [][16]byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.capabilities = caps
}

// SetFoodGroupVersions sets the instance's supported food group versions.
func (s *SessionInstance) SetFoodGroupVersions(versions [wire.MDir + 1]uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.foodGroupVersions = versions
}

// SetKerberosAuth sets whether Kerberos authentication was used for this instance.
func (s *SessionInstance) SetKerberosAuth(enabled bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.kerberosAuth = enabled
}

// SetMultiConnFlag sets the multi-connection flag for this instance.
func (s *SessionInstance) SetMultiConnFlag(flag wire.MultiConnFlag) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.multiConnFlag = flag
}

// SetProfile sets the user's profile information.
func (s *SessionInstance) SetProfile(profile UserProfile) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.profile = profile
}

// SetRemoteAddr sets the instance's remote IP address.
func (s *SessionInstance) SetRemoteAddr(remoteAddr *netip.AddrPort) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.remoteAddr = remoteAddr
}

// SetUserInfoFlag sets a flag in the user info bitmask.
func (s *SessionInstance) SetUserInfoFlag(flag uint16) (flags uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if flag == wire.OServiceUserFlagUnavailable {
		s.awayTime = s.session.nowFn()
	}
	s.userInfoBitmask |= flag
	return s.userInfoBitmask
}

// SetUserStatusBitmask sets the user status bitmask.
func (s *SessionInstance) SetUserStatusBitmask(bitmask uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if bitmask&wire.OServiceUserStatusAway == wire.OServiceUserStatusAway {
		if !s.away() {
			s.awayTime = s.session.nowFn()
		}
	}
	s.userStatusBitmask = bitmask
}

// SignonTime returns the session's sign-on time.
func (s *SessionInstance) SignonTime() time.Time {
	return s.session.SignonTime()
}

// TypingEventsEnabled indicates whether the session wants to send and receive typing events.
func (s *SessionInstance) TypingEventsEnabled() bool {
	return s.session.TypingEventsEnabled()
}

// UserInfoBitmask returns the user info bitmask.
func (s *SessionInstance) UserInfoBitmask() uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userInfoBitmask
}

// UserStatusBitmask returns the user status bitmask.
func (s *SessionInstance) UserStatusBitmask() uint32 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userStatusBitmask
}

// caps retrieves instance capabilities.
func (s *SessionInstance) caps() [][16]byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.capabilities
}

//
// Message Sending
//

// ReceiveMessage returns a channel of messages relayed via this instance.
func (s *SessionInstance) ReceiveMessage() chan wire.SNACMessage {
	return s.msgCh
}

// RelayMessageToInstance receives a SNAC message and passes it to the instance's message channel.
func (s *SessionInstance) RelayMessageToInstance(msg wire.SNACMessage) SessSendStatus {
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
