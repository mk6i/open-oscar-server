package state

import (
	"bytes"
	"net/netip"
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

// Session represents shared user-level data across all sessions for a user.
// This contains data that is shared across multiple concurrent sessions for the same screen name.
type Session struct {
	mutex sync.RWMutex

	// User identity (shared across all sessions)
	displayScreenName DisplayScreenName
	identScreenName   IdentScreenName
	uin               uint32
	memberSince       time.Time

	// User-level settings and profile (shared)
	warning         uint16
	warningCh       chan uint16
	offlineMsgCount int
	chatRoomCookie  string

	// Rate limiting (shared across all sessions per user)
	rateLimitStates         [5]RateClassState
	rateLimitStatesOriginal [5]RateClassState
	lastObservedStates      [5]RateClassState

	// Active instances for this user
	instances []*SessionInstance
	// SessionInstance counter for this session group
	instanceCounter uint8

	initOnce sync.Once
	shutdown func()
}

// NewSession creates a new Session for a user.
func NewSession() *Session {
	return &Session{
		warningCh:       make(chan uint16, 1),
		instances:       make([]*SessionInstance, 0),
		instanceCounter: 0,
		shutdown:        func() {},
	}
}

// NewInstance creates a new SessionInstance within a Session.
func NewInstance(session *Session) *SessionInstance {
	instance := &SessionInstance{
		Session:           session,
		instanceNum:       session.generateInstanceNum(),
		msgCh:             make(chan wire.SNACMessage, 1000),
		nowFn:             time.Now,
		stopCh:            make(chan struct{}),
		signonTime:        time.Now(),
		caps:              make([][16]byte, 0),
		foodGroupVersions: defaultFoodGroupVersions(),
		userInfoBitmask:   wire.OServiceUserFlagOSCARFree,
		userStatusBitmask: wire.OServiceUserStatusAvailable,
	}
	session.AddInstance(instance)
	return instance
}

// ============================================================================
// Session methods (User-level data)
// ============================================================================

// AddInstance adds an instance to the session group.
func (s *Session) AddInstance(instance *SessionInstance) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.instances = append(s.instances, instance)
}

// RemoveInstance removes an instance from the session group.
func (s *Session) RemoveInstance(instance *SessionInstance) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for i, inst := range s.instances {
		if inst.instanceNum == instance.instanceNum {
			s.instances = append(s.instances[:i], s.instances[i+1:]...)
			break
		}
	}
}

// InstanceCount returns the number of total instances in the session group.
func (s *Session) InstanceCount() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.instances)
}

// Instances returns all live instances.
func (s *Session) Instances() []*SessionInstance {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.instances
}

// HasLiveInstances returns true if the session has at least one live instance.
func (s *Session) HasLiveInstances() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, instance := range s.instances {
		if instance.Live() {
			return true
		}
	}
	return false
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

// OnClose registers a function to be called once all instances have closed.
func (s *Session) OnClose(fn func()) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.shutdown = fn
}

// allAway returns true if all active instances are away.
func (s *Session) allAway() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	activeCount := 0
	awayCount := 0

	for _, instance := range s.instances {
		instance.mutex.RLock()
		if !instance.closed {
			activeCount++
			if instance.awayMessage != "" {
				awayCount++
			}
		}
		instance.mutex.RUnlock()
	}

	return activeCount > 0 && activeCount == awayCount
}

// allIdle returns true if all active instances are idle.
func (s *Session) allIdle() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	activeCount := 0
	idleCount := 0

	for _, instance := range s.instances {
		instance.mutex.RLock()
		if !instance.closed {
			activeCount++
			if instance.idle {
				idleCount++
			}
		}
		instance.mutex.RUnlock()
	}

	return activeCount > 0 && activeCount == idleCount
}

// AllInactive returns true if all instances are not active.
// An instance is considered inactive if it is closed, idle, or has an away message.
func (s *Session) AllInactive() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(s.instances) == 0 {
		return true // No instances means all are inactive
	}

	for _, instance := range s.instances {
		instance.mutex.RLock()
		isActive := !instance.closed && !instance.idle && instance.awayMessage == ""
		instance.mutex.RUnlock()

		if isActive {
			return false // Found at least one active instance
		}
	}

	return true // All instances are inactive
}

// mostRecentIdleTime returns the most recent idle time from all instances.
func (s *Session) mostRecentIdleTime() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var mostRecent time.Time
	for _, instance := range s.instances {
		instance.mutex.RLock()
		if !instance.closed && instance.idle && instance.idleTime.After(mostRecent) {
			mostRecent = instance.idleTime
		}
		instance.mutex.RUnlock()
	}

	return mostRecent
}

// SetDisplayScreenName sets the user's display screen name (shared across all sessions).
func (s *Session) SetDisplayScreenName(displayScreenName DisplayScreenName) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.displayScreenName = displayScreenName
}

// DisplayScreenName returns the user's display screen name.
func (s *Session) DisplayScreenName() DisplayScreenName {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.displayScreenName
}

// SetIdentScreenName sets the user's identity screen name (shared across all sessions).
func (s *Session) SetIdentScreenName(screenName IdentScreenName) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.identScreenName = screenName
}

// IdentScreenName returns the user's identity screen name.
func (s *Session) IdentScreenName() IdentScreenName {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.identScreenName
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

// SetWarning sets the user's warning level (shared across all sessions).
func (s *Session) SetWarning(warning uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.warning = warning
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

// EvaluateRateLimit checks and updates the rate limit state.
func (s *Session) EvaluateRateLimit(now time.Time, rateClassID wire.RateLimitClassID) wire.RateLimitStatus {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if all active instances are bots - don't rate limit bots
	allBots := true
	hasActiveInstances := false
	for _, instance := range s.instances {
		if !instance.closed {
			hasActiveInstances = true
			instance.mutex.RLock()
			isBot := instance.userInfoBitmask&wire.OServiceUserFlagBot == wire.OServiceUserFlagBot
			instance.mutex.RUnlock()
			if !isBot {
				allBots = false
				break
			}
		}
	}
	if hasActiveInstances && allBots {
		return wire.RateLimitStatusClear // don't rate limit bots
	}

	rateClass := &s.rateLimitStates[rateClassID-1]

	status, newLevel := wire.CheckRateLimit(rateClass.LastTime, now, rateClass.RateClass, rateClass.CurrentLevel, rateClass.LimitedNow)
	rateClass.CurrentLevel = newLevel
	rateClass.CurrentStatus = status
	rateClass.LastTime = now
	rateClass.LimitedNow = status == wire.RateLimitStatusLimited

	return status
}

// TLVUserInfo returns a TLV list containing session information aggregated from all instances.
func (s *Session) TLVUserInfo() wire.TLVUserInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return wire.TLVUserInfo{
		ScreenName:   string(s.displayScreenName),
		WarningLevel: uint16(s.warning),
		TLVBlock: wire.TLVBlock{
			TLVList: s.userInfo(),
		},
	}
}

func (s *Session) userInfo() wire.TLVList {
	tlvs := wire.TLVList{}

	// Get the best instance for each TLV value
	earliestInstance := s.getEarliestInstance()
	mostCapableCaps := s.getMostCapableCaps()

	// sign-in timestamp - use earliest instance
	if earliestInstance != nil {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(earliestInstance.signonTime.Unix())))
	}

	// user info flags - user-level with aggregated away status
	var uFlags uint16
	for _, instance := range s.instances {
		if !instance.closed {
			instance.mutex.RLock()
			uFlags = instance.userInfoBitmask
			instance.mutex.RUnlock()
			break
		}
	}
	if s.allAway() {
		uFlags |= wire.OServiceUserFlagUnavailable
	}
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uFlags))

	// user status flags - user-level (shared)
	var statusBitmask uint32
	for _, instance := range s.instances {
		if !instance.closed {
			instance.mutex.RLock()
			statusBitmask = instance.userStatusBitmask
			instance.mutex.RUnlock()
			break
		}
	}
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, statusBitmask))

	// idle status - use most recent idle time if all instances are idle
	if s.allIdle() {
		mostRecentIdleTime := s.mostRecentIdleTime()
		if !mostRecentIdleTime.IsZero() {
			// Find an instance with the most recent idle time to get the nowFn
			var nowFn func() time.Time
			for _, instance := range s.instances {
				if !instance.closed && instance.idle && instance.idleTime.Equal(mostRecentIdleTime) {
					nowFn = instance.nowFn
					break
				}
			}
			if nowFn != nil {
				tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(nowFn().Sub(mostRecentIdleTime).Minutes())))
			}
		}
	}

	// set buddy icon metadata, if user has buddy icon (from any instance)
	if bartID, hasIcon := s.BuddyIcon(); hasIcon {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, bartID))
	}

	// ICQ direct-connect info. The TLV is required for buddy arrival events to
	// work in ICQ, even if the values are set to default.
	if uFlags&wire.OServiceUserFlagICQ == wire.OServiceUserFlagICQ {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoICQDC, wire.ICQDCInfo{}))
	}

	// capabilities - show most capable instance (union of all capabilities)
	if len(mostCapableCaps) > 0 {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, mostCapableCaps))
	}

	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)))

	return tlvs
}

// getEarliestInstance returns the instance with the earliest signon time
func (s *Session) getEarliestInstance() *SessionInstance {
	var earliest *SessionInstance
	for _, instance := range s.instances {
		if !instance.closed {
			if earliest == nil || instance.signonTime.Before(earliest.signonTime) {
				earliest = instance
			}
		}
	}
	return earliest
}

// getMostCapableCaps returns the union of all capabilities from all instances
func (s *Session) getMostCapableCaps() [][16]byte {
	capMap := make(map[[16]byte]bool)

	for _, instance := range s.instances {
		if !instance.closed {
			for _, cap := range instance.caps {
				capMap[cap] = true
			}
		}
	}

	// Convert map back to slice and sort for deterministic order
	caps := make([][16]byte, 0, len(capMap))
	for cap := range capMap {
		caps = append(caps, cap)
	}

	// Sort capabilities by their byte values for deterministic order
	for i := 0; i < len(caps); i++ {
		for j := i + 1; j < len(caps); j++ {
			if bytes.Compare(caps[i][:], caps[j][:]) > 0 {
				caps[i], caps[j] = caps[j], caps[i]
			}
		}
	}

	return caps
}

// BuddyIcon returns the buddy icon from the first instance that has one set.
func (s *Session) BuddyIcon() (wire.BARTID, bool) {
	for _, instance := range s.instances {
		if !instance.closed {
			instance.mutex.RLock()
			if instance.buddyIcon.Type != 0 {
				icon := instance.buddyIcon
				instance.mutex.RUnlock()
				return icon, true
			}
			instance.mutex.RUnlock()
		}
	}
	return wire.BARTID{}, false
}

// AwayMessage returns the away message if all instances are away. It returns
// the away message from the first instance that has one set. If not all
// instances are away, it returns an empty string.
func (s *Session) AwayMessage() string {
	if !s.allAway() {
		return ""
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, instance := range s.instances {
		if !instance.closed {
			instance.mutex.RLock()
			if instance.awayMessage != "" {
				msg := instance.awayMessage
				instance.mutex.RUnlock()
				return msg
			}
			instance.mutex.RUnlock()
		}
	}
	return ""
}

// Profile returns the first non-empty profile from all instances.
func (s *Session) Profile() UserProfile {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, instance := range s.instances {
		if !instance.closed {
			instance.mutex.RLock()
			if !instance.profile.Empty() {
				profile := instance.profile
				instance.mutex.RUnlock()
				return profile
			}
			instance.mutex.RUnlock()
		}
	}
	return UserProfile{}
}

// SignonTime returns the signon time from the earliest instance.
func (s *Session) SignonTime() time.Time {
	earliestInstance := s.getEarliestInstance()
	if earliestInstance != nil {
		return earliestInstance.SignonTime()
	}
	return time.Time{}
}

// Close closes all instances in the session.
func (s *Session) Close() {
	s.mutex.RLock()
	instances := make([]*SessionInstance, len(s.instances))
	copy(instances, s.instances)
	s.mutex.RUnlock()

	for _, instance := range instances {
		instance.Close()
	}
}

// Idle returns true if all active instances are idle.
func (s *Session) Idle() bool {
	return s.allIdle()
}

// IdleTime returns the latest idle time if all instances are idle. If not all
// instances are idle, it returns a zero time.
func (s *Session) IdleTime() time.Time {
	if !s.allIdle() {
		return time.Time{}
	}
	return s.mostRecentIdleTime()
}

// generateInstanceNum generates the next instance number for this session group.
func (s *Session) generateInstanceNum() uint8 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.instanceCounter++
	if s.instanceCounter == 0 {
		s.instanceCounter = 1 // Start from 1, skip 0
	}
	return s.instanceCounter
}

// SetMemberSince sets the member since timestamp.
func (s *Session) SetMemberSince(t time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.memberSince = t
}

// MemberSince reports when the user became a member.
func (s *Session) MemberSince() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.memberSince
}

// SetOfflineMsgCount sets the offline message count.
func (s *Session) SetOfflineMsgCount(count int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.offlineMsgCount = count
}

// OfflineMsgCount returns the offline message count.
func (s *Session) OfflineMsgCount() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.offlineMsgCount
}

// SetChatRoomCookie sets the chat room cookie.
func (s *Session) SetChatRoomCookie(cookie string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.chatRoomCookie = cookie
}

// ChatRoomCookie gets the chat room cookie.
func (s *Session) ChatRoomCookie() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.chatRoomCookie
}

// UserInfoBitmask returns the user info bitmask from the first instance.
func (s *Session) UserInfoBitmask() uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(s.instances) == 0 {
		return 0
	}

	// Get from first instance
	for _, instance := range s.instances {
		if !instance.closed {
			instance.mutex.RLock()
			bitmask := instance.userInfoBitmask
			instance.mutex.RUnlock()
			return bitmask
		}
	}
	return 0
}

// UserStatusBitmask returns the user status bitmask from the first instance.
func (s *Session) UserStatusBitmask() uint32 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(s.instances) == 0 {
		return 0
	}

	// Get from first instance
	for _, instance := range s.instances {
		if !instance.closed {
			instance.mutex.RLock()
			bitmask := instance.userStatusBitmask
			instance.mutex.RUnlock()
			return bitmask
		}
	}
	return 0
}

func (s *Session) Instance(num uint8) *SessionInstance {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, instance := range s.instances {
		if instance.instanceNum == num {
			return instance
		}
	}
	return nil
}

// SessionInstance represents a single session instance with per-session data.
// Each SessionInstance embeds a reference to its parent Session.
type SessionInstance struct {
	*Session

	mutex sync.RWMutex

	// Unique instance identifier
	instanceNum uint8

	// Per-session connection state
	remoteAddr     *netip.AddrPort
	signonTime     time.Time
	signonComplete bool
	closed         bool
	stopCh         chan struct{}
	msgCh          chan wire.SNACMessage
	kerberosAuth   bool

	// Per-session client information
	clientID            string
	caps                [][16]byte
	foodGroupVersions   [wire.MDir + 1]uint16
	multiConnFlag       wire.MultiConnFlag
	typingEventsEnabled bool

	// Per-session state
	idle              bool
	idleTime          time.Time
	awayMessage       string
	nowFn             func() time.Time
	userInfoBitmask   uint16
	userStatusBitmask uint32

	// Per-session profile and buddy icon
	profile   UserProfile
	buddyIcon wire.BARTID
}

// SetRemoteAddr sets the instance's remote IP address.
func (s *SessionInstance) SetRemoteAddr(remoteAddr *netip.AddrPort) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.remoteAddr = remoteAddr
}

// RemoteAddr returns the instance's remote IP address.
func (s *SessionInstance) RemoteAddr() (remoteAddr *netip.AddrPort) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.remoteAddr
}

// SetSignonTime sets the instance's sign-on time.
func (s *SessionInstance) SetSignonTime(t time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.signonTime = t
}

// SignonTime reports when the instance signed on.
func (s *SessionInstance) SignonTime() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.signonTime
}

// SignonComplete indicates whether the instance has completed the sign-on sequence.
func (s *SessionInstance) SignonComplete() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.signonComplete
}

// SetSignonComplete indicates that the instance has completed the sign-on sequence.
func (s *SessionInstance) SetSignonComplete() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.signonComplete = true
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

// SetIdle sets the instance's idle state.
func (s *SessionInstance) SetIdle(dur time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idle = true
	// set the time the instance became idle
	s.idleTime = s.nowFn().Add(-dur)
}

// UnsetIdle removes the instance's idle state.
func (s *SessionInstance) UnsetIdle() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idle = false
}

// SetAwayMessage sets the instance's away message.
func (s *SessionInstance) SetAwayMessage(awayMessage string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.awayMessage = awayMessage
}

// AwayMessage returns the instance's away message.
func (s *SessionInstance) AwayMessage() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.awayMessage
}

// SetClientID sets the instance's client ID.
func (s *SessionInstance) SetClientID(clientID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.clientID = clientID
}

// ClientID retrieves the instance's client ID.
func (s *SessionInstance) ClientID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.clientID
}

// SetCaps sets capability UUIDs for the instance.
func (s *SessionInstance) SetCaps(caps [][16]byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.caps = caps
}

// Caps retrieves instance capabilities.
func (s *SessionInstance) Caps() [][16]byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.caps
}

// SetFoodGroupVersions sets the instance's supported food group versions.
func (s *SessionInstance) SetFoodGroupVersions(versions [wire.MDir + 1]uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.foodGroupVersions = versions
}

// FoodGroupVersions retrieves the instance's supported food group versions.
func (s *SessionInstance) FoodGroupVersions() [wire.MDir + 1]uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.foodGroupVersions
}

// SetTypingEventsEnabled sets whether the instance wants to send and receive typing events.
func (s *SessionInstance) SetTypingEventsEnabled(enabled bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.typingEventsEnabled = enabled
}

// TypingEventsEnabled indicates whether the instance wants to send and receive typing events.
func (s *SessionInstance) TypingEventsEnabled() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.typingEventsEnabled
}

// SetMultiConnFlag sets the multi-connection flag for this instance.
func (s *SessionInstance) SetMultiConnFlag(flag wire.MultiConnFlag) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.multiConnFlag = flag
}

// MultiConnFlag retrieves the multi-connection flag for this instance.
func (s *SessionInstance) MultiConnFlag() wire.MultiConnFlag {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.multiConnFlag
}

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

// Close shuts down the instance's ability to relay messages.
func (s *SessionInstance) Close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.close()
}

func (s *SessionInstance) close() {
	if s.closed {
		return
	}
	close(s.stopCh)
	s.closed = true
	// Remove this instance from its session group
	s.Session.RemoveInstance(s)
	if s.InstanceCount() == 0 {
		s.shutdown()
	}
}

// Closed blocks until the instance is closed.
func (s *SessionInstance) Closed() <-chan struct{} {
	return s.stopCh
}

func (s *SessionInstance) IsClosed() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.closed
}

// InstanceNum returns the unique instance identifier.
func (s *SessionInstance) InstanceNum() uint8 {
	return s.instanceNum
}

// Live returns whether the instance is ready to receive messages.
func (s *SessionInstance) Live() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return !s.closed && s.signonComplete
}

// Active returns true if the instance is active. An instance is considered active if:
// - it is not closed
// - it has completed the sign-on sequence
// - it is not idle
// - it has no away message
func (s *SessionInstance) Active() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return !s.closed && s.signonComplete && !s.idle && s.awayMessage == ""
}

// ============================================================================
// SessionInstance methods (Backward compatibility wrapper)
// ============================================================================

// Invisible returns true if the user is invisible.
func (s *SessionInstance) Invisible() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userStatusBitmask&wire.OServiceUserStatusInvisible == wire.OServiceUserStatusInvisible
}

// EvaluateRateLimit checks and updates the session's rate limit state
// for the given rate class ID. If the rate status reaches 'disconnect',
// the session is closed. Rate limits are not enforced if the user is a bot
// (has wire.OServiceUserFlagBot set in their user info bitmask).
func (s *SessionInstance) EvaluateRateLimit(now time.Time, rateClassID wire.RateLimitClassID) wire.RateLimitStatus {
	status := s.Session.EvaluateRateLimit(now, rateClassID)

	if status == wire.RateLimitStatusDisconnect {
		s.Close()
	}

	return status
}

// Helper functions

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

// SetKerberosAuth sets whether Kerberos authentication was used for this session.
func (s *SessionInstance) SetKerberosAuth(enabled bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.kerberosAuth = enabled
}

// KerberosAuth indicates whether Kerberos authentication was used for this session.
func (s *SessionInstance) KerberosAuth() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.kerberosAuth
}

// SetProfile sets the user's profile information.
func (s *SessionInstance) SetProfile(profile UserProfile) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.profile = profile
}

// Profile returns the user's profile information.
func (s *SessionInstance) Profile() UserProfile {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.profile
}

// SetBuddyIcon stores the session's buddy icon metadata.
func (s *SessionInstance) SetBuddyIcon(icon wire.BARTID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.buddyIcon = icon
}

// BuddyIcon returns the session's buddy icon metadata and reports whether it
// has been set. The icon is considered set if its type is non-zero.
func (s *SessionInstance) BuddyIcon() (wire.BARTID, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	icon := s.buddyIcon
	return icon, icon.Type != 0
}

// SetUserInfoFlag sets a flag in the user info bitmask.
func (s *SessionInstance) SetUserInfoFlag(flag uint16) (flags uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.userInfoBitmask |= flag
	return s.userInfoBitmask
}

// ClearUserInfoFlag clears a flag from the user info bitmask.
func (s *SessionInstance) ClearUserInfoFlag(flag uint16) (flags uint16) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.userInfoBitmask &^= flag
	return s.userInfoBitmask
}

// UserInfoBitmask returns the user info bitmask.
func (s *SessionInstance) UserInfoBitmask() uint16 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userInfoBitmask
}

// SetUserStatusBitmask sets the user status bitmask.
func (s *SessionInstance) SetUserStatusBitmask(bitmask uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.userStatusBitmask = bitmask
}

// UserStatusBitmask returns the user status bitmask.
func (s *SessionInstance) UserStatusBitmask() uint32 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.userStatusBitmask
}

// RelayMessage receives a SNAC message from a user and passes it on
// asynchronously to the consumer of this session's messages. It returns
// SessSendStatus to indicate whether the message was successfully sent or
// not. This method is non-blocking.
func (s *SessionInstance) RelayMessage(msg wire.SNACMessage) SessSendStatus {
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
