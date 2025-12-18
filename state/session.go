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

// SessionGroup represents shared user-level data across all sessions for a user.
// This contains data that is shared across multiple concurrent sessions for the same screen name.
type SessionGroup struct {
	mutex sync.RWMutex

	// User identity (shared across all sessions)
	displayScreenName DisplayScreenName
	identScreenName   IdentScreenName
	uin               uint32
	memberSince       time.Time

	// User-level settings and profile (shared)
	userInfoBitmask   uint16
	userStatusBitmask uint32
	warning           uint16
	warningCh         chan uint16
	profile           UserProfile
	buddyIcon         wire.BARTID
	offlineMsgCount   int

	// Rate limiting (shared across all sessions per user)
	rateLimitStates         [5]RateClassState
	rateLimitStatesOriginal [5]RateClassState
	lastObservedStates      [5]RateClassState

	// Active instances for this user
	instances []*Instance
	// Instance counter for this session group
	instanceCounter uint8
}

// Instance represents a single session instance with per-session data.
// Each Instance embeds a reference to its parent SessionGroup.
type Instance struct {
	*SessionGroup

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
	idle           bool
	idleTime       time.Time
	awayMessage    string
	chatRoomCookie string
	nowFn          func() time.Time
}

// Session represents a user's current session. This is the main interface that
// maintains backward compatibility while internally using SessionGroup and Instance.
type Session struct {
	*SessionGroup
	*Instance
}

// NewSession returns a new instance of Session with embedded SessionGroup and Instance.
func NewSession() *Session {
	sessionGroup := NewSessionGroup()
	instance := NewInstance(sessionGroup)
	sessionGroup.AddInstance(instance)

	return &Session{
		SessionGroup: sessionGroup,
		Instance:     instance,
	}
}

// NewSessionGroup creates a new SessionGroup for a user.
func NewSessionGroup() *SessionGroup {
	return &SessionGroup{
		userInfoBitmask:   wire.OServiceUserFlagOSCARFree,
		userStatusBitmask: wire.OServiceUserStatusAvailable,
		warningCh:         make(chan uint16, 1),
		instances:         make([]*Instance, 0),
		instanceCounter:   0,
	}
}

// NewInstance creates a new Instance within a SessionGroup.
func NewInstance(sessionGroup *SessionGroup) *Instance {
	now := time.Now()
	instanceNum := sessionGroup.generateInstanceNum()

	return &Instance{
		SessionGroup:      sessionGroup,
		instanceNum:       instanceNum,
		msgCh:             make(chan wire.SNACMessage, 1000),
		nowFn:             time.Now,
		stopCh:            make(chan struct{}),
		signonTime:        now,
		caps:              make([][16]byte, 0),
		foodGroupVersions: defaultFoodGroupVersions(),
	}
}

// ============================================================================
// SessionGroup methods (User-level data)
// ============================================================================

// AddInstance adds an instance to the session group.
func (sg *SessionGroup) AddInstance(instance *Instance) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.instances = append(sg.instances, instance)
}

// RemoveInstance removes an instance from the session group.
func (sg *SessionGroup) RemoveInstance(instance *Instance) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	for i, inst := range sg.instances {
		if inst.instanceNum == instance.instanceNum {
			sg.instances = append(sg.instances[:i], sg.instances[i+1:]...)
			break
		}
	}
}

// InstanceCount returns the number of total instances in the session group.
func (sg *SessionGroup) InstanceCount() int {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return len(sg.instances)
}

// GetInstances returns a copy of all active instances.
func (sg *SessionGroup) GetInstances() []*Instance {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	instances := make([]*Instance, len(sg.instances))
	copy(instances, sg.instances) // todo what? do we copy here?
	return instances
}

// GetActiveInstances returns only non-closed instances.
func (sg *SessionGroup) GetActiveInstances() []*Instance {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	var active []*Instance
	for _, instance := range sg.instances {
		instance.mutex.RLock()
		if !instance.closed {
			active = append(active, instance)
		}
		instance.mutex.RUnlock()
	}
	return active
}

// GetNonAwayInstances returns instances that are not away.
func (sg *SessionGroup) GetNonAwayInstances() []*Instance {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	var nonAway []*Instance
	for _, instance := range sg.instances {
		instance.mutex.RLock()
		if !instance.closed && instance.awayMessage == "" {
			nonAway = append(nonAway, instance)
		}
		instance.mutex.RUnlock()
	}
	return nonAway
}

// IsAllAway returns true if all active instances are away.
func (sg *SessionGroup) IsAllAway() bool {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	activeCount := 0
	awayCount := 0

	for _, instance := range sg.instances {
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

// IsAllIdle returns true if all active instances are idle.
func (sg *SessionGroup) IsAllIdle() bool {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	activeCount := 0
	idleCount := 0

	for _, instance := range sg.instances {
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
func (sg *SessionGroup) AllInactive() bool {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	if len(sg.instances) == 0 {
		return true // No instances means all are inactive
	}

	for _, instance := range sg.instances {
		instance.mutex.RLock()
		isActive := !instance.closed && !instance.idle && instance.awayMessage == ""
		instance.mutex.RUnlock()

		if isActive {
			return false // Found at least one active instance
		}
	}

	return true // All instances are inactive
}

// GetMostRecentIdleTime returns the most recent idle time from all instances.
func (sg *SessionGroup) GetMostRecentIdleTime() time.Time {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	var mostRecent time.Time
	for _, instance := range sg.instances {
		instance.mutex.RLock()
		if !instance.closed && instance.idle && instance.idleTime.After(mostRecent) {
			mostRecent = instance.idleTime
		}
		instance.mutex.RUnlock()
	}

	return mostRecent
}

// SetDisplayScreenName sets the user's display screen name (shared across all sessions).
func (sg *SessionGroup) SetDisplayScreenName(displayScreenName DisplayScreenName) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.displayScreenName = displayScreenName
}

// DisplayScreenName returns the user's display screen name.
func (sg *SessionGroup) DisplayScreenName() DisplayScreenName {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.displayScreenName
}

// SetIdentScreenName sets the user's identity screen name (shared across all sessions).
func (sg *SessionGroup) SetIdentScreenName(screenName IdentScreenName) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.identScreenName = screenName
}

// IdentScreenName returns the user's identity screen name.
func (sg *SessionGroup) IdentScreenName() IdentScreenName {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.identScreenName
}

// SetUIN sets the user's ICQ number (shared across all sessions).
func (sg *SessionGroup) SetUIN(uin uint32) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.uin = uin
}

// UIN returns the user's ICQ number.
func (sg *SessionGroup) UIN() uint32 {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.uin
}

// SetUserInfoFlag sets a flag in the user info bitmask (shared across all sessions).
func (sg *SessionGroup) SetUserInfoFlag(flag uint16) (flags uint16) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.userInfoBitmask |= flag
	return sg.userInfoBitmask
}

// ClearUserInfoFlag clears a flag from the user info bitmask (shared across all sessions).
func (sg *SessionGroup) ClearUserInfoFlag(flag uint16) (flags uint16) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.userInfoBitmask &^= flag
	return sg.userInfoBitmask
}

// UserInfoBitmask returns the user info bitmask.
func (sg *SessionGroup) UserInfoBitmask() (flags uint16) {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.userInfoBitmask
}

// SetUserStatusBitmask sets the user status bitmask (shared across all sessions).
func (sg *SessionGroup) SetUserStatusBitmask(bitmask uint32) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.userStatusBitmask = bitmask
}

// UserStatusBitmask returns the user status bitmask.
func (sg *SessionGroup) UserStatusBitmask() uint32 {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.userStatusBitmask
}

// SetWarning sets the user's warning level (shared across all sessions).
func (sg *SessionGroup) SetWarning(warning uint16) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.warning = warning
}

// Warning returns the user's current warning level.
func (sg *SessionGroup) Warning() uint16 {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.warning
}

// WarningCh returns the warning notification channel.
func (sg *SessionGroup) WarningCh() chan uint16 {
	return sg.warningCh
}

// RateLimitStates returns the current rate limit states (shared across all sessions).
func (sg *SessionGroup) RateLimitStates() [5]RateClassState {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.rateLimitStates
}

// SetRateClasses sets the rate limit classes (shared across all sessions).
func (sg *SessionGroup) SetRateClasses(now time.Time, classes wire.RateLimitClasses) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	var newStates [5]RateClassState
	for i, class := range classes.All() {
		newStates[i] = RateClassState{
			CurrentLevel:  class.MaxLevel,
			CurrentStatus: wire.RateLimitStatusClear,
			LastTime:      now,
			RateClass:     class,
			Subscribed:    sg.lastObservedStates[i].Subscribed,
		}
	}

	if sg.lastObservedStates[0].ID == 0 {
		sg.lastObservedStates = newStates
	} else {
		sg.lastObservedStates = sg.rateLimitStates
	}

	sg.rateLimitStates = newStates
	sg.rateLimitStatesOriginal = newStates
}

// ScaleWarningAndRateLimit increments the user's warning level and scales rate limits.
func (sg *SessionGroup) ScaleWarningAndRateLimit(incr int16, classID wire.RateLimitClassID) (bool, uint16) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	// Handle warning level increment
	newWarning := int32(sg.warning) + int32(incr)
	if newWarning > 1000 {
		return false, 0
	}
	if newWarning < 0 {
		sg.warning = 0 // clamp min at 0
	} else {
		sg.warning = uint16(newWarning)
	}

	pct := float32(incr) / 1000.0

	// create reference variables for better readability
	rateClass := &sg.rateLimitStates[classID-1]
	originalRateClass := &sg.rateLimitStatesOriginal[classID-1]

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

	sg.warningCh <- sg.warning

	return true, sg.warning
}

// SubscribeRateLimits subscribes to rate limit updates.
func (sg *SessionGroup) SubscribeRateLimits(classes []wire.RateLimitClassID) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	for _, classID := range classes {
		sg.rateLimitStates[classID-1].Subscribed = true
	}
}

// ObserveRateChanges updates rate limit states and returns changes.
func (sg *SessionGroup) ObserveRateChanges(now time.Time) (classDelta []RateClassState, stateDelta []RateClassState) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	for i, params := range sg.rateLimitStates {
		if !params.Subscribed {
			continue
		}

		state, level := wire.CheckRateLimit(params.LastTime, now, params.RateClass, params.CurrentLevel, params.LimitedNow)
		sg.rateLimitStates[i].CurrentStatus = state

		// clear limited now flag if passing from limited state to clear state
		if sg.rateLimitStates[i].LimitedNow && state == wire.RateLimitStatusClear {
			sg.rateLimitStates[i].LimitedNow = false
			sg.rateLimitStates[i].CurrentLevel = level
		}

		// did rate class change?
		if params.RateClass != sg.lastObservedStates[i].RateClass {
			classDelta = append(classDelta, sg.rateLimitStates[i])
		}

		// did rate limit status change?
		if sg.lastObservedStates[i].CurrentStatus != sg.rateLimitStates[i].CurrentStatus {
			stateDelta = append(stateDelta, sg.rateLimitStates[i])
		}

		// save it for next time
		sg.lastObservedStates[i] = sg.rateLimitStates[i]
	}

	return classDelta, stateDelta
}

// EvaluateRateLimit checks and updates the rate limit state.
func (sg *SessionGroup) EvaluateRateLimit(now time.Time, rateClassID wire.RateLimitClassID) wire.RateLimitStatus {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	if sg.userInfoBitmask&wire.OServiceUserFlagBot == wire.OServiceUserFlagBot {
		return wire.RateLimitStatusClear // don't rate limit bots
	}

	rateClass := &sg.rateLimitStates[rateClassID-1]

	status, newLevel := wire.CheckRateLimit(rateClass.LastTime, now, rateClass.RateClass, rateClass.CurrentLevel, rateClass.LimitedNow)
	rateClass.CurrentLevel = newLevel
	rateClass.CurrentStatus = status
	rateClass.LastTime = now
	rateClass.LimitedNow = status == wire.RateLimitStatusLimited

	return status
}

// RelayMessage receives a SNAC message and passes it to all active instances.
// Returns SessSendOK if at least one instance successfully received the message,
// SessSendClosed if no active instances exist, or SessQueueFull if all instances
// have full message queues.
func (sg *SessionGroup) RelayMessage(msg wire.SNACMessage) SessSendStatus {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	activeInstances := 0
	successfulSends := 0
	fullQueues := 0

	for _, instance := range sg.instances {
		instance.mutex.RLock()
		if !instance.closed {
			activeInstances++
			select {
			case instance.msgCh <- msg:
				successfulSends++
			case <-instance.stopCh:
				// Instance is closed, skip it
			default:
				// Queue is full for this instance
				fullQueues++
			}
		}
		instance.mutex.RUnlock()
	}

	if activeInstances == 0 {
		return SessSendClosed
	}

	if successfulSends > 0 {
		return SessSendOK
	}

	if fullQueues == activeInstances {
		return SessQueueFull
	}

	return SessSendClosed
}

func (sg *SessionGroup) RelayMessageExceptSelf(self *Instance, msg wire.SNACMessage) SessSendStatus {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	activeInstances := 0
	successfulSends := 0
	fullQueues := 0

	for _, instance := range sg.instances {
		if instance == self {
			continue
		}
		instance.mutex.RLock()
		if !instance.closed {
			activeInstances++
			select {
			case instance.msgCh <- msg:
				successfulSends++
			case <-instance.stopCh:
				// Instance is closed, skip it
			default:
				// Queue is full for this instance
				fullQueues++
			}
		}
		instance.mutex.RUnlock()
	}

	if activeInstances == 0 {
		return SessSendClosed
	}

	if successfulSends > 0 {
		return SessSendOK
	}

	if fullQueues == activeInstances {
		return SessQueueFull
	}

	return SessSendClosed
}

func (sg *SessionGroup) RelayMessageActiveOnly(msg wire.SNACMessage) SessSendStatus {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	activeInstances := 0
	successfulSends := 0
	fullQueues := 0

	for _, instance := range sg.instances {
		if !instance.Active() {
			continue
		}
		instance.mutex.RLock()
		if !instance.closed {
			activeInstances++
			select {
			case instance.msgCh <- msg:
				successfulSends++
			case <-instance.stopCh:
				// Instance is closed, skip it
			default:
				// Queue is full for this instance
				fullQueues++
			}
		}
		instance.mutex.RUnlock()
	}

	if activeInstances == 0 {
		return SessSendClosed
	}

	if successfulSends > 0 {
		return SessSendOK
	}

	if fullQueues == activeInstances {
		return SessQueueFull
	}

	return SessSendClosed
}

// TLVUserInfo returns a TLV list containing session information aggregated from all instances.
func (sg *SessionGroup) TLVUserInfo() wire.TLVUserInfo {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()

	return wire.TLVUserInfo{
		ScreenName:   string(sg.displayScreenName),
		WarningLevel: uint16(sg.warning),
		TLVBlock: wire.TLVBlock{
			TLVList: sg.userInfo(),
		},
	}
}

func (sg *SessionGroup) userInfo() wire.TLVList {
	tlvs := wire.TLVList{}

	// Get the best instance for each TLV value
	earliestInstance := sg.getEarliestInstance()
	mostCapableCaps := sg.getMostCapableCaps()

	// sign-in timestamp - use earliest instance
	if earliestInstance != nil {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(earliestInstance.signonTime.Unix())))
	}

	// user info flags - user-level with aggregated away status
	uFlags := sg.userInfoBitmask
	if sg.IsAllAway() {
		uFlags |= wire.OServiceUserFlagUnavailable
	}
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uFlags))

	// user status flags - user-level (shared)
	tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, sg.userStatusBitmask))

	// idle status - use most recent idle time if all instances are idle
	if sg.IsAllIdle() {
		mostRecentIdleTime := sg.GetMostRecentIdleTime()
		if !mostRecentIdleTime.IsZero() {
			// Find an instance with the most recent idle time to get the nowFn
			var nowFn func() time.Time
			for _, instance := range sg.instances {
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

	// set buddy icon metadata, if user has buddy icon
	if bartID, hasIcon := sg.BuddyIcon(); hasIcon {
		tlvs.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, bartID))
	}

	// ICQ direct-connect info. The TLV is required for buddy arrival events to
	// work in ICQ, even if the values are set to default.
	if sg.userInfoBitmask&wire.OServiceUserFlagICQ == wire.OServiceUserFlagICQ {
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
func (sg *SessionGroup) getEarliestInstance() *Instance {
	var earliest *Instance
	for _, instance := range sg.instances {
		if !instance.closed {
			if earliest == nil || instance.signonTime.Before(earliest.signonTime) {
				earliest = instance
			}
		}
	}
	return earliest
}

// getMostCapableCaps returns the union of all capabilities from all instances
func (sg *SessionGroup) getMostCapableCaps() [][16]byte {
	capMap := make(map[[16]byte]bool)

	for _, instance := range sg.instances {
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

// ============================================================================
// Instance methods (Session-specific data)
// ============================================================================

// SetRemoteAddr sets the instance's remote IP address.
func (i *Instance) SetRemoteAddr(remoteAddr *netip.AddrPort) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.remoteAddr = remoteAddr
}

// RemoteAddr returns the instance's remote IP address.
func (i *Instance) RemoteAddr() (remoteAddr *netip.AddrPort) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.remoteAddr
}

// SetSignonTime sets the instance's sign-on time.
func (i *Instance) SetSignonTime(t time.Time) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.signonTime = t
}

// SignonTime reports when the instance signed on.
func (i *Instance) SignonTime() time.Time {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.signonTime
}

// SignonComplete indicates whether the instance has completed the sign-on sequence.
func (i *Instance) SignonComplete() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.signonComplete
}

// SetSignonComplete indicates that the instance has completed the sign-on sequence.
func (i *Instance) SetSignonComplete() {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.signonComplete = true
}

// Idle reports the instance's idle state.
func (i *Instance) Idle() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.idle
}

// IdleTime reports when the instance went idle.
func (i *Instance) IdleTime() time.Time {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.idleTime
}

// SetIdle sets the instance's idle state.
func (i *Instance) SetIdle(dur time.Duration) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.idle = true
	// set the time the instance became idle
	i.idleTime = i.nowFn().Add(-dur)
}

// UnsetIdle removes the instance's idle state.
func (i *Instance) UnsetIdle() {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.idle = false
}

// SetAwayMessage sets the instance's away message.
func (i *Instance) SetAwayMessage(awayMessage string) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.awayMessage = awayMessage
}

// AwayMessage returns the instance's away message.
func (i *Instance) AwayMessage() string {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.awayMessage
}

// SetChatRoomCookie sets the chat room cookie for the instance.
func (i *Instance) SetChatRoomCookie(cookie string) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.chatRoomCookie = cookie
}

// ChatRoomCookie gets the chat room cookie for the instance.
func (i *Instance) ChatRoomCookie() string {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.chatRoomCookie
}

// SetClientID sets the instance's client ID.
func (i *Instance) SetClientID(clientID string) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.clientID = clientID
}

// ClientID retrieves the instance's client ID.
func (i *Instance) ClientID() string {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.clientID
}

// SetCaps sets capability UUIDs for the instance.
func (i *Instance) SetCaps(caps [][16]byte) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.caps = caps
}

// Caps retrieves instance capabilities.
func (i *Instance) Caps() [][16]byte {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.caps
}

// SetFoodGroupVersions sets the instance's supported food group versions.
func (i *Instance) SetFoodGroupVersions(versions [wire.MDir + 1]uint16) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.foodGroupVersions = versions
}

// FoodGroupVersions retrieves the instance's supported food group versions.
func (i *Instance) FoodGroupVersions() [wire.MDir + 1]uint16 {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.foodGroupVersions
}

// SetTypingEventsEnabled sets whether the instance wants to send and receive typing events.
func (i *Instance) SetTypingEventsEnabled(enabled bool) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.typingEventsEnabled = enabled
}

// TypingEventsEnabled indicates whether the instance wants to send and receive typing events.
func (i *Instance) TypingEventsEnabled() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.typingEventsEnabled
}

// SetMultiConnFlag sets the multi-connection flag for this instance.
func (i *Instance) SetMultiConnFlag(flag wire.MultiConnFlag) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.multiConnFlag = flag
}

// MultiConnFlag retrieves the multi-connection flag for this instance.
func (i *Instance) MultiConnFlag() wire.MultiConnFlag {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.multiConnFlag
}

// ReceiveMessage returns a channel of messages relayed via this instance.
func (i *Instance) ReceiveMessage() chan wire.SNACMessage {
	return i.msgCh
}

// RelayMessageToInstance receives a SNAC message and passes it to the instance's message channel.
func (i *Instance) RelayMessageToInstance(msg wire.SNACMessage) SessSendStatus {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	if i.closed {
		return SessSendClosed
	}
	select {
	case i.msgCh <- msg:
		return SessSendOK
	case <-i.stopCh:
		return SessSendClosed
	default:
		return SessQueueFull
	}
}

// Close shuts down the instance's ability to relay messages.
func (i *Instance) Close() {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.close()
}

func (i *Instance) close() {
	if i.closed {
		return
	}
	close(i.stopCh)
	i.closed = true
	// Remove this instance from its session group
	i.SessionGroup.RemoveInstance(i)
}

// Closed blocks until the instance is closed.
func (i *Instance) Closed() <-chan struct{} {
	return i.stopCh
}

// InstanceNum returns the unique instance identifier.
func (i *Instance) InstanceNum() uint8 {
	return i.instanceNum
}

// Active returns true if the instance is active. An instance is considered active if:
// - it is not closed
// - it is not idle
// - it has no away message
func (i *Instance) Active() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	return !i.closed && !i.idle && i.awayMessage == ""
}

// ============================================================================
// Session methods (Backward compatibility wrapper)
// ============================================================================

// Invisible returns true if the user is invisible.
func (s *Session) Invisible() bool {
	s.SessionGroup.mutex.RLock()
	defer s.SessionGroup.mutex.RUnlock()
	return s.SessionGroup.userStatusBitmask&wire.OServiceUserStatusInvisible == wire.OServiceUserStatusInvisible
}

// EvaluateRateLimit checks and updates the session's rate limit state
// for the given rate class ID. If the rate status reaches 'disconnect',
// the session is closed. Rate limits are not enforced if the user is a bot
// (has wire.OServiceUserFlagBot set in their user info bitmask).
func (s *Session) EvaluateRateLimit(now time.Time, rateClassID wire.RateLimitClassID) wire.RateLimitStatus {
	status := s.SessionGroup.EvaluateRateLimit(now, rateClassID)

	if status == wire.RateLimitStatusDisconnect {
		s.Close()
	}

	return status
}

// Helper functions

// generateInstanceNum generates the next instance number for this session group.
func (sg *SessionGroup) generateInstanceNum() uint8 {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()

	sg.instanceCounter++
	if sg.instanceCounter == 0 {
		sg.instanceCounter = 1 // Start from 1, skip 0
	}
	return sg.instanceCounter
}

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
func (i *Instance) SetKerberosAuth(enabled bool) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.kerberosAuth = enabled
}

// KerberosAuth indicates whether Kerberos authentication was used for this session.
func (i *Instance) KerberosAuth() bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.kerberosAuth
}

// SetProfile sets the user's profile information.
func (sg *SessionGroup) SetProfile(profile UserProfile) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.profile = profile
}

// Profile returns the user's profile information.
func (sg *SessionGroup) Profile() UserProfile {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.profile
}

// SetBuddyIcon stores the session's buddy icon metadata.
func (sg *SessionGroup) SetBuddyIcon(icon wire.BARTID) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.buddyIcon = icon
}

// BuddyIcon returns the session's buddy icon metadata and reports whether it
// has been set. The icon is considered set if its type is non-zero.
func (sg *SessionGroup) BuddyIcon() (wire.BARTID, bool) {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	icon := sg.buddyIcon
	return icon, icon.Type != 0
}

// SetMemberSince sets the member since timestamp.
func (sg *SessionGroup) SetMemberSince(t time.Time) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.memberSince = t
}

// MemberSince reports when the user became a member.
func (sg *SessionGroup) MemberSince() time.Time {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.memberSince
}

// SetOfflineMsgCount sets the offline message count.
func (sg *SessionGroup) SetOfflineMsgCount(count int) {
	sg.mutex.Lock()
	defer sg.mutex.Unlock()
	sg.offlineMsgCount = count
}

// OfflineMsgCount returns the offline message count.
func (sg *SessionGroup) OfflineMsgCount() int {
	sg.mutex.RLock()
	defer sg.mutex.RUnlock()
	return sg.offlineMsgCount
}
