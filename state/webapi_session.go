package state

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"strconv"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// ErrNoWebAPISession is returned when a WebAPI session is not found.
	ErrNoWebAPISession = errors.New("WebAPI session not found")
	// ErrWebAPISessionExpired is returned when a WebAPI session has expired.
	ErrWebAPISessionExpired = errors.New("WebAPI session expired")
	// ErrWebAPISessionManagerClosed is returned when a session is requested from
	// a manager that has been shut down.
	ErrWebAPISessionManagerClosed = errors.New("WebAPI session manager is shut down")
)

// Web API session lifecycle timeline.
//
// A web client keeps its session alive by long-polling GET /aim/fetchEvents.
// Every authenticated request touches the session (middleware.RequireSession
// calls TouchSession at request arrival), sliding expiry to now + the TTL. A
// single poll blocks for up to 60s (the fetchEvents long-poll cap) and the
// client waits ~500ms (TimeToNextFetch) before re-polling, so in steady state a
// healthy client touches the session at worst every ~60-65s once jitter is
// included. That worst-case touch interval is the floor the TTL must clear.
//
// If a client hangs up without calling endSession, its last touch was at its
// last poll: the session then expires webAPISessionTTL later and the reaper
// sweeps it within one webAPISessionReapInterval tick. So a silent client is
// removed (and its OSCAR session closed) within TTL + tick of going quiet.
const (
	// webAPISessionTTL bounds how long a session survives without a poll. It is
	// sized to absorb one missed poll cycle: ~60s for the normal cycle, ~60s for
	// the absorbed miss, plus ~20s of jitter margin. Two consecutive misses mean
	// the client is genuinely gone and the session is reaped.
	webAPISessionTTL = 150 * time.Second

	// webAPISessionReapInterval is how often the cleanup goroutine sweeps for
	// expired sessions (~TTL/5). A dead session lingers at most
	// webAPISessionTTL + webAPISessionReapInterval before removal.
	webAPISessionReapInterval = 30 * time.Second
)

// WebAPISession represents an active Web AIM API session.
type WebAPISession struct {
	AimSID              string                                         // Unique session ID for web client
	ScreenName          DisplayScreenName                              // User identity
	OSCARSession        *SessionInstance                               // Bridge to existing OSCAR session
	OSCARCookie         []byte                                         // OSCAR auth cookie for the startOSCARSession handoff
	BOSHost             string                                         // BOS host advertised to the web client
	BOSPort             int                                            // BOS port advertised to the web client
	UseSSL              bool                                           // Whether the handoff advertised an SSL BOS connection
	BaseURL             string                                         // Web API base URL advertised to the web client, used to build absolute asset URLs
	Events              []string                                       // Subscribed event types
	EventQueue          *types.EventQueue                              // Per-session event queue
	DevID               string                                         // Developer ID that created this session
	ClientName          string                                         // Client application name
	ClientVersion       string                                         // Client application version
	CreatedAt           time.Time                                      // SessionInstance creation time
	LastAccessed        time.Time                                      // Last activity time
	ExpiresAt           time.Time                                      // SessionInstance expiration time
	FetchTimeout        int                                            // Long-polling timeout in milliseconds
	TimeToNextFetch     int                                            // Suggested delay before next fetch
	RemoteAddr          string                                         // Client IP address
	TempBuddies         map[string]bool                                // Temporary buddies for this session only
	BuddyListRefresher  func(ctx context.Context) (interface{}, error) // Called on feedbag changes to push buddylist event
	PermitDenyRefresher func(ctx context.Context) (interface{}, error) // Called on feedbag changes to push permitDeny event
	MyInfoRefresher     func(ctx context.Context) (interface{}, error) // Called on self user-info updates (e.g. icon change) to push myInfo event
	BuddyAliasLoader    func(ctx context.Context) (map[string]string, error)
	// BuddyIconURL formats the absolute buddyIcon URL for a buddy from the icon
	// hash carried in a presence SNAC. Returns "" when no URL can be published.
	BuddyIconURL func(screenName IdentScreenName, hash []byte) string
	aliases      map[string]string // cached BuddyAliasLoader result, nil when unloaded or invalidated
	aliasMu      sync.Mutex
	imLog        map[string][]WebAPIStoredIM
	imLogMu      sync.Mutex
	logger       *slog.Logger // Logger for debugging
	listeners    sync.WaitGroup
}

// IsExpired checks if the session has expired.
func (s *WebAPISession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Aliases returns this session owner's private buddy aliases, keyed by normalized
// screen name. Aliases live in the owner's feedbag, so the map is loaded once and
// cached until a feedbag change invalidates it: a signon that brings a large buddy
// list online costs one feedbag query instead of one per buddy.
//
// The map is owned by the session and must not be mutated by callers.
//
// aliasMu is deliberately held across the load rather than released while the
// feedbag is queried. Another instance of the owner can rename a buddy mid-query,
// and its FeedbagUpdateItem SNAC invalidates this cache; if the load ran outside
// the lock, that query's pre-rename result could be stored *after* the
// invalidation and serve the old alias until the next feedbag change. Holding the
// lock makes the invalidation wait for the load and then win.
func (s *WebAPISession) Aliases(ctx context.Context) map[string]string {
	s.aliasMu.Lock()
	defer s.aliasMu.Unlock()

	// The loader is wired after the session is created, so an event arriving in
	// that window has no way to resolve aliases.
	if s.BuddyAliasLoader == nil {
		return nil
	}
	if s.aliases == nil {
		aliases, err := s.BuddyAliasLoader(ctx)
		if err != nil {
			s.logger.Error("failed to load buddy aliases", "err", err.Error())
			return nil
		}
		s.aliases = aliases
	}
	return s.aliases
}

// InvalidateAliases drops the cached alias map so the next Aliases call reloads it.
// Callers that change the owner's feedbag must call this: the feedbag service
// relays FeedbagUpdateItem only to the owner's *other* instances, so a session
// never sees a SNAC for its own writes.
func (s *WebAPISession) InvalidateAliases() {
	s.aliasMu.Lock()
	defer s.aliasMu.Unlock()
	s.aliases = nil
}

// aliasFor returns this session owner's private alias for buddy, or "" when none is
// set. The web client deletes the alias it holds whenever it merges a user map, so
// every event naming a buddy has to repeat it.
func (s *WebAPISession) aliasFor(buddy IdentScreenName) string {
	// Runs on the SNAC listener goroutine, which has no request context.
	return s.Aliases(context.Background())[buddy.String()]
}

// Touch updates the last accessed time and extends expiration if needed.
func (s *WebAPISession) Touch() {
	s.LastAccessed = time.Now()
	newExpiry := s.LastAccessed.Add(webAPISessionTTL)
	if newExpiry.After(s.ExpiresAt) {
		s.ExpiresAt = newExpiry
	}
}

// IsSubscribedTo checks if the session is subscribed to a specific event type.
func (s *WebAPISession) IsSubscribedTo(eventType string) bool {
	for _, event := range s.Events {
		if event == eventType {
			return true
		}
	}
	return false
}

// StartListeningToOSCARSession starts a goroutine that listens to the OSCAR session's
// message channel and converts SNAC messages into WebAPI events.
func (s *WebAPISession) StartListeningToOSCARSession() {
	if s.OSCARSession == nil {
		return
	}

	// Start goroutine to listen for OSCAR messages
	s.listeners.Add(1)
	go func() {
		defer s.listeners.Done()
		msgCh := s.OSCARSession.ReceiveMessage()
		for {
			select {
			case msg, ok := <-msgCh:
				if !ok {
					// Channel closed, OSCAR session ended
					return
				}
				s.handleSNACMessage(msg)
			case <-s.OSCARSession.Closed():
				// OSCAR session closed
				return
			}
		}
	}()
}

// Close tears down the session: it releases any parked event fetchers, closes
// the OSCAR instance, and waits for the listener goroutine to unwind. Safe to
// call more than once.
func (s *WebAPISession) Close() {
	s.EventQueue.Close()
	s.OSCARSession.CloseInstance()
	s.listeners.Wait()
}

// handleSNACMessage converts a SNAC message into WebAPI events and pushes them to the event queue.
func (s *WebAPISession) handleSNACMessage(msg wire.SNACMessage) {
	if s.EventQueue == nil {
		return
	}

	// Convert SNAC message to WebAPI events based on food group and subgroup
	switch msg.Frame.FoodGroup {
	case wire.ICBM:
		s.handleICBMMessage(msg)
	case wire.Buddy:
		s.handleBuddyMessage(msg)
	case wire.Feedbag:
		s.handleFeedbagMessage(msg)
	case wire.OService:
		s.handleOServiceMessage(msg)
	}
}

// handleOServiceMessage handles OService SNAC messages relayed to the session's
// own OSCAR instance. The only one we surface is OServiceUserInfoUpdate, which the
// server relays to a user when their own user info changes (notably a buddy icon
// upload or clear). The client re-renders its identity badge from myInfo events
// only, so we translate this into a fresh myInfo.
func (s *WebAPISession) handleOServiceMessage(msg wire.SNACMessage) {
	if msg.Frame.SubGroup != wire.OServiceUserInfoUpdate {
		return
	}
	if !s.IsSubscribedTo("myInfo") && !s.IsSubscribedTo("presence") {
		return
	}
	if s.MyInfoRefresher == nil {
		return
	}
	data, err := s.MyInfoRefresher(context.Background())
	if err != nil {
		s.logger.Error("failed to refresh myInfo after user-info update", "err", err)
		return
	}
	s.EventQueue.Push(types.EventType("myInfo"), data)
}

// handleICBMMessage handles ICBM (instant messaging) SNAC messages.
func (s *WebAPISession) handleICBMMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.ICBMChannelMsgToClient:
		s.handleIncomingIM(msg)
	case wire.ICBMClientEvent:
		s.handleTypingNotification(msg)
	}
}

// handleIncomingIM handles incoming instant messages.
func (s *WebAPISession) handleIncomingIM(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("im") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x04_0x07_ICBMChannelMsgToClient)
	if !ok {
		return
	}

	// Extract message text from TLV data
	var messageText string
	if msgData, hasMsg := body.Bytes(wire.ICBMTLVAOLIMData); hasMsg {
		if text, err := wire.UnmarshalICBMMessageText(msgData); err == nil {
			messageText = text
		}
	}

	if messageText == "" {
		return
	}

	// Check if it's an auto-response (channel 2)
	autoResponse := body.ChannelID == 0x0002

	// msgId must be unique per delivered event. The OSCAR cookie is not a
	// reliable unique id (some clients reuse it across messages), and the web
	// client dedupes its conversation list by msgId, silently dropping any
	// collisions. Mint a fresh random id instead of reusing body.Cookie.
	msgID := strconv.FormatUint(mrand.Uint64(), 16)
	// SNAC user info carries the sender's display screen name. The web client
	// keys conversations and users by the normalized aimId and only renders
	// displayId, so the two forms must not be interchanged.
	partnerDisplay := body.ScreenName
	partnerAimID := NewIdentScreenName(partnerDisplay).String()
	nowSec := time.Now().Unix()
	s.AddStoredIM(partnerAimID, partnerAimID, messageText, msgID, nowSec)

	// Create IM event
	imEvent := types.IMEvent{
		Source: types.UserInfo{
			AimID:     partnerAimID,
			DisplayID: partnerDisplay,
			Friendly:  s.aliasFor(NewIdentScreenName(partnerAimID)),
			UserType:  "aim",
			State:     "online",
		},
		Message:   messageText,
		MsgID:     msgID,
		Timestamp: float64(time.Now().Unix()),
		AutoResp:  autoResponse,
	}

	s.EventQueue.Push(types.EventTypeIM, imEvent)
	s.logger.Debug("delivered instant message",
		"from", partnerDisplay,
		"to", s.ScreenName)

	if s.IsSubscribedTo("conversation") {
		// unread is 0 here, not 1, because the "im" event pushed above already
		// causes the client to increment its own persisted per-buddy unread
		// tally. The "Recent chats" badge is the sum of that persisted tally and
		// this conversation's unreadCount, so sending 1 here would double-count
		// the message (badge shows 2 for the first IM). Mirrors the sent-IM path,
		// which also passes 0.
		s.EventQueue.Push(types.EventTypeConversation, types.ConversationEventData("update", []map[string]interface{}{
			types.ConversationEntry(
				partnerAimID,
				partnerDisplay,
				messageText,
				msgID,
				partnerAimID,
				false,
				0,
			),
		}))
	}
}

// handleTypingNotification handles typing notifications.
func (s *WebAPISession) handleTypingNotification(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("typing") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x04_0x14_ICBMClientEvent)
	if !ok {
		return
	}

	// Event types: 0x0000=none, 0x0001=typed (paused), 0x0002=typing
	var typingStatus string
	switch body.Event {
	case 0x0002:
		typingStatus = "typing"
	case 0x0001:
		typingStatus = "typed"
	default:
		typingStatus = "none"
	}

	typingEvent := types.TypingEvent{
		AimID:        NewIdentScreenName(body.ScreenName).String(),
		TypingStatus: typingStatus,
	}

	s.EventQueue.Push(types.EventTypeTyping, typingEvent)
}

// handleBuddyMessage handles buddy/presence SNAC messages.
func (s *WebAPISession) handleBuddyMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.BuddyArrived:
		s.handleBuddyArrived(msg)
	case wire.BuddyDeparted:
		s.handleBuddyDeparted(msg)
	}
}

// handleBuddyArrived handles when a buddy comes online.
func (s *WebAPISession) handleBuddyArrived(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("presence") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x03_0x0B_BuddyArrived)
	if !ok {
		return
	}

	stateStr := "online"
	// For BuddyArrived updates, infer presence state from the TLVUserInfo.
	// Away and invisible transitions are typically broadcast using BuddyArrived
	// with updated user flags/status bits, not BuddyDeparted.
	if body.IsInvisible() {
		stateStr = "offline"
	} else if body.IsAway() {
		stateStr = "away"
	} else if mask, ok := body.Uint32BE(wire.OServiceUserInfoStatus); ok {
		if mask&wire.OServiceUserStatusDND == wire.OServiceUserStatusDND {
			stateStr = "dnd"
		} else if mask&wire.OServiceUserStatusAway == wire.OServiceUserStatusAway {
			stateStr = "away"
		}
	}

	buddy := NewIdentScreenName(body.ScreenName)
	presenceEvent := types.PresenceEvent{
		AimID:    buddy.String(),
		Friendly: s.aliasFor(buddy),
		State:    stateStr,
		UserType: "aim",
	}

	// A BuddyArrived carries the buddy's current icon in TLV 0x1D whenever they
	// have one, so an icon change (or clear, which arrives as the sentinel hash)
	// rides along on the presence broadcast. Publish the matching URL: with an
	// icon it is content-addressed; without one it is the placeholder URL, which
	// differs from any prior icon URL and so clears a removed icon under the
	// client's shallow merge. An empty result (no origin known) is omitted, which
	// preserves whatever icon the client already holds.
	if s.BuddyIconURL != nil {
		var hash []byte
		if b, ok := body.Bytes(wire.OServiceUserInfoBARTInfo); ok {
			var id wire.BARTID
			if err := wire.UnmarshalBE(&id, bytes.NewBuffer(b)); err == nil {
				hash = id.Hash
			}
		}
		presenceEvent.BuddyIcon = s.BuddyIconURL(buddy, hash)
	}

	s.EventQueue.Push(types.EventTypePresence, presenceEvent)
}

// handleBuddyDeparted handles when a buddy goes offline.
func (s *WebAPISession) handleBuddyDeparted(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("presence") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x03_0x0C_BuddyDeparted)
	if !ok {
		return
	}

	buddy := NewIdentScreenName(body.ScreenName)
	// BuddyIcon is deliberately omitted: an offline buddy keeps their icon, and
	// omitting it lets the client's merge preserve the icon it already holds.
	presenceEvent := types.PresenceEvent{
		AimID:    buddy.String(),
		Friendly: s.aliasFor(buddy),
		State:    "offline",
		UserType: "aim",
	}

	s.EventQueue.Push(types.EventTypePresence, presenceEvent)
}

func (s *WebAPISession) handleFeedbagMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.FeedbagInsertItem, wire.FeedbagUpdateItem, wire.FeedbagDeleteItem:
		// A buddy item carries its alias, so any feedbag write can change the map.
		s.InvalidateAliases()

		if s.BuddyListRefresher != nil {
			groups, err := s.BuddyListRefresher(context.Background())
			if err != nil {
				s.logger.Error("failed to refresh buddy list after feedbag change", "err", err)
			} else {
				s.EventQueue.Push(types.EventTypeBuddyList, map[string]interface{}{"groups": groups})
			}
		}
		if msg.Frame.SubGroup == wire.FeedbagUpdateItem && s.PermitDenyRefresher != nil {
			body, ok := msg.Body.(wire.SNAC_0x13_0x09_FeedbagUpdateItem)
			if ok {
				for _, item := range body.Items {
					if item.ClassID == wire.FeedbagClassIDPermit ||
						item.ClassID == wire.FeedbagClassIDDeny ||
						item.ClassID == wire.FeedbagClassIdPdinfo {
						pdd, err := s.PermitDenyRefresher(context.Background())
						if err != nil {
							s.logger.Error("failed to refresh permit/deny after feedbag change", "err", err)
						} else {
							s.EventQueue.Push(types.EventTypePermitDeny, pdd)
						}
						break
					}
				}
			}
		}
	}
}

// WebAPISessionManager manages Web API sessions with thread-safe operations.
// Construct it with NewWebAPISessionManager and drive its reaper with Run.
type WebAPISessionManager struct {
	sessions map[string]*WebAPISession // Keyed by aimsid
	mu       sync.RWMutex
	closed   bool           // set by Shutdown; rejects new sessions and makes drain idempotent
	stopCh   chan struct{}  // closed by Shutdown to stop the reaper
	reaperWG sync.WaitGroup // tracks a running reaper so Shutdown can join it
}

// NewWebAPISessionManager creates a new WebAPI session manager. It does not start
// any goroutines; call Run to start reaping expired sessions.
func NewWebAPISessionManager() *WebAPISessionManager {
	return &WebAPISessionManager{
		sessions: make(map[string]*WebAPISession),
		stopCh:   make(chan struct{}),
	}
}

// CreateSession creates a new WebAPI session.
//
// The session does not begin listening to its OSCAR instance yet: the caller
// must wire the session's refresher callbacks (BuddyListRefresher, BuddyIconURL,
// MyInfoRefresher, ...) and then call StartListeningToOSCARSession. Wiring them
// after the listener starts would race the goroutine, which reads them as it
// converts SNACs into events.
func (m *WebAPISessionManager) CreateSession(screenName DisplayScreenName, devID string, events []string, oscarSession *SessionInstance, baseURL string, logger *slog.Logger) (*WebAPISession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Refuse to create sessions once shut down: the reaper is stopped, so a
	// session added now would never be closed or reaped.
	if m.closed {
		return nil, ErrWebAPISessionManagerClosed
	}

	// Generate unique session ID
	aimsid, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &WebAPISession{
		AimSID:          aimsid,
		ScreenName:      screenName,
		OSCARSession:    oscarSession,
		BaseURL:         baseURL,
		Events:          events,
		EventQueue:      types.NewEventQueue(1000), // Max 1000 events per session
		DevID:           devID,
		CreatedAt:       now,
		LastAccessed:    now,
		ExpiresAt:       now.Add(webAPISessionTTL),
		FetchTimeout:    60000, // 60 seconds default for better stability
		TimeToNextFetch: 500,   // 500ms suggested delay
		logger:          logger,
	}

	m.sessions[aimsid] = session

	// The caller starts the OSCAR listener (StartListeningToOSCARSession) once it
	// has wired the session's refresher callbacks; starting it here would race
	// those assignments.

	return session, nil
}

// GetSession retrieves a session by aimsid.
func (m *WebAPISessionManager) GetSession(ctx context.Context, aimsid string) (*WebAPISession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[aimsid]
	if !exists {
		return nil, ErrNoWebAPISession
	}

	if session.IsExpired() {
		return nil, ErrWebAPISessionExpired
	}

	return session, nil
}

// RemoveSession removes a session by aimsid.
func (m *WebAPISessionManager) RemoveSession(ctx context.Context, aimsid string) error {
	m.mu.Lock()

	session, exists := m.sessions[aimsid]
	if !exists {
		m.mu.Unlock()
		return ErrNoWebAPISession
	}

	delete(m.sessions, aimsid)
	m.mu.Unlock()

	// Tear down outside the lock: CloseInstance fans out to buddy-departed
	// broadcasts and signout, which we don't want to run under m.mu.
	session.Close()
	return nil
}

// TouchSession updates the last accessed time for a session.
func (m *WebAPISessionManager) TouchSession(ctx context.Context, aimsid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[aimsid]
	if !exists {
		return ErrNoWebAPISession
	}

	session.Touch()
	return nil
}

// Run reaps expired sessions on a fixed interval until ctx is cancelled or
// Shutdown is called. The caller owns the goroutine's lifecycle; typically
// launch it under the server's errgroup:
//
//	g.Go(func() error { mgr.Run(ctx); return nil })
//
// Run is a no-op once the manager is closed, so a reaper that loses the race
// with Shutdown never starts reaping a drained manager.
func (m *WebAPISessionManager) Run(ctx context.Context) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	// Registering under m.mu is what makes Shutdown's join sound: Shutdown flips
	// closed under the same lock, so a reaper either registers before Shutdown
	// waits or is turned away here.
	m.reaperWG.Add(1)
	m.mu.Unlock()
	defer m.reaperWG.Done()

	ticker := time.NewTicker(webAPISessionReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.reapExpired()
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// reapExpired removes every expired session and tears it down.
func (m *WebAPISessionManager) reapExpired() {
	m.mu.Lock()
	now := time.Now()
	var expired []*WebAPISession
	for aimsid, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, aimsid)
			expired = append(expired, session)
		}
	}
	m.mu.Unlock()

	// Tear down outside the lock: CloseInstance fans out to buddy-departed
	// broadcasts and signout, which we don't want to run under m.mu.
	for _, session := range expired {
		session.Close()
	}
}

// Shutdown drains and closes all sessions, stops the reaper started by Run, and
// blocks further CreateSession calls. It does not depend on the caller
// cancelling Run's context. Safe to call more than once, though only the first
// call waits for the drain.
func (m *WebAPISessionManager) Shutdown() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	close(m.stopCh)

	sessions := make([]*WebAPISession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	// Clear all sessions
	m.sessions = make(map[string]*WebAPISession)
	m.mu.Unlock()

	// Tear down outside the lock: CloseInstance fans out to buddy-departed
	// broadcasts and signout, which we don't want to run under m.mu.
	for _, session := range sessions {
		session.Close()
	}
	m.reaperWG.Wait()
}

// generateSessionID creates a cryptographically secure session ID.
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
