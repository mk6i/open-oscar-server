package webapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/state"
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

// Session represents an active Web AIM API session.
type Session struct {
	AimSID              string                                         // Unique session ID for web client
	ScreenName          state.DisplayScreenName                        // User identity
	OSCARSession        *state.SessionInstance                         // Bridge to existing OSCAR session
	BaseURL             string                                         // Web API base URL advertised to the web client, used to build absolute asset URLs
	Events              []string                                       // Subscribed event types
	EventQueue          *EventQueue                                    // Per-session event queue
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
	BuddyIconURL func(screenName state.IdentScreenName, hash []byte) string
	aliases      map[string]string // cached BuddyAliasLoader result, nil when unloaded or invalidated
	aliasMu      sync.Mutex
	imLog        map[string][]WebAPIStoredIM
	imLogMu      sync.Mutex
	sentIMs      map[uint64]string // OSCAR message cookie -> the msgId given to the client
	sentIMOrder  []uint64          // insertion order of sentIMs, oldest first
	sentIMMu     sync.Mutex
	// IMRateClassID is the rate class that sending an IM spends. The web client
	// renders any rate limit event as the IM banner, so only this class's updates
	// may reach it. Zero disables the alert.
	IMRateClassID wire.RateLimitClassID
	logger        *slog.Logger // Logger for debugging
	listeners     sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	closeMu sync.Mutex
	closed  bool
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
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
func (s *Session) Aliases(ctx context.Context) map[string]string {
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
func (s *Session) InvalidateAliases() {
	s.aliasMu.Lock()
	defer s.aliasMu.Unlock()
	s.aliases = nil
}

// aliasFor returns this session owner's private alias for buddy, or "" when none is
// set. The web client deletes the alias it holds whenever it merges a user map, so
// every event naming a buddy has to repeat it.
func (s *Session) aliasFor(buddy state.IdentScreenName) string {
	// Runs on the SNAC listener goroutine, which has no request context.
	return s.Aliases(s.ctx)[buddy.String()]
}

// Touch updates the last accessed time and extends expiration if needed.
func (s *Session) Touch() {
	s.LastAccessed = time.Now()
	newExpiry := s.LastAccessed.Add(webAPISessionTTL)
	if newExpiry.After(s.ExpiresAt) {
		s.ExpiresAt = newExpiry
	}
}

// IsSubscribedTo checks if the session is subscribed to a specific event type.
func (s *Session) IsSubscribedTo(eventType string) bool {
	for _, event := range s.Events {
		if event == eventType {
			return true
		}
	}
	return false
}

// StartListeningToOSCARSession starts a goroutine that listens to the OSCAR session's
// message channel and converts SNAC messages into WebAPI events.
func (s *Session) StartListeningToOSCARSession() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return
	}

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
				// The OSCAR instance went away without this session asking — a
				// boot, a rate-limit disconnect. Tell the client rather than
				// leaving its parked fetcher to hang: a sessionEnded event
				// releases the poll at once and the client signs off on the
				// spot, instead of waiting out the reaper's next sweep.
				//
				// A teardown this session started needs no event, and gets
				// none: Close closes the queue before it closes the instance,
				// so this Push is a no-op on that path.
				s.EventQueue.Push(EventTypeSessionEnded, struct{}{})
				return
			}
		}
	}()
}

// Close tears down the session: it releases any parked event fetchers, closes
// the OSCAR instance, and waits for the listener goroutine to unwind. Safe to
// call more than once.
func (s *Session) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	s.closeMu.Unlock()

	s.EventQueue.Close()
	s.OSCARSession.CloseInstance()

	s.cancel()
	s.listeners.Wait()
}

// handleSNACMessage converts a SNAC message into WebAPI events and pushes them to the event queue.
func (s *Session) handleSNACMessage(msg wire.SNACMessage) {
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
// own OSCAR instance.
func (s *Session) handleOServiceMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.OServiceUserInfoUpdate:
		s.handleUserInfoUpdate(msg)
	case wire.OServiceRateParamChange:
		s.handleRateLimitUpdate(msg)
	}
}

// handleUserInfoUpdate surfaces OServiceUserInfoUpdate, which the server relays to
// a user when their own user info changes (notably a buddy icon upload or clear).
// The client re-renders its identity badge from myInfo events only, so we
// translate this into a fresh myInfo.
func (s *Session) handleUserInfoUpdate(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("myInfo") && !s.IsSubscribedTo("presence") {
		return
	}
	if s.MyInfoRefresher == nil {
		return
	}
	data, err := s.MyInfoRefresher(s.ctx)
	if err != nil {
		s.logger.Error("failed to refresh myInfo after user-info update", "err", err)
		return
	}
	s.EventQueue.Push(EventType("myInfo"), data)
}

// handleRateLimitUpdate translates a rate limit status change — broadcast by the
// account's rate limit monitor — into a rateLimit event. Only the IM class is
// surfaced, since the client feeds any rateLimit event into the
// conversation-window alert. Code 1 is a class-params change, not a status
// transition, and is ignored.
func (s *Session) handleRateLimitUpdate(msg wire.SNACMessage) {
	if s.IMRateClassID == 0 {
		return
	}
	body, ok := msg.Body.(wire.SNAC_0x01_0x0A_OServiceRateParamsChange)
	if !ok {
		return
	}
	if wire.RateLimitClassID(body.Rate.ID) != s.IMRateClassID {
		return
	}

	var status string
	switch body.Code {
	case 2:
		status = "warn"
	case 3:
		status = "limit"
	case 4:
		status = "clear"
	default:
		return
	}

	s.EventQueue.Push(EventTypeRateLimit, RateLimitEvent{
		Classes: []RateLimitClass{
			{ID: int(body.Rate.ID), Status: status},
		},
	})
}

// handleICBMMessage handles ICBM (instant messaging) SNAC messages.
func (s *Session) handleICBMMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.ICBMChannelMsgToClient:
		s.handleIncomingIM(msg)
	case wire.ICBMClientEvent:
		s.handleTypingNotification(msg)
	case wire.ICBMClientErr:
		s.handleClientError(msg)
	}
}

// handleIncomingIM handles incoming instant messages.
func (s *Session) handleIncomingIM(msg wire.SNACMessage) {
	body, ok := msg.Body.(wire.SNAC_0x04_0x07_ICBMChannelMsgToClient)
	if !ok {
		return
	}

	// A send time is only stamped on a message replayed out of the offline store,
	// so its presence marks this as a delivery of something sent while the user was
	// signed off, and carries the moment the sender actually sent it.
	sentTime, isOffline := body.Uint32BE(wire.ICBMTLVSendTime)

	// Retrieval answers only the instance that asked, and StartSession asks only
	// when the client subscribed to offlineIM, so a stamped message here is one
	// this session requested. A live IM still needs the im subscription.
	if !isOffline && !s.IsSubscribedTo("im") {
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
	partnerAimID := state.NewIdentScreenName(partnerDisplay).String()

	// An offline message is logged under the time it was sent, so the stored-IM
	// history it lands in stays in the order the conversation happened.
	timestamp := time.Now().Unix()
	if isOffline {
		timestamp = int64(sentTime)
	}
	s.AddStoredIM(partnerAimID, partnerAimID, messageText, msgID, timestamp)

	if isOffline {
		// The client resolves an offline sender from aimId and friendly alone,
		// so friendly falls back to the sender's own formatting when the viewer
		// has no alias for them.
		friendly := s.aliasFor(state.NewIdentScreenName(partnerAimID))
		if friendly == "" {
			friendly = partnerDisplay
		}
		s.EventQueue.Push(EventTypeOfflineIM, OfflineIMEvent{
			AimID:     partnerAimID,
			Friendly:  friendly,
			Message:   messageText,
			MsgID:     msgID,
			Timestamp: timestamp,
			Imf:       imfPlainText,
			AutoResp:  autoResponse,
		})
		s.logger.Debug("delivered offline instant message",
			"from", partnerDisplay,
			"to", s.ScreenName,
			"sent", timestamp)
	} else {
		s.EventQueue.Push(EventTypeIM, IMEvent{
			Source: UserInfo{
				AimID:     partnerAimID,
				DisplayID: partnerDisplay,
				Friendly:  s.aliasFor(state.NewIdentScreenName(partnerAimID)),
				UserType:  "aim",
				State:     "online",
			},
			Message:   messageText,
			MsgID:     msgID,
			Timestamp: timestamp,
			Imf:       imfPlainText,
			AutoResp:  autoResponse,
		})
		s.logger.Debug("delivered instant message",
			"from", partnerDisplay,
			"to", s.ScreenName)
	}

	if s.IsSubscribedTo("conversation") {
		// unread is 0 here, not 1, because the "im"/"offlineIM" event pushed above
		// already causes the client to increment its own persisted per-buddy unread
		// tally. The "Recent chats" badge is the sum of that persisted tally and
		// this conversation's unreadCount, so sending 1 here would double-count
		// the message (badge shows 2 for the first IM). Mirrors the sent-IM path,
		// which also passes 0.
		s.EventQueue.Push(EventTypeConversation, ConversationEventData("update", []ConversationEntryData{
			ConversationEntry(
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

// handleClientError translates ICBMClientErr — the recipient reporting that it
// could not handle a message already delivered to it — into a clientError event
// for the sender. Only OSCAR clients raise this SNAC.
func (s *Session) handleClientError(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("im") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x04_0x0B_ICBMClientErr)
	if !ok {
		return
	}

	// The SNAC names the erroring party by their own formatting, so both the
	// normalized aimId and displayId are sent, along with the viewer's alias.
	sender := state.NewIdentScreenName(body.ScreenName)

	channel := "im"
	if body.ChannelID == wire.ICBMChannelRendezvous {
		channel = "data"
	}

	s.EventQueue.Push(EventTypeClientError, ClientErrorEvent{
		Source: UserInfo{
			AimID:     sender.String(),
			DisplayID: body.ScreenName,
			Friendly:  s.aliasFor(sender),
			UserType:  "aim",
		},
		Cookie:  s.msgIDForCookie(body.Cookie),
		Channel: channel,
	})
}

// handleTypingNotification handles typing notifications.
func (s *Session) handleTypingNotification(msg wire.SNACMessage) {
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

	typingEvent := TypingEvent{
		AimID:        state.NewIdentScreenName(body.ScreenName).String(),
		TypingStatus: typingStatus,
	}

	s.EventQueue.Push(EventTypeTyping, typingEvent)
}

// handleBuddyMessage handles buddy/presence SNAC messages.
func (s *Session) handleBuddyMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.BuddyArrived:
		s.handleBuddyArrived(msg)
	case wire.BuddyDeparted:
		s.handleBuddyDeparted(msg)
	}
}

// handleBuddyArrived handles when a buddy comes online.
func (s *Session) handleBuddyArrived(msg wire.SNACMessage) {
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
	} else if st := statusBitState(body.TLVUserInfo); st != "" {
		stateStr = st
	} else if body.IsAway() {
		stateStr = "away"
	} else if mask, ok := body.Uint32BE(wire.OServiceUserInfoStatus); ok {
		if mask&wire.OServiceUserStatusDND == wire.OServiceUserStatusDND {
			stateStr = "dnd"
		} else if mask&wire.OServiceUserStatusAway == wire.OServiceUserStatusAway {
			stateStr = "away"
		}
	}

	buddy := state.NewIdentScreenName(body.ScreenName)
	presenceEvent := PresenceEvent{
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

	s.EventQueue.Push(EventTypePresence, presenceEvent)
}

// handleBuddyDeparted handles when a buddy goes offline.
func (s *Session) handleBuddyDeparted(msg wire.SNACMessage) {
	if !s.IsSubscribedTo("presence") {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x03_0x0C_BuddyDeparted)
	if !ok {
		return
	}

	buddy := state.NewIdentScreenName(body.ScreenName)
	// BuddyIcon is deliberately omitted: an offline buddy keeps their icon, and
	// omitting it lets the client's merge preserve the icon it already holds.
	presenceEvent := PresenceEvent{
		AimID:    buddy.String(),
		Friendly: s.aliasFor(buddy),
		State:    "offline",
		UserType: "aim",
	}

	s.EventQueue.Push(EventTypePresence, presenceEvent)
}

// feedbagResultAuthRequired is the per-item feedbag result meaning the target's ICQ
// settings require authorization, so the item was not stored.
const feedbagResultAuthRequired = uint16(0x000E)

// refreshBuddyList re-reads the roster and pushes it to the client. Runs on the SNAC
// listener goroutine, so it uses the session context rather than a request context.
func (s *Session) refreshBuddyList() {
	// A buddy item carries its alias, so any feedbag write can change the map.
	s.InvalidateAliases()

	if s.BuddyListRefresher == nil {
		return
	}
	payload, err := s.BuddyListRefresher(s.ctx)
	if err != nil {
		s.logger.Error("failed to refresh buddy list after feedbag change", "err", err)
		return
	}
	s.EventQueue.Push(EventTypeBuddyList, payload)
}

func (s *Session) handleFeedbagMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.FeedbagStatus:
		// Insert/update/delete below reach only a user's *other* instances, so this
		// is the one notification a session gets for its own feedbag write.
		if !s.IsSubscribedTo(string(EventTypeBuddyList)) {
			return
		}
		if body, ok := msg.Body.(wire.SNAC_0x13_0x0E_FeedbagStatus); ok {
			// A buddy declined for authorization is not stored, and is simply
			// absent from the refreshed roster.
			for _, result := range body.Results {
				if result == feedbagResultAuthRequired {
					s.logger.Info("feedbag item declined pending authorization")
					break
				}
			}
		}
		s.refreshBuddyList()

	case wire.FeedbagInsertItem, wire.FeedbagUpdateItem, wire.FeedbagDeleteItem:
		s.refreshBuddyList()

		if s.PermitDenyRefresher != nil {
			// An insert and an update both relay an UpdateItem body; only a
			// delete carries a DeleteItem body.
			var items []wire.FeedbagItem
			switch body := msg.Body.(type) {
			case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
				items = body.Items
			case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
				items = body.Items
			}
			for _, item := range items {
				if item.ClassID == wire.FeedbagClassIDPermit ||
					item.ClassID == wire.FeedbagClassIDDeny ||
					item.ClassID == wire.FeedbagClassIdPdinfo {
					pdd, err := s.PermitDenyRefresher(s.ctx)
					if err != nil {
						s.logger.Error("failed to refresh permit/deny after feedbag change", "err", err)
					} else {
						s.EventQueue.Push(EventTypePermitDeny, pdd)
					}
					break
				}
			}
		}
	}
}

// SessionManager manages Web API sessions with thread-safe operations.
// Construct it with NewSessionManager and drive its reaper with Run.
type SessionManager struct {
	sessions map[string]*Session // Keyed by aimsid
	mu       sync.RWMutex
	closed   bool           // set by Shutdown; rejects new sessions and makes drain idempotent
	stopCh   chan struct{}  // closed by Shutdown to stop the reaper
	reaperWG sync.WaitGroup // tracks a running reaper so Shutdown can join it
}

// NewSessionManager creates a new WebAPI session manager. It does not start
// any goroutines; call Run to start reaping expired sessions.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
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
func (m *SessionManager) CreateSession(screenName state.DisplayScreenName, devID string, events []string, oscarSession *state.SessionInstance, baseURL string, logger *slog.Logger) (*Session, error) {
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
	sessCtx, sessCancel := context.WithCancel(context.Background())
	session := &Session{
		ctx:             sessCtx,
		cancel:          sessCancel,
		AimSID:          aimsid,
		ScreenName:      screenName,
		OSCARSession:    oscarSession,
		BaseURL:         baseURL,
		Events:          events,
		EventQueue:      NewEventQueue(1000), // Max 1000 events per session
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
func (m *SessionManager) GetSession(ctx context.Context, aimsid string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[aimsid]
	if !exists {
		return nil, ErrNoWebAPISession
	}

	if session.IsExpired() {
		return nil, ErrWebAPISessionExpired
	}

	// A rate-limit disconnect (EvaluateRateLimit -> Session.CloseSession) closes
	// every instance for the account while this web session is still unexpired.
	// The aimsid must stop resolving at that point, otherwise a client told to
	// disconnect could keep issuing charged requests against a dead session (the
	// reaper only removes it on time expiry, up to a TTL later).
	if session.OSCARSession.IsClosed() {
		return nil, ErrWebAPISessionExpired
	}

	return session, nil
}

// RemoveSession removes a session by aimsid.
func (m *SessionManager) RemoveSession(ctx context.Context, aimsid string) error {
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
func (m *SessionManager) TouchSession(ctx context.Context, aimsid string) error {
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
func (m *SessionManager) Run(ctx context.Context) {
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

// reapExpired removes every dead session and tears it down. A session is dead
// once it has passed its expiry, or once its underlying OSCAR session has been
// closed out from under it (e.g. by a rate-limit disconnect) — the latter is
// already rejected by GetSession, and reaping it here frees the entry promptly
// rather than leaving it until time expiry.
func (m *SessionManager) reapExpired() {
	m.mu.Lock()
	now := time.Now()
	var expired []*Session
	for aimsid, session := range m.sessions {
		if now.After(session.ExpiresAt) || session.OSCARSession.IsClosed() {
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
// call waits for the drain. The drain is bounded by ctx: Shutdown returns
// ctx.Err() rather than block forever on a listener that ignores cancellation.
func (m *SessionManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.stopCh)

	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	// Clear all sessions
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		// Tear down outside the lock: CloseInstance fans out to buddy-departed
		// broadcasts and signout, which we don't want to run under m.mu.
		for _, session := range sessions {
			session.Close()
		}
		m.reaperWG.Wait()
	}()

	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// generateSessionID creates a cryptographically secure session ID.
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// sentIMCookieLimit bounds the cookie->msgId map. An error arrives within seconds
// of the send, so a small window suffices; the oldest entry is evicted once full.
const sentIMCookieLimit = 256

// RecordSentIM remembers the msgId handed out for an outgoing message, keyed by the
// OSCAR cookie that message carries on the wire. The two are unrelated by
// construction, so a clientError — which names its message by cookie — could not
// otherwise say which message it refers to.
func (s *Session) RecordSentIM(cookie uint64, msgID string) {
	if s == nil || msgID == "" {
		return
	}
	s.sentIMMu.Lock()
	defer s.sentIMMu.Unlock()
	if s.sentIMs == nil {
		s.sentIMs = make(map[uint64]string)
	}
	if _, seen := s.sentIMs[cookie]; !seen {
		s.sentIMOrder = append(s.sentIMOrder, cookie)
	}
	s.sentIMs[cookie] = msgID
	if len(s.sentIMOrder) > sentIMCookieLimit {
		delete(s.sentIMs, s.sentIMOrder[0])
		s.sentIMOrder = s.sentIMOrder[1:]
	}
}

// msgIDForCookie resolves an OSCAR message cookie back to the msgId handed out for
// it, or "" when the message is not one this session sent.
func (s *Session) msgIDForCookie(cookie uint64) string {
	if s == nil {
		return ""
	}
	s.sentIMMu.Lock()
	defer s.sentIMMu.Unlock()
	return s.sentIMs[cookie]
}

// WebAPIStoredIM is one message in a Web AIM session's in-memory IM log.
// The Web AIM client expects fetchStoredIMs entries with sender, message, msgId, and date.
type WebAPIStoredIM struct {
	Sender  string
	Message string
	MsgID   string
	Date    int64 // Unix seconds
}

// AddStoredIM appends a message to the per-partner log for this session.
func (s *Session) AddStoredIM(partnerAimID, sender, message, msgID string, date int64) {
	if s == nil || partnerAimID == "" || message == "" {
		return
	}
	s.imLogMu.Lock()
	defer s.imLogMu.Unlock()
	if s.imLog == nil {
		s.imLog = make(map[string][]WebAPIStoredIM)
	}
	s.imLog[normalizeWebAPIAimID(partnerAimID)] = append(s.imLog[normalizeWebAPIAimID(partnerAimID)], WebAPIStoredIM{
		Sender:  sender,
		Message: message,
		MsgID:   msgID,
		Date:    date,
	})
}

// StoredIM is one entry in a fetchStoredIMs reply.
type StoredIM struct {
	Sender  string `json:"sender" xml:"sender"`
	Message string `json:"message" xml:"message"`
	MsgID   string `json:"msgId" xml:"msgId"`
	Date    int64  `json:"date" xml:"date"`
}

// StoredIMQuery describes filters for fetchStoredIMs.
type StoredIMQuery struct {
	PartnerAimID string
	StartTime    int64
	EndTime      int64
	NToGet       int
	SortOrder    string
	SkipMsgID    string
	StopMsgID    string
}

// GetStoredIMs returns stored messages for a conversation partner, filtered and sorted
// per the Web AIM client's fetchStoredIMs parameters.
func (s *Session) GetStoredIMs(q StoredIMQuery) []StoredIM {
	if s == nil || q.PartnerAimID == "" {
		return nil
	}

	s.imLogMu.Lock()
	msgs := append([]WebAPIStoredIM(nil), s.imLog[normalizeWebAPIAimID(q.PartnerAimID)]...)
	s.imLogMu.Unlock()

	if len(msgs) == 0 {
		return []StoredIM{}
	}

	filtered := make([]WebAPIStoredIM, 0, len(msgs))
	for _, msg := range msgs {
		if q.StartTime > 0 && msg.Date < q.StartTime {
			continue
		}
		if q.EndTime > 0 && msg.Date > q.EndTime {
			continue
		}
		filtered = append(filtered, msg)
	}

	descending := strings.EqualFold(q.SortOrder, "descendingDate")
	sort.Slice(filtered, func(i, j int) bool {
		if descending {
			return filtered[i].Date > filtered[j].Date
		}
		return filtered[i].Date < filtered[j].Date
	})

	if q.SkipMsgID != "" {
		for i, msg := range filtered {
			if msg.MsgID == q.SkipMsgID {
				filtered = filtered[i+1:]
				break
			}
		}
	}
	if q.StopMsgID != "" {
		for i, msg := range filtered {
			if msg.MsgID == q.StopMsgID {
				filtered = filtered[:i]
				break
			}
		}
	}

	n := q.NToGet
	if n <= 0 {
		n = 100
	}
	if len(filtered) > n {
		filtered = filtered[:n]
	}

	out := make([]StoredIM, len(filtered))
	for i, msg := range filtered {
		out[i] = StoredIM(msg)
	}
	return out
}

// normalizeWebAPIAimID keys the IM log by the same normalization the web client
// applies to aimIds, so a partner stored from a display screen name is still
// found when the client queries by aimId.
func normalizeWebAPIAimID(aimID string) string {
	return state.NewIdentScreenName(aimID).String()
}
