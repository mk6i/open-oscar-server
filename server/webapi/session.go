package webapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/server/oscarclient"
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

// webAPICaps are the capabilities the Web API advertises on behalf of its
// clients. It seeds every session's capability list and is sent as-is at
// sign-on, so the two never drift.
var webAPICaps = [][16]byte{
	wire.CapICQCh2Extended,
	wire.CapUTF8Messages,
}

// Session represents an active Web AIM API session.
type Session struct {
	AimSID              string                                 // Unique session ID for web client
	ScreenName          state.DisplayScreenName                // User identity
	BaseURL             string                                 // Web API base URL advertised to the web client, used to build absolute asset URLs
	Events              []string                               // Subscribed event types
	EventQueue          *EventQueue                            // Per-session event queue
	ClientName          string                                 // Client application name
	ClientVersion       string                                 // Client application version
	CreatedAt           time.Time                              // SessionInstance creation time
	LastAccessed        time.Time                              // Last activity time
	ExpiresAt           time.Time                              // SessionInstance expiration time
	FetchTimeout        int                                    // Long-polling timeout in milliseconds
	TimeToNextFetch     int                                    // Suggested delay before next fetch
	RemoteAddr          string                                 // Client IP address
	BuddyListRefresher  func(ctx context.Context) (any, error) // Called on feedbag changes to push buddylist event
	PermitDenyRefresher func(ctx context.Context) (any, error) // Called on feedbag changes to push permitDeny event
	// BuddyIconURL formats the absolute buddyIcon URL for a buddy from the icon
	// hash carried in a presence SNAC. Returns "" when no URL can be published.
	BuddyIconURL func(screenName state.IdentScreenName, hash []byte) string
	// feedbag is the owner's feedbag as the OSCAR server confirmed it, plus
	// the change the session is waiting on.
	feedbag state.FeedbagMirror
	// feedbagMu admits one feedbag change or reload at a time. A change holds
	// it from the snapshot it diffs against to its last FeedbagStatus.
	feedbagMu sync.Mutex
	// feedbagStale is set when a feedbag change or reload fails, so the
	// server's feedbag may differ from the mirror. The mirror is reloaded
	// before the next change, or when a rate class clears.
	feedbagStale atomic.Bool
	// feedbagQuery is the session's outstanding feedbag query.
	feedbagQuery feedbagQuery
	// presence is the session's view of its buddies' last-known presence, keyed by
	// normalized aimId and fed by the BuddyArrived/BuddyDeparted SNACs the inbound
	// loop receives.
	presence    map[string]BuddyPresence
	presenceMu  sync.RWMutex
	imLog       map[string][]WebAPIStoredIM
	imLogMu     sync.Mutex
	imRepeats   map[uint64]uint64 // count of IMs received, by hash of sender, cookie and text
	imRepeatsMu sync.Mutex
	sentIMs     map[uint64]string // OSCAR message cookie -> the msgId given to the client
	sentIMOrder []uint64          // insertion order of sentIMs, oldest first
	sentIMMu    sync.Mutex
	// typingPeers lists all peers whose last live IM asked for typing events.
	// Only these peers are sent this session's typing events.
	typingPeers   map[string]bool
	typingPeersMu sync.Mutex
	// IMRateClassID is the rate class that sending an IM spends. The web client
	// renders any rate limit event as the IM banner, so only this class's updates
	// may reach it. Zero disables the alert.
	IMRateClassID wire.RateLimitClassID
	logger        *slog.Logger // Logger for debugging

	// bos is the session's connection to the OSCAR BOS service.
	bos oscarclient.Conn
	// cache matches replies from the OSCAR server to the requests that
	// produced them.
	cache *oscarclient.SNACCache
	// snacRateLimits maps SNACs to the rate classes the OSCAR server charges.
	snacRateLimits wire.SNACRateLimits
	// requestTimeout bounds how long a request waits for its reply.
	requestTimeout time.Duration
	// rates holds the rate class status the OSCAR server last announced.
	rates rateLimitState
	// self is the session owner's user info.
	self selfInfo
	// online is closed once the OSCAR server has finished bringing the
	// session online.
	online     chan struct{}
	onlineOnce sync.Once
	// refreshCh wakes the refresher, which reloads a stale feedbag and
	// pushes the buddy list. It holds one request, so requests made while
	// one is pending coalesce.
	refreshCh chan struct{}
	// lookups bounds the session's calls to routes made of rate-limit-exempt
	// lookups.
	lookups *rate.Limiter

	// g runs the session's goroutines, which end when ctx is cancelled.
	g      *errgroup.Group
	ctx    context.Context
	cancel context.CancelFunc

	closeMu sync.Mutex
	closed  bool

	capabilities [][16]byte
	capsMu       sync.RWMutex
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// BuddyPresence is a buddy's last-known presence, assembled from the
// BuddyArrived and BuddyDeparted SNACs a session receives. It carries only what
// those SNACs carry: an away message lives in the locate reply's LocateInfo and
// is not part of a presence broadcast.
type BuddyPresence struct {
	DisplayID  string // screen name as the buddy formats it
	State      string // "online", "away", "idle", "occupied", "dnd", "offline"
	StatusMsg  string
	OnlineTime int64
	IdleTime   int // minutes
	Caps       [][16]byte
	IconHash   []byte
}

// Online reports whether the buddy is visible to the viewer.
func (p BuddyPresence) Online() bool {
	return p.State != "offline"
}

// BuddyPresence returns a buddy's last-known presence and whether the session
// has one. Callers rendering the roster treat a miss as offline.
func (s *Session) BuddyPresence(buddy state.IdentScreenName) (BuddyPresence, bool) {
	s.presenceMu.RLock()
	defer s.presenceMu.RUnlock()
	p, ok := s.presence[buddy.String()]
	return p, ok
}

// setBuddyPresence records a buddy's presence, replacing whatever was there.
func (s *Session) setBuddyPresence(buddy state.IdentScreenName, p BuddyPresence) {
	s.presenceMu.Lock()
	defer s.presenceMu.Unlock()
	if s.presence == nil {
		s.presence = make(map[string]BuddyPresence)
	}
	s.presence[buddy.String()] = p
}

// setBuddyOffline marks a buddy offline, keeping the display name last seen for
// them. A BuddyDeparted carries no TLV block, so nothing else survives: an
// offline buddy publishes no icon, status message or mood.
func (s *Session) setBuddyOffline(buddy state.IdentScreenName) {
	s.presenceMu.Lock()
	defer s.presenceMu.Unlock()
	if s.presence == nil {
		s.presence = make(map[string]BuddyPresence)
	}
	s.presence[buddy.String()] = BuddyPresence{
		DisplayID: s.presence[buddy.String()].DisplayID,
		State:     "offline",
	}
}

// forgetBuddyPresence drops a buddy's cached presence. Callers do this when the
// viewer stops watching them: OSCAR notifies only users who currently watch each
// other, so no arrival or departure for that buddy is relayed here again.
func (s *Session) forgetBuddyPresence(buddy state.IdentScreenName) {
	s.presenceMu.Lock()
	defer s.presenceMu.Unlock()
	delete(s.presence, buddy.String())
}

// forgetUnlistedBuddies drops the cached presence of the named buddies that are no
// longer on the roster. One still listed in another group is still watched.
func (s *Session) forgetUnlistedBuddies(names []string) {
	if len(names) == 0 {
		return
	}
	items := s.Feedbag()
	for _, name := range names {
		if stillListsBuddy(items, name) {
			continue
		}
		s.forgetBuddyPresence(state.NewIdentScreenName(name))
	}
}

// isAIMViewer reports whether the session owner is an AIM account.
func (s *Session) isAIMViewer() bool {
	return s.ScreenName.IdentScreenName().UIN() == 0
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
func (s *Session) IsSubscribedTo(eventType EventType) bool {
	return slices.Contains(s.Events, string(eventType))
}

// PushEvent queues an event for delivery to the web client.
func (s *Session) PushEvent(eventType EventType, data any) {
	s.EventQueue.Push(eventType, data)
}

// Start translates the SNACs the session receives from the OSCAR server into
// events. The caller wires the session's callbacks first, since the inbound
// loop reads them.
func (s *Session) Start() {
	s.goAsync(s.recvBOS)
	s.goAsync(s.refreshBuddyLists)
}

// goAsync runs f in the session's goroutine group, which Close cancels and
// waits for. It does nothing once the session is closing.
func (s *Session) goAsync(f func(ctx context.Context) error) {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return
	}
	s.g.Go(func() error { return f(s.ctx) })
}

// Close tears down the session: it releases any parked event fetchers, closes
// the OSCAR connection, and waits for the session's goroutines to finish. Safe
// to call more than once.
func (s *Session) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	s.closeMu.Unlock()

	s.EventQueue.Close()
	s.cancel()
	s.bos.Close()
	_ = s.g.Wait()
}

// oscarClosed reports whether the session's OSCAR connection has closed.
func (s *Session) oscarClosed() bool {
	select {
	case <-s.bos.Closed():
		return true
	default:
		return false
	}
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
	case wire.Stats:
		// The server sets the report interval last when it brings a session
		// online, after the arrivals of the owner's online buddies.
		if msg.Frame.SubGroup == wire.StatsSetMinReportInterval {
			s.onlineOnce.Do(func() { close(s.online) })
		}
	}
}

// handleOServiceMessage handles OService SNAC messages relayed to the session's
// own OSCAR instance.
func (s *Session) handleOServiceMessage(msg wire.SNACMessage) {
	switch msg.Frame.SubGroup {
	case wire.OServiceUserInfoUpdate:
		if body, ok := msg.Body.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate); ok && len(body.UserInfo) > 0 {
			s.self.setRelayed(body.UserInfo[0])
		}
		s.handleUserInfoUpdate(msg)
	case wire.OServiceRateParamChange:
		if body, ok := msg.Body.(wire.SNAC_0x01_0x0A_OServiceRateParamsChange); ok {
			s.rates.announce(body.Code, body.Rate, time.Now())
			// the server may have dropped feedbag changes while limited
			if body.Code == rateParamsChangeClear && s.feedbagStale.Load() {
				s.wakeRefresher()
			}
		}
		s.handleRateLimitUpdate(msg)
	}
}

// handleUserInfoUpdate surfaces OServiceUserInfoUpdate, which the server relays to
// a user when their own user info changes (notably a buddy icon upload or clear).
// The client re-renders its identity badge from myInfo events only, so we
// translate this into a fresh myInfo. The away message is the one field read off
// the session, since no user info block carries the text.
func (s *Session) handleUserInfoUpdate(msg wire.SNACMessage) {
	if !s.IsSubscribedTo(EventTypeMyInfo) && !s.IsSubscribedTo(EventTypePresence) {
		return
	}

	body, ok := msg.Body.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
	if !ok || len(body.UserInfo) == 0 {
		return
	}
	info := body.UserInfo[0]

	screenName := state.DisplayScreenName(info.ScreenName)
	webState := selfWebState(info, screenName.IdentScreenName().UIN() == 0)

	// A missing icon TLV yields a nil hash, which publishes the placeholder URL
	// and so clears an icon the client still holds.
	hash := buddyIconHash(info)

	myInfo := buildMyInfo(
		screenName,
		webState,
		s.BuddyIconURL(screenName.IdentScreenName(), hash),
		moodIconURL(s.BaseURL, webState, userInfoCaps(info)),
	)
	myInfo.AwayMsg = s.self.awayMessage()
	myInfo.StatusMsg = userStatusMsg(info)

	s.PushEvent(EventTypeMyInfo, myInfo)
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

	s.PushEvent(EventTypeRateLimit, RateLimitEvent{
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

	if !isOffline && (body.ChannelID == wire.ICBMChannelIM || body.ChannelID == wire.ICBMChannelMIME) {
		s.setPeerWantsTyping(state.NewIdentScreenName(body.ScreenName), body.HasTag(wire.ICBMTLVWantEvents))
	}

	// Retrieval answers only the instance that asked, and StartSession asks only
	// when the client subscribed to offlineIM, so a stamped message here is one
	// this session requested. A live IM still needs the im subscription.
	if !isOffline && !s.IsSubscribedTo(EventTypeIM) {
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

	// SNAC user info carries the sender's display screen name. The web client
	// keys conversations and users by the normalized aimId and only renders
	// displayId, so the two forms must not be interchanged.
	partnerDisplay := body.ScreenName
	partner := state.NewIdentScreenName(partnerDisplay)
	partnerAimID := partner.String()
	msgID := s.incomingIMID(partner, body.Cookie, messageText)

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
		friendly := s.aliasFor(partner)
		if friendly == "" {
			friendly = partnerDisplay
		}
		s.PushEvent(EventTypeOfflineIM, OfflineIMEvent{
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
		source := UserInfo{
			AimID:     partnerAimID,
			DisplayID: partnerDisplay,
			Friendly:  s.aliasFor(partner),
			UserType:  userTypeFor(partner),
		}
		if presence, ok := s.BuddyPresence(partner); ok {
			source.State = presence.State
			source.OnlineTime = presence.OnlineTime
		}

		s.PushEvent(EventTypeIM, IMEvent{
			Source:    source,
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

	if s.IsSubscribedTo(EventTypeConversation) {
		// unread is 0 here, not 1, because the "im"/"offlineIM" event pushed above
		// already causes the client to increment its own persisted per-buddy unread
		// tally. The "Recent chats" badge is the sum of that persisted tally and
		// this conversation's unreadCount, so sending 1 here would double-count
		// the message (badge shows 2 for the first IM). Mirrors the sent-IM path,
		// which also passes 0.
		s.PushEvent(EventTypeConversation, ConversationEventData("update", []ConversationEntryData{
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
	if !s.IsSubscribedTo(EventTypeIM) {
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

	s.PushEvent(EventTypeClientError, ClientErrorEvent{
		Source: UserInfo{
			AimID:     sender.String(),
			DisplayID: body.ScreenName,
			Friendly:  s.aliasFor(sender),
			UserType:  userTypeFor(sender),
		},
		Cookie:  s.msgIDForCookie(body.Cookie),
		Channel: channel,
	})
}

// handleTypingNotification handles typing notifications.
func (s *Session) handleTypingNotification(msg wire.SNACMessage) {
	if !s.IsSubscribedTo(EventTypeTyping) {
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

	s.PushEvent(EventTypeTyping, typingEvent)
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
//
// For BuddyArrived updates, presence state is inferred from the TLVUserInfo.
// Away and invisible transitions are typically broadcast using BuddyArrived
// with updated user flags/status bits, not BuddyDeparted.
func (s *Session) handleBuddyArrived(msg wire.SNACMessage) {
	body, ok := msg.Body.(wire.SNAC_0x03_0x0B_BuddyArrived)
	if !ok {
		return
	}

	buddy := state.NewIdentScreenName(body.ScreenName)
	presence := buddyPresenceFrom(body.TLVUserInfo, s.isAIMViewer())

	s.setBuddyPresence(buddy, presence)

	if !s.IsSubscribedTo(EventTypePresence) {
		return
	}

	presenceEvent := PresenceEvent{
		AimID:      buddy.String(),
		Friendly:   s.aliasFor(buddy),
		State:      presence.State,
		UserType:   userTypeFor(buddy),
		StatusMsg:  presence.StatusMsg,
		IdleTime:   presence.IdleTime,
		OnlineTime: presence.OnlineTime,
		MoodIcon:   moodIconURL(s.BaseURL, presence.State, presence.Caps),
	}

	// A BuddyArrived carries the buddy's current icon in TLV 0x1D whenever they
	// have one, so an icon change (or clear, which arrives as the sentinel hash)
	// rides along on the presence broadcast. Publish the matching URL: with an
	// icon it is content-addressed; without one it is the placeholder URL, which
	// differs from any prior icon URL and so clears a removed icon under the
	// client's shallow merge. An empty result (no origin known) is omitted, which
	// preserves whatever icon the client already holds.
	if s.BuddyIconURL != nil {
		presenceEvent.BuddyIcon = s.BuddyIconURL(buddy, presence.IconHash)
	}

	s.PushEvent(EventTypePresence, presenceEvent)
}

// bartIDs returns the BART items a user info block carries. They travel as a list
// in one TLV: a user's buddy icon and status message ride in it together.
func bartIDs(info wire.TLVUserInfo) []wire.BARTID {
	b, ok := info.Bytes(wire.OServiceUserInfoBARTInfo)
	if !ok {
		return nil
	}
	var ids []wire.BARTID
	if err := wire.UnmarshalBE(&ids, bytes.NewReader(b)); err != nil {
		return nil
	}
	return ids
}

// buddyIconHash returns the buddy icon hash carried in a user info block, or nil
// when it carries none.
func buddyIconHash(info wire.TLVUserInfo) []byte {
	for _, id := range bartIDs(info) {
		if id.Type == wire.BARTTypesBuddyIcon || id.Type == wire.BARTTypesBuddyIconSmall {
			return id.Hash
		}
	}
	return nil
}

// userStatusMsg returns the status message carried in a user info block, or ""
// when it carries none or one that cannot be decoded.
func userStatusMsg(info wire.TLVUserInfo) string {
	for _, id := range bartIDs(info) {
		msg, err := id.StatusText()
		if err != nil {
			continue
		}
		if msg != "" {
			return msg
		}
	}
	return ""
}

// sessionStatusMsg returns the status message a session currently advertises.
func sessionStatusMsg(instance *state.SessionInstance) string {
	status, _ := instance.Session().Status()
	msg, err := status.StatusText()
	if err != nil {
		return ""
	}
	return msg
}

// buddyWebState reports the web state a buddy's user info describes, along with
// the minutes they have been idle. Invisibility reads as offline. Idle is always
// reported, but only upgrades an otherwise online user to "idle".
func buddyWebState(info wire.TLVUserInfo, isAIMViewer bool) (string, int) {
	idle := 0
	if mins, ok := info.Uint16BE(wire.OServiceUserInfoIdleTime); ok {
		idle = int(mins)
	}

	if info.IsInvisible() {
		return "offline", idle
	}

	// statusBitState must be consulted before IsAway: Busy and DND also raise
	// the unavailable flag, so an away-first test reports every busy user as
	// away.
	if st := statusBitState(info, isAIMViewer); st != "" {
		return st, idle
	}
	if info.IsAway() {
		return "away", idle
	}
	if mask, ok := info.Uint32BE(wire.OServiceUserInfoStatus); ok && mask&wire.OServiceUserStatusAway != 0 {
		return "away", idle
	}
	if idle > 0 {
		return "idle", idle
	}
	return "online", idle
}

// buddyPresenceFrom builds a presence record from the user info block a
// BuddyArrived carries. isAIMViewer decides whether Busy and DND collapse to
// "away".
func buddyPresenceFrom(info wire.TLVUserInfo, isAIMViewer bool) BuddyPresence {
	st, idle := buddyWebState(info, isAIMViewer)

	p := BuddyPresence{
		DisplayID: info.ScreenName,
		State:     st,
		IdleTime:  idle,
		StatusMsg: userStatusMsg(info),
		Caps:      userInfoCaps(info),
		IconHash:  buddyIconHash(info),
	}
	if tod, ok := info.Uint32BE(wire.OServiceUserInfoSignonTOD); ok {
		p.OnlineTime = int64(tod)
	}
	return p
}

// hasAwayMsg reports whether a state is one whose user may be advertising an
// away message.
func hasAwayMsg(webState string) bool {
	switch webState {
	case "away", "occupied", "dnd":
		return true
	}
	return false
}

// awayMessage reads a buddy's away message, which lives in the locate reply's
// LocateInfo and so is absent from presence broadcasts. Callers ask only for a
// buddy the view already reports as unavailable.
func (s *Session) awayMessage(ctx context.Context, buddy state.IdentScreenName) string {
	reply, err := s.request(ctx, wire.Locate, wire.LocateUserInfoQuery,
		wire.SNAC_0x02_0x05_LocateUserInfoQuery{
			Type:       uint16(wire.LocateTypeUnavailable),
			ScreenName: buddy.String(),
		}, wire.LocateUserInfoReply)
	if err != nil {
		s.logger.WarnContext(ctx, "failed to query away message",
			"screenName", buddy.String(), "error", err)
		return ""
	}

	info, ok := reply.Body.(wire.SNAC_0x02_0x06_LocateUserInfoReply)
	if !ok {
		// Locate error => the buddy went offline or blocked the caller between
		// their arrival and this query.
		return ""
	}

	msg, _ := info.LocateInfo.String(wire.LocateTLVTagsInfoUnavailableData)
	return msg
}

// handleBuddyDeparted handles when a buddy goes offline.
func (s *Session) handleBuddyDeparted(msg wire.SNACMessage) {
	body, ok := msg.Body.(wire.SNAC_0x03_0x0C_BuddyDeparted)
	if !ok {
		return
	}

	buddy := state.NewIdentScreenName(body.ScreenName)

	// Recorded before the subscription check, for the same reason as arrivals.
	s.setBuddyOffline(buddy)

	if !s.IsSubscribedTo(EventTypePresence) {
		return
	}

	// BuddyIcon is deliberately omitted: an offline buddy keeps their icon, and
	// omitting it lets the client's merge preserve the icon it already holds.
	presenceEvent := PresenceEvent{
		AimID:    buddy.String(),
		Friendly: s.aliasFor(buddy),
		State:    "offline",
		UserType: userTypeFor(buddy),
	}

	s.PushEvent(EventTypePresence, presenceEvent)
}

// feedbagResultAuthRequired is the per-item feedbag result meaning the target's ICQ
// settings require authorization, so the item was not stored.
const feedbagResultAuthRequired = uint16(0x000E)

// refreshBuddyList asks the refresher to push the buddy list to the client.
// Building it needs replies from the OSCAR server, which the inbound loop
// can't wait for. Requests made while one is pending coalesce into it.
func (s *Session) refreshBuddyList() {
	if s.IsSubscribedTo(EventTypeBuddyList) {
		s.wakeRefresher()
	}
}

// wakeRefresher asks the refresher to run.
func (s *Session) wakeRefresher() {
	select {
	case s.refreshCh <- struct{}{}:
	default:
	}
}

// refreshBuddyLists reloads a stale feedbag and pushes the buddy list to
// the client each time it's woken, until ctx is done.
func (s *Session) refreshBuddyLists(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.refreshCh:
			s.reloadStaleFeedbag(ctx)
			if s.BuddyListRefresher == nil || !s.IsSubscribedTo(EventTypeBuddyList) {
				continue
			}
			payload, err := s.BuddyListRefresher(ctx)
			if err != nil {
				s.logger.Error("failed to refresh buddy list after feedbag change", "err", err)
				continue
			}
			s.PushEvent(EventTypeBuddyList, payload)
		}
	}
}

// handleFeedbagMessage applies the feedbag changes made at the owner's other
// locations. A FeedbagStatus arriving here answers a change the session gave
// up on, so the mirror is already stale and reloads before the next change.
func (s *Session) handleFeedbagMessage(msg wire.SNACMessage) {
	var items []wire.FeedbagItem
	var del bool
	switch body := msg.Body.(type) {
	case wire.SNAC_0x13_0x08_FeedbagInsertItem:
		items = body.Items
	case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
		items = body.Items
	case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
		items, del = body.Items, true
	default:
		return
	}

	s.applyRemoteFeedbag(del, items)

	// Only a delete carries items that may leave buddies unwatched.
	if del {
		var removed []string
		for _, item := range items {
			if item.ClassID == wire.FeedbagClassIdBuddy && item.Name != "" {
				removed = append(removed, item.Name)
			}
		}
		s.forgetUnlistedBuddies(removed)
	}

	s.refreshBuddyList()

	if s.PermitDenyRefresher != nil {
		for _, item := range items {
			if item.ClassID == wire.FeedbagClassIDPermit ||
				item.ClassID == wire.FeedbagClassIDDeny ||
				item.ClassID == wire.FeedbagClassIdPdinfo {
				pdd, err := s.PermitDenyRefresher(s.ctx)
				if err != nil {
					s.logger.Error("failed to refresh permit/deny after feedbag change", "err", err)
				} else {
					s.PushEvent(EventTypePermitDeny, pdd)
				}
				break
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

// CreateSession creates a new WebAPI session whose OSCAR connection is bos.
//
// The session does not translate the SNACs it receives yet: the caller must
// wire the session's refresher callbacks (BuddyListRefresher, BuddyIconURL,
// ...) and then call Start. Wiring them after Start would race the inbound
// loop, which reads them as it converts SNACs into events.
func (m *SessionManager) CreateSession(screenName state.DisplayScreenName, events []string, bos oscarclient.Conn, snacRateLimits wire.SNACRateLimits, baseURL string, logger *slog.Logger) (*Session, error) {
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

	session := newSession(aimsid, screenName, events, bos, snacRateLimits, baseURL, logger)
	m.sessions[aimsid] = session

	return session, nil
}

// newSession creates a session over the OSCAR connection bos.
func newSession(aimsid string, screenName state.DisplayScreenName, events []string, bos oscarclient.Conn, snacRateLimits wire.SNACRateLimits, baseURL string, logger *slog.Logger) *Session {
	now := time.Now()
	sessCtx, sessCancel := context.WithCancel(context.Background())
	g, gCtx := errgroup.WithContext(sessCtx)
	return &Session{
		ctx:             gCtx,
		cancel:          sessCancel,
		g:               g,
		AimSID:          aimsid,
		ScreenName:      screenName,
		BaseURL:         baseURL,
		Events:          events,
		EventQueue:      NewEventQueue(1000), // Max 1000 events per session
		CreatedAt:       now,
		LastAccessed:    now,
		ExpiresAt:       now.Add(webAPISessionTTL),
		FetchTimeout:    60000, // 60 seconds default for better stability
		TimeToNextFetch: 500,   // 500ms suggested delay
		logger:          logger,
		capabilities:    slices.Clone(webAPICaps),
		bos:             bos,
		cache:           oscarclient.NewSNACCache(),
		snacRateLimits:  snacRateLimits,
		requestTimeout:  defaultRequestTimeout,
		refreshCh:       make(chan struct{}, 1),
		online:          make(chan struct{}),
		lookups:         rate.NewLimiter(rate.Every(lookupInterval), lookupBurst),
	}
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

	// A closed OSCAR connection (a boot, a rate-limit disconnect) ends the
	// session while it is still unexpired. The aimsid must stop resolving at
	// that point rather than when the reaper next sweeps it.
	if session.oscarClosed() {
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
		if now.After(session.ExpiresAt) || session.oscarClosed() {
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

// setPeerWantsTyping records whether a peer's latest IM asked for typing events.
func (s *Session) setPeerWantsTyping(peer state.IdentScreenName, wants bool) {
	s.typingPeersMu.Lock()
	defer s.typingPeersMu.Unlock()
	if !wants {
		delete(s.typingPeers, peer.String())
		return
	}
	if s.typingPeers == nil {
		s.typingPeers = make(map[string]bool)
	}
	s.typingPeers[peer.String()] = true
}

// PeerWantsTyping reports whether a peer's latest IM asked for typing events. A
// peer that has not sent this session an IM has not asked.
func (s *Session) PeerWantsTyping(peer state.IdentScreenName) bool {
	s.typingPeersMu.Lock()
	defer s.typingPeersMu.Unlock()
	return s.typingPeers[peer.String()]
}

// WebAPIStoredIM is one message in a Web AIM session's in-memory IM log.
// The Web AIM client expects fetchStoredIMs entries with sender, message, msgId, and date.
type WebAPIStoredIM struct {
	Sender  string
	Message string
	MsgID   string
	Date    int64 // Unix seconds
}

// incomingIMID returns the msgId of an IM received from sender. Every session
// of the account derives the same msgId for an IM, since the client keeps one
// IM history for all of the account's tabs and dedupes it by msgId. Senders
// may reuse a cookie, so the msgId also counts the IMs with the same sender,
// cookie and text that the session received before.
func (s *Session) incomingIMID(sender state.IdentScreenName, cookie uint64, text string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sender.String()))
	_, _ = h.Write([]byte{0})
	_ = binary.Write(h, binary.BigEndian, cookie)
	_, _ = h.Write([]byte(text))
	key := h.Sum64()

	s.imRepeatsMu.Lock()
	if s.imRepeats == nil {
		s.imRepeats = make(map[uint64]uint64)
	}
	n := s.imRepeats[key]
	s.imRepeats[key] = n + 1
	s.imRepeatsMu.Unlock()

	_ = binary.Write(h, binary.BigEndian, n)
	return strconv.FormatUint(h.Sum64(), 16)
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

func (s *Session) Caps() [][16]byte {
	s.capsMu.RLock()
	defer s.capsMu.RUnlock()
	return slices.Clone(s.capabilities)
}

// ClearMood removes the mood capability the session advertises, if any. The
// user then presents whatever presence state they are in.
func (s *Session) ClearMood() {
	s.capsMu.Lock()
	defer s.capsMu.Unlock()
	s.clearMood()
}

// clearMood drops every mood capability the session advertises. The caller must
// hold s.capsMu.
func (s *Session) clearMood() {
	s.capabilities = slices.DeleteFunc(s.capabilities, func(cap [16]byte) bool {
		return wire.IsMoodCap(cap)
	})
}

// SetMood replaces the mood capability the session advertises. A client shows
// one mood at a time, so whichever mood was set before is dropped.
//
// It panics when mood is not a mood capability: the caller resolves it from the
// mood table, so anything else is a programming error rather than bad input.
func (s *Session) SetMood(mood uuid.UUID) {
	s.capsMu.Lock()
	defer s.capsMu.Unlock()

	if !wire.IsMoodCap(mood) {
		panic("uuid is not a mood capability")
	}

	s.clearMood()

	s.capabilities = append(s.capabilities, mood)
}

// normalizeWebAPIAimID keys the IM log by the same normalization the web client
// applies to aimIds, so a partner stored from a display screen name is still
// found when the client queries by aimId.
func normalizeWebAPIAimID(aimID string) string {
	return state.NewIdentScreenName(aimID).String()
}
