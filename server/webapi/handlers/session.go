package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/webapi/middleware"
	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// SessionHandler handles Web AIM API session management endpoints.
type SessionHandler struct {
	SessionManager   *state.WebAPISessionManager
	OSCARAuthService AuthService
	FeedbagService   FeedbagService
	ICBMService      ICBMService
	BuddyListManager *BuddyListManager
	IconSource       BuddyIconSource
	Logger           *slog.Logger
	OServiceService  OServiceService
	// the same SNAC-to-rate-class mapping RateLimitMiddleware enforces against, so
	// the class a session alerts on cannot drift from the one it is charged
	SNACRateLimits  wire.SNACRateLimits
	FnSessCfg       func(sess *state.Session)
	FnSessInit      func(instance *state.SessionInstance) func() error
	FnInstanceClose func(instance *state.SessionInstance) func()
}

// AuthService defines methods needed for authentication.
type AuthService interface {
	BUCPChallenge(ctx context.Context, bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error)
	BUCPLogin(ctx context.Context, bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, endpointCfg config.Endpoint) (wire.SNACMessage, error)
	CrackCookie(authCookie []byte) (state.ServerCookie, error)
	RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie, conf func(sess *state.Session)) (*state.SessionInstance, error)
	FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error)
	Signout(ctx context.Context, session *state.Session)
	SignoutChat(ctx context.Context, sess *state.Session)
}

// SessionManager defines methods for OSCAR session management.
type SessionManager interface {
	AddSession(ctx context.Context, screenName state.DisplayScreenName, doMultiSess bool, cfg ...func(sess *state.Session)) (*state.SessionInstance, error)
	RemoveSession(session *state.Session)
	RelayToScreenName(ctx context.Context, screenName state.IdentScreenName, msg wire.SNACMessage)
}

// BuddyListRegistry defines methods for buddy list management.
type BuddyListRegistry interface {
	RegisterBuddyList(ctx context.Context, screenName state.IdentScreenName) error
	UnregisterBuddyList(ctx context.Context, screenName state.IdentScreenName) error
}

type ChatSessionManager interface {
	RemoveUserFromAllChats(user state.IdentScreenName)
}

// MyInfo is the user's own identity blob, which the Web AIM client renders in
// its identity badge. It is both the startSession payload's myInfo and the
// myInfo event's data.
type MyInfo struct {
	AimID     string `json:"aimId" xml:"aimId"`
	DisplayID string `json:"displayId" xml:"displayId"`
	Friendly  string `json:"friendly" xml:"friendly"`
	State     string `json:"state" xml:"state"`
	UserType  string `json:"userType" xml:"userType"` // "aim", "icq"
	Bot       bool   `json:"bot" xml:"bot"`
	Service   string `json:"service" xml:"service"` // "AIM", "ICQ" (compared case-sensitively)
	// Capabilities is always sent, empty included, because the client iterates it
	// unconditionally.
	Capabilities []string `json:"capabilities" xml:"capabilities>capability"`
	// BuddyIcon is omitted when empty so the client's merge preserves the icon it
	// already holds.
	BuddyIcon   string      `json:"buddyIcon,omitempty" xml:"buddyIcon,omitempty"`
	AwayMsg     string      `json:"awayMsg,omitempty" xml:"awayMsg,omitempty"`
	StatusMsg   string      `json:"statusMsg,omitempty" xml:"statusMsg,omitempty"`
	OnlineTime  int64       `json:"onlineTime,omitempty" xml:"onlineTime,omitempty"`
	MemberSince int64       `json:"memberSince,omitempty" xml:"memberSince,omitempty"`
	Self        *MyInfoSelf `json:"self,omitempty" xml:"self,omitempty"`
}

// MyInfoSelf carries the session-scoped half of myInfo: the instance the client
// is talking to and the limits it must respect.
type MyInfoSelf struct {
	InstNum        int        `json:"instNum" xml:"instNum"`
	LoginTime      int64      `json:"loginTime" xml:"loginTime"`
	SessionTimeout int        `json:"sessionTimeout" xml:"sessionTimeout"`
	Events         []string   `json:"events" xml:"events>event"`
	AssertCaps     []string   `json:"assertCaps" xml:"assertCaps>capability"`
	RightsInfo     RightsInfo `json:"rightsInfo" xml:"rightsInfo"`
}

// RightsInfo reports the account limits the client enforces client-side.
type RightsInfo struct {
	MaxDenies            int `json:"maxDenies" xml:"maxDenies"`
	MaxPermits           int `json:"maxPermits" xml:"maxPermits"`
	MaxWatchers          int `json:"maxWatchers" xml:"maxWatchers"`
	MaxBuddies           int `json:"maxBuddies" xml:"maxBuddies"`
	MaxTempBuddies       int `json:"maxTempBuddies" xml:"maxTempBuddies"`
	MaxIMSize            int `json:"maxIMSize" xml:"maxIMSize"`
	MinInterIcbmInterval int `json:"minInterIcbmInterval" xml:"minInterIcbmInterval"`
	MaxSourceEvil        int `json:"maxSourceEvil" xml:"maxSourceEvil"`
	MaxDstEvil           int `json:"maxDstEvil" xml:"maxDstEvil"`
	MaxSigLen            int `json:"maxSigLen" xml:"maxSigLen"`
}

// WellKnownUrls advertises the API roots to clients that discover them rather
// than deriving them.
type WellKnownUrls struct {
	WebApiBase        string `json:"webApiBase" xml:"webApiBase"`
	FetchBaseURL      string `json:"fetchBaseURL" xml:"fetchBaseURL"`
	LifestreamApiBase string `json:"lifestreamApiBase" xml:"lifestreamApiBase"`
}

// StartSessionEvents seeds the client with the first value of each event it
// subscribed to, so it renders a populated UI before its first fetchEvents.
// Each field is absent unless the client asked for that event.
type StartSessionEvents struct {
	MyInfo     *MyInfo         `json:"myInfo,omitempty" xml:"myInfo,omitempty"`
	BuddyList  *BuddyListData  `json:"buddylist,omitempty" xml:"buddylist,omitempty"`
	Preference *PreferenceData `json:"preference,omitempty" xml:"preference,omitempty"`
	PermitDeny interface{}     `json:"permitDeny,omitempty" xml:"permitDeny,omitempty"`
}

// BuddyListData is the buddylist event payload and the buddy list half of the
// startSession seed.
type BuddyListData struct {
	Groups []WebAPIBuddyGroup `json:"groups" xml:"groups>group"`
}

// StartSessionData is the startSession payload.
type StartSessionData struct {
	AimSID          string `json:"aimsid" xml:"aimsid"`
	Ts              int64  `json:"ts" xml:"ts"`
	FetchTimeout    int    `json:"fetchTimeout" xml:"fetchTimeout"`
	TimeToNextFetch int    `json:"timeToNextFetch" xml:"timeToNextFetch"`
	// FetchBaseURL sits directly in data, not in wellKnownUrls: it is where the
	// client reads its poll URL from.
	FetchBaseURL  string              `json:"fetchBaseURL" xml:"fetchBaseURL"`
	MyInfo        *MyInfo             `json:"myInfo,omitempty" xml:"myInfo,omitempty"`
	Events        *StartSessionEvents `json:"events,omitempty" xml:"events,omitempty"`
	WellKnownUrls *WellKnownUrls      `json:"wellKnownUrls,omitempty" xml:"wellKnownUrls,omitempty"`
}

// StartSession handles GET /aim/startSession requests.
func (h *SessionHandler) StartSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get API key info from context (set by auth middleware)
	apiKey, ok := ctx.Value(middleware.ContextKeyAPIKey).(*state.WebAPIKey)
	if !ok {
		h.sendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// Parse parameters
	params := r.URL.Query()

	// Get authentication token if provided
	authToken := params.Get("a")

	// Get client info
	clientName := params.Get("clientName")
	if clientName == "" {
		clientName = "WebAIM"
	}
	clientVersion := params.Get("clientVersion")
	if clientVersion == "" {
		clientVersion = "1.0"
	}

	// Get events to subscribe to
	eventsParam := params.Get("events")
	var events []string
	if eventsParam != "" {
		events = strings.Split(eventsParam, ",")
		h.Logger.DebugContext(ctx, "parsing events from request",
			"eventsParam", eventsParam,
			"parsedEvents", events,
		)
	} else {
		// Default events if none specified
		events = []string{"buddylist", "presence", "im", "sentIM"}
		h.Logger.DebugContext(ctx, "using default events",
			"events", events,
		)
	}

	// Get timeout settings
	timeout := 60000 // Default 60 seconds for better stability with Gromit
	if t := params.Get("timeout"); t != "" {
		if val, err := strconv.Atoi(t); err == nil && val > 0 {
			timeout = val * 1000 // Convert to milliseconds
		}
	}

	// A Web API session must be bridged to an authenticated OSCAR session;
	// anonymous guests are not supported.
	if authToken == "" {
		h.sendError(w, r, http.StatusUnauthorized, "authentication token required")
		return
	}

	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(authToken))
	if err != nil {
		h.Logger.Warn("invalid authentication token (base64)", "error", err)
		h.sendError(w, r, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	cookie, err := h.OSCARAuthService.CrackCookie(rawCookie)
	if err != nil {
		h.Logger.Warn("invalid authentication token", "error", err)
		h.sendError(w, r, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	screenName := cookie.ScreenName
	tokenPreview := authToken
	if len(tokenPreview) > 8 {
		tokenPreview = tokenPreview[:8] + "..."
	}
	h.Logger.Info("authenticated session requested",
		"token", tokenPreview,
		"screenName", screenName)

	var instance *state.SessionInstance

	// Create OSCAR session
	instance, err = h.OSCARAuthService.RegisterBOSSession(ctx, cookie, h.FnSessCfg)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to create OSCAR session", "err", err.Error())
		h.sendError(w, r, http.StatusServiceUnavailable, "unable to establish session")
		return
	}

	if err = instance.Session().RunOnce(h.FnSessInit(instance)); err != nil {
		h.Logger.ErrorContext(context.Background(), "failed to init session", "err", err.Error())
		// RunOnce has already closed the whole session; this is belt-and-braces,
		// since CloseInstance is idempotent and nothing else owns the instance yet.
		instance.CloseInstance()
		h.sendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	instance.OnClose(h.FnInstanceClose(instance))

	if err := h.FeedbagService.Use(ctx, instance); err != nil {
		h.Logger.ErrorContext(ctx, "failed to use feedbag", "err", err.Error())
	}

	// A web client signals that it wants typing events through its event
	// subscription, not through a stored feedbag buddy pref. Reflect that
	// on the OSCAR session so ICBMService attaches the WantEvents TLV to
	// outgoing IMs, prompting recipients to send typing notifications
	// back. This must run after FeedbagService.Use, which otherwise
	// overwrites the flag from stored prefs the web user may not have set.
	instance.Session().SetTypingEventsEnabled(slices.Contains(events, "typing"))

	instance.SetSignonComplete()

	if err := h.OServiceService.ClientOnline(ctx, wire.BOS, wire.SNAC_0x01_0x02_OServiceClientOnline{}, instance); err != nil {
		h.Logger.ErrorContext(ctx, "failed to set client online", "err", err.Error())
		instance.CloseInstance()
		h.sendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// The rate class sending an IM spends. Only its updates surface to the client's
	// conversation-window alert, which renders any rateLimit event as the IM
	// banner. A miss yields zero, which disables the alert rather than indexing a
	// rate class that isn't there.
	imRateClassID, ok := h.SNACRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		h.Logger.ErrorContext(ctx, "no rate class maps to sending an IM, rate limit events are disabled")
	}

	// Subscribe the same way an OSCAR client does at handshake, so the per-account
	// monitor broadcasts this class's transitions to this session.
	if imRateClassID != 0 {
		h.OServiceService.RateParamsSubAdd(ctx, instance, wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
			ClassIDs: []uint16{uint16(imRateClassID)},
		})
	}

	// Create WebAPI session
	// Record the origin the client reached us on. Asset URLs published to the
	// client (buddy icons) must be absolute, since the client page is served from
	// a different origin than this API, and they are built in places that have no
	// request in hand. Pinning the origin here also keeps those URLs on the same
	// host as the wellKnownUrls advertised below. It is passed into CreateSession
	// so it is set before the session is published and its listener goroutine can
	// read it.
	baseURL := baseURLFromRequest(r)

	session, err := h.SessionManager.CreateSession(screenName, apiKey.DevID, events, instance, baseURL, h.Logger)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to create session", "err", err.Error())
		// CreateSession refuses once the manager is shut down, so this is the
		// path a startSession racing shutdown takes. The WebAPISession that
		// would have owned the instance was never created.
		instance.CloseInstance()
		h.sendError(w, r, http.StatusInternalServerError, "failed to create session")
		return
	}

	h.Logger.DebugContext(ctx, "session created with event subscriptions",
		"aimsid", session.AimSID,
		"events", events,
	)

	// Wire buddy list refresher so feedbag SNACs from the OSCAR bridge trigger a buddylist event.
	// The refresher yields the whole buddylist event payload, not just the groups,
	// so the session that pushes it does not have to know the payload's shape.
	session.BuddyListRefresher = func(ctx context.Context) (interface{}, error) {
		groups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session)
		if err != nil {
			return nil, err
		}
		return &BuddyListData{Groups: groups}, nil
	}

	// Wire the alias loader so OSCAR-driven im/presence events can repeat the
	// buddy's friendly name. The client discards the alias it holds each time it
	// merges a user map, so an event that omits it renames the buddy. The session
	// caches what this returns until a feedbag change invalidates it.
	session.BuddyAliasLoader = func(ctx context.Context) (map[string]string, error) {
		return LookupBuddyAliases(ctx, h.FeedbagService, session.OSCARSession)
	}

	// Wire the buddy-icon URL formatter so presence broadcasts (BuddyArrived) can
	// publish a buddy's current icon from the hash carried in the SNAC, no lookup.
	session.BuddyIconURL = func(sn state.IdentScreenName, hash []byte) string {
		return h.IconSource.URLForHash(session.BaseURL, sn, hash)
	}

	// Wire the myInfo refresher so a self user-info update (icon upload/clear)
	// re-renders the identity badge. currentWebState reflects the user's live
	// presence; PublishedURL reflects the feedbag icon, already updated by the time
	// the OServiceUserInfoUpdate is relayed.
	session.MyInfoRefresher = func(ctx context.Context) (interface{}, error) {
		icon := h.IconSource.PublishedURL(ctx, session.BaseURL, screenName.IdentScreenName())
		return buildMyInfo(screenName, currentWebState(session.OSCARSession), icon), nil
	}

	// Wire permit/deny refresher so FeedbagUpdateItem SNACs trigger a permitDeny event.
	session.PermitDenyRefresher = func(ctx context.Context) (interface{}, error) {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery}
		fb, err := h.FeedbagService.Query(ctx, session.OSCARSession, frame)
		if err != nil {
			return nil, err
		}
		reply, ok := fb.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
		if !ok {
			return nil, fmt.Errorf("unexpected feedbag reply type")
		}
		return permitDenyData(reply.Items), nil
	}

	// Only IM-class rate limit updates should surface to the client alert.
	session.IMRateClassID = imRateClassID
	seedRateLimitAlert(session, imRateClassID)

	// Now that every refresher callback is wired, start the OSCAR listener. Doing
	// this inside CreateSession would race these assignments, since the goroutine
	// reads the callbacks as it converts SNACs into events.
	session.StartListeningToOSCARSession()

	// Store client info
	session.ClientName = clientName
	session.ClientVersion = clientVersion
	session.FetchTimeout = timeout
	session.RemoteAddr = r.RemoteAddr

	// The identity badge renders the user's own icon from myInfo, which is the
	// only event it binds its self-presence render to. PublishedURL always yields
	// a URL (the blank placeholder when the user has no icon) so that clearing the
	// icon propagates to the badge.
	myIconURL := h.IconSource.PublishedURL(ctx, baseURL, screenName.IdentScreenName())

	now := time.Now().Unix()

	// Prepare response
	data := &StartSessionData{
		AimSID:          session.AimSID,
		Ts:              now,
		FetchTimeout:    session.FetchTimeout,
		TimeToNextFetch: session.TimeToNextFetch,
		// Gromit expects fetchBaseURL directly in data, not in wellKnownUrls
		FetchBaseURL: fmt.Sprintf("%s/aim/fetchEvents?aimsid=%s&seqNum=0", baseURL, session.AimSID),
		// Add wellKnownUrls for other clients that might use it.
		WellKnownUrls: &WellKnownUrls{
			WebApiBase:   baseURL + "/",
			FetchBaseURL: baseURL + "/aim/fetchEvents",
			// The client appends the bare method name to this base, so it has to
			// carry the /lifestream/ path the routes are registered under.
			LifestreamApiBase: baseURL + "/lifestream/",
		},
		Events: &StartSessionEvents{},
	}

	myInfoPayload := buildMyInfo(screenName, "online", myIconURL)
	myInfoPayload.OnlineTime = time.Now().Unix()
	myInfoPayload.MemberSince = time.Now().Unix() - 86400*30 // 30 days ago
	myInfoPayload.Self = &MyInfoSelf{
		InstNum:        1,
		LoginTime:      time.Now().Unix(),
		SessionTimeout: 30,
		Events:         events,
		AssertCaps:     []string{},
		RightsInfo: RightsInfo{
			MaxDenies:            500,
			MaxPermits:           500,
			MaxWatchers:          3000,
			MaxBuddies:           500,
			MaxTempBuddies:       160,
			MaxIMSize:            3987,
			MinInterIcbmInterval: 1000,
			MaxSourceEvil:        900,
			MaxDstEvil:           999,
			MaxSigLen:            4096,
		},
	}
	data.MyInfo = myInfoPayload
	data.Events.MyInfo = myInfoPayload

	// Seeds that only queue an event are keyed off the subscription rather than
	// iterated with it, so the server fixes their order and each is queued once.
	// myInfo and presence render the identity badge from the same payload and the
	// client subscribes to both, which a per-subscription loop would queue twice.
	if slices.Contains(events, "myInfo") || slices.Contains(events, "presence") {
		myInfoData := buildMyInfo(screenName, "online", myIconURL)
		myInfoData.OnlineTime = time.Now().Unix()
		myInfoData.MemberSince = time.Now().Unix() - 86400*30 // 30 days ago
		session.EventQueue.Push(types.EventTypeMyInfo, myInfoData)
	}

	if slices.Contains(events, "conversation") {
		session.EventQueue.Push(types.EventTypeConversation,
			types.ConversationEventData("list", nil))
	}

	// The remaining seeds also populate the response payload, so they stay keyed off
	// the subscription list they are rendered into.
	for _, event := range events {
		switch types.EventType(event) {
		case types.EventTypeBuddyList:
			buddyGroups := []WebAPIBuddyGroup{}
			if h.BuddyListManager != nil {
				var err error
				buddyGroups, err = h.BuddyListManager.GetBuddyListForUser(ctx, session)
				if err != nil {
					h.Logger.ErrorContext(ctx, "failed to get buddy list", "err", err.Error())
					buddyGroups = []WebAPIBuddyGroup{}
				}
			}
			if buddyGroups == nil {
				buddyGroups = []WebAPIBuddyGroup{}
			}
			blPayload := &BuddyListData{Groups: buddyGroups}
			data.Events.BuddyList = blPayload
			session.EventQueue.Push(types.EventTypeBuddyList, blPayload)
		case types.EventTypePreference:
			// Seed the client with effective preference values: the user's stored
			// prefs where set, and the server-side spec defaults otherwise. The
			// client reads its buddy-list display prefs (e.g. showGroups) only from
			// this event and has no default of its own for them, so an omitted pref
			// would silently fall back to the client's hidden default and, for
			// showGroups, hide group headers.
			prefPayload := &PreferenceData{}
			if item, err := buddyPrefsItem(ctx, h.FeedbagService, session.OSCARSession); err != nil {
				h.Logger.ErrorContext(ctx, "failed to get preferences", "err", err.Error())
			} else {
				prefPayload = effectiveBuddyPrefs(item.TLVList)
			}
			data.Events.Preference = prefPayload
			session.EventQueue.Push(types.EventTypePreference, prefPayload)
		case types.EventTypePermitDeny:
			// The client keeps its privacy state solely in the model this event
			// populates. Both the block/unblock menu action and the "blocked"
			// presence state read that model and no-op silently while it is
			// empty, so the session has to start with one.
			var pdPayload interface{} = PermitDenyData{PDMode: "permitAll"}
			if pdd, err := session.PermitDenyRefresher(ctx); err != nil {
				h.Logger.ErrorContext(ctx, "failed to get permit/deny settings", "err", err.Error())
			} else {
				pdPayload = pdd
			}
			data.Events.PermitDeny = pdPayload
			session.EventQueue.Push(types.EventTypePermitDeny, pdPayload)
		}
	}

	// Drain messages stored while the user was signed off. The service relays them
	// as ordinary ICBMChannelMsgToClient SNACs stamped with a send time, which the
	// listener started above turns into offlineIM events. Retrieval deletes them
	// from the store and the Web API has no ack, so this is the one delivery attempt.
	// Skip it for a client that did not subscribe, which leaves the messages stored
	// for a session that wants them rather than spending them on one that does not.
	//
	// This trails every event queued above because the listener pushes from its own
	// goroutine, so anything drained here can overtake a later push. An offlineIM
	// names its sender by bare aimId and leaves the client to resolve the display
	// name against the buddy list it holds, and the conversation list is rebuilt from
	// scratch on the first "list" the client sees. Both of those events are queued in
	// the loop above, so the drain has to come after it.
	if slices.Contains(events, "offlineIM") {
		frame := wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMOfflineRetrieve,
			RequestID: wire.ReqIDFromServer,
		}
		if _, err := h.ICBMService.OfflineRetrieve(ctx, instance, frame); err != nil {
			h.Logger.ErrorContext(ctx, "failed to retrieve offline messages", "err", err.Error())
		}
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = data

	// Send response in requested format (JSON, JSONP, XML, or AMF)
	SendResponse(w, r, resp, h.Logger)

	h.Logger.DebugContext(ctx, "session started",
		"aimsid", session.AimSID,
		"screen_name", screenName,
		"dev_id", apiKey.DevID,
		"events", events,
		"format", r.URL.Query().Get("f"),
	)
}

// EndSession handles GET /aim/endSession requests.
func (h *SessionHandler) EndSession(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

	// RemoveSession evicts the session from the manager and tears it down
	// (closes the event queue and the OSCAR instance). Without this the aimsid
	// stays resolvable until the reaper sweeps it, and RequireSession would keep
	// handing handlers a session whose OSCAR instance is already closed.
	if err := h.SessionManager.RemoveSession(ctx, session.AimSID); err != nil {
		h.Logger.ErrorContext(ctx, "failed to remove session", "err", err.Error())
	}

	// Send response
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"

	// Send response in requested format (JSON, JSONP, or AMF)
	SendResponse(w, r, resp, h.Logger)

	h.Logger.DebugContext(ctx, "session ended",
		"aimsid", session.AimSID,
		"screen_name", session.ScreenName,
	)
}

// sendError sends a Web AIM API error envelope, honoring JSONP when requested.
func (h *SessionHandler) sendError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	resp := BaseResponse{}
	resp.Response.StatusCode = statusCode
	resp.Response.StatusText = message
	SendResponse(w, r, resp, h.Logger)
}

// buildMyInfo assembles the shared base of a myInfo payload — the user's own
// identity blob that the AIM client renders in its identity badge.
//
// It carries only fields that are safe to repeat on every myInfo: the client's
// user-object merge deletes friendly and capabilities before merging, so both
// must be present on each push or the badge loses them. Time-sensitive fields
// (onlineTime, memberSince) are intentionally excluded — a mid-session refresh
// omits them so the client keeps the signon time it already has; the startSession
// builders add them explicitly. buddyIcon is included only when non-empty; an
// empty value would be dropped by the client merge anyway, and the placeholder
// URL (not "") is what clears an icon.
func buildMyInfo(screenName state.DisplayScreenName, webState, buddyIcon string) *MyInfo {
	// The web client compares userType/service case-sensitively; a UIN account must
	// report ICQ so it renders as an ICQ contact rather than AIM.
	userType, service := "aim", "AIM"
	if screenName.IsUIN() {
		userType, service = "icq", "ICQ"
	}
	return &MyInfo{
		AimID:     screenName.IdentScreenName().String(),
		DisplayID: screenName.String(),
		Friendly:  screenName.String(),
		State:     webState,
		UserType:  userType,
		// Never nil: the client iterates capabilities unconditionally.
		Capabilities: []string{},
		Bot:          false,
		Service:      service,
		BuddyIcon:    buddyIcon,
	}
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// baseURLFromRequest returns the absolute base URL the client reached this
// server on, used to build asset URLs that the client loads directly.
func baseURLFromRequest(r *http.Request) string {
	return fmt.Sprintf("%s://%s", requestScheme(r), r.Host)
}
