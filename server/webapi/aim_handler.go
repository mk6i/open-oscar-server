package webapi

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/oscarclient"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// AimHandler serves the /aim/* Web AIM API endpoints.
type AimHandler struct {
	SessionManager   *SessionManager
	AuthService      AuthService
	BuddyListManager *BuddyListManager
	IconSource       BuddyIconSource
	// Dialer connects sessions to the OSCAR server.
	Dialer oscarclient.Dialer
	// BOSListener is the listener group startOSCARSession advertises a BOS
	// address from.
	BOSListener config.ListenerGroup
	// SNACRateLimits maps SNACs to the rate classes the OSCAR server charges.
	SNACRateLimits wire.SNACRateLimits
	Logger         *slog.Logger
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
	Service   string `json:"service,omitempty" xml:"service,omitempty"` // Non-native network; omitted for AIM
	// Capabilities is always sent, empty included, because the client iterates it
	// unconditionally.
	Capabilities []string `json:"capabilities" xml:"capabilities>capability"`
	// BuddyIcon is omitted when empty so the client's merge preserves the icon it
	// already holds.
	BuddyIcon   string      `json:"buddyIcon,omitempty" xml:"buddyIcon,omitempty"`
	MoodIcon    string      `json:"moodIcon,omitempty" xml:"moodIcon,omitempty"`
	MoodTitle   string      `json:"moodTitle,omitempty" xml:"moodTitle,omitempty"`
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
	PermitDeny any             `json:"permitDeny,omitempty" xml:"permitDeny,omitempty"`
	Service    *ServiceData    `json:"service,omitempty" xml:"service,omitempty"`
}

// BuddyListData is the buddylist event payload and the buddy list half of the
// startSession seed.
type BuddyListData struct {
	Groups []BuddyGroup `json:"groups" xml:"groups>group"`
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

// StartSession handles GET|POST /aim/startSession requests.
func (h *AimHandler) StartSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	authToken := param(r, "a")

	// Get client info
	clientName := param(r, "clientName")
	if clientName == "" {
		clientName = "WebAIM"
	}
	clientVersion := param(r, "clientVersion")
	if clientVersion == "" {
		clientVersion = "1.0"
	}

	// Get events to subscribe to
	eventsParam := param(r, "events")
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
	if t := param(r, "timeout"); t != "" {
		if val, err := strconv.Atoi(t); err == nil && val > 0 {
			timeout = val * 1000 // Convert to milliseconds
		}
	}

	// A Web API session must be bridged to an authenticated OSCAR session;
	// anonymous guests are not supported.
	if authToken == "" {
		SendEnvelopeStatus(w, r, http.StatusUnauthorized, "authentication token required", h.Logger)
		return
	}

	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(authToken))
	if err != nil {
		h.Logger.Warn("invalid authentication token (base64)", "error", err)
		SendEnvelopeStatus(w, r, http.StatusUnauthorized, "invalid or expired token", h.Logger)
		return
	}
	cookie, _, err := h.AuthService.CrackCookie(rawCookie)
	if err != nil {
		h.Logger.Warn("invalid authentication token", "error", err)
		SendEnvelopeStatus(w, r, http.StatusUnauthorized, "invalid or expired token", h.Logger)
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

	// The token is the login cookie that a BOS connection signs on with.
	signonCtx, cancel := context.WithTimeout(ctx, bosSignonTimeout)
	defer cancel()
	bos, err := h.Dialer.ConnectService(signonCtx, clientAddr(r), rawCookie)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to connect to BOS", "err", err.Error())
		SendEnvelopeStatus(w, r, http.StatusServiceUnavailable, "unable to establish session", h.Logger)
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

	// Create WebAPI session
	// Record the origin the client reached us on. Asset URLs published to the
	// client (buddy icons) must be absolute, since the client page is served from
	// a different origin than this API, and they are built in places that have no
	// request in hand. Pinning the origin here also keeps those URLs on the same
	// host as the wellKnownUrls advertised below. It is passed into CreateSession
	// so it is set before the session is published and its inbound loop can
	// read it.
	baseURL := baseURLFromRequest(r)

	session, err := h.SessionManager.CreateSession(screenName, events, bos, h.SNACRateLimits, baseURL, h.Logger)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to create session", "err", err.Error())
		// CreateSession refuses once the manager is shut down, so this is the
		// path a startSession racing shutdown takes.
		bos.Close()
		SendEnvelopeStatus(w, r, http.StatusInternalServerError, "failed to create session", h.Logger)
		return
	}

	h.Logger.DebugContext(ctx, "session created with event subscriptions",
		"aimsid", session.AimSID,
		"events", events,
	)

	// Wire buddy list refresher so feedbag SNACs from the OSCAR bridge trigger a buddylist event.
	// The refresher yields the whole buddylist event payload, not just the groups,
	// so the session that pushes it does not have to know the payload's shape.
	session.BuddyListRefresher = func(ctx context.Context) (any, error) {
		return &BuddyListData{Groups: h.BuddyListManager.GetBuddyListForUser(ctx, session)}, nil
	}

	// Wire the buddy-icon URL formatter so presence broadcasts (BuddyArrived) can
	// publish a buddy's current icon from the hash carried in the SNAC, no lookup.
	session.BuddyIconURL = func(sn state.IdentScreenName, hash []byte) string {
		return h.IconSource.URLForHash(session.BaseURL, sn, hash)
	}

	// Wire permit/deny refresher so FeedbagUpdateItem SNACs trigger a permitDeny event.
	session.PermitDenyRefresher = func(ctx context.Context) (any, error) {
		return permitDenyData(session.Feedbag()), nil
	}

	// Only IM-class rate limit updates should surface to the client alert.
	session.IMRateClassID = imRateClassID

	// Now that every refresher callback is wired, start the inbound loop, which
	// delivers the replies sign-on waits for.
	session.Start()

	if err := session.signOn(signonCtx); err != nil {
		h.Logger.ErrorContext(ctx, "failed to sign on", "err", err.Error())
		_ = h.SessionManager.RemoveSession(ctx, session.AimSID)
		SendEnvelopeStatus(w, r, http.StatusInternalServerError, "internal server error", h.Logger)
		return
	}
	seedRateLimitAlert(session, imRateClassID)

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

	myMoodURL := moodIconURL(baseURL, "online", userInfoCaps(session.self.userInfo()))
	myInfoPayload := buildMyInfo(screenName, "online", myIconURL, myMoodURL)
	myInfoPayload.StatusMsg = userStatusMsg(session.self.userInfo())
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
			MaxTempBuddies:       maxTempBuddies,
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
	if slices.Contains(events, string(EventTypeMyInfo)) || slices.Contains(events, string(EventTypePresence)) {
		myInfoData := buildMyInfo(screenName, "online", myIconURL, myMoodURL)
		myInfoData.StatusMsg = userStatusMsg(session.self.userInfo())
		myInfoData.OnlineTime = time.Now().Unix()
		myInfoData.MemberSince = time.Now().Unix() - 86400*30 // 30 days ago
		session.PushEvent(EventTypeMyInfo, myInfoData)
	}

	if slices.Contains(events, string(EventTypeConversation)) {
		session.PushEvent(EventTypeConversation,
			ConversationEventData("list", nil))
	}

	if slices.Contains(events, string(EventTypeService)) {
		svcPayload := newServiceData()
		data.Events.Service = svcPayload
		session.PushEvent(EventTypeService, svcPayload)
	}

	// The remaining seeds also populate the response payload, so they stay keyed off
	// the subscription list they are rendered into.
	for _, event := range events {
		switch EventType(event) {
		case EventTypeBuddyList:
			blPayload := &BuddyListData{Groups: h.BuddyListManager.GetBuddyListForUser(ctx, session)}
			data.Events.BuddyList = blPayload
			session.PushEvent(EventTypeBuddyList, blPayload)
		case EventTypePreference:
			// Seed the client with effective preference values: the user's stored
			// prefs where set, and the server-side spec defaults otherwise. The
			// client reads its buddy-list display prefs (e.g. showGroups) only from
			// this event and has no default of its own for them, so an omitted pref
			// would silently fall back to the client's hidden default and, for
			// showGroups, hide group headers.
			prefPayload := effectiveBuddyPrefs(buddyPrefsItem(session.Feedbag()).TLVList)
			data.Events.Preference = prefPayload
			session.PushEvent(EventTypePreference, prefPayload)
		case EventTypePermitDeny:
			// The client keeps its privacy state solely in the model this event
			// populates. Both the block/unblock menu action and the "blocked"
			// presence state read that model and no-op silently while it is
			// empty, so the session has to start with one.
			var pdPayload any = PermitDenyData{PDMode: "permitAll"}
			if pdd, err := session.PermitDenyRefresher(ctx); err != nil {
				h.Logger.ErrorContext(ctx, "failed to get permit/deny settings", "err", err.Error())
			} else {
				pdPayload = pdd
			}
			data.Events.PermitDeny = pdPayload
			session.PushEvent(EventTypePermitDeny, pdPayload)
		}
	}

	// Drain messages stored while the user was signed off. The service relays them
	// as ordinary ICBMChannelMsgToClient SNACs stamped with a send time, which the
	// inbound loop started above turns into offlineIM events. Retrieval deletes them
	// from the store and the Web API has no ack, so this is the one delivery attempt.
	// Skip it for a client that did not subscribe, which leaves the messages stored
	// for a session that wants them rather than spending them on one that does not.
	//
	// This trails every event queued above because the inbound loop pushes from its own
	// goroutine, so anything drained here can overtake a later push. An offlineIM
	// names its sender by bare aimId and leaves the client to resolve the display
	// name against the buddy list it holds, and the conversation list is rebuilt from
	// scratch on the first "list" the client sees. Both of those events are queued in
	// the loop above, so the drain has to come after it.
	if slices.Contains(events, string(EventTypeOfflineIM)) {
		if err := session.send(wire.ICBM, wire.ICBMOfflineRetrieve, struct{}{}); err != nil {
			h.Logger.ErrorContext(ctx, "failed to retrieve offline messages", "err", err.Error())
		}
	}

	// Send response in requested format (JSON, JSONP, XML, or AMF)
	SendOK(w, r, data, h.Logger)

	h.Logger.DebugContext(ctx, "session started",
		"aimsid", session.AimSID,
		"screen_name", screenName,
		"events", events,
		"format", r.URL.Query().Get("f"),
	)
}

// EndSession handles GET /aim/endSession requests.
func (h *AimHandler) EndSession(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	// RemoveSession evicts the session from the manager and tears it down
	// (closes the event queue and the OSCAR instance). Without this the aimsid
	// stays resolvable until the reaper sweeps it, and RequireSession would keep
	// handing handlers a session whose OSCAR instance is already closed.
	if err := h.SessionManager.RemoveSession(ctx, session.AimSID); err != nil {
		h.Logger.ErrorContext(ctx, "failed to remove session", "err", err.Error())
	}

	// Send response

	// Send response in requested format (JSON, JSONP, or AMF)
	SendOK(w, r, nil, h.Logger)

	h.Logger.DebugContext(ctx, "session ended",
		"aimsid", session.AimSID,
		"screen_name", session.ScreenName,
	)
}

// FetchEventsData contains the events and metadata.
type FetchEventsData struct {
	Events          []Event `json:"events" xml:"events>event"`
	LastSeqNum      uint64  `json:"lastSeqNum" xml:"lastSeqNum"`
	TimeToNextFetch int     `json:"timeToNextFetch" xml:"timeToNextFetch"`
	FetchBaseURL    string  `json:"fetchBaseURL" xml:"fetchBaseURL"`
}

// FetchEvents handles GET /aim/fetchEvents requests with long-polling support.
func (h *AimHandler) FetchEvents(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := session.AimSID

	// Get sequence number parameter
	var lastSeqNum uint64
	if seqStr := r.URL.Query().Get("seqNum"); seqStr != "" {
		if val, err := strconv.ParseUint(seqStr, 10, 64); err == nil {
			lastSeqNum = val
		}
	}

	// Timeout is in milliseconds (per Web API spec and client behavior).
	timeout := time.Duration(session.FetchTimeout) * time.Millisecond
	if timeoutStr := r.URL.Query().Get("timeout"); timeoutStr != "" {
		if val, err := strconv.Atoi(timeoutStr); err == nil && val > 0 {
			timeout = time.Duration(val) * time.Millisecond
		}
	}

	// Limit maximum timeout to 60 seconds
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}

	// Create a context with timeout for the fetch operation
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Fetch events from the queue (will block until events available or timeout)
	events, err := session.EventQueue.Fetch(fetchCtx, lastSeqNum, timeout)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			// timeout is normal - return empty events array
			events = []Event{}
		} else {
			h.Logger.ErrorContext(ctx, "failed to fetch events", "err", err.Error())
			SendError(w, r, http.StatusInternalServerError, "failed to fetch events")
			return
		}
	}

	// Determine the last sequence number
	newLastSeqNum := lastSeqNum
	if len(events) > 0 {
		newLastSeqNum = events[len(events)-1].SeqNum
	}

	// A nil slice renders as JSON null, which a client reading data.events
	// strictly rejects.
	if events == nil {
		events = []Event{}
	}

	// Prepare response
	data := &FetchEventsData{
		Events:          events,
		LastSeqNum:      newLastSeqNum,
		TimeToNextFetch: session.TimeToNextFetch,
		// Include fetchBaseURL with updated sequence number for next request
		FetchBaseURL: fmt.Sprintf("%s/aim/fetchEvents?aimsid=%s&seqNum=%d",
			baseURLFromRequest(r), aimsid, newLastSeqNum),
	}

	SendOK(w, r, data, h.Logger)

	if len(events) > 0 {
		h.Logger.DebugContext(ctx, "events fetched",
			"aimsid", aimsid,
			"count", len(events),
			"last_seq", newLastSeqNum,
		)
	}
}

// maxTempBuddies caps how many screen names one addTempBuddy or removeTempBuddy
// call may carry.
const maxTempBuddies = 160

// AddTempBuddy handles GET /aim/addTempBuddy requests.
// Temporary buddies live for the duration of the OSCAR session; they are not
// persisted to the feedbag.
func (h *AimHandler) AddTempBuddy(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyNames := targetNames(r)
	if len(buddyNames) == 0 {
		SendError(w, r, http.StatusBadRequest, "missing buddy names (t parameter)")
		return
	}
	if len(buddyNames) > maxTempBuddies {
		SendError(w, r, http.StatusBadRequest, fmt.Sprintf("too many buddy names (max %d)", maxTempBuddies))
		return
	}

	snac := wire.SNAC_0x03_0x0F_BuddyAddTempBuddies{}
	for _, buddyName := range buddyNames {
		snac.Buddies = append(snac.Buddies, struct {
			ScreenName string `oscar:"len_prefix=uint8"`
		}{ScreenName: buddyName})
	}

	if err := session.send(wire.Buddy, wire.BuddyAddTempBuddies, snac); err != nil {
		h.Logger.ErrorContext(ctx, "add temp buddies failed", "aimsid", aimsid, "err", err.Error())
		sendRequestError(w, r, err, "unable to add temporary buddies", h.Logger)
		return
	}

	SendOK(w, r, nil, h.Logger)

	h.Logger.InfoContext(ctx, "temporary buddies added",
		"aimsid", aimsid,
		"buddies", buddyNames,
		"count", len(buddyNames),
	)
}

// RemoveTempBuddy handles GET /aim/removeTempBuddy requests.
// This removes temporary session buddies added via addTempBuddy.
func (h *AimHandler) RemoveTempBuddy(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()
	aimsid := r.URL.Query().Get("aimsid")

	buddyNames := targetNames(r)
	if len(buddyNames) == 0 {
		SendError(w, r, http.StatusBadRequest, "missing buddy names (t parameter)")
		return
	}
	if len(buddyNames) > maxTempBuddies {
		SendError(w, r, http.StatusBadRequest, fmt.Sprintf("too many buddy names (max %d)", maxTempBuddies))
		return
	}

	snac := wire.SNAC_0x03_0x10_BuddyDelTempBuddies{}
	for _, buddyName := range buddyNames {
		snac.Buddies = append(snac.Buddies, struct {
			ScreenName string `oscar:"len_prefix=uint8"`
		}{ScreenName: buddyName})
	}

	if err := session.send(wire.Buddy, wire.BuddyDelTempBuddies, snac); err != nil {
		h.Logger.ErrorContext(ctx, "remove temp buddies failed", "aimsid", aimsid, "err", err.Error())
		sendRequestError(w, r, err, "unable to remove temporary buddies", h.Logger)
		return
	}

	for _, buddyName := range buddyNames {
		session.forgetBuddyPresence(state.NewIdentScreenName(buddyName))
	}

	SendOK(w, r, nil, h.Logger)

	h.Logger.InfoContext(ctx, "temporary buddies removed",
		"aimsid", aimsid,
		"buddies", buddyNames,
		"count", len(buddyNames),
	)
}

// SetForwardDomain acknowledges the client's forward-domain registration.
// The Web AIM client fires this once when the session goes online; name may be
// the literal string "null" for local/dev servers.
func (h *AimHandler) SetForwardDomain(w http.ResponseWriter, r *http.Request) {
	SendOK(w, r, nil, h.Logger)
}

// ReportAction acknowledges a client-side UI telemetry ping. The Web AIM client
// fires this on menu clicks and similar interactions with an action param of the
// form "type=click,id=block-user-chatmenu"; it ignores the response.
func (h *AimHandler) ReportAction(w http.ResponseWriter, r *http.Request) {
	SendOK(w, r, nil, h.Logger)
}

// StoredDataItems is the client-side data blob store, which this server does
// not keep, so it always answers with an empty items list.
type StoredDataItems struct {
	Items []string `json:"items" xml:"items>item"`
}

// GetData returns empty client-side data blobs (buddy list favorites, etc.).
func (h *AimHandler) GetData(w http.ResponseWriter, r *http.Request) {
	SendOK(w, r, &StoredDataItems{Items: []string{}}, h.Logger)
}

// StartOSCARSessionResponse represents the response for startOSCARSession endpoint.
type StartOSCARSessionResponse struct {
	Response struct {
		StatusCode int    `json:"statusCode" xml:"statusCode"`
		StatusText string `json:"statusText" xml:"statusText"`
		Data       struct {
			Host   string `json:"host" xml:"host"`
			Port   int    `json:"port" xml:"port"`
			Cookie string `json:"cookie" xml:"cookie"`
			// TLSCertName is the certificate name the client verifies BOS against.
			// Omitted rather than sent empty: its absence means connect in the clear.
			TLSCertName string `json:"tlsCertName,omitempty" xml:"tlsCertName,omitempty"`
		} `json:"data" xml:"data"`
	} `json:"response"`
}

// MarshalXML renders the envelope with the same flat root as BaseResponse.
func (s StartOSCARSessionResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	return e.EncodeElement(s.Response, xml.StartElement{Name: xml.Name{Local: "response"}})
}

// StartOSCARSession handles GET /aim/startOSCARSession requests, which hand a
// client that authenticated over HTTP the address of a BOS server and the
// cookie to sign on with. The token in "a" is the auth cookie clientLogin
// minted, already what BOS expects, so it is handed straight back.
//
// The sig_sha256 the client computes over the query string is not checked: that
// signature is keyed by HMAC(password, sessionSecret), and clientLogin keeps
// neither past the response.
func (h *AimHandler) StartOSCARSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.Logger.InfoContext(ctx, "startOSCARSession requested",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent())

	params := r.URL.Query()

	token := params.Get("a")
	if token == "" {
		h.Logger.Warn("missing authentication token")
		SendError(w, r, http.StatusUnauthorized, "authentication token required")
		return
	}

	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		h.Logger.WarnContext(ctx, "invalid authentication token (base64)", "err", err.Error())
		SendError(w, r, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	cookie, _, err := h.AuthService.CrackCookie(rawCookie)
	if err != nil {
		h.Logger.WarnContext(ctx, "invalid authentication token", "err", err.Error())
		SendError(w, r, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	// Encryption the server cannot provide degrades to a plaintext host, which a
	// client doing opportunistic encryption expects when no certificate is named.
	// The sign-on cookie then crosses the wire in the clear, so the downgrade is
	// logged rather than left to be inferred from the absent tlsCertName.
	useTLS := parseBoolParam(params.Get("useTLS"))
	endpoint := h.BOSListener.PlainEndpoint()
	if useTLS {
		ssl, ok := h.BOSListener.SSLEndpoint()
		if !ok {
			h.Logger.WarnContext(ctx, "TLS requested but no SSL listener is configured, advertising a plaintext BOS host",
				"screen_name", cookie.ScreenName)
			useTLS = false
		} else {
			endpoint = ssl
		}
	}

	host, portStr, err := net.SplitHostPort(endpoint.AdvertisedHost())
	if err != nil {
		h.Logger.ErrorContext(ctx, "unable to split advertised BOS host", "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}
	port, _ := strconv.Atoi(portStr)

	resp := &StartOSCARSessionResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "Ok"
	resp.Response.Data.Host = host
	resp.Response.Data.Port = port
	// Base64, the encoding the client decodes the cookie with.
	resp.Response.Data.Cookie = base64.StdEncoding.EncodeToString(rawCookie)
	if useTLS {
		// The advertised SSL host is the name the certificate is issued to.
		resp.Response.Data.TLSCertName = host
	}

	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "OSCAR session bridge created",
		"screen_name", cookie.ScreenName,
		"bos_host", host,
		"bos_port", port,
		"use_tls", useTLS)
}

// parseBoolParam parses a boolean parameter from query string.
func parseBoolParam(value string) bool {
	value = strings.ToLower(value)
	return value == "true" || value == "1" || value == "yes"
}

// seedRateLimitAlert raises the client's rate limit alert when a session starts
// on an account that is already rate limited.
//
// The server announces transitions, not current state, so a session signing on
// mid-limit missed the one that raised the alert — and the client's alert is
// sticky, so the eventual "clear" would arrive with nothing to dismiss. The
// session learns the current state from the rate params it reads at sign-on.
//
// Only the limited state is seeded: alert is a warning the user cannot act on,
// and seeding clear would render nothing.
func seedRateLimitAlert(session *Session, classID wire.RateLimitClassID) {
	if classID == 0 {
		return
	}
	if _, limited := session.rates.limited(classID, time.Now()); !limited {
		return
	}

	session.PushEvent(EventTypeRateLimit, RateLimitEvent{
		Classes: []RateLimitClass{
			{
				ID:     int(classID),
				Status: rateLimitStatusName(wire.RateLimitStatusLimited),
			},
		},
	})
}

// bosSignonTimeout bounds how long startSession waits to connect to BOS and
// sign on.
const bosSignonTimeout = 15 * time.Second

// clientAddr returns the address r came from, which the OSCAR server records
// as the session's.
func clientAddr(r *http.Request) net.Addr {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{}
	}
	return net.TCPAddrFromAddrPort(addrPort)
}

// buildMyInfo assembles the shared base of a myInfo payload — the user's own
// identity blob that the AIM client renders in its identity badge.
//
// It carries only fields that are safe to repeat on every myInfo: the client's
// user-object merge deletes friendly and capabilities before merging, so both
// must be present on each push or the badge loses them. Time-sensitive fields
// (onlineTime, memberSince) are intentionally excluded — a mid-session refresh
// omits them so the client keeps the signon time it already has; the
// builders add them explicitly. buddyIcon is included only when non-empty; an
// empty value would be dropped by the client merge anyway, and the placeholder
// URL (not "") is what clears an icon. moodIcon is a parameter rather than a
// field the callers set, because omitting it clears the user's mood.
func buildMyInfo(screenName state.DisplayScreenName, webState, buddyIcon, moodIcon string) *MyInfo {
	return &MyInfo{
		AimID:     screenName.IdentScreenName().String(),
		DisplayID: screenName.String(),
		Friendly:  screenName.String(),
		State:     webState,
		UserType:  userTypeFor(screenName.IdentScreenName()),
		Service:   serviceFor(screenName.IdentScreenName()),
		// Never nil: the client iterates capabilities unconditionally.
		Capabilities: []string{},
		Bot:          false,
		BuddyIcon:    buddyIcon,
		MoodIcon:     moodIcon,
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
