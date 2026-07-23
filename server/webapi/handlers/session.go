package handlers

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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
	BuddyListManager *BuddyListManager
	IconSource       BuddyIconSource
	Logger           *slog.Logger
	OServiceService  OServiceService
	FnSessCfg        func(sess *state.Session)
	FnSessInit       func(instance *state.SessionInstance) func() error
	FnInstanceClose  func(instance *state.SessionInstance) func()
}

// AuthService defines methods needed for authentication.
type AuthService interface {
	BUCPChallenge(ctx context.Context, bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error)
	BUCPLogin(ctx context.Context, bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, advertisedHost string) (wire.SNACMessage, error)
	CrackCookie(authCookie []byte) (state.ServerCookie, error)
	RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie, conf func(sess *state.Session)) (*state.SessionInstance, error)
	FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error)
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

// BuddyGroup represents a group of buddies.
type BuddyGroup struct {
	Name    string  `json:"name"`
	Buddies []Buddy `json:"buddies"`
}

// Buddy represents a buddy in the buddy list.
type Buddy struct {
	AimID     string `json:"aimId"`
	State     string `json:"state"`
	StatusMsg string `json:"statusMsg,omitempty"`
	AwayMsg   string `json:"awayMsg,omitempty"`
	UserType  string `json:"userType"`
}

// StartSessionResponse represents the response for startSession endpoint.
type StartSessionResponse struct {
	Response struct {
		StatusCode int    `json:"statusCode"`
		StatusText string `json:"statusText"`
		Data       struct {
			AimSID          string                 `json:"aimsid"`
			Ts              int64                  `json:"ts"`
			FetchTimeout    int                    `json:"fetchTimeout"`
			TimeToNextFetch int                    `json:"timeToNextFetch"`
			FetchBaseURL    string                 `json:"fetchBaseURL"` // Gromit expects this directly in data!
			MyInfo          map[string]interface{} `json:"myInfo,omitempty"`
			Events          map[string]interface{} `json:"events,omitempty"`
			WellKnownUrls   map[string]string      `json:"wellKnownUrls,omitempty"`
		} `json:"data"`
	} `json:"response"`
}

// StartSessionXMLResponse represents the XML response for startSession endpoint.
type StartSessionXMLResponse struct {
	XMLName    xml.Name `xml:"response"`
	StatusCode int      `xml:"statusCode"`
	StatusText string   `xml:"statusText"`
	Data       struct {
		AimSID          string `xml:"aimsid"`
		FetchTimeout    int    `xml:"fetchTimeout"`
		TimeToNextFetch int    `xml:"timeToNextFetch"`
		FetchBaseURL    string `xml:"fetchBaseURL"` // Gromit expects this directly!
		WellKnownUrls   *struct {
			WebApiBase        string `xml:"webApiBase"`
			FetchBaseURL      string `xml:"fetchBaseURL"`
			LifestreamApiBase string `xml:"lifestreamApiBase"`
		} `xml:"wellKnownUrls,omitempty"`
		MyInfo *struct {
			AimID     string `xml:"aimId"`
			DisplayID string `xml:"displayId"`
			Buddylist struct {
				Groups *[]BuddyGroup `xml:"group,omitempty"`
			} `xml:"buddylist,omitempty"`
		} `xml:"myInfo,omitempty"`
		Events *struct {
			BuddyList struct {
				Groups *[]BuddyGroup `xml:"group,omitempty"`
			} `xml:"buddylist"`
		} `xml:"events,omitempty"`
	} `xml:"data"`
}

// EndSessionResponse represents the response for endSession endpoint.
type EndSessionResponse struct {
	Response struct {
		StatusCode int    `json:"statusCode"`
		StatusText string `json:"statusText"`
	} `json:"response"`
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
		// Nothing owns the instance yet, so close it here. Left open, it stays
		// registered in the session manager, counting against the user's
		// concurrent-instance budget until the server restarts.
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
	session.BuddyListRefresher = func(ctx context.Context) (interface{}, error) {
		groups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session)
		if err != nil {
			return nil, err
		}
		// CANNED: keep the fake group chat present across feedbag-driven refreshes.
		// TODO(groupchat): list the user's joined rooms.
		return append(groups, CannedGroupChatGroup()), nil
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

	// Queue myInfo event for authenticated users
	if authToken != "" {
		for _, event := range events {
			if event == "myInfo" || event == "presence" {
				myInfoData := buildMyInfo(screenName, "online", myIconURL)
				myInfoData["onlineTime"] = time.Now().Unix()
				myInfoData["memberSince"] = time.Now().Unix() - 86400*30 // 30 days ago
				session.EventQueue.Push(types.EventType("myInfo"), myInfoData)
				break
			}
		}
		for _, event := range events {
			if event == "conversation" {
				// CANNED: seed a fake group chat so we can confirm the conversation
				// "list" event drives the client's "Group Chats" section. Real
				// per-user room membership persistence would replace this list.
				// TODO(groupchat): load the user's joined rooms and list them here.
				session.EventQueue.Push(types.EventTypeConversation,
					types.ConversationEventData("list", []map[string]interface{}{
						types.ConversationGroupEntry("4-0-Canned Group Chat", "Canned Group Chat", 1),
					}))
				break
			}
		}
	}

	now := time.Now().Unix()

	// Prepare response
	resp := StartSessionResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data.AimSID = session.AimSID
	resp.Response.Data.Ts = now
	resp.Response.Data.FetchTimeout = session.FetchTimeout
	resp.Response.Data.TimeToNextFetch = session.TimeToNextFetch
	// Gromit expects fetchBaseURL directly in data, not in wellKnownUrls
	resp.Response.Data.FetchBaseURL = fmt.Sprintf("%s/aim/fetchEvents?aimsid=%s&seqNum=0", baseURL, session.AimSID)

	// Add wellKnownUrls for other clients that might use it.
	resp.Response.Data.WellKnownUrls = map[string]string{
		"webApiBase":        baseURL + "/",
		"fetchBaseURL":      baseURL + "/aim/fetchEvents",
		"lifestreamApiBase": baseURL + "/",
	}

	if authToken != "" {
		myInfoPayload := buildMyInfo(screenName, "online", myIconURL)
		myInfoPayload["onlineTime"] = time.Now().Unix()
		myInfoPayload["memberSince"] = time.Now().Unix() - 86400*30 // 30 days ago
		myInfoPayload["self"] = map[string]interface{}{
			"instNum":        1,
			"loginTime":      time.Now().Unix(),
			"sessionTimeout": 30,
			"events":         events,
			"assertCaps":     []string{},
			"rightsInfo": map[string]interface{}{
				"maxDenies":            500,
				"maxPermits":           500,
				"maxWatchers":          3000,
				"maxBuddies":           500,
				"maxTempBuddies":       160,
				"maxIMSize":            3987,
				"minInterIcbmInterval": 1000,
				"maxSourceEvil":        900,
				"maxDstEvil":           999,
				"maxSigLen":            4096,
			},
		}
		resp.Response.Data.MyInfo = myInfoPayload
		if resp.Response.Data.Events == nil {
			resp.Response.Data.Events = make(map[string]interface{})
		}
		resp.Response.Data.Events["myInfo"] = myInfoPayload
	}

	for _, event := range events {
		switch types.EventType(event) {
		case types.EventTypeBuddyList:
			buddyGroups := []WebAPIBuddyGroup{}
			if authToken != "" && h.BuddyListManager != nil {
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
			// CANNED: surface a fake group chat under the client's "Group chats"
			// buddy-list section. TODO(groupchat): list the user's joined rooms.
			buddyGroups = append(buddyGroups, CannedGroupChatGroup())
			blPayload := map[string]interface{}{"groups": buddyGroups}
			if resp.Response.Data.Events == nil {
				resp.Response.Data.Events = make(map[string]interface{})
			}
			resp.Response.Data.Events["buddylist"] = blPayload
			if authToken != "" {
				session.EventQueue.Push(types.EventTypeBuddyList, blPayload)
			}
		case types.EventTypePreference:
			// Seed the client with effective preference values: the user's stored
			// prefs where set, and the server-side spec defaults otherwise. The
			// client reads its buddy-list display prefs (e.g. showGroups) only from
			// this event and has no default of its own for them, so an omitted pref
			// would silently fall back to the client's hidden default and, for
			// showGroups, hide group headers.
			prefPayload := map[string]interface{}{}
			if authToken != "" && session.OSCARSession != nil {
				if item, err := buddyPrefsItem(ctx, h.FeedbagService, session.OSCARSession); err != nil {
					h.Logger.ErrorContext(ctx, "failed to get preferences", "err", err.Error())
				} else {
					prefPayload = effectiveBuddyPrefs(item.TLVList)
				}
			}
			if resp.Response.Data.Events == nil {
				resp.Response.Data.Events = make(map[string]interface{})
			}
			resp.Response.Data.Events["preference"] = prefPayload
			if authToken != "" {
				session.EventQueue.Push(types.EventTypePreference, prefPayload)
			}
		}
	}

	// Check response format
	format := r.URL.Query().Get("f")
	if format == "" {
		format = "json" // default to JSON
	}

	// Send response in requested format
	if format == "xml" {
		// Build XML response
		xmlResp := StartSessionXMLResponse{}
		xmlResp.StatusCode = 200
		xmlResp.StatusText = "OK"
		xmlResp.Data.AimSID = session.AimSID
		xmlResp.Data.FetchTimeout = timeout
		xmlResp.Data.TimeToNextFetch = 500
		// Gromit expects fetchBaseURL directly in data
		xmlResp.Data.FetchBaseURL = fmt.Sprintf("%s/aim/fetchEvents?aimsid=%s&seqNum=0", baseURL, session.AimSID)

		// Add wellKnownUrls for other clients
		xmlBase := baseURL + "/"
		xmlResp.Data.WellKnownUrls = &struct {
			WebApiBase        string `xml:"webApiBase"`
			FetchBaseURL      string `xml:"fetchBaseURL"`
			LifestreamApiBase string `xml:"lifestreamApiBase"`
		}{
			WebApiBase:        xmlBase,
			FetchBaseURL:      baseURL + "/aim/fetchEvents",
			LifestreamApiBase: xmlBase,
		}

		// Add myInfo with user data
		xmlResp.Data.MyInfo = &struct {
			AimID     string `xml:"aimId"`
			DisplayID string `xml:"displayId"`
			Buddylist struct {
				Groups *[]BuddyGroup `xml:"group,omitempty"`
			} `xml:"buddylist,omitempty"`
		}{
			AimID:     session.ScreenName.IdentScreenName().String(),
			DisplayID: session.ScreenName.String(),
		}

		// Add buddy list if requested in myInfo or events
		for _, event := range events {
			if event == "buddylist" || event == "myInfo" {
				var buddyGroups []BuddyGroup

				if authToken != "" && h.BuddyListManager != nil {
					// Fetch actual buddy list from service
					webAPIGroups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session)
					if err != nil {
						h.Logger.ErrorContext(ctx, "failed to get buddy list for XML response", "err", err.Error())
						buddyGroups = []BuddyGroup{}
					} else {
						// Convert WebAPIBuddyGroup to handler.BuddyGroup
						for _, webGroup := range webAPIGroups {
							group := BuddyGroup{
								Name:    webGroup.Name,
								Buddies: []Buddy{},
							}
							for _, webBuddy := range webGroup.Buddies {
								buddy := Buddy{
									AimID:     webBuddy.AimID,
									State:     webBuddy.State,
									StatusMsg: webBuddy.StatusMsg,
									AwayMsg:   webBuddy.AwayMsg,
									UserType:  webBuddy.UserType,
								}
								group.Buddies = append(group.Buddies, buddy)
							}
							buddyGroups = append(buddyGroups, group)
						}
					}
				} else {
					buddyGroups = []BuddyGroup{}
				}

				// Add to myInfo buddylist
				xmlResp.Data.MyInfo.Buddylist.Groups = &buddyGroups

				// Also add to events if specifically requested
				if event == "buddylist" {
					if xmlResp.Data.Events == nil {
						xmlResp.Data.Events = &struct {
							BuddyList struct {
								Groups *[]BuddyGroup `xml:"group,omitempty"`
							} `xml:"buddylist"`
						}{}
					}
					xmlResp.Data.Events.BuddyList.Groups = &buddyGroups
				}
				break
			}
		}

		// Send XML response
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")

		// Build complete XML string first
		xmlData, err := xml.Marshal(xmlResp)
		if err != nil {
			h.Logger.Error("failed to marshal XML response", "error", err)
			h.sendError(w, r, http.StatusInternalServerError, "internal server error")
			return
		}

		// Write XML declaration and data as one response
		xmlOutput := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>%s`, xmlData)
		w.Header().Set("Content-Length", strconv.Itoa(len(xmlOutput)))
		_, _ = fmt.Fprint(w, xmlOutput)
	} else {
		// Send response in requested format (JSON, JSONP, or AMF)
		SendResponse(w, r, resp, h.Logger)
	}

	h.Logger.DebugContext(ctx, "session started",
		"aimsid", session.AimSID,
		"screen_name", screenName,
		"dev_id", apiKey.DevID,
		"events", events,
		"format", format,
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
	resp := EndSessionResponse{}
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
func buildMyInfo(screenName state.DisplayScreenName, webState, buddyIcon string) map[string]interface{} {
	// The web client compares userType/service case-sensitively; a UIN account must
	// report ICQ so it renders as an ICQ contact rather than AIM.
	userType, service := "aim", "AIM"
	if screenName.IsUIN() {
		userType, service = "icq", "ICQ"
	}
	myInfo := map[string]interface{}{
		"aimId":        screenName.IdentScreenName().String(),
		"displayId":    screenName.String(),
		"friendly":     screenName.String(),
		"state":        webState,
		"userType":     userType,
		"capabilities": []string{},
		"bot":          false,
		"service":      service,
	}
	if buddyIcon != "" {
		myInfo["buddyIcon"] = buddyIcon
	}
	return myInfo
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
