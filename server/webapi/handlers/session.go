package handlers

import (
	"context"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
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
	SessionManager      *state.WebAPISessionManager
	OSCARSessionManager SessionManager
	OSCARAuthService    AuthService
	BuddyListService    BuddyListService
	BuddyListRegistry   BuddyListRegistry
	BuddyBroadcaster    BuddyBroadcaster
	BuddyListManager    *BuddyListManager
	TokenStore          TokenStore
	Logger              *slog.Logger
}

// AuthService defines methods needed for authentication.
type AuthService interface {
	BUCPChallenge(ctx context.Context, bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error)
	BUCPLogin(ctx context.Context, bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, newUserFn func(screenName state.DisplayScreenName) (state.User, error), advertisedHost string) (wire.SNACMessage, error)
	RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie) (*state.Session, error)
}

// SessionManager defines methods for OSCAR session management.
type SessionManager interface {
	AddSession(ctx context.Context, screenName state.DisplayScreenName) (*state.Session, error)
	RemoveSession(sess *state.Session)
	RelayToScreenName(ctx context.Context, screenName state.IdentScreenName, msg wire.SNACMessage)
}

// BuddyListRegistry defines methods for buddy list management.
type BuddyListRegistry interface {
	RegisterBuddyList(ctx context.Context, screenName state.IdentScreenName) error
	UnregisterBuddyList(ctx context.Context, screenName state.IdentScreenName) error
}

// BuddyListService defines methods for buddy list operations.
type BuddyListService interface {
	GetBuddyList(ctx context.Context, screenName state.IdentScreenName) ([]BuddyGroup, error)
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
			FetchTimeout    int                    `json:"fetchTimeout"`
			TimeToNextFetch int                    `json:"timeToNextFetch"`
			FetchBaseURL    string                 `json:"fetchBaseURL"` // Gromit expects this directly in data!
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
			WebApiBase   string `xml:"webApiBase"`
			FetchBaseURL string `xml:"fetchBaseURL"`
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
		h.sendError(w, http.StatusInternalServerError, "internal server error")
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

	// Determine screen name from auth token or anonymous
	var screenName state.DisplayScreenName

	if authToken != "" {
		// Validate auth token and get screen name
		if h.TokenStore == nil {
			h.Logger.Error("TokenStore not configured")
			h.sendError(w, http.StatusInternalServerError, "authentication not configured")
			return
		}
		identScreenName, err := h.TokenStore.ValidateToken(r.Context(), authToken)
		if err != nil {
			h.Logger.Warn("invalid authentication token",
				"error", err)
			h.sendError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		// For WebAPI sessions, we can use the IdentScreenName directly as DisplayScreenName
		// since WRAITH handles the display formatting
		screenName = state.DisplayScreenName(identScreenName.String())
		tokenPreview := authToken
		if len(tokenPreview) > 8 {
			tokenPreview = tokenPreview[:8] + "..."
		}
		h.Logger.Info("authenticated session requested",
			"token", tokenPreview,
			"screenName", screenName)
	} else {
		// Anonymous session - generate guest name
		screenName = state.DisplayScreenName("Guest_" + strconv.FormatInt(time.Now().Unix(), 36))
		h.Logger.Info("anonymous session requested",
			"screenName", screenName)
	}

	// Create OSCAR session for authenticated users
	var oscarSession *state.Session
	var err error
	if authToken != "" && h.OSCARSessionManager != nil {
		// Create OSCAR session
		oscarSession, err = h.OSCARSessionManager.AddSession(ctx, screenName)
		if err != nil {
			h.Logger.ErrorContext(ctx, "failed to create OSCAR session", "err", err.Error())
			// Continue without OSCAR session - WebAPI can work standalone
			oscarSession = nil
		} else {
			oscarSession.SetSignonComplete()

			// Register buddy list
			if h.BuddyListRegistry != nil {
				if err := h.BuddyListRegistry.RegisterBuddyList(ctx, screenName.IdentScreenName()); err != nil {
					h.Logger.ErrorContext(ctx, "failed to register buddy list", "err", err.Error())
				}
			}

			// Broadcast buddy arrival to OSCAR clients
			if h.BuddyBroadcaster != nil {
				if err := h.BuddyBroadcaster.BroadcastBuddyArrived(ctx, oscarSession.IdentScreenName(), oscarSession.TLVUserInfo()); err != nil {
					h.Logger.ErrorContext(ctx, "failed to broadcast buddy arrival", "err", err.Error())
				}
			}
		}
	}

	// Create WebAPI session
	session, err := h.SessionManager.CreateSession(r.Context(), screenName, apiKey.DevID, events, oscarSession, h.Logger)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to create session", "err", err.Error())
		h.sendError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	h.Logger.DebugContext(ctx, "session created with event subscriptions",
		"aimsid", session.AimSID,
		"events", events,
	)

	// Store client info
	session.ClientName = clientName
	session.ClientVersion = clientVersion
	session.FetchTimeout = timeout
	session.RemoteAddr = r.RemoteAddr

	// Queue myInfo event for authenticated users
	if authToken != "" {
		for _, event := range events {
			if event == "myInfo" || event == "presence" {
				myInfoData := map[string]interface{}{
					"aimId":        screenName.String(),
					"displayId":    screenName.String(),
					"state":        "online",
					"onlineTime":   time.Now().Unix(),
					"memberSince":  time.Now().Unix() - 86400*30, // 30 days ago
					"capabilities": []string{},
					"bot":          false,
					"service":      "aim",
				}
				session.EventQueue.Push(types.EventType("myInfo"), myInfoData)
				break
			}
		}
	}

	// Prepare response
	resp := StartSessionResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data.AimSID = session.AimSID
	resp.Response.Data.FetchTimeout = session.FetchTimeout
	resp.Response.Data.TimeToNextFetch = session.TimeToNextFetch
	// Gromit expects fetchBaseURL directly in data, not in wellKnownUrls
	resp.Response.Data.FetchBaseURL = fmt.Sprintf("http://%s/aim/fetchEvents?aimsid=%s&seqNum=0", r.Host, session.AimSID)

	// Add wellKnownUrls for other clients that might use it
	resp.Response.Data.WellKnownUrls = map[string]string{
		"webApiBase":   fmt.Sprintf("http://%s/", r.Host),
		"fetchBaseURL": fmt.Sprintf("http://%s/aim/fetchEvents", r.Host),
	}

	// Add myInfo data if authenticated
	if authToken != "" {
		if resp.Response.Data.Events == nil {
			resp.Response.Data.Events = make(map[string]interface{})
		}
		resp.Response.Data.Events["myInfo"] = map[string]interface{}{
			"aimId":        screenName.String(),
			"displayId":    screenName.String(),
			"state":        "online",
			"onlineTime":   time.Now().Unix(),
			"memberSince":  time.Now().Unix() - 86400*30, // 30 days ago
			"capabilities": []string{},
			"bot":          false,
			"service":      "aim",
			"self": map[string]interface{}{
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
			},
		}
	}

	// If buddy list event is subscribed, include initial buddy list
	for _, event := range events {
		if event == "buddylist" {
			if authToken != "" && h.BuddyListManager != nil {
				// Fetch actual buddy list from service
				buddyGroups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session.ScreenName.IdentScreenName())
				if err != nil {
					h.Logger.ErrorContext(ctx, "failed to get buddy list", "err", err.Error())
					// Continue with empty buddy list
					buddyGroups = []WebAPIBuddyGroup{}
				}

				// Convert to handler format and include in response
				if resp.Response.Data.Events == nil {
					resp.Response.Data.Events = make(map[string]interface{})
				}
				resp.Response.Data.Events["buddylist"] = map[string]interface{}{
					"groups": buddyGroups,
				}

			} else {
				// No auth token, return empty buddy list
				if resp.Response.Data.Events == nil {
					resp.Response.Data.Events = make(map[string]interface{})
				}
				resp.Response.Data.Events["buddylist"] = map[string]interface{}{
					"groups": []WebAPIBuddyGroup{},
				}
			}
			break
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
		xmlResp.Data.FetchBaseURL = fmt.Sprintf("http://%s/aim/fetchEvents?aimsid=%s&seqNum=0", r.Host, session.AimSID)

		// Add wellKnownUrls for other clients
		xmlResp.Data.WellKnownUrls = &struct {
			WebApiBase   string `xml:"webApiBase"`
			FetchBaseURL string `xml:"fetchBaseURL"`
		}{
			WebApiBase:   fmt.Sprintf("http://%s/", r.Host),
			FetchBaseURL: fmt.Sprintf("http://%s/aim/fetchEvents", r.Host),
		}

		// Add myInfo with user data
		xmlResp.Data.MyInfo = &struct {
			AimID     string `xml:"aimId"`
			DisplayID string `xml:"displayId"`
			Buddylist struct {
				Groups *[]BuddyGroup `xml:"group,omitempty"`
			} `xml:"buddylist,omitempty"`
		}{
			AimID:     session.ScreenName.String(),
			DisplayID: session.ScreenName.String(),
		}

		// Add buddy list if requested in myInfo or events
		for _, event := range events {
			if event == "buddylist" || event == "myInfo" {
				var buddyGroups []BuddyGroup

				if authToken != "" && h.BuddyListManager != nil {
					// Fetch actual buddy list from service
					webAPIGroups, err := h.BuddyListManager.GetBuddyListForUser(ctx, session.ScreenName.IdentScreenName())
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
			h.sendError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		// Write XML declaration and data as one response
		xmlOutput := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>%s`, xmlData)
		w.Header().Set("Content-Length", strconv.Itoa(len(xmlOutput)))
		fmt.Fprint(w, xmlOutput)
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
func (h *SessionHandler) EndSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session ID from parameters
	aimsid := r.URL.Query().Get("aimsid")
	if aimsid == "" {
		h.sendError(w, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Get session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		if err == state.ErrNoWebAPISession {
			h.sendError(w, http.StatusNotFound, "session not found")
		} else if err == state.ErrWebAPISessionExpired {
			h.sendError(w, http.StatusGone, "session expired")
		} else {
			h.sendError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Clean up OSCAR session if present
	if session.OSCARSession != nil && h.OSCARSessionManager != nil {
		// Broadcast departure to OSCAR clients
		if h.BuddyBroadcaster != nil {
			if err := h.BuddyBroadcaster.BroadcastBuddyDeparted(ctx, session.OSCARSession); err != nil {
				h.Logger.ErrorContext(ctx, "failed to broadcast buddy departure", "err", err.Error())
			}
		}

		// Unregister buddy list
		if h.BuddyListRegistry != nil {
			if err := h.BuddyListRegistry.UnregisterBuddyList(ctx, session.ScreenName.IdentScreenName()); err != nil {
				h.Logger.ErrorContext(ctx, "failed to unregister buddy list", "err", err.Error())
			}
		}

		// Remove OSCAR session
		h.OSCARSessionManager.RemoveSession(session.OSCARSession)
		session.OSCARSession = nil
	}

	// Remove session
	if err := h.SessionManager.RemoveSession(r.Context(), aimsid); err != nil {
		h.Logger.ErrorContext(ctx, "failed to remove session", "err", err.Error())
		h.sendError(w, http.StatusInternalServerError, "failed to end session")
		return
	}

	// Send response
	resp := EndSessionResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"

	// Send response in requested format (JSON, JSONP, or AMF)
	SendResponse(w, r, resp, h.Logger)

	h.Logger.DebugContext(ctx, "session ended",
		"aimsid", aimsid,
		"screen_name", session.ScreenName,
	)
}

// sendError is a convenience method that wraps the common SendError function.
func (h *SessionHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	SendError(w, statusCode, message)
}
