package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mk6i/open-oscar-server/server/webapi/middleware"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// OSCARBridgeHandler handles Web API to OSCAR protocol bridging endpoints.
// This handler is responsible for creating a bridge between web-based clients
// and the native OSCAR protocol, allowing web clients to connect to OSCAR services.
type OSCARBridgeHandler struct {
	SessionManager   *state.WebAPISessionManager
	OSCARAuthService OSCARAuthService
	CookieBaker      CookieBaker
	BridgeStore      OSCARBridgeStore
	Config           OSCARConfig
	Logger           *slog.Logger
}

// OSCARAuthService defines methods needed for OSCAR authentication and session management.
type OSCARAuthService interface {
	// RegisterBOSSession creates a new BOS (Basic OSCAR Service) session
	RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie) (*state.Session, error)
	// RetrieveBOSSession retrieves an existing BOS session
	RetrieveBOSSession(ctx context.Context, authCookie state.ServerCookie) (*state.Session, error)
	// Signout ends an OSCAR session
	Signout(ctx context.Context, sess *state.Session)
}

// CookieBaker issues and validates authentication cookies for OSCAR services.
type CookieBaker interface {
	// Issue creates a new authentication cookie from the given payload
	Issue(data []byte) ([]byte, error)
	// Crack verifies and decodes an authentication cookie
	Crack(data []byte) ([]byte, error)
}

// OSCARBridgeStore manages the persistence of OSCAR bridge sessions.
type OSCARBridgeStore interface {
	// SaveBridgeSession stores the mapping between WebAPI and OSCAR sessions
	SaveBridgeSession(ctx context.Context, webSessionID string, oscarCookie []byte, bosHost string, bosPort int) error
	// GetBridgeSession retrieves bridge session details
	GetBridgeSession(ctx context.Context, webSessionID string) (*state.OSCARBridgeSession, error)
	// DeleteBridgeSession removes a bridge session
	DeleteBridgeSession(ctx context.Context, webSessionID string) error
}

// OSCARConfig provides configuration for OSCAR services.
type OSCARConfig interface {
	// GetBOSAddress returns the BOS server address for client connections
	GetBOSAddress() (host string, port int)
	// GetSSLBOSAddress returns the SSL-enabled BOS server address
	GetSSLBOSAddress() (host string, port int)
	// IsSSLAvailable checks if SSL is configured for BOS connections
	IsSSLAvailable() bool
	// IsAuthDisabled returns whether authentication is disabled
	IsAuthDisabled() bool
}

// StartOSCARSessionRequest represents the request parameters for startOSCARSession.
type StartOSCARSessionRequest struct {
	AimSID   string // WebAPI session ID
	UseSSL   bool   // Whether to use SSL for the OSCAR connection
	Compress bool   // Whether to use compression (not implemented)
}

// StartOSCARSessionResponse represents the response for startOSCARSession endpoint.
type StartOSCARSessionResponse struct {
	XMLName  xml.Name `xml:"response" json:"-"`
	Response struct {
		StatusCode int    `json:"statusCode" xml:"statusCode"`
		StatusText string `json:"statusText" xml:"statusText"`
		Data       struct {
			Host        string `json:"host" xml:"host"`
			Port        int    `json:"port" xml:"port"`
			Cookie      string `json:"cookie" xml:"cookie"`
			UseSSL      bool   `json:"useSSL" xml:"useSSL"`
			Encryption  string `json:"encryption,omitempty" xml:"encryption,omitempty"`
			Compression string `json:"compression,omitempty" xml:"compression,omitempty"`
		} `json:"data" xml:"data"`
	} `json:"response" xml:"-"`
	// For XML responses, flatten the structure
	StatusCode int    `json:"-" xml:"statusCode"`
	StatusText string `json:"-" xml:"statusText"`
	Data       struct {
		Host        string `json:"-" xml:"host"`
		Port        int    `json:"-" xml:"port"`
		Cookie      string `json:"-" xml:"cookie"`
		UseSSL      bool   `json:"-" xml:"useSSL"`
		Encryption  string `json:"-" xml:"encryption,omitempty"`
		Compression string `json:"-" xml:"compression,omitempty"`
	} `json:"-" xml:"data"`
}

// StartOSCARSession handles GET /aim/startOSCARSession requests.
// This endpoint creates a bridge between a WebAPI session and the native OSCAR protocol,
// returning connection details that allow a web client to establish a direct OSCAR connection.
//
// The endpoint performs the following operations:
// 1. Validates the WebAPI session
// 2. Creates an OSCAR authentication cookie
// 3. Optionally pre-registers a BOS session
// 4. Returns connection details (host, port, cookie)
//
// Parameters:
//   - aimsid: The WebAPI session ID (required)
//   - useSSL: Whether to use SSL connection (optional, default: false)
//   - compress: Whether to use compression (optional, not implemented)
//   - f: Response format - "json" or "xml" (optional, default: "json")
//
// Returns:
//   - 200 OK: Successfully created OSCAR session bridge
//   - 400 Bad Request: Missing or invalid parameters
//   - 401 Unauthorized: Invalid or expired WebAPI session
//   - 500 Internal Server Error: Failed to create OSCAR session
func (h *OSCARBridgeHandler) StartOSCARSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Log the request
	h.Logger.InfoContext(ctx, "startOSCARSession requested",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent())

	// Get API key info from context (set by auth middleware)
	apiKey, ok := ctx.Value(middleware.ContextKeyAPIKey).(*state.WebAPIKey)
	if !ok {
		h.Logger.Error("API key not found in context")
		h.sendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// Verify that this API key has permission to create OSCAR sessions
	if !h.hasOSCARBridgeCapability(apiKey) {
		h.Logger.Warn("API key lacks OSCAR bridge capability",
			"dev_id", apiKey.DevID)
		h.sendError(w, r, http.StatusForbidden, "OSCAR bridge not enabled for this application")
		return
	}

	// Parse request parameters
	params := r.URL.Query()
	aimsid := params.Get("aimsid")

	if aimsid == "" {
		h.Logger.Warn("missing aimsid parameter")
		h.sendError(w, r, http.StatusBadRequest, "missing aimsid parameter")
		return
	}

	// Validate WebAPI session
	session, err := h.SessionManager.GetSession(r.Context(), aimsid)
	if err != nil {
		if err == state.ErrNoWebAPISession {
			h.Logger.Warn("session not found", "aimsid", aimsid)
			h.sendError(w, r, http.StatusNotFound, "session not found")
		} else if err == state.ErrWebAPISessionExpired {
			h.Logger.Warn("session expired", "aimsid", aimsid)
			h.sendError(w, r, http.StatusGone, "session expired")
		} else {
			h.Logger.Error("failed to get session", "error", err)
			h.sendError(w, r, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// Touch the session to update last access time
	h.SessionManager.TouchSession(r.Context(), aimsid)

	// Check if session already has an OSCAR bridge
	if session.OSCARSession != nil {
		h.Logger.Info("session already has OSCAR bridge",
			"aimsid", aimsid,
			"screen_name", session.ScreenName)
		// Return existing connection details
		h.returnExistingBridge(w, r, session)
		return
	}

	// Parse optional parameters
	useSSL := h.parseBoolParam(params.Get("useSSL"))
	compress := h.parseBoolParam(params.Get("compress"))

	// Check SSL availability if requested
	if useSSL && !h.Config.IsSSLAvailable() {
		h.Logger.Warn("SSL requested but not available")
		h.sendError(w, r, http.StatusBadRequest, "SSL not available")
		return
	}

	// Create OSCAR authentication cookie
	cookie, err := h.createOSCARCookie(session)
	if err != nil {
		h.Logger.Error("failed to create OSCAR cookie",
			"error", err,
			"screen_name", session.ScreenName)
		h.sendError(w, r, http.StatusInternalServerError, "failed to create authentication cookie")
		return
	}

	// Get BOS server address
	var host string
	var port int
	if useSSL {
		host, port = h.Config.GetSSLBOSAddress()
	} else {
		host, port = h.Config.GetBOSAddress()
	}

	// Store bridge session in database
	if h.BridgeStore != nil {
		if err := h.BridgeStore.SaveBridgeSession(ctx, aimsid, cookie, host, port); err != nil {
			h.Logger.Error("failed to save bridge session",
				"error", err,
				"aimsid", aimsid)
			// Continue anyway - the bridge will work without persistence
		}
	}

	// Prepare response
	resp := h.buildResponse(host, port, cookie, useSSL, compress)

	// Send response in requested format
	h.sendResponse(w, r, resp)

	h.Logger.InfoContext(ctx, "OSCAR session bridge created",
		"aimsid", aimsid,
		"screen_name", session.ScreenName,
		"bos_host", host,
		"bos_port", port,
		"use_ssl", useSSL,
		"compress", compress)
}

// createOSCARCookie generates an OSCAR authentication cookie for the session.
func (h *OSCARBridgeHandler) createOSCARCookie(session *state.WebAPISession) ([]byte, error) {
	// Create server cookie with session details
	serverCookie := state.ServerCookie{
		Service:       wire.BOS, // Basic OSCAR Service
		ScreenName:    session.ScreenName,
		ClientID:      fmt.Sprintf("WebAPI-%s", session.ClientName),
		MultiConnFlag: 0, // Single connection
	}

	// Marshal the cookie to bytes
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(serverCookie, buf); err != nil {
		return nil, fmt.Errorf("failed to marshal server cookie: %w", err)
	}

	// Issue the cookie with HMAC signature
	cookie, err := h.CookieBaker.Issue(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to issue cookie: %w", err)
	}

	return cookie, nil
}

// hasOSCARBridgeCapability checks if the API key has permission to create OSCAR bridges.
func (h *OSCARBridgeHandler) hasOSCARBridgeCapability(apiKey *state.WebAPIKey) bool {
	if len(apiKey.Capabilities) == 0 {
		return true // No restrictions if capabilities not specified
	}

	// Check if OSCAR bridge is explicitly enabled
	for _, cap := range apiKey.Capabilities {
		if cap == "oscar_bridge" || cap == "*" {
			return true
		}
	}

	return false
}

// parseBoolParam parses a boolean parameter from query string.
func (h *OSCARBridgeHandler) parseBoolParam(value string) bool {
	value = strings.ToLower(value)
	return value == "true" || value == "1" || value == "yes"
}

// returnExistingBridge returns details for an existing OSCAR bridge.
func (h *OSCARBridgeHandler) returnExistingBridge(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	// Retrieve existing bridge details from store
	if h.BridgeStore != nil {
		bridge, err := h.BridgeStore.GetBridgeSession(r.Context(), session.AimSID)
		if err == nil && bridge != nil {
			resp := h.buildResponse(bridge.BOSHost, bridge.BOSPort, bridge.OSCARCookie, bridge.UseSSL, false)
			h.sendResponse(w, r, resp)
			return
		}
	}

	// If we can't retrieve the bridge, return an error
	h.sendError(w, r, http.StatusInternalServerError, "failed to retrieve existing bridge")
}

// buildResponse constructs the response object.
func (h *OSCARBridgeHandler) buildResponse(host string, port int, cookie []byte, useSSL, compress bool) *StartOSCARSessionResponse {
	resp := &StartOSCARSessionResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data.Host = host
	resp.Response.Data.Port = port
	resp.Response.Data.Cookie = hex.EncodeToString(cookie) // Hex encode the cookie
	resp.Response.Data.UseSSL = useSSL

	// Add encryption info if SSL is used
	if useSSL {
		resp.Response.Data.Encryption = "TLS"
	}

	// Add compression info if requested (not implemented)
	if compress {
		resp.Response.Data.Compression = "none" // Compression not implemented
	}

	// Duplicate data for XML format
	resp.StatusCode = resp.Response.StatusCode
	resp.StatusText = resp.Response.StatusText
	resp.Data.Host = resp.Response.Data.Host
	resp.Data.Port = resp.Response.Data.Port
	resp.Data.Cookie = resp.Response.Data.Cookie
	resp.Data.UseSSL = resp.Response.Data.UseSSL
	resp.Data.Encryption = resp.Response.Data.Encryption
	resp.Data.Compression = resp.Response.Data.Compression

	return resp
}

// sendResponse sends the response in the requested format.
func (h *OSCARBridgeHandler) sendResponse(w http.ResponseWriter, r *http.Request, resp *StartOSCARSessionResponse) {
	// Use the centralized SendResponse function which handles all formats
	SendResponse(w, r, resp, h.Logger)
}

// sendError sends an error response in the appropriate format.
func (h *OSCARBridgeHandler) sendError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	// SendError already detects format from Content-Type header
	SendError(w, statusCode, message)
}
