package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// AuthHandler handles Web AIM API authentication endpoints.
type AuthHandler struct {
	AuthService AuthService
	CookieBaker CookieBaker
	UserManager UserRetriever
	Logger      *slog.Logger
}

// UserRetriever looks up local AIM accounts.
type UserRetriever interface {
	User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)
}

type OServiceService interface {
	ClientOnline(ctx context.Context, service uint16, inBody wire.SNAC_0x01_0x02_OServiceClientOnline, instance *state.SessionInstance) error
}

// ClientLoginRequest represents the request body for clientLogin.
type ClientLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	DevID    string `json:"devId"`
}

// GetToken handles GET /auth/getToken requests.
// The Web AIM client uses this JSONP endpoint to exchange SSO session cookies for an API token.
func (h *AuthHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devID := r.URL.Query().Get("devId")

	loginID, tokenBytes, ok := h.resolveGetTokenSession(ctx, r)
	if !ok || loginID == "" {
		h.Logger.DebugContext(ctx, "getToken: no session, returning redirect",
			"devId", devID,
			"host", r.Host)
		resp := BaseResponse{}
		resp.Response.StatusCode = 401
		resp.Response.StatusText = "Unauthorized"
		resp.Response.Data = map[string]interface{}{
			"redirectURL": h.loginRedirectURL(r),
		}
		SendResponse(w, r, resp, h.Logger)
		return
	}

	if h.UserManager != nil {
		user, err := h.UserManager.User(ctx, loginID.IdentScreenName())
		if err != nil {
			h.Logger.ErrorContext(ctx, "getToken: user lookup failed", "error", err, "loginId", loginID)
			SendError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if user == nil {
			h.Logger.DebugContext(ctx, "getToken: user not found", "loginId", loginID)
			resp := BaseResponse{}
			resp.Response.StatusCode = 401
			resp.Response.StatusText = "Unauthorized"
			resp.Response.Data = map[string]interface{}{
				"redirectURL": h.loginRedirectURL(r),
			}
			SendResponse(w, r, resp, h.Logger)
			return
		}
	}

	if len(tokenBytes) == 0 {
		var err error
		tokenBytes, err = h.issueAuthCookie(loginID, devID)
		if err != nil {
			h.Logger.ErrorContext(ctx, "getToken: failed to issue token", "error", err, "loginId", loginID)
			SendError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{
		"token": map[string]interface{}{
			"a":         base64.URLEncoding.EncodeToString(tokenBytes),
			"expiresIn": "86400",
		},
		"userData": map[string]interface{}{
			"attributes": map[string]interface{}{
				"loginId": string(loginID),
			},
		},
	}
	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "getToken succeeded", "loginId", loginID, "devId", devID)
}

func (h *AuthHandler) resolveGetTokenSession(ctx context.Context, r *http.Request) (state.DisplayScreenName, []byte, bool) {
	if token := r.URL.Query().Get("a"); token != "" {
		if loginID, cookie, ok := h.loginFromToken(token); ok {
			return loginID, cookie, true
		}
	}

	if c, err := r.Cookie("oldAimToken"); err == nil && c.Value != "" {
		token, err := url.QueryUnescape(c.Value)
		if err != nil {
			token = c.Value
		}
		if loginID, cookie, ok := h.loginFromToken(token); ok {
			return loginID, cookie, true
		}
	}

	if c, err := r.Cookie("localAuthUser"); err == nil && c.Value != "" {
		if loginID, ok := parseLocalAuthUser(c.Value); ok {
			return loginID, nil, true
		}
	}

	for _, name := range []string{"RSP_USER", "RSP_LOCAL"} {
		if c, err := r.Cookie(name); err == nil {
			if loginID, ok := parseRSPCookie(c.Value); ok {
				return loginID, nil, true
			}
		}
	}

	return "", nil, false
}

func (h *AuthHandler) loginFromToken(token string) (state.DisplayScreenName, []byte, bool) {
	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", nil, false
	}
	serverCookie, err := h.AuthService.CrackCookie(rawCookie)
	if err != nil {
		return "", nil, false
	}
	return serverCookie.ScreenName, rawCookie, true
}

func parseLocalAuthUser(value string) (state.DisplayScreenName, bool) {
	parts := strings.SplitN(value, "||", 2)
	loginID := strings.TrimSpace(parts[0])
	if loginID == "" {
		return "", false
	}
	return state.DisplayScreenName(loginID), true
}

func parseRSPCookie(value string) (state.DisplayScreenName, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if decoded, err := url.QueryUnescape(value); err == nil && decoded != "" {
		value = decoded
	}
	// RSP cookies typically contain the screen name directly.
	if strings.ContainsAny(value, " \t\r\n") {
		return "", false
	}
	return state.DisplayScreenName(value), true
}

func (h *AuthHandler) issueAuthCookie(screenName state.DisplayScreenName, devID string) ([]byte, error) {
	if h.CookieBaker == nil {
		return nil, fmt.Errorf("cookie baker not configured")
	}
	clientID := devID
	if clientID == "" {
		clientID = "WebAIM"
	}
	serverCookie := state.ServerCookie{
		Service:       wire.BOS,
		ScreenName:    screenName,
		ClientID:      clientID,
		MultiConnFlag: uint8(wire.MultiConnFlagsRecentClient),
	}
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(serverCookie, buf); err != nil {
		return nil, err
	}
	return h.CookieBaker.Issue(buf.Bytes())
}

func (h *AuthHandler) loginRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/_cqr/login/login.psp", scheme, r.Host)
}

// ClientLogin handles POST /auth/clientLogin requests.
// This endpoint authenticates users and returns an authentication token.
func (h *AuthHandler) ClientLogin(w http.ResponseWriter, r *http.Request) {
	var username, password, devID string

	// Check Content-Type to determine how to parse the request
	contentType := r.Header.Get("Content-Type")

	if contentType == "application/json" {
		// Parse JSON body
		var req ClientLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.Logger.Error("failed to parse JSON clientLogin request", "error", err)
			SendError(w, http.StatusBadRequest, "invalid JSON format")
			return
		}
		username = req.Username
		password = req.Password
	} else {
		// Parse form-encoded or URL parameters
		if err := r.ParseForm(); err != nil {
			h.Logger.Error("failed to parse form data", "error", err)
			SendError(w, http.StatusBadRequest, "invalid form data")
			return
		}

		// Try form values first, then fall back to query parameters
		username = r.FormValue("s")
		if username == "" {
			username = r.FormValue("username")
		}
		password = r.FormValue("pwd")
		if password == "" {
			password = r.FormValue("password")
		}
		devID = r.FormValue("devId")

		h.Logger.Debug("form-encoded login attempt",
			"username", username,
			"has_password", password != "",
			"devId", devID,
			"form", r.Form)
	}

	// Validate required fields
	if username == "" || password == "" {
		SendError(w, http.StatusBadRequest, "username and password required")
		return
	}

	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, username))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, password))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))

	block, err := h.AuthService.FLAPLogin(r.Context(), signonFrame, "")
	if err != nil {
		h.Logger.DebugContext(r.Context(), err.Error())
		SendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if block.HasTag(wire.LoginTLVTagsErrorSubcode) {
		h.Logger.DebugContext(r.Context(), "login failed")
		SendError(w, http.StatusUnauthorized, "username and password required")
		return
	}

	authCookie, ok := block.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !ok {
		h.Logger.DebugContext(r.Context(), "login cookie not found")
		SendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Generate session secret (for signing subsequent requests)
	sessionSecret, err := h.generateToken()
	if err != nil {
		h.Logger.Error("failed to generate session secret", "error", err)
		SendError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build response
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{
		"token": map[string]interface{}{
			"a":         base64.URLEncoding.EncodeToString(authCookie),
			"expiresIn": "86400", // 24 hours in seconds
		},
		"loginId":        username,
		"screenName":     username,
		"sessionSecret":  sessionSecret,
		"hostTime":       time.Now().Unix(),
		"tokenExpiresIn": 86400, // 24 hours in seconds
	}

	// Send response in requested format (JSON, JSONP, XML, or AMF)
	SendResponse(w, r, resp, h.Logger)

	h.Logger.Info("user authenticated successfully",
		"username", username,
		"screenName", username)
}

// generateToken generates a secure random token.
func (h *AuthHandler) generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
