package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// AuthHandler handles Web AIM API authentication endpoints.
type AuthHandler struct {
	AuthService AuthService
	UserManager UserManager
	TokenStore  TokenStore
	Logger      *slog.Logger
	DisableAuth bool
}

// UserManager defines methods for user authentication.
type UserManager interface {
	// AuthenticateUser verifies username and password
	AuthenticateUser(ctx context.Context, username, password string) (*state.User, error)
	// FindUserByScreenName finds a user by their screen name
	FindUserByScreenName(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)
	// InsertUser creates a new user (for DISABLE_AUTH mode)
	InsertUser(ctx context.Context, u state.User) error
}

// TokenStore manages authentication tokens.
type TokenStore interface {
	// StoreToken saves an authentication token for a user
	StoreToken(ctx context.Context, token string, screenName state.IdentScreenName, expiresAt time.Time) error
	// ValidateToken checks if a token is valid and returns the associated screen name
	ValidateToken(ctx context.Context, token string) (state.IdentScreenName, error)
	// DeleteToken removes a token
	DeleteToken(ctx context.Context, token string) error
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
		devID = req.DevID
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
			"a":         base64.StdEncoding.EncodeToString(authCookie),
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
