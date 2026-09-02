package webapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// AuthToken is the opaque credential the client presents on later requests.
//
// ExpiresIn is a string because that is the shape the client is given, even
// though ClientLoginData.TokenExpiresIn carries the same quantity as a number.
type AuthToken struct {
	A         string `json:"a" xml:"a"`
	ExpiresIn string `json:"expiresIn" xml:"expiresIn"`
}

// GetTokenData is the getToken payload.
type GetTokenData struct {
	Token    AuthToken `json:"token" xml:"token"`
	UserData UserData  `json:"userData" xml:"userData"`
}

// UserData wraps the attributes getToken reports about the account.
type UserData struct {
	Attributes UserAttributes `json:"attributes" xml:"attributes"`
}

// UserAttributes names the account the token belongs to.
type UserAttributes struct {
	LoginID string `json:"loginId" xml:"loginId"`
}

// GetInfoData is the auth/getInfo payload.
type GetInfoData struct {
	UserData GetInfoUser `json:"userData" xml:"userData"`
}

// GetInfoUser names the account the presented token belongs to. Clients read both
// keys strictly, so neither is omitted when empty.
type GetInfoUser struct {
	LoginID     string `json:"loginId" xml:"loginId"`
	DisplayName string `json:"displayName" xml:"displayName"`
}

// ClientLoginData is the clientLogin payload.
type ClientLoginData struct {
	Token          AuthToken `json:"token" xml:"token"`
	LoginID        string    `json:"loginId" xml:"loginId"`
	ScreenName     string    `json:"screenName" xml:"screenName"`
	SessionSecret  string    `json:"sessionSecret" xml:"sessionSecret"`
	HostTime       int64     `json:"hostTime" xml:"hostTime"`
	TokenExpiresIn int       `json:"tokenExpiresIn" xml:"tokenExpiresIn"`
}

// RedirectData sends an unauthenticated client to the login page.
type RedirectData struct {
	RedirectURL string `json:"redirectURL" xml:"redirectURL"`
}

// AuthHandler handles Web AIM API authentication endpoints.
type AuthHandler struct {
	AuthService AuthService
	Logger      *slog.Logger
}

// GetToken handles GET /auth/getToken requests.
// The Web AIM client uses this JSONP endpoint to exchange SSO session cookies for an API token.
func (h *AuthHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devID := r.URL.Query().Get("devId")

	// The cookie is spent either way: consumed on success, and cleared on failure
	// so a browser holding a dead token stops presenting it.
	clearBOSTokenCookie(w)

	loginID, authCookie, expiry, ok := h.resolveGetTokenSession(r)
	if !ok {
		h.Logger.DebugContext(ctx, "getToken: no token, returning redirect",
			"devId", devID,
			"host", r.Host)
		resp := BaseResponse{}
		resp.Response.StatusCode = 401
		resp.Response.StatusText = "Unauthorized"
		resp.Response.Data = &RedirectData{RedirectURL: h.loginRedirectURL(r)}
		SendResponse(w, r, resp, h.Logger)
		return
	}

	SendOK(w, r, &GetTokenData{
		Token: AuthToken{
			A:         base64.URLEncoding.EncodeToString(authCookie),
			ExpiresIn: strconv.Itoa(int(math.Round(time.Until(expiry).Seconds()))),
		},
		UserData: UserData{Attributes: UserAttributes{LoginID: string(loginID)}},
	}, h.Logger)

	h.Logger.InfoContext(ctx, "getToken succeeded", "loginId", loginID, "devId", devID)
}

// resolveGetTokenSession identifies the caller from the BOS token parked at
// sign-in.
func (h *AuthHandler) resolveGetTokenSession(r *http.Request) (state.DisplayScreenName, []byte, time.Time, bool) {
	c, err := r.Cookie(bosTokenCookie)
	if err != nil || c.Value == "" {
		return "", nil, time.Time{}, false
	}
	token, err := url.QueryUnescape(c.Value)
	if err != nil {
		token = c.Value
	}
	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", nil, time.Time{}, false
	}
	serverCookie, expiry, err := h.AuthService.CrackCookie(rawCookie)
	if err != nil {
		return "", nil, time.Time{}, false
	}
	return serverCookie.ScreenName, rawCookie, expiry, true
}

// The lifetimes the clientLogin tokenType parameter names.
const (
	shortTermTTL = 24 * time.Hour
	longTermTTL  = 365 * 24 * time.Hour
)

// tokenTypeTTL resolves the clientLogin tokenType parameter to a token lifetime.
// The parameter is "shortterm" (the default), "longterm", or a count of seconds,
// and the server grants no more than longTermTTL either way.
func tokenTypeTTL(tokenType string) (time.Duration, error) {
	tokenType = strings.TrimSpace(tokenType)

	switch strings.ToLower(tokenType) {
	case "", "shortterm":
		return shortTermTTL, nil
	case "longterm":
		return longTermTTL, nil
	}

	secs, err := strconv.ParseUint(tokenType, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tokenType %q is not shortterm, longterm, or a count of seconds", tokenType)
	}
	// bound the count before scaling it, so an absurd value is an error rather
	// than an overflowed duration
	maxSecs := uint64(longTermTTL / time.Second)
	if secs == 0 || secs > maxSecs {
		return 0, fmt.Errorf("tokenType %q is outside the range 1-%d seconds", tokenType, maxSecs)
	}
	return time.Duration(secs) * time.Second, nil
}

// errInvalidCredentials reports that the auth service rejected the screen name or
// password, as opposed to failing to answer at all.
var errInvalidCredentials = errors.New("invalid screen name or password")

// authenticateCredentials verifies the credentials and returns the auth cookie minted
// by the OSCAR auth service. It returns errInvalidCredentials when the credentials are
// rejected.
func (h *AuthHandler) authenticateCredentials(ctx context.Context, username, password, clientID string, ttl time.Duration) ([]byte, error) {
	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, username))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, password))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, clientID))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsTokenTTL, uint32(ttl.Seconds())))

	block, err := h.AuthService.FLAPLogin(ctx, signonFrame, config.Endpoint{})
	if err != nil {
		return nil, fmt.Errorf("FLAPLogin: %w", err)
	}
	if block.HasTag(wire.LoginTLVTagsErrorSubcode) {
		return nil, errInvalidCredentials
	}
	authCookie, ok := block.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !ok {
		return nil, fmt.Errorf("login response carries no authorization cookie")
	}
	return authCookie, nil
}

// clientIDForDevID names the client on the session for callers that only know the
// Web API devId.
func clientIDForDevID(devID string) string {
	if devID == "" {
		return "WebAIM"
	}
	return devID
}

func (h *AuthHandler) loginRedirectURL(r *http.Request) string {
	// requestScheme, not r.TLS: TLS is terminated upstream, so the scheme survives
	// only in the header.
	return fmt.Sprintf("%s://%s/_cqr/login/login.psp", requestScheme(r), r.Host)
}

// Logout clears the token cookie and sends the browser to the login page. A
// sign-in whose getToken never ran leaves a token in the browser for the rest of
// its life, so signing out has to spend it rather than trust that something
// else already did.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	clearBOSTokenCookie(w)

	loginURL := h.loginRedirectURL(r)
	q := url.Values{}
	if devID := r.URL.Query().Get("devId"); devID != "" {
		q.Set("devId", devID)
	}
	if succURL := r.URL.Query().Get("succUrl"); succURL != "" {
		q.Set("succUrl", succURL)
	}
	if enc := q.Encode(); enc != "" {
		loginURL += "?" + enc
	}

	h.Logger.InfoContext(r.Context(), "logout", "devId", r.URL.Query().Get("devId"))
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// ClientLogin handles POST /auth/clientLogin requests.
// This endpoint authenticates users and returns an authentication token.
func (h *AuthHandler) ClientLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.Logger.Error("failed to parse form data", "error", err)
		SendError(w, r, http.StatusBadRequest, "invalid form data")
		return
	}

	username := r.PostFormValue("s")
	if username == "" {
		username = r.PostFormValue("username")
	}
	password := r.PostFormValue("pwd")
	if password == "" {
		password = r.PostFormValue("password")
	}
	devID := r.PostFormValue("devId")
	tokenType := r.PostFormValue("tokenType")

	h.Logger.Debug("clientLogin attempt",
		"username", username,
		"has_password", password != "",
		"devId", devID,
		"form", r.Form)

	// Validate required fields
	if username == "" || password == "" {
		SendErrorDetail(w, r, http.StatusBadRequest, statusMissingParameter, 0, "username and password required")
		return
	}

	ttl, err := tokenTypeTTL(tokenType)
	if err != nil {
		h.Logger.DebugContext(r.Context(), "clientLogin rejected tokenType", "tokenType", tokenType, "error", err)
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0, err.Error())
		return
	}

	authCookie, err := h.authenticateCredentials(r.Context(), username, password, clientIDForDevID(devID), ttl)
	if err != nil {
		h.Logger.DebugContext(r.Context(), "clientLogin failed", "username", username, "error", err)
		if errors.Is(err, errInvalidCredentials) {
			SendErrorDetail(w, r, http.StatusUnauthorized, statusMoreAuthRequired, detailBadPassword,
				"invalid screen name or password")
			return
		}
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// No cookie here: this endpoint's caller receives the token in the response
	// body and presents it to startSession itself.

	// Generate session secret (for signing subsequent requests)
	sessionSecret, err := h.generateToken()
	if err != nil {
		h.Logger.Error("failed to generate session secret", "error", err)
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build response

	// Send response in requested format (JSON, JSONP, XML, or AMF)
	SendOK(w, r, &ClientLoginData{
		Token: AuthToken{
			A:         base64.URLEncoding.EncodeToString(authCookie),
			ExpiresIn: strconv.Itoa(int(ttl.Seconds())),
		},
		LoginID:       username,
		ScreenName:    username,
		SessionSecret: sessionSecret,
		HostTime:      time.Now().Unix(),
		// A number here where token.expiresIn is a string, as the client expects.
		TokenExpiresIn: int(ttl.Seconds()),
	}, h.Logger)

	h.Logger.Info("user authenticated successfully",
		"username", username,
		"screenName", username,
		"tokenTTL", ttl)
}

// defaultAuthFreshness is the reqAuthFreshness applied when a caller names none.
const defaultAuthFreshness = 24 * time.Hour

// GetInfo handles GET and POST /auth/getInfo, reporting which account the token in
// "a" belongs to. It mints nothing: a caller that cannot be answered is told to
// authenticate again.
func (h *AuthHandler) GetInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// This endpoint does not renew. Refusing gives a client expecting a token some
	// status to react to; a 200 with no token gives it nothing.
	if isTrueParam(param(r, "renewToken")) {
		h.Logger.DebugContext(ctx, "getInfo: refused a renewal request")
		h.sendGetInfoRedirect(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	token := param(r, "a")
	if token == "" {
		h.sendGetInfoRedirect(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		h.Logger.DebugContext(ctx, "getInfo: token is not valid base64", "error", err)
		h.sendGetInfoRedirect(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	serverCookie, expiry, err := h.AuthService.CrackCookie(rawCookie)
	if err != nil {
		h.Logger.DebugContext(ctx, "getInfo: token rejected", "error", err)
		h.sendGetInfoRedirect(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// One key signs every cookie, so a service-transfer cookie verifies just like a
	// login token while recording no authentication. A non-zero TokenTTL is the only
	// positive evidence of a login: wire.BOS is 0x0000, so testing Service alone
	// admits the linked-account transfer cookie (foodgroup/oservice.go:662), which
	// then satisfies any freshness check.
	if serverCookie.Service != wire.BOS || serverCookie.ChatCookie != "" || serverCookie.TokenTTL == 0 {
		h.Logger.WarnContext(ctx, "getInfo: rejected a cookie that is not a login token",
			"service", serverCookie.Service, "loginId", serverCookie.ScreenName)
		h.sendGetInfoRedirect(w, r, http.StatusUnauthorized, "Unauthorized")
		return
	}

	freshness, ok := authFreshness(r)
	if !ok {
		SendEnvelopeStatus(w, r, statusParameterError, "reqAuthFreshness is not a count of seconds", h.Logger)
		return
	}

	if age := authAge(serverCookie, expiry); age > freshness {
		h.Logger.DebugContext(ctx, "getInfo: authentication is too stale",
			"loginId", serverCookie.ScreenName, "age", age, "required", freshness)
		h.sendGetInfoRedirect(w, r, statusMoreAuthRequired, "More authentication required")
		return
	}

	// The cookie's screen name carries the user's own capitalization; without a
	// session there is nothing better to look up.
	name := serverCookie.ScreenName.String()
	SendOK(w, r, &GetInfoData{
		UserData: GetInfoUser{LoginID: name, DisplayName: name},
	}, h.Logger)
}

// sendGetInfoRedirect refuses a getInfo, naming where to authenticate instead.
// SendEnvelopeStatus cannot be used: it sends no data, so the client has nowhere to
// go.
func (h *AuthHandler) sendGetInfoRedirect(w http.ResponseWriter, r *http.Request, statusCode int, statusText string) {
	resp := BaseResponse{}
	resp.Response.StatusCode = statusCode
	resp.Response.StatusText = statusText
	resp.Response.Data = &RedirectData{RedirectURL: h.loginRedirectURL(r)}
	SendResponse(w, r, resp, h.Logger)
}

// authFreshness reads the reqAuthFreshness parameter, reporting false when it is
// present but unusable. Absent, it is the spec's 24 hours.
func authFreshness(r *http.Request) (time.Duration, bool) {
	raw := strings.TrimSpace(param(r, "reqAuthFreshness"))
	if raw == "" {
		return defaultAuthFreshness, true
	}
	secs, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

// authAge is how long ago the cookie's owner authenticated. Nothing records a login
// time, but the granted lifetime subtracted from the expiry gives the issue instant.
// Callers must reject a cookie with no TokenTTL first.
//
// CrackCookie has already rejected an expired cookie, so the age is always under the
// granted lifetime: a freshness requirement at or above the grant never fires.
func authAge(cookie state.ServerCookie, expiry time.Time) time.Duration {
	issued := expiry.Add(-time.Duration(cookie.TokenTTL) * time.Second)
	return max(time.Since(issued), 0)
}

// generateToken generates a secure random token.
func (h *AuthHandler) generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// bosTokenCookie is the cookie the browser presents to getToken. The name is the
// one AIM's own client knows, kept so a client running against the non-Web API
// path finds what it expects.
const bosTokenCookie = "oldAimToken"

var loginPSPPage = template.Must(template.New("login.psp").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in to AIM</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; background: #0e95ad; margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: #fff; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,.2); width: 360px; padding: 32px; }
    h1 { margin: 0 0 8px; font-size: 24px; color: #222; }
    p { margin: 0 0 20px; color: #666; font-size: 14px; }
    label { display: block; font-size: 13px; font-weight: bold; margin-bottom: 6px; color: #333; }
    input[type=text], input[type=password] { width: 100%; box-sizing: border-box; padding: 10px 12px; margin-bottom: 16px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
    button { width: 100%; padding: 12px; border: 0; border-radius: 4px; background: #ff6600; color: #fff; font-size: 15px; font-weight: bold; cursor: pointer; }
    button:hover { background: #e55c00; }
    .error { background: #fdecea; color: #b42318; border: 1px solid #f5c2c0; border-radius: 4px; padding: 10px 12px; margin-bottom: 16px; font-size: 13px; }
  </style>
</head>
<body>
  <form class="card" method="post" action="/_cqr/login/login.psp">
    <h1>AIM Sign In</h1>
    <p>Sign in with your Open OSCAR account.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <label for="loginId">Screen name</label>
    <input id="loginId" name="loginId" type="text" autocomplete="username" value="{{.LoginID}}" required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <input type="hidden" name="devId" value="{{.DevID}}">
    <input type="hidden" name="supportedIdType" value="{{.SupportedIDType}}">
    <input type="hidden" name="succUrl" value="{{.SuccURL}}">
    <input type="hidden" name="r" value="{{.R}}">
    <button type="submit">Sign In</button>
  </form>
</body>
</html>`))

type loginPSPPageData struct {
	Error           string
	LoginID         string
	DevID           string
	SupportedIDType string
	SuccURL         string
	R               string
}

// LoginPSP handles GET and POST /_cqr/login/login.psp for Web AIM SSO login.
func (h *AuthHandler) LoginPSP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.renderLoginPSP(w, r, loginPSPPageData{
			DevID:           r.URL.Query().Get("devId"),
			SupportedIDType: r.URL.Query().Get("supportedIdType"),
			SuccURL:         r.URL.Query().Get("succUrl"),
			R:               r.URL.Query().Get("r"),
		})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		loginID := strings.TrimSpace(r.FormValue("loginId"))
		if loginID == "" {
			loginID = strings.TrimSpace(r.FormValue("s"))
		}
		password := r.FormValue("password")
		if password == "" {
			password = r.FormValue("pwd")
		}

		data := loginPSPPageData{
			LoginID:         loginID,
			DevID:           r.FormValue("devId"),
			SupportedIDType: r.FormValue("supportedIdType"),
			SuccURL:         r.FormValue("succUrl"),
			R:               r.FormValue("r"),
		}

		if loginID == "" || password == "" {
			data.Error = "Screen name and password are required."
			h.renderLoginPSP(w, r, data)
			return
		}

		authCookie, err := h.authenticateCredentials(r.Context(), loginID, password, clientIDForDevID(data.DevID), shortTermTTL)
		if err != nil {
			if errors.Is(err, errInvalidCredentials) {
				h.Logger.DebugContext(r.Context(), "login.psp failed", "loginId", loginID)
				data.Error = "Invalid screen name or password."
				h.renderLoginPSP(w, r, data)
				return
			}
			h.Logger.ErrorContext(r.Context(), "login.psp could not authenticate", "loginId", loginID, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		setBOSTokenCookie(w, authCookie)

		redirectURL := safeLoginRedirectURL(r, data.SuccURL)
		h.Logger.InfoContext(r.Context(), "login.psp succeeded", "loginId", loginID, "redirect", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *AuthHandler) renderLoginPSP(w http.ResponseWriter, r *http.Request, data loginPSPPageData) {
	if data.SuccURL == "" {
		data.SuccURL = defaultLoginSuccURL(r)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginPSPPage.Execute(w, data); err != nil {
		h.Logger.ErrorContext(r.Context(), "failed to render login.psp", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// setBOSTokenCookie hands the BOS token from the login response to the browser.
func setBOSTokenCookie(w http.ResponseWriter, authCookie []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     bosTokenCookie,
		Value:    base64.URLEncoding.EncodeToString(authCookie),
		Path:     "/",
		Expires:  time.Now().Add(shortTermTTL),
		MaxAge:   int(shortTermTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearBOSTokenCookie expires the token cookie. getToken calls it on every
// request, spending the token whether or not it was any good, so a reload finds
// nothing to sign in with.
func clearBOSTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     bosTokenCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func defaultLoginSuccURL(r *http.Request) string {
	return requestScheme(r) + "://" + r.Host + "/"
}

func safeLoginRedirectURL(r *http.Request, succURL string) string {
	succURL = strings.TrimSpace(succURL)
	if succURL == "" {
		return defaultLoginSuccURL(r)
	}
	target, err := url.Parse(succURL)
	if err != nil {
		return defaultLoginSuccURL(r)
	}
	if target.Host == "" {
		return succURL
	}
	reqHost := hostnameOnly(r.Host)
	targetHost := hostnameOnly(target.Host)
	if targetHost == reqHost || targetHost == "localhost" || targetHost == "127.0.0.1" {
		return succURL
	}
	return defaultLoginSuccURL(r)
}

func hostnameOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
