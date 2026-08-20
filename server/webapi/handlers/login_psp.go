package handlers

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// bosTokenCookie is the cookie the browser presents to getToken. The name is the
// one AIM's own client knows, kept so a client running against the non-Web API
// path finds what it expects.
const bosTokenCookie = "oldAimToken"

// bosTokenTTL mirrors the expiry stamped by HMACCookieBaker.Issue
// (state/cookie.go). The token only has to survive login.psp -> getToken ->
// startSession, so its brief life is what makes every later visit sign in again.
const bosTokenTTL = time.Minute

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

		authCookie, err := h.authenticateCredentials(r.Context(), loginID, password, clientIDForDevID(data.DevID))
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

// setBOSTokenCookie hands the BOS token from the login response to the browser,
// which carries it as far as the getToken that follows the redirect. It is a
// bearer credential, so HttpOnly keeps it out of reach of page scripts, and its
// MaxAge matches the token's own life so the browser drops it on the same
// schedule the server stops honouring it.
func setBOSTokenCookie(w http.ResponseWriter, authCookie []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     bosTokenCookie,
		Value:    base64.URLEncoding.EncodeToString(authCookie),
		Path:     "/",
		Expires:  time.Now().Add(bosTokenTTL),
		MaxAge:   int(bosTokenTTL.Seconds()),
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
