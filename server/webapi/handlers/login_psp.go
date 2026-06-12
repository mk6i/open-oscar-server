package handlers

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

const loginPSPCookieMaxAge = 86400

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

		if err := h.authenticateCredentials(r, loginID, password); err != nil {
			h.Logger.DebugContext(r.Context(), "login.psp failed", "loginId", loginID, "error", err)
			data.Error = "Invalid screen name or password."
			h.renderLoginPSP(w, r, data)
			return
		}

		screenName := state.DisplayScreenName(loginID)
		h.setLoginPSPCookies(w, screenName)
		redirectURL := safeLoginRedirectURL(r, data.SuccURL)
		h.Logger.InfoContext(r.Context(), "login.psp succeeded", "loginId", screenName, "redirect", redirectURL)
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

func (h *AuthHandler) authenticateCredentials(r *http.Request, username, password string) error {
	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, username))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, password))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))

	block, err := h.AuthService.FLAPLogin(r.Context(), signonFrame, "")
	if err != nil {
		return err
	}
	if block.HasTag(wire.LoginTLVTagsErrorSubcode) {
		return fmt.Errorf("login failed")
	}
	return nil
}

func (h *AuthHandler) setLoginPSPCookies(w http.ResponseWriter, screenName state.DisplayScreenName) {
	loginID := string(screenName)
	expires := time.Now().Add(loginPSPCookieMaxAge * time.Second)
	cookie := func(name, value string) *http.Cookie {
		return &http.Cookie{
			Name:     name,
			Value:    value,
			Path:     "/",
			Expires:  expires,
			MaxAge:   loginPSPCookieMaxAge,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
		}
	}
	http.SetCookie(w, cookie("RSP_USER", loginID))
	http.SetCookie(w, cookie("RSP_LOCAL", loginID))
	http.SetCookie(w, cookie("localAuthUser", loginID+"||"+loginID))
}

func defaultLoginSuccURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/"
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
