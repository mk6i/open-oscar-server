package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestAuthHandler_LoginPSP_GET(t *testing.T) {
	handler := &AuthHandler{Logger: slog.Default()}

	req := httptest.NewRequest(http.MethodGet, "/_cqr/login/login.psp?devId=dev1&succUrl=http%3A%2F%2Flocalhost%3A8000%2F", nil)
	rr := httptest.NewRecorder()

	handler.LoginPSP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rr.Body.String(), "AIM Sign In")
	assert.Contains(t, rr.Body.String(), `name="devId" value="dev1"`)
}

func TestAuthHandler_Logout(t *testing.T) {
	handler := &AuthHandler{Logger: slog.Default()}

	req := httptest.NewRequest(http.MethodGet, "/auth/logout?f=json&a=sometoken&devId=dev1&succUrl=http%3A%2F%2Flocalhost%3A8000%2F.client%2F", nil)
	rr := httptest.NewRecorder()

	handler.Logout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	loc, err := url.Parse(rr.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "/_cqr/login/login.psp", loc.Path)
	assert.Equal(t, "dev1", loc.Query().Get("devId"))
	assert.Equal(t, "http://localhost:8000/.client/", loc.Query().Get("succUrl"))

	// Nothing to clear: getToken spent the token cookie signing this client in.
	assert.Empty(t, rr.Result().Cookies())
}

func TestAuthHandler_LoginPSP_POST_Success(t *testing.T) {
	var got wire.FLAPSignonFrame
	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				got = inFrame
				return successfulLoginBlock(), nil
			},
		},
		Logger: slog.Default(),
	}

	form := url.Values{}
	form.Set("loginId", "testuser")
	form.Set("password", "secret")
	form.Set("devId", "dev1")
	form.Set("succUrl", "http://localhost:8000/")
	req := httptest.NewRequest(http.MethodPost, "/_cqr/login/login.psp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.LoginPSP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "http://localhost:8000/", rr.Header().Get("Location"))

	set := make(map[string]*http.Cookie)
	for _, c := range rr.Result().Cookies() {
		set[c.Name] = c
	}

	// The cookie carries the BOS token from the login response, unchanged.
	tokenCookie := set[bosTokenCookie]
	if assert.NotNil(t, tokenCookie) {
		assert.True(t, tokenCookie.HttpOnly)
		raw, err := base64.URLEncoding.DecodeString(tokenCookie.Value)
		assert.NoError(t, err)
		assert.Equal(t, loginBlockCookie, raw)
		// It outlives the redirect but little else.
		assert.Equal(t, int(bosTokenTTL.Seconds()), tokenCookie.MaxAge)
	}

	for _, name := range []string{"RSP_USER", "RSP_LOCAL", "localAuthUser"} {
		assert.NotContains(t, set, name)
	}

	// The devId names the client on the resulting session.
	clientID, ok := got.String(wire.LoginTLVTagsClientIdentity)
	assert.True(t, ok, "signon frame should carry a client identity")
	assert.Equal(t, "dev1", clientID)
}

func TestAuthHandler_LoginPSP_POST_ServiceErrors(t *testing.T) {
	tests := []struct {
		name      string
		flapLogin func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error)
	}{
		{
			name: "LoginResponseHasNoCookie",
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				return blockWithoutCookie(), nil
			},
		},
		{
			name: "AuthServiceUnreachable",
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				return wire.TLVRestBlock{}, errors.New("boom")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &AuthHandler{
				AuthService: &testAuthService{flapLogin: tt.flapLogin},
				Logger:      slog.Default(),
			}

			form := url.Values{}
			form.Set("loginId", "testuser")
			form.Set("password", "secret")
			req := httptest.NewRequest(http.MethodPost, "/_cqr/login/login.psp", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			handler.LoginPSP(rr, req)

			// A broken auth service must not read as a mistyped password.
			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.NotContains(t, rr.Body.String(), "Invalid screen name or password")
			assert.Empty(t, rr.Result().Cookies())
		})
	}
}

func TestAuthHandler_LoginPSP_POST_InvalidCredentials(t *testing.T) {
	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				return failedLoginBlock(), nil
			},
		},
		Logger: slog.Default(),
	}

	form := url.Values{}
	form.Set("loginId", "testuser")
	form.Set("password", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/_cqr/login/login.psp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.LoginPSP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid screen name or password")
}

func TestDefaultLoginSuccURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://ras.dev/_cqr/login/login.psp", nil)
	assert.Equal(t, "http://ras.dev/", defaultLoginSuccURL(req))

	// TLS terminated upstream, so the scheme only survives in the header.
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.Equal(t, "https://ras.dev/", defaultLoginSuccURL(req))
}

func TestSafeLoginRedirectURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/_cqr/login/login.psp", nil)

	assert.Equal(t, "http://localhost:8000/", safeLoginRedirectURL(req, "http://localhost:8000/"))
	assert.Equal(t, "http://localhost/", safeLoginRedirectURL(req, "http://evil.example/"))
}
