package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

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

	// SSO cookies are expired so the browser is logged out.
	cleared := map[string]bool{}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}
	for _, name := range []string{"RSP_USER", "RSP_LOCAL", "localAuthUser", "oldAimToken"} {
		assert.True(t, cleared[name], "expected %s cookie to be cleared", name)
	}
}

func TestAuthHandler_LoginPSP_POST_Success(t *testing.T) {
	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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

	cookies := rr.Result().Cookies()
	names := make(map[string]string, len(cookies))
	for _, c := range cookies {
		names[c.Name] = c.Value
	}
	assert.Equal(t, "testuser", names["RSP_USER"])
	assert.Equal(t, "testuser", names["RSP_LOCAL"])
	assert.Equal(t, "testuser||testuser", names["localAuthUser"])
}

func TestAuthHandler_LoginPSP_POST_InvalidCredentials(t *testing.T) {
	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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

func TestSafeLoginRedirectURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/_cqr/login/login.psp", nil)

	assert.Equal(t, "http://localhost:8000/", safeLoginRedirectURL(req, "http://localhost:8000/"))
	assert.Equal(t, "http://localhost/", safeLoginRedirectURL(req, "http://evil.example/"))
}
