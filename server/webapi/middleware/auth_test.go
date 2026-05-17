package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
)

type stubValidator struct {
	key *state.WebAPIKey
	err error
}

func (s stubValidator) GetAPIKeyByDevKey(ctx context.Context, devKey string) (*state.WebAPIKey, error) {
	return s.key, s.err
}

func (s stubValidator) UpdateLastUsed(ctx context.Context, devKey string) error {
	return nil
}

func newMiddleware(v APIKeyValidator) *AuthMiddleware {
	return NewAuthMiddleware(v, slog.Default())
}

// TestAuthenticate_MissingKey_FormatAware verifies that the auth middleware
// honors the `f=xml` query parameter when rejecting a request that's missing
// the `k` API key parameter — and that both formats use the canonical
// {response:{statusCode,statusText}} envelope.
func TestAuthenticate_MissingKey_FormatAware(t *testing.T) {
	mw := newMiddleware(stubValidator{err: state.ErrNoAPIKey})

	t.Run("xml format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/aim/startOSCARSession?f=xml", nil)
		rr := httptest.NewRecorder()

		mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("middleware should have short-circuited")
		})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Header().Get("Content-Type"), "xml")
		body := rr.Body.String()
		assert.Contains(t, body, `<?xml version="1.0"`)
		assert.Contains(t, body, "<statusCode>400</statusCode>")
		assert.Contains(t, body, "<statusText>required parameter &#39;k&#39; is missing</statusText>")
	})

	t.Run("json format (default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/aim/startOSCARSession", nil)
		rr := httptest.NewRecorder()

		mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("middleware should have short-circuited")
		})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
		body := strings.TrimSpace(rr.Body.String())
		assert.Contains(t, body, `"statusCode":400`)
		assert.Contains(t, body, `"statusText":"required parameter 'k' is missing"`)
		// Confirm we use the new {response:{...}} envelope, not the legacy {error,code} shape.
		assert.Contains(t, body, `"response":`)
		assert.NotContains(t, body, `"error":`)
		assert.NotContains(t, body, `"code":`)
	})
}

// TestAuthenticate_InvalidKey_FormatAware covers the second-most-common error
// path: middleware rejects an unknown API key. ICQ 7.x hits this with its
// hardcoded devId — and needs an XML response to parse the failure.
func TestAuthenticate_InvalidKey_FormatAware(t *testing.T) {
	mw := newMiddleware(stubValidator{err: state.ErrNoAPIKey})

	req := httptest.NewRequest("GET", "/aim/startOSCARSession?k=bogus&f=xml", nil)
	rr := httptest.NewRecorder()

	mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("middleware should have short-circuited")
	})).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "xml")
	body := rr.Body.String()
	assert.Contains(t, body, "<statusCode>403</statusCode>")
	assert.Contains(t, body, "<statusText>invalid API key</statusText>")
}
