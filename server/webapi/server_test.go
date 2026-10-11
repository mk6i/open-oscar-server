package webapi

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Clients use the root URL as a connectivity check, so it must return a
// well-formed JSON envelope.
func TestGetHelloWorldHandlerReturnsEmptyEnvelope(t *testing.T) {
	h := Handler{Logger: slog.Default()}

	rr := httptest.NewRecorder()
	h.GetHelloWorldHandler(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`, rr.Body.String())
}
