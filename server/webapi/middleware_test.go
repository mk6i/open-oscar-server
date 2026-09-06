package webapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func newTestMiddleware() *AuthMiddleware {
	return NewAuthMiddleware(discardLogger())
}

// The Web AIM client permanently downgrades to JSONP when a cross-origin
// response arrives without Access-Control-Allow-Origin: it reads the response
// the browser blocked as a status-0 empty one, and aim.client.js onXhrFailed_
// clears its useXhr flag and never sets it again. One uncovered response is
// enough to latch that, so the CORS layer wraps the whole mux and every layer
// below it — routed, rejected, and unrouted alike — answers with the header.
//
// These cases go through the handler the listener actually serves, so they
// cover the configured allowlist end to end rather than the options struct.
func TestServer_CORS(t *testing.T) {
	// What most cases are configured with; a case overrides it to exercise the
	// wildcard and empty modes.
	defaultOrigins := []string{"https://ras.dev", "http://ras.dev", "http://localhost:8000"}

	tests := []struct {
		name string
		// nil means defaultOrigins.
		allowedOrigins []string
		method         string
		path           string
		origin         string
		// Setting reqMethod makes the request a preflight.
		reqMethod   string
		reqHeaders  string
		wantStatus  int
		wantOrigin  string
		wantMethods string
		wantHeaders string
		wantMaxAge  string
	}{
		// Each layer that can produce a response must carry the header.
		{
			name: "public auth endpoint", method: http.MethodPost, path: "/auth/clientLogin",
			origin: "https://ras.dev", wantStatus: http.StatusBadRequest, wantOrigin: "https://ras.dev",
		},
		{
			name: "session rejection", method: http.MethodGet, path: "/aim/fetchEvents",
			origin: "https://ras.dev", wantStatus: http.StatusBadRequest, wantOrigin: "https://ras.dev",
		},
		{
			name: "stub route", method: http.MethodGet, path: "/aim/getData",
			origin: "https://ras.dev", wantStatus: http.StatusOK, wantOrigin: "https://ras.dev",
		},
		{
			name: "unrouted 404", method: http.MethodGet, path: "/service/getAttributes/nope",
			origin: "https://ras.dev", wantStatus: http.StatusNotFound, wantOrigin: "https://ras.dev",
		},

		// An origin is the scheme, host and port together, so the allowlist
		// admits exactly what it names and nothing adjacent.
		{
			name: "allowed origin, other scheme", method: http.MethodGet, path: "/aim/getData",
			origin: "http://ras.dev", wantStatus: http.StatusOK, wantOrigin: "http://ras.dev",
		},
		{
			name: "allowed origin, other port", method: http.MethodGet, path: "/aim/getData",
			origin: "http://localhost:8000", wantStatus: http.StatusOK, wantOrigin: "http://localhost:8000",
		},
		{
			name: "different port is a different origin", method: http.MethodGet, path: "/aim/getData",
			origin: "http://localhost", wantStatus: http.StatusOK,
		},
		{
			name: "different scheme is a different origin", method: http.MethodGet, path: "/aim/getData",
			origin: "https://localhost:8000", wantStatus: http.StatusOK,
		},
		{
			// The suffix a naive HasSuffix check would wave through.
			name: "attacker-registrable suffix", method: http.MethodGet, path: "/aim/getData",
			origin: "https://ras.dev.evil.example", wantStatus: http.StatusOK,
		},
		{
			name: "unlisted origin", method: http.MethodGet, path: "/aim/getData",
			origin: "http://evil.example", wantStatus: http.StatusOK,
		},
		{
			// A same-origin request sends no Origin, so there is nothing to allow.
			name: "no origin header", method: http.MethodGet, path: "/aim/getData",
			wantStatus: http.StatusOK,
		},

		// A preflight is answered by the CORS layer alone: it reaches no route,
		// so it needs no aimsid and 404s on no path.
		{
			name: "preflight GET", method: http.MethodOptions, path: "/im/sendIM",
			origin: "https://ras.dev", reqMethod: http.MethodGet,
			wantStatus: http.StatusNoContent, wantOrigin: "https://ras.dev",
			wantMethods: http.MethodGet, wantMaxAge: "3600",
		},
		{
			// Lowercase, as the Fetch spec requires a browser to send it: the
			// CORS layer matches these names byte for byte.
			name: "preflight POST with a header", method: http.MethodOptions, path: "/im/sendIM",
			origin: "https://ras.dev", reqMethod: http.MethodPost, reqHeaders: "content-type",
			wantStatus: http.StatusNoContent, wantOrigin: "https://ras.dev",
			wantMethods: http.MethodPost, wantHeaders: "content-type", wantMaxAge: "3600",
		},
		{
			name: "preflight on an unrouted path", method: http.MethodOptions, path: "/totally/unrouted",
			origin: "https://ras.dev", reqMethod: http.MethodPost,
			wantStatus: http.StatusNoContent, wantOrigin: "https://ras.dev",
			wantMethods: http.MethodPost, wantMaxAge: "3600",
		},
		{
			// Every route is a GET or a POST, so anything else is refused with
			// no CORS headers and the browser never sends the real request.
			name: "preflight PUT refused", method: http.MethodOptions, path: "/im/sendIM",
			origin: "https://ras.dev", reqMethod: http.MethodPut, wantStatus: http.StatusNoContent,
		},
		{
			name: "preflight DELETE refused", method: http.MethodOptions, path: "/im/sendIM",
			origin: "https://ras.dev", reqMethod: http.MethodDelete, wantStatus: http.StatusNoContent,
		},
		{
			name: "preflight with an unlisted header refused", method: http.MethodOptions, path: "/im/sendIM",
			origin: "https://ras.dev", reqMethod: http.MethodGet, reqHeaders: "x-not-allowed",
			wantStatus: http.StatusNoContent,
		},

		// The configured modes.
		{
			name: "wildcard allows any origin", allowedOrigins: []string{"*"},
			method: http.MethodGet, path: "/aim/getData", origin: "http://never.seen.example",
			wantStatus: http.StatusOK, wantOrigin: "http://never.seen.example",
		},
		{
			// envconfig splits on commas without trimming.
			name: "entries are trimmed", allowedOrigins: []string{" https://ras.dev ", "  "},
			method: http.MethodGet, path: "/aim/getData", origin: "https://ras.dev",
			wantStatus: http.StatusOK, wantOrigin: "https://ras.dev",
		},
		{
			// An unset or empty value means "any origin", same as a lone *.
			name: "empty allowlist allows any origin", allowedOrigins: []string{"  "},
			method: http.MethodGet, path: "/aim/getData", origin: "http://never.seen.example",
			wantStatus: http.StatusOK, wantOrigin: "http://never.seen.example",
		},
		{
			name: "unset allowlist allows any origin", allowedOrigins: []string{},
			method: http.MethodGet, path: "/aim/getData", origin: "http://never.seen.example",
			wantStatus: http.StatusOK, wantOrigin: "http://never.seen.example",
		},
		{
			// A wildcard may also stand in for the port.
			name: "port wildcard matches any port", allowedOrigins: []string{"http://localhost:*"},
			method: http.MethodGet, path: "/aim/getData", origin: "http://localhost:9999",
			wantStatus: http.StatusOK, wantOrigin: "http://localhost:9999",
		},
		{
			name: "port wildcard does not match another host", allowedOrigins: []string{"http://localhost:*"},
			method: http.MethodGet, path: "/aim/getData", origin: "http://evil.example:9999",
			wantStatus: http.StatusOK,
		},
		{
			// One wildcard per entry, standing in for 0 or more characters.
			name: "subdomain wildcard matches", allowedOrigins: []string{"https://*.example.com"},
			method: http.MethodGet, path: "/aim/getData", origin: "https://web.example.com",
			wantStatus: http.StatusOK, wantOrigin: "https://web.example.com",
		},
		{
			name: "subdomain wildcard does not match another domain", allowedOrigins: []string{"https://*.example.com"},
			method: http.MethodGet, path: "/aim/getData", origin: "https://web.evil.example",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origins := tt.allowedOrigins
			if origins == nil {
				origins = defaultOrigins
			}
			h := testServerHandler(t, origins)

			r := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			if tt.reqMethod != "" {
				r.Header.Set("Access-Control-Request-Method", tt.reqMethod)
			}
			if tt.reqHeaders != "" {
				r.Header.Set("Access-Control-Request-Headers", tt.reqHeaders)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			assert.Equal(t, tt.wantStatus, w.Code)
			// An allowed origin is echoed back rather than answered with "*";
			// a rejected one gets no header at all, so the browser blocks it.
			assert.Equal(t, tt.wantOrigin, w.Header().Get("Access-Control-Allow-Origin"))
			assert.Contains(t, w.Header().Get("Vary"), "Origin")

			// Credentials are not enabled, so the browser is never told to send them.
			assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))

			// These answer a preflight and mean nothing on any other response.
			assert.Equal(t, tt.wantMethods, w.Header().Get("Access-Control-Allow-Methods"))
			assert.Equal(t, tt.wantHeaders, strings.ToLower(w.Header().Get("Access-Control-Allow-Headers")))
			assert.Equal(t, tt.wantMaxAge, w.Header().Get("Access-Control-Max-Age"))
		})
	}
}

// testServerHandler builds the handler the listener actually serves, so the CORS
// layer under test is the one NewServer configures.
func testServerHandler(t *testing.T, allowedOrigins []string) http.Handler {
	t.Helper()
	handler := Handler{
		Logger:         slog.Default(),
		AllowedOrigins: allowedOrigins,
	}
	srv := NewServer([]string{"127.0.0.1:0"}, slog.Default(), handler, NewSessionManager())
	require.NotEmpty(t, srv.servers)
	return srv.servers[0].Handler
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRequireSession_ReadsAimsidFromPOSTBody(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
	}{
		{
			name:        "declared form body",
			body:        "aimsid=abc&message=hello",
			contentType: "application/x-www-form-urlencoded",
		},
		{
			// No Content-Type announced; the request is form data all the same.
			name: "untyped form body",
			body: "aimsid=abc&message=hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMiddleware()
			reached := false
			h := m.RequireSession(okSessionResolver{},
				func(w http.ResponseWriter, r *http.Request, _ *Session) {
					reached = true
					assert.Equal(t, "hello", param(r, "message"))
					w.WriteHeader(http.StatusOK)
				})

			r := httptest.NewRequest(http.MethodPost, "/im/sendIM", strings.NewReader(tt.body))
			if tt.contentType != "" {
				r.Header.Set("Content-Type", tt.contentType)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			assert.True(t, reached, "request was rejected before reaching the handler")
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// The session layer's own rejections must be JSONP-wrapped too, otherwise a
// client already in JSONP mode gets a script-tag syntax error instead of the
// reason.
func TestAuthErrorsHonorJSONP(t *testing.T) {
	m := newTestMiddleware()

	t.Run("session error", func(t *testing.T) {
		h := m.RequireSession(&stubSessionResolver{}, func(http.ResponseWriter, *http.Request, *Session) {
			t.Fatal("handler should not run")
		})

		r := httptest.NewRequest(http.MethodGet, "/im/sendIM?c=_callbacks_._x&r=7", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		body := w.Body.String()
		assert.True(t, strings.HasPrefix(body, "_callbacks_._x("), "got %s", body)
		assert.True(t, strings.HasSuffix(body, ");"), "got %s", body)
		assert.Contains(t, body, `"statusCode":400`)
		assert.Contains(t, body, `"requestId":"7"`)
		// A 4xx would stop the browser executing the script tag.
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("without a callback the session error keeps its HTTP status", func(t *testing.T) {
		h := m.RequireSession(&stubSessionResolver{}, func(http.ResponseWriter, *http.Request, *Session) {
			t.Fatal("handler should not run")
		})

		r := httptest.NewRequest(http.MethodGet, "/im/sendIM", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "json")
	})
}

// An XML client cannot parse a JSON error, so it reports an unreadable response
// instead of the reason the session layer rejected it.
func TestAuthErrorsHonorXML(t *testing.T) {
	m := newTestMiddleware()
	h := m.RequireSession(&stubSessionResolver{}, func(http.ResponseWriter, *http.Request, *Session) {
		t.Fatal("handler should not run")
	})

	t.Run("format in the query string", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/aim/startOSCARSession?f=xml", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		assert.Contains(t, w.Header().Get("Content-Type"), "xml")
		assert.Contains(t, w.Body.String(), "<statusCode>400</statusCode>")
	})

	// A POST states the format in its body, the only place clientLogin sends it.
	t.Run("format in the POST body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/auth/clientLogin", strings.NewReader("s=testuser&f=xml"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		assert.Contains(t, w.Header().Get("Content-Type"), "xml")
		assert.Contains(t, w.Body.String(), "<statusCode>400</statusCode>")
	})

	// A client on the <script> transport needs executable JS back whatever "f"
	// says; XML there is a script load failure with no reason attached.
	t.Run("a callback outranks the format", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/aim/startOSCARSession?f=xml&c=cb&r=3", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		body := w.Body.String()
		assert.True(t, strings.HasPrefix(body, "cb("), "got %s", body)
		assert.Contains(t, body, `"statusCode":400`)
		assert.Contains(t, body, `"requestId":"3"`)
	})
}

// okSessionResolver always resolves, so RequireSession reaches the handler.
type okSessionResolver struct{}

func (okSessionResolver) GetSession(context.Context, string) (*Session, error) {
	return &Session{}, nil
}

func (okSessionResolver) TouchSession(context.Context, string) error { return nil }

// stubSessionResolver never resolves a session, so RequireSession always rejects.
type stubSessionResolver struct{}

func (stubSessionResolver) GetSession(context.Context, string) (*Session, error) {
	return nil, assert.AnError
}

func (stubSessionResolver) TouchSession(context.Context, string) error { return nil }

func newTestRateLimitMiddleware() *RateLimitMiddleware {
	return NewRateLimitMiddleware(wire.DefaultSNACRateLimits(), slog.New(slog.DiscardHandler))
}

// assertRateLimited checks that a response is the Web API's rate limit
// rejection: HTTP 200 at the transport level so the client parses the body,
// with envelope code 430 carrying the rejection inside. wantRetryAfter is the
// expected Retry-After header, "" for a rejection that carries none.
func assertRateLimited(t *testing.T, rec *httptest.ResponseRecorder, wantRetryAfter string) {
	t.Helper()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, wantRetryAfter, rec.Header().Get("Retry-After"))

	var envelope struct {
		Response struct {
			StatusCode int    `json:"statusCode"`
			StatusText string `json:"statusText"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.Equal(t, statusRateLimited, envelope.Response.StatusCode)
	assert.Equal(t, "rate limit exceeded", envelope.Response.StatusText)
}

func TestRateLimitMiddleware_OSCAR(t *testing.T) {
	tests := []struct {
		name string
		// foodGroup/subGroup passed to the middleware
		foodGroup uint16
		subGroup  uint16
		// requests is how many times the wrapped handler is invoked
		requests int
		// wantCalls is how many of those requests reach the handler
		wantCalls int
		// wantRetryAfter is the Retry-After header on the final rejection, "" for
		// a rejection that carries none
		wantRetryAfter string
	}{
		{
			name:      "first request is allowed",
			foodGroup: wire.ICBM,
			subGroup:  wire.ICBMChannelMsgToHost,
			requests:  1,
			wantCalls: 1,
		},
		{
			name:      "a burst trips the limit",
			foodGroup: wire.ICBM,
			subGroup:  wire.ICBMChannelMsgToHost,
			requests:  5,
			wantCalls: 1,
			// retryAfterFor rounds the sub-second wait these tight classes need
			// up to the minRetryAfter floor.
			wantRetryAfter: "1",
		},
		{
			name:      "sustained abuse escalates to disconnect",
			foodGroup: wire.ICBM,
			subGroup:  wire.ICBMChannelMsgToHost,
			// the 7th request drives the average below DisconnectLevel
			requests:  7,
			wantCalls: 1,
			// a disconnected session has no aimsid left to retry with
			wantRetryAfter: "",
		},
		{
			// A non-IM class is enforced the same way. The middleware only ever
			// rejects; notifying the client is the per-account monitor's job, and
			// it surfaces only the IM class to the alert.
			name:           "a non-IM class is still enforced",
			foodGroup:      wire.Feedbag,
			subGroup:       wire.FeedbagInsertItem,
			requests:       5,
			wantCalls:      1,
			wantRetryAfter: "1",
		},
		{
			name: "unmapped SNAC fails open",
			// 0xFFFF is not a food group, so no rate class maps to it
			foodGroup: 0xFFFF,
			subGroup:  0xFFFF,
			requests:  5,
			wantCalls: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newTestWebAPISession(t, tightRateLimitClasses())
			middleware := newTestRateLimitMiddleware()

			calls := 0
			handler := middleware.OSCAR(tt.foodGroup, tt.subGroup)(
				func(w http.ResponseWriter, r *http.Request, s *Session) {
					calls++
					w.WriteHeader(http.StatusOK)
				})

			var last *httptest.ResponseRecorder
			for range tt.requests {
				last = httptest.NewRecorder()
				handler(last, httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)
			}

			assert.Equal(t, tt.wantCalls, calls)
			// The middleware enforces the limit but never pushes rate limit
			// events; that is the per-account monitor's responsibility.
			assert.Empty(t, rateLimitEventStatuses(t, session))

			if tt.wantCalls < tt.requests {
				assertRateLimited(t, last, tt.wantRetryAfter)
			} else {
				assert.Equal(t, http.StatusOK, last.Code)
			}
		})
	}
}

// Retry-After must name a wait that actually clears the limit. A rejected
// request is still charged, so a client retrying on the advertised interval
// drives the moving average toward that interval: a hint below the class's
// ClearLevel holds the average under the bar and the client stays limited
// forever.
func TestRetryAfterFor_clearsTheLimit(t *testing.T) {
	classes := wire.DefaultRateLimitClasses()

	for _, class := range classes.All() {
		t.Run(fmt.Sprintf("class %d", class.ID), func(t *testing.T) {
			sess := state.NewSession()
			sess.AddInstance()

			now := time.Now()
			sess.SetRateClasses(now, classes)

			// Burst until the class trips.
			var status wire.RateLimitStatus
			for status != wire.RateLimitStatusLimited {
				now = now.Add(100 * time.Millisecond)
				status = sess.EvaluateRateLimit(now, class.ID)
				require.NotEqual(t, wire.RateLimitStatusDisconnect, status, "burst escalated past limited")
			}

			// Wait exactly as long as the rejection advertised, then retry.
			retryAfter := retryAfterFor(sess.RateLimitStates()[class.ID-1])
			now = now.Add(retryAfter)

			assert.Equal(t, wire.RateLimitStatusClear, sess.EvaluateRateLimit(now, class.ID),
				"honoring a Retry-After of %s did not clear the limit", retryAfter)
		})
	}
}

// The rejection advertises the wait computed for the class it charged, not a
// flat one.
func TestRateLimitMiddleware_OSCAR_retryAfterMatchesClass(t *testing.T) {
	session := newTestWebAPISession(t, wire.DefaultRateLimitClasses())
	middleware := newTestRateLimitMiddleware()

	handler := middleware.OSCAR(wire.ICBM, wire.ICBMChannelMsgToHost)(
		func(w http.ResponseWriter, r *http.Request, s *Session) {})

	classID, ok := wire.DefaultSNACRateLimits().RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	require.True(t, ok)

	// Back-to-back requests trip the limit; keep going until one is rejected.
	var rec *httptest.ResponseRecorder
	for range 20 {
		rec = httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)
		if rec.Header().Get("Retry-After") != "" {
			break
		}
	}

	want := retryAfterFor(session.OSCARSession.Session().RateLimitStates()[classID-1])
	assert.Equal(t, fmt.Sprintf("%d", int(want.Seconds())), rec.Header().Get("Retry-After"))
	// The production IM class clears at 5100ms, so the wait is necessarily
	// longer than the flat 5s hint this replaced.
	assert.Greater(t, want, 5*time.Second)
}

// The rejection is encoded in whatever format the request negotiates, via the
// same SendResponse path a normal handler uses.
func TestRateLimitMiddleware_sendRateLimited(t *testing.T) {
	tests := []struct {
		name string
		// query is appended to the request URL
		query string
		// wantCode is the transport status
		wantCode int
		// wantBody is the exact response body
		wantBody string
		// wantContentType is a substring of the Content-Type header
		wantContentType string
	}{
		{
			name:            "plain JSON",
			query:           "",
			wantCode:        http.StatusOK,
			wantBody:        `{"response":{"statusCode":430,"statusText":"rate limit exceeded","data":{}}}`,
			wantContentType: "application/json",
		},
		{
			name:            "JSONP callback",
			query:           "?c=myCallback",
			wantCode:        http.StatusOK,
			wantBody:        `myCallback({"response":{"statusCode":430,"statusText":"rate limit exceeded","data":{}}});`,
			wantContentType: "application/javascript",
		},
		{
			// The client correlates a JSONP reply solely by response.requestId,
			// so the request's "r" param must be echoed back or the request hangs.
			name:            "JSONP callback echoes requestId",
			query:           "?c=myCallback&r=42",
			wantCode:        http.StatusOK,
			wantBody:        `myCallback({"response":{"statusCode":430,"statusText":"rate limit exceeded","requestId":"42","data":{}}});`,
			wantContentType: "application/javascript",
		},
		{
			// Parens would let the callback name inject script; SendResponse
			// rejects the malformed callback rather than reflecting it.
			name:     "invalid JSONP callback is rejected",
			query:    "?c=alert(1)",
			wantCode: http.StatusBadRequest,
			// sendJSONError encodes with json.Encoder, which appends a newline.
			wantBody:        "{\"response\":{\"statusCode\":400,\"statusText\":\"invalid callback parameter\",\"data\":{}}}\n",
			wantContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM"+tt.query, nil), 5*time.Second)

			body, err := io.ReadAll(rec.Body)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantCode, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), tt.wantContentType)
			assert.Equal(t, tt.wantBody, string(body))
		})
	}
}

// A client asking for XML or AMF (via f= or the Accept header) still gets a
// parseable rejection envelope rather than JSON, since the rejection rides the
// same SendResponse path as a normal handler.
func TestRateLimitMiddleware_sendRateLimited_nonJSONFormats(t *testing.T) {
	t.Run("f=xml", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM?f=xml", nil), 5*time.Second)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "5", rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "xml")
		body := rec.Body.String()
		assert.Contains(t, body, "<statusCode>430</statusCode>")
		assert.Contains(t, body, "rate limit exceeded")
	})

	t.Run("f=amf", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM?f=amf", nil), 5*time.Second)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "5", rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "amf")
		assert.NotEmpty(t, rec.Body.Bytes())
	})

	t.Run("Accept amf", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/im/sendIM", nil)
		req.Header.Set("Accept", "application/x-amf")
		newTestRateLimitMiddleware().sendRateLimited(rec, req, 5*time.Second)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "amf")
		assert.NotEmpty(t, rec.Body.Bytes())
	})
}

func TestRateLimitStatusName(t *testing.T) {
	tests := []struct {
		name   string
		status wire.RateLimitStatus
		want   string
	}{
		{name: "clear", status: wire.RateLimitStatusClear, want: "clear"},
		{name: "alert maps to the client's warn", status: wire.RateLimitStatusAlert, want: "warn"},
		{name: "limited", status: wire.RateLimitStatusLimited, want: "limit"},
		{name: "disconnect", status: wire.RateLimitStatusDisconnect, want: "disconnect"},
		{name: "unknown status has no client equivalent", status: wire.RateLimitStatus(0), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rateLimitStatusName(tt.status))
		})
	}
}
