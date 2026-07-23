package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// tightRateLimitClasses returns rate classes scaled down so tests run fast.
//
// OSCAR's moving average tracks the interval between requests in milliseconds,
// seeded at MaxLevel, and each back-to-back request halves it at WindowSize 2.
// So from 200 the sequence is 100 (clear), 50 (limited), 25, 12, 6 — the second
// request trips the limit, and none of the first five fall below the disconnect
// threshold. Recovering past ClearLevel takes a ~150ms pause rather than the
// several seconds the production classes would need.
func tightRateLimitClasses() wire.RateLimitClasses {
	var classes [5]wire.RateClass
	for i := range classes {
		classes[i] = wire.RateClass{
			ID:              wire.RateLimitClassID(i + 1),
			WindowSize:      2,
			ClearLevel:      100,
			AlertLevel:      80,
			LimitLevel:      70,
			DisconnectLevel: 2,
			MaxLevel:        200,
		}
	}
	return wire.NewRateLimitClasses(classes)
}

// newTestWebAPISession builds a WebAPI session backed by a real OSCAR session
// with rate limit state initialized, mirroring what RegisterBOSSession does at
// startSession time.
func newTestWebAPISession(t *testing.T, classes wire.RateLimitClasses) *state.WebAPISession {
	t.Helper()

	instance := state.NewSession().AddInstance()
	instance.Session().SetIdentScreenName(state.NewIdentScreenName("me"))
	instance.Session().SetDisplayScreenName("me")
	instance.Session().SetRateClasses(time.Now(), classes)

	return &state.WebAPISession{
		AimSID:       "aimsid-1",
		ScreenName:   "me",
		OSCARSession: instance,
		EventQueue:   types.NewEventQueue(10),
	}
}

func newTestRateLimitMiddleware() *RateLimitMiddleware {
	return NewRateLimitMiddleware(wire.DefaultSNACRateLimits(), slog.New(slog.DiscardHandler))
}

// rateLimitEventStatuses returns the status string of every rateLimit event
// queued on the session, in order.
func rateLimitEventStatuses(t *testing.T, session *state.WebAPISession) []string {
	t.Helper()

	var statuses []string
	for _, event := range session.EventQueue.GetAllEvents() {
		if event.Type != types.EventTypeRateLimit {
			continue
		}
		payload, ok := event.Data.(types.RateLimitEvent)
		if !assert.True(t, ok, "rateLimit event carried %T", event.Data) {
			continue
		}
		if assert.Len(t, payload.Classes, 1) {
			statuses = append(statuses, payload.Classes[0].Status)
		}
	}
	return statuses
}

// assertRateLimited checks that a response is the Web API's rate limit
// rejection: HTTP 200 at the transport level so the client parses the body,
// with envelope code 430 carrying the rejection inside.
func assertRateLimited(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "5", rec.Header().Get("Retry-After"))

	var envelope struct {
		Response struct {
			StatusCode int    `json:"statusCode"`
			StatusText string `json:"statusText"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.Equal(t, rateLimitStatusCode, envelope.Response.StatusCode)
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
		// wantEvents are the rateLimit event statuses pushed to the session
		wantEvents []string
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
			// clear -> limit on the second request; the rest stay limited and
			// so push nothing further.
			wantEvents: []string{"limit"},
		},
		{
			name:      "sustained abuse escalates to disconnect",
			foodGroup: wire.ICBM,
			subGroup:  wire.ICBMChannelMsgToHost,
			// the 7th request drives the average below DisconnectLevel
			requests:  7,
			wantCalls: 1,
			// EvaluateRateLimit closes the session on disconnect, so the event
			// is best-effort; it is queued but the client may never fetch it.
			wantEvents: []string{"limit", "disconnect"},
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
				func(w http.ResponseWriter, r *http.Request, s *state.WebAPISession) {
					calls++
					w.WriteHeader(http.StatusOK)
				})

			var last *httptest.ResponseRecorder
			for range tt.requests {
				last = httptest.NewRecorder()
				handler(last, httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)
			}

			assert.Equal(t, tt.wantCalls, calls)
			assert.Equal(t, tt.wantEvents, rateLimitEventStatuses(t, session))

			if tt.wantCalls < tt.requests {
				assertRateLimited(t, last)
			} else {
				assert.Equal(t, http.StatusOK, last.Code)
			}
		})
	}
}

// The client only dismisses its rate limit alert when it receives a "clear"
// event, and only pushes on a transition, so a recovering session must produce
// exactly one clear.
func TestRateLimitMiddleware_OSCAR_pushesClearOnRecovery(t *testing.T) {
	session := newTestWebAPISession(t, tightRateLimitClasses())
	middleware := newTestRateLimitMiddleware()

	handler := middleware.OSCAR(wire.ICBM, wire.ICBMChannelMsgToHost)(
		func(w http.ResponseWriter, r *http.Request, s *state.WebAPISession) {})

	// Trip the limit.
	for range 3 {
		handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)
	}
	assert.Equal(t, []string{"limit"}, rateLimitEventStatuses(t, session))

	// Let the moving average recover past ClearLevel. See tightRateLimitClasses
	// for why this is a short wait rather than a stubbed clock.
	time.Sleep(250 * time.Millisecond)

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"limit", "clear"}, rateLimitEventStatuses(t, session))
}

// A session that trips the limit and then goes idle must still be told it
// recovered: the fetchEvents poll carries the clear even though no charged
// request arrives to recompute the status.
func TestRateLimitMiddleware_RecoverOnPoll(t *testing.T) {
	session := newTestWebAPISession(t, tightRateLimitClasses())
	middleware := newTestRateLimitMiddleware()

	oscar := middleware.OSCAR(wire.ICBM, wire.ICBMChannelMsgToHost)(
		func(w http.ResponseWriter, r *http.Request, s *state.WebAPISession) {})

	// Trip the limit.
	for range 3 {
		oscar(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)
	}
	assert.Equal(t, []string{"limit"}, rateLimitEventStatuses(t, session))

	// Let the moving average recover past ClearLevel without sending anything.
	// See tightRateLimitClasses for why this is a short wait, not a stubbed clock.
	time.Sleep(250 * time.Millisecond)

	calls := 0
	poll := middleware.RecoverOnPoll(func(w http.ResponseWriter, r *http.Request, s *state.WebAPISession) {
		calls++
	})

	// The poll surfaces the clear and still serves the handler.
	poll(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/aim/fetchEvents", nil), session)
	assert.Equal(t, 1, calls)
	assert.Equal(t, []string{"limit", "clear"}, rateLimitEventStatuses(t, session))

	// A second poll after recovery pushes nothing further.
	poll(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/aim/fetchEvents", nil), session)
	assert.Equal(t, 2, calls)
	assert.Equal(t, []string{"limit", "clear"}, rateLimitEventStatuses(t, session))
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
			wantBody:        `{"response":{"statusCode":430,"statusText":"rate limit exceeded"}}`,
			wantContentType: "application/json",
		},
		{
			name:            "JSONP callback",
			query:           "?c=myCallback",
			wantCode:        http.StatusOK,
			wantBody:        `myCallback({"response":{"statusCode":430,"statusText":"rate limit exceeded"}});`,
			wantContentType: "application/javascript",
		},
		{
			// The client correlates a JSONP reply solely by response.requestId,
			// so the request's "r" param must be echoed back or the request hangs.
			name:            "JSONP callback echoes requestId",
			query:           "?c=myCallback&r=42",
			wantCode:        http.StatusOK,
			wantBody:        `myCallback({"response":{"statusCode":430,"statusText":"rate limit exceeded","requestId":"42"}});`,
			wantContentType: "application/javascript",
		},
		{
			// Parens would let the callback name inject script; SendResponse
			// rejects the malformed callback rather than reflecting it.
			name:     "invalid JSONP callback is rejected",
			query:    "?c=alert(1)",
			wantCode: http.StatusBadRequest,
			// sendJSONError encodes with json.Encoder, which appends a newline.
			wantBody:        "{\"response\":{\"statusCode\":400,\"statusText\":\"invalid callback parameter\"}}\n",
			wantContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM"+tt.query, nil))

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
		newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM?f=xml", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "5", rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "xml")
		body := rec.Body.String()
		assert.Contains(t, body, "<statusCode>430</statusCode>")
		assert.Contains(t, body, "rate limit exceeded")
	})

	t.Run("f=amf", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM?f=amf", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "5", rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "amf")
		assert.NotEmpty(t, rec.Body.Bytes())
	})

	t.Run("Accept amf", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/im/sendIM", nil)
		req.Header.Set("Accept", "application/x-amf")
		newTestRateLimitMiddleware().sendRateLimited(rec, req)

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
