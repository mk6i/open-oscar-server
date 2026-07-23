package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// rateLimitStatusCode is the Web AIM API envelope code for a rate-limited
// request. The AIM web client swallows 430 on the IM path so that the rateLimit
// event owns the user-facing message instead of a generic send failure alert.
const rateLimitStatusCode = 430

// rateLimitRetryAfter is the Retry-After hint sent with a rate-limited response.
// The OSCAR limiter tracks a moving average rather than a fixed window, so there
// is no exact time at which the limit clears; this is a conservative nudge.
const rateLimitRetryAfter = 5 * time.Second

// SessionHandlerFunc is the session-aware handler shape that
// AuthMiddleware.RequireSession invokes once it has resolved an aimsid.
type SessionHandlerFunc = func(http.ResponseWriter, *http.Request, *state.WebAPISession)

// RateLimitMiddleware enforces OSCAR rate limits on Web API routes that reach a
// food group.
//
// Such routes are limited by OSCAR itself: OSCAR charges the session's shared
// per-rate-class budget, the same budget a native OSCAR or TOC client spends, so
// a user cannot dodge a limit by switching transports. Routes that reach no food
// group are not limited here; edge rate limiting (a reverse proxy keyed by client
// IP) is expected to cover the unauthenticated login/asset endpoints and the
// authenticated bookkeeping ones.
//
// It lives alongside the handlers (rather than in the middleware package) so that
// its rejection can be encoded through the same SendResponse path the handlers
// use, honoring the request's JSON/JSONP/XML/AMF format.
type RateLimitMiddleware struct {
	snacRateLimits wire.SNACRateLimits
	logger         *slog.Logger
}

// NewRateLimitMiddleware creates a RateLimitMiddleware. snacRateLimits is the
// same SNAC-to-rate-class mapping the OSCAR and TOC servers use.
func NewRateLimitMiddleware(snacRateLimits wire.SNACRateLimits, logger *slog.Logger) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		snacRateLimits: snacRateLimits,
		logger:         logger,
	}
}

// OSCAR returns middleware that charges one unit against the OSCAR rate class
// mapped to (foodGroup, subGroup) before invoking the wrapped handler. It is the
// HTTP counterpart of the TOC server's per-command rate check.
//
// A SNAC with no rate class mapping is allowed through, since refusing traffic
// because the server's own table is incomplete would be worse than not limiting
// it.
func (l *RateLimitMiddleware) OSCAR(foodGroup uint16, subGroup uint16) func(SessionHandlerFunc) SessionHandlerFunc {
	return func(next SessionHandlerFunc) SessionHandlerFunc {
		return func(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
			ctx := r.Context()

			rateClassID, ok := l.snacRateLimits.RateClassLookup(foodGroup, subGroup)
			if !ok {
				l.logger.ErrorContext(ctx, "rate limit not found, allowing request through",
					"foodgroup", wire.FoodGroupName(foodGroup),
					"subgroup", wire.SubGroupName(foodGroup, subGroup))
				next(w, r, session)
				return
			}

			sess := session.OSCARSession.Session()
			prev := sess.RateLimitStates()[rateClassID-1].CurrentStatus
			status := sess.EvaluateRateLimit(time.Now(), rateClassID)

			if status != prev {
				l.pushRateLimitEvent(session, rateClassID, status)
			}

			// Disconnect is rejected alongside Limited: EvaluateRateLimit has
			// already closed the account's OSCAR session by the time it returns,
			// so there is nothing left for the handler to act on. That close also
			// invalidates the aimsid (GetSession stops resolving a session whose
			// OSCAR instance is closed), so every subsequent request is turned
			// away at RequireSession rather than reaching here again.
			if status == wire.RateLimitStatusLimited || status == wire.RateLimitStatusDisconnect {
				l.logger.DebugContext(ctx, "(webapi) rate limit exceeded, dropping request",
					"foodgroup", wire.FoodGroupName(foodGroup),
					"subgroup", wire.SubGroupName(foodGroup, subGroup),
					"status", rateLimitStatusName(status))
				l.sendRateLimited(w, r)
				return
			}

			next(w, r, session)
		}
	}
}

// RecoverOnPoll re-evaluates rate limit recovery before serving a long poll,
// pushing a rateLimit transition — in practice the "clear" that dismisses the
// client's alert — for any class that has recovered since the session's last
// charged request.
//
// It exists because OSCAR only recomputes rate limit status when a charged
// request arrives (see OSCAR), so a session that trips the limit and then goes
// idle would never learn it recovered and the client's rate limit alert, which is
// sticky until a "clear" arrives, would linger. fetchEvents is the natural
// carrier: the client polls it continuously, so running recovery here surfaces
// the clear within a poll cycle without the user having to send anything. The
// push happens before next() so a freshly cleared status rides out on this poll's
// response rather than the following one.
func (l *RateLimitMiddleware) RecoverOnPoll(next SessionHandlerFunc) SessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
		sess := session.OSCARSession.Session()
		for _, rc := range sess.RecoverRateLimits(time.Now()) {
			l.pushRateLimitEvent(session, rc.ID, rc.CurrentStatus)
		}
		next(w, r, session)
	}
}

// pushRateLimitEvent notifies the client that its rate limit status changed so
// it can show (or dismiss) the rate limit alert. The disconnect push is
// best-effort: EvaluateRateLimit closes the session before the queue drains.
func (l *RateLimitMiddleware) pushRateLimitEvent(session *state.WebAPISession, classID wire.RateLimitClassID, status wire.RateLimitStatus) {
	name := rateLimitStatusName(status)
	if name == "" {
		return
	}
	session.EventQueue.Push(types.EventTypeRateLimit, types.RateLimitEvent{
		Classes: []types.RateLimitClass{
			{
				ID:     int(classID),
				Status: name,
			},
		},
	})
}

// rateLimitStatusName maps an OSCAR rate limit status onto the status string the
// web client switches on. It returns "" for a status the client does not know.
func rateLimitStatusName(status wire.RateLimitStatus) string {
	switch status {
	case wire.RateLimitStatusClear:
		return "clear"
	case wire.RateLimitStatusAlert:
		return "warn"
	case wire.RateLimitStatusLimited:
		return "limit"
	case wire.RateLimitStatusDisconnect:
		return "disconnect"
	default:
		return ""
	}
}

// sendRateLimited writes a rate limit rejection. The transport status is 200 and
// the rejection lives entirely in the Web AIM API envelope's own rate limit code.
//
// The transport status is deliberately not 429: the AIM client's WIM request layer
// (XhrManager) and its Fetcher only parse the response body on a 2xx. A non-2xx is
// routed to their error handlers, which synthesize a generic "request failed"
// result and never look at the body, so the envelope's 430 — which the client
// swallows on the IM path in favor of the rateLimit event — would go unread and the
// user would see a generic send failure instead.
//
// The body is encoded via SendResponse, so it honors the request's format
// (JSON/JSONP/XML/AMF) and echoes the request id into response.requestId — which
// the JSONP fallback needs to correlate the reply, or its UI hangs — exactly as a
// normal handler response would.
func (l *RateLimitMiddleware) sendRateLimited(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rateLimitRetryAfter.Seconds())))

	resp := BaseResponse{}
	resp.Response.StatusCode = rateLimitStatusCode
	resp.Response.StatusText = "rate limit exceeded"

	SendResponse(w, r, resp, l.logger)
}
