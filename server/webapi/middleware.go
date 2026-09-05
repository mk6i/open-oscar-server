package webapi

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// AuthMiddleware provides session resolution and CORS handling for Web API
// endpoints.
type AuthMiddleware struct {
	Logger *slog.Logger
}

// NewAuthMiddleware creates a new authentication middleware instance.
func NewAuthMiddleware(logger *slog.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		Logger: logger,
	}
}

// RequireSession resolves the aimsid session and passes it to next. It rejects
// requests whose session is missing or expired with an auth error. On success it
// touches the session, sliding its expiry forward; this is the keepalive that
// holds a long-polling client's session open (see the session lifecycle timeline
// on state's Session manager).
//
// startSession is the only thing that creates a session and it always attaches an
// OSCAR session (anonymous guests are unsupported), so downstream handlers treat
// session.OSCARSession as non-nil.
func (m *AuthMiddleware) RequireSession(sm SessionResolver, next func(http.ResponseWriter, *http.Request, *Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aimsid := param(r, "aimsid")
		if aimsid == "" {
			SendError(w, r, http.StatusBadRequest, "missing aimsid parameter")
			return
		}
		session, err := sm.GetSession(r.Context(), aimsid)
		if err != nil {
			SendError(w, r, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		_ = sm.TouchSession(r.Context(), aimsid)
		next(w, r, session)
	})
}

// CORSMiddleware emits CORS headers and answers preflight requests. Every origin
// is allowed; the aimsid session is the security boundary.
//
// It must be the OUTERMOST middleware on every route. A response that the session
// layer rejects still needs an Access-Control-Allow-Origin header: without one
// the browser blocks the response, and the Web AIM client reads a status-0 empty
// response as "CORS blocked" and permanently downgrades its whole request
// pipeline to JSONP (aim.client.js onXhrFailed_ clears its useXhr flag and never
// sets it again). A single 400/401 from the session layer is enough to latch it.
//
// It reads nothing from the request body, so a POST body reaches the handler
// unconsumed.
func (m *AuthMiddleware) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// The response body varies with the request Origin, so it must not be
		// cached under a single key across origins.
		w.Header().Add("Vary", "Origin")

		// Echoing the origin back, rather than sending "*", is what lets the
		// client send credentials.
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SessionHandlerFunc is the session-aware handler shape that
// AuthMiddleware.RequireSession invokes once it has resolved an aimsid.
type SessionHandlerFunc = func(http.ResponseWriter, *http.Request, *Session)

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
// It lives in package webapi (rather than in server/oscar/middleware) so that its
// rejection can be encoded through the same SendResponse path the handlers use,
// honoring the request's JSON/JSONP/XML/AMF format.
//
// It only enforces the limit (the 430 rejection). Telling the client its status
// changed is the job of OServiceService.MonitorRateLimits.
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
		return func(w http.ResponseWriter, r *http.Request, session *Session) {
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
			status := sess.EvaluateRateLimit(time.Now(), rateClassID)

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

				// A disconnected session has no aimsid left to retry with, so
				// there is no wait to advertise.
				var retryAfter time.Duration
				if status == wire.RateLimitStatusLimited {
					retryAfter = retryAfterFor(sess.RateLimitStates()[rateClassID-1])
				}
				l.sendRateLimited(w, r, retryAfter)
				return
			}

			next(w, r, session)
		}
	}
}

// minRetryAfter floors the Retry-After hint sent with a rate-limited response.
// The computed wait can round down to nothing when a class is barely over its
// limit, and a hint of zero invites an immediate retry.
const minRetryAfter = 1 * time.Second

// retryAfterFor returns how long the client must wait for its next request on
// this class to clear the limit.
//
// OSCAR's limiter has no fixed window: it tracks a moving average of the gap
// between requests, and a request lifts the limit only once that average climbs
// back to ClearLevel. Inverting CheckRateLimit's update for the elapsed time that
// lands the new average exactly on ClearLevel gives
//
//	elapsed = ClearLevel*WindowSize - CurrentLevel*(WindowSize-1)
//
// A flat hint cannot work here, because a rejected request is still charged: a
// client retrying on a fixed interval drives the average toward that interval, so
// any hint below the class's ClearLevel holds the average just under the bar and
// the client stays limited forever. The production ICBM class clears at 5100ms,
// which a 5s hint would do exactly.
func retryAfterFor(rcs state.RateClassState) time.Duration {
	neededMs := int64(rcs.ClearLevel)*int64(rcs.WindowSize) - int64(rcs.CurrentLevel)*int64(rcs.WindowSize-1)

	// Retry-After carries whole seconds, so round up: a hint that is short by a
	// fraction of a second reproduces the same never-clears loop. A class barely
	// over its limit can compute to no wait at all, hence the floor.
	return max(time.Duration((neededMs+999)/1000)*time.Second, minRetryAfter)
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
//
// A retryAfter of zero sends no Retry-After header, for the rejections that have
// nothing to retry.
func (l *RateLimitMiddleware) sendRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = statusRateLimited
	resp.Response.StatusText = "rate limit exceeded"

	SendResponse(w, r, resp, l.logger)
}

// RequestLogger logs each request with method, path, and raw query string.
func RequestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
		)
		next.ServeHTTP(w, r)
	})
}
