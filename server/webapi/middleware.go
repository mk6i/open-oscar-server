package webapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// AuthMiddleware resolves the aimsid session for Web API endpoints.
type AuthMiddleware struct {
	Logger *slog.Logger
}

// NewAuthMiddleware creates a new session middleware instance.
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

// SessionHandlerFunc is the session-aware handler shape that
// AuthMiddleware.RequireSession invokes once it has resolved an aimsid.
type SessionHandlerFunc = func(http.ResponseWriter, *http.Request, *Session)

// lookupInterval and lookupBurst bound how often a session may call the
// routes made of rate-limit-exempt lookups, which the OSCAR server doesn't
// charge.
const (
	lookupInterval = time.Second
	lookupBurst    = 10
)

// limitLookups returns middleware that rejects a session's lookup route
// requests beyond its lookup rate.
func limitLookups(logger *slog.Logger) func(SessionHandlerFunc) SessionHandlerFunc {
	return func(next SessionHandlerFunc) SessionHandlerFunc {
		return func(w http.ResponseWriter, r *http.Request, session *Session) {
			if !session.lookups.Allow() {
				sendRateLimited(w, r, lookupInterval, logger)
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

// retryAfter returns how long a client must wait for its next request on a
// class the OSCAR server announced with params to clear the limit.
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
func retryAfter(params wire.RateParamsSNAC) time.Duration {
	clearLevel, windowSize, currentLevel := int64(params.ClearLevel), int64(params.WindowSize), int64(params.CurrentLevel)
	neededMs := clearLevel*windowSize - currentLevel*(windowSize-1)

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
func sendRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration, logger *slog.Logger) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = statusRateLimited
	resp.Response.StatusText = "rate limit exceeded"

	SendResponse(w, r, resp, logger)
}

// sendRequestError answers a request that failed to reach the OSCAR server or
// get its reply: a rate limit rejection when the rate class is limited, and an
// internal error with text otherwise.
func sendRequestError(w http.ResponseWriter, r *http.Request, err error, text string, logger *slog.Logger) {
	var limited *rateLimitError
	if errors.As(err, &limited) {
		sendRateLimited(w, r, limited.retryAfter, logger)
		return
	}
	SendError(w, r, http.StatusInternalServerError, text)
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
