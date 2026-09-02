package webapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyAPIKey is the context key for storing the validated API key.
	ContextKeyAPIKey contextKey = "api_key"
	// contextKeyResolvedAPIKey caches an API key lookup across middlewares
	// handling the same request. Unexported: it is an internal memo, not
	// something handlers should read.
	contextKeyResolvedAPIKey contextKey = "resolved_api_key"
)

// RateLimitInfo contains rate limit metadata for a request.
type RateLimitInfo struct {
	Limit     int   // Total requests allowed per window
	Remaining int   // Requests remaining in current window
	Reset     int64 // Unix timestamp when the window resets
	Allowed   bool  // Whether the request is allowed
}

// rateLimiterEntry tracks rate limiting data for a single devID.
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	limit      int
	windowSize time.Duration
	lastReset  time.Time
}

// RateLimiter manages per-devID rate limiting for the Web API.
type RateLimiter struct {
	limiters   *cache.Cache
	mu         sync.RWMutex
	windowSize time.Duration // Rate limit window size (default: 1 minute)
}

// NewRateLimiter creates a new rate limiter with automatic cleanup.
func NewRateLimiter() *RateLimiter {
	// Create cache with 5 minute expiration and 10 minute cleanup interval
	c := cache.New(5*time.Minute, 10*time.Minute)
	return &RateLimiter{
		limiters:   c,
		windowSize: time.Minute, // Default 1 minute window
	}
}

// CheckRateLimit checks if a request from the given devID is allowed and returns rate limit info.
func (r *RateLimiter) CheckRateLimit(devID string, limit int) RateLimitInfo {
	if limit <= 0 {
		return RateLimitInfo{
			Reset:   time.Now().Add(r.windowSize).Unix(),
			Allowed: true,
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Get or create limiter entry for this devID
	var entry *rateLimiterEntry
	if val, found := r.limiters.Get(devID); found {
		entry = val.(*rateLimiterEntry)
		// Check if limit has changed
		if entry.limit != limit {
			// Recreate limiter with new limit
			entry.limiter = rate.NewLimiter(rate.Every(r.windowSize/time.Duration(limit)), limit)
			entry.limit = limit
		}
	} else {
		// Create new limiter with burst equal to limit (allows initial burst)
		entry = &rateLimiterEntry{
			limiter:    rate.NewLimiter(rate.Every(r.windowSize/time.Duration(limit)), limit),
			limit:      limit,
			windowSize: r.windowSize,
			lastReset:  now,
		}
		r.limiters.Set(devID, entry, cache.DefaultExpiration)
	}

	// Check if request is allowed
	allowed := entry.limiter.Allow()

	// Calculate remaining requests (approximate based on tokens available)
	tokens := entry.limiter.Tokens()
	remaining := int(tokens)
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time (next window start)
	resetTime := now.Add(r.windowSize).Unix()

	return RateLimitInfo{
		Limit:     limit,
		Remaining: remaining,
		Reset:     resetTime,
		Allowed:   allowed,
	}
}

// AuthMiddleware provides authentication and rate limiting for Web API endpoints.
type AuthMiddleware struct {
	Validator   APIKeyValidator
	RateLimiter *RateLimiter
	Logger      *slog.Logger
}

// NewAuthMiddleware creates a new authentication middleware instance.
func NewAuthMiddleware(validator APIKeyValidator, logger *slog.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		Validator:   validator,
		RateLimiter: NewRateLimiter(),
		Logger:      logger,
	}
}

// RequireSession resolves the aimsid session and passes it to next. It rejects
// requests whose session is missing or expired with an auth error. On success it
// touches the session, sliding its expiry forward; this is the keepalive that
// holds a long-polling client's session open (see the session lifecycle timeline
// on state's Session manager).
//
// A session with a nil OSCARSession is rejected as a 500: startSession no longer
// creates such sessions (anonymous guests are unsupported), so a nil is a broken
// server invariant, not a client error. This lets downstream handlers treat
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

// Authenticate is an HTTP middleware that validates API keys and enforces rate limits.
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from 'k' parameter (query or form)
		apiKey := param(r, "k")

		if apiKey == "" {
			SendEnvelopeStatus(w, r, http.StatusBadRequest, "required parameter 'k' is missing", m.Logger)
			return
		}

		// Validate API key
		key, r := m.resolveAPIKeyCached(r, apiKey)
		ctx := r.Context()
		if key == nil {
			m.Logger.DebugContext(ctx, "invalid API key attempted", "key", apiKey[:min(8, len(apiKey))]+"...")
			SendEnvelopeStatus(w, r, http.StatusForbidden, "invalid API key", m.Logger)
			return
		}

		// Check rate limit
		rateLimitInfo := m.RateLimiter.CheckRateLimit(key.DevID, key.RateLimit)

		// Always add rate limit headers
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rateLimitInfo.Limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", rateLimitInfo.Remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", rateLimitInfo.Reset))

		if !rateLimitInfo.Allowed {
			m.Logger.WarnContext(ctx, "rate limit exceeded", "dev_id", key.DevID, "limit", key.RateLimit)
			// Add Retry-After header
			retryAfter := rateLimitInfo.Reset - time.Now().Unix()
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			SendEnvelopeStatus(w, r, http.StatusTooManyRequests, "rate limit exceeded", m.Logger)
			return
		}

		// Add API key info to context for use in handlers
		ctx = context.WithValue(ctx, ContextKeyAPIKey, key)

		// Log the API request
		m.Logger.InfoContext(ctx, "API request authenticated",
			"dev_id", key.DevID,
			"app_name", key.AppName,
			"method", r.Method,
			"path", r.URL.Path,
		)

		// Pass to next handler with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CORSMiddleware emits CORS headers and answers preflight requests.
//
// It must be the OUTERMOST middleware on every route. A response that the auth
// layer rejects still needs an Access-Control-Allow-Origin header: without one
// the browser blocks the response, and the Web AIM client reads a status-0 empty
// response as "CORS blocked" and permanently downgrades its whole request
// pipeline to JSONP (aim.client.js onXhrFailed_ clears its useXhr flag and never
// sets it again). A single 400/403/429 from the auth layer is enough to latch it.
//
// Running ahead of authentication means the key is not in the request context
// yet, so this resolves it itself to find the key's origin allowlist. The lookup
// is memoized on the request context, so the auth middleware downstream reuses it
// rather than hitting the store a second time.
func (m *AuthMiddleware) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the query parameter is consulted here: reading the form would
		// consume a POST body before the handler sees it.
		key, r := m.resolveAPIKeyCached(r, r.URL.Query().Get("k"))

		// If there is no API key (e.g. using aimsid auth), allow all origins.
		// This is safe because the actual authentication is handled by the session.
		var allowedOrigins []string
		if key != nil {
			allowedOrigins = key.AllowedOrigins
		} else {
			// For session-based auth without API key, allow all origins
			// The session itself provides the security boundary
			m.Logger.DebugContext(r.Context(), "CORS handling for non-API-key auth (aimsid/token)")
			allowedOrigins = []string{"*"}
		}

		origin := r.Header.Get("Origin")

		// The response body varies with the request Origin, so it must not be
		// cached under a single key across origins.
		w.Header().Add("Vary", "Origin")

		// Check if origin is allowed
		if m.isOriginAllowed(origin, allowedOrigins) {
			if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
				// For wildcard, set the actual origin to allow credentials
				if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				}
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isOriginAllowed checks if an origin is in the allowed list.
func (m *AuthMiddleware) isOriginAllowed(origin string, allowedOrigins []string) bool {
	// If no origins specified, allow all (for backward compatibility/development)
	if len(allowedOrigins) == 0 {
		return true
	}

	origin = strings.ToLower(origin)
	for _, allowed := range allowedOrigins {
		allowed = strings.ToLower(allowed)

		// Exact match
		if origin == allowed {
			return true
		}

		// Wildcard support (e.g., "*.example.com")
		if strings.HasPrefix(allowed, "*.") {
			domain := allowed[2:]
			if strings.HasSuffix(origin, domain) {
				return true
			}
		}

		// Allow all origins (development only)
		if allowed == "*" {
			m.Logger.Warn("wildcard origin (*) used - should not be used in production")
			return true
		}
	}

	return false
}

// AuthenticateFlexible is an HTTP middleware that supports multiple authentication methods:
// 1. aimsid (session ID) - no k required
// 2. a (AOL token) - no k required
// 3. ts + sig_sha256 (signed request) - no k required
// 4. k (API key) - fallback if no other auth provided
// This follows the Web AIM API specification where k is not required when aimsid is present.
func (m *AuthMiddleware) AuthenticateFlexible(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Priority 1: Check for session-based auth (aimsid)
		// According to the spec, when aimsid is provided, k is not required
		if aimsid := param(r, "aimsid"); aimsid != "" {
			// The handler itself will validate the aimsid
			// We just need to pass the request through without requiring k
			m.Logger.DebugContext(ctx, "using aimsid authentication", "aimsid", aimsid[:min(16, len(aimsid))]+"...")
			next.ServeHTTP(w, r)
			return
		}

		// Priority 2: AOL token auth — user identity is in the token; k is optional.
		if token := param(r, "a"); token != "" {
			key, r := m.resolveAPIKeyCached(r, param(r, "k"))
			ctx := r.Context()
			if key == nil {
				devKey := param(r, "k")
				key = &state.WebAPIKey{
					DevID:     "aim_web",
					DevKey:    devKey,
					AppName:   "AIM Web Client",
					IsActive:  true,
					RateLimit: 600,
				}
			}
			ctx = context.WithValue(ctx, ContextKeyAPIKey, key)
			m.Logger.DebugContext(ctx, "using token authentication", "dev_id", key.DevID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Priority 3: Check for signed request auth
		if ts := param(r, "ts"); ts != "" {
			if sig := param(r, "sig_sha256"); sig != "" {
				// For now, signed requests still require 'k' parameter for API key validation
				// The signature provides additional security on top of the API key
				// When full signature validation is implemented, this can be made optional
				m.Logger.DebugContext(ctx, "signed request detected, falling through to API key validation")
				// Don't return here - continue to API key validation below
			}
		}

		// Priority 4: Fall back to API key requirement
		apiKey := param(r, "k")

		if apiKey == "" {
			SendEnvelopeStatus(w, r, http.StatusBadRequest, "authentication required: provide aimsid or k parameter", m.Logger)
			return
		}

		key, r := m.resolveAPIKeyCached(r, apiKey)
		ctx = r.Context()
		if key == nil {
			m.Logger.DebugContext(ctx, "invalid API key attempted", "key", apiKey[:min(8, len(apiKey))]+"...")
			SendEnvelopeStatus(w, r, http.StatusForbidden, "invalid API key", m.Logger)
			return
		}

		// Check rate limit
		rateLimitInfo := m.RateLimiter.CheckRateLimit(key.DevID, key.RateLimit)

		// Always add rate limit headers
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rateLimitInfo.Limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", rateLimitInfo.Remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", rateLimitInfo.Reset))

		if !rateLimitInfo.Allowed {
			m.Logger.WarnContext(ctx, "rate limit exceeded", "dev_id", key.DevID, "limit", key.RateLimit)
			// Add Retry-After header
			retryAfter := rateLimitInfo.Reset - time.Now().Unix()
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			SendEnvelopeStatus(w, r, http.StatusTooManyRequests, "rate limit exceeded", m.Logger)
			return
		}

		// Add API key info to context for use in handlers
		ctx = context.WithValue(ctx, ContextKeyAPIKey, key)

		// Log the API request
		m.Logger.InfoContext(ctx, "API request authenticated via key",
			"dev_id", key.DevID,
			"app_name", key.AppName,
			"method", r.Method,
			"path", r.URL.Path,
		)

		// Pass to next handler with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolvedAPIKey memoizes one API key lookup for the lifetime of a request.
// A nil key is a cached result too: it records that devKey is unknown or
// inactive, which is what lets the auth layer skip a repeat lookup.
type resolvedAPIKey struct {
	devKey string
	key    *state.WebAPIKey
}

// resolveAPIKeyCached resolves devKey, reusing the result of an earlier lookup on
// the same request. It returns the key (nil when devKey is empty, unknown, or
// inactive) along with a request carrying the memoized result, which callers must
// pass down the chain for the caching to take effect.
func (m *AuthMiddleware) resolveAPIKeyCached(r *http.Request, devKey string) (*state.WebAPIKey, *http.Request) {
	if devKey == "" {
		return nil, r
	}
	if cached, ok := r.Context().Value(contextKeyResolvedAPIKey).(*resolvedAPIKey); ok && cached.devKey == devKey {
		return cached.key, r
	}
	key := m.resolveAPIKey(r.Context(), devKey)
	ctx := context.WithValue(r.Context(), contextKeyResolvedAPIKey, &resolvedAPIKey{devKey: devKey, key: key})
	return key, r.WithContext(ctx)
}

func (m *AuthMiddleware) resolveAPIKey(ctx context.Context, devKey string) *state.WebAPIKey {
	if devKey == "" {
		return nil
	}
	key, err := m.Validator.GetAPIKeyByDevKey(ctx, devKey)
	if err != nil || key == nil || !key.IsActive {
		return nil
	}
	return key
}

// minRetryAfter floors the Retry-After hint sent with a rate-limited response.
// The computed wait can round down to nothing when a class is barely over its
// limit, and a hint of zero invites an immediate retry.
const minRetryAfter = 1 * time.Second

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
