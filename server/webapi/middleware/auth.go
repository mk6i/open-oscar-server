package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/state"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyAPIKey is the context key for storing the validated API key.
	ContextKeyAPIKey contextKey = "api_key"
	// ContextKeyDevID is the context key for storing the developer ID.
	ContextKeyDevID contextKey = "dev_id"
)

// APIKeyValidator defines methods for validating Web API keys.
type APIKeyValidator interface {
	// GetAPIKeyByDevKey retrieves and validates an API key by its dev_key value.
	GetAPIKeyByDevKey(ctx context.Context, devKey string) (*state.WebAPIKey, error)
	// UpdateLastUsed updates the last_used timestamp for an API key.
	UpdateLastUsed(ctx context.Context, devKey string) error
}

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

// Allow checks if a request from the given devID is allowed based on rate limits.
func (r *RateLimiter) Allow(devID string, limit int) bool {
	info := r.CheckRateLimit(devID, limit)
	return info.Allowed
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

// Authenticate is an HTTP middleware that validates API keys and enforces rate limits.
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from 'k' parameter (query or form)
		apiKey := r.URL.Query().Get("k")
		if apiKey == "" {
			// Try form value for POST requests
			apiKey = r.FormValue("k")
		}

		if apiKey == "" {
			m.sendErrorResponse(w, http.StatusBadRequest, "required parameter 'k' is missing")
			return
		}

		// Validate API key
		ctx := r.Context()
		key, err := m.Validator.GetAPIKeyByDevKey(ctx, apiKey)
		if err != nil {
			if err == state.ErrNoAPIKey {
				m.Logger.DebugContext(ctx, "invalid API key attempted", "key", apiKey[:min(8, len(apiKey))]+"...")
				m.sendErrorResponse(w, http.StatusForbidden, "invalid API key")
				return
			}
			m.Logger.ErrorContext(ctx, "error validating API key", "err", err.Error())
			m.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
			return
		}

		// Check if key is active
		if !key.IsActive {
			m.Logger.DebugContext(ctx, "inactive API key used", "dev_id", key.DevID)
			m.sendErrorResponse(w, http.StatusForbidden, "API key is inactive")
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
			m.sendErrorResponse(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		// Update last used timestamp asynchronously
		go func() {
			if err := m.Validator.UpdateLastUsed(context.Background(), apiKey); err != nil {
				m.Logger.Error("failed to update last_used timestamp", "err", err.Error())
			}
		}()

		// Add API key info to context for use in handlers
		ctx = context.WithValue(ctx, ContextKeyAPIKey, key)
		ctx = context.WithValue(ctx, ContextKeyDevID, key.DevID)

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

// CORSMiddleware handles CORS headers based on allowed origins for the API key.
func (m *AuthMiddleware) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get API key from context (set by Authenticate middleware)
		key, ok := r.Context().Value(ContextKeyAPIKey).(*state.WebAPIKey)

		// If no API key in context (e.g., using aimsid auth), allow all origins
		// This is safe because the actual authentication is handled by the session
		var allowedOrigins []string
		if ok && key != nil {
			allowedOrigins = key.AllowedOrigins
		} else {
			// For session-based auth without API key, allow all origins
			// The session itself provides the security boundary
			m.Logger.DebugContext(r.Context(), "CORS handling for non-API-key auth (aimsid/token)")
			allowedOrigins = []string{"*"}
		}

		origin := r.Header.Get("Origin")

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

// CapabilitiesMiddleware checks if the API key has the required capability for an endpoint.
func (m *AuthMiddleware) CapabilitiesMiddleware(requiredCapability string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get API key from context
			key, ok := r.Context().Value(ContextKeyAPIKey).(*state.WebAPIKey)
			if !ok {
				m.Logger.Error("CapabilitiesMiddleware called without authentication context")
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			// If no capabilities are defined, allow all (backward compatibility)
			if len(key.Capabilities) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Check if required capability is present
			hasCapability := false
			for _, cap := range key.Capabilities {
				if cap == requiredCapability || cap == "*" {
					hasCapability = true
					break
				}
			}

			if !hasCapability {
				m.Logger.WarnContext(r.Context(), "capability check failed",
					"dev_id", key.DevID,
					"required", requiredCapability,
					"available", key.Capabilities,
				)
				m.sendErrorResponse(w, http.StatusForbidden, fmt.Sprintf("missing required capability: %s", requiredCapability))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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

// sendErrorResponse sends a JSON error response.
func (m *AuthMiddleware) sendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error": message,
		"code":  statusCode,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		m.Logger.Error("failed to encode error response", "err", err.Error())
	}
}

// GetAPIKeyFromContext retrieves the API key from the request context.
func GetAPIKeyFromContext(ctx context.Context) (*state.WebAPIKey, bool) {
	key, ok := ctx.Value(ContextKeyAPIKey).(*state.WebAPIKey)
	return key, ok
}

// GetDevIDFromContext retrieves the developer ID from the request context.
func GetDevIDFromContext(ctx context.Context) (string, bool) {
	devID, ok := ctx.Value(ContextKeyDevID).(string)
	return devID, ok
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
		if aimsid := r.URL.Query().Get("aimsid"); aimsid != "" {
			// The handler itself will validate the aimsid
			// We just need to pass the request through without requiring k
			m.Logger.DebugContext(ctx, "using aimsid authentication", "aimsid", aimsid[:min(16, len(aimsid))]+"...")
			next.ServeHTTP(w, r)
			return
		}

		// Priority 2: Check for AOL token auth
		if token := r.URL.Query().Get("a"); token != "" {
			// Token auth is present, but we still need to validate the API key
			// The token provides user authentication while the API key identifies the app
			m.Logger.DebugContext(ctx, "token authentication detected, will validate API key as well")
			// Don't return here - continue to API key validation below
		}

		// Priority 3: Check for signed request auth
		if ts := r.URL.Query().Get("ts"); ts != "" {
			if sig := r.URL.Query().Get("sig_sha256"); sig != "" {
				// For now, signed requests still require 'k' parameter for API key validation
				// The signature provides additional security on top of the API key
				// When full signature validation is implemented, this can be made optional
				m.Logger.DebugContext(ctx, "signed request detected, falling through to API key validation")
				// Don't return here - continue to API key validation below
			}
		}

		// Priority 4: Fall back to API key requirement
		apiKey := r.URL.Query().Get("k")
		if apiKey == "" {
			// Try form value for POST requests
			apiKey = r.FormValue("k")
		}

		if apiKey == "" {
			m.sendErrorResponse(w, http.StatusBadRequest, "authentication required: provide aimsid or k parameter")
			return
		}

		// Validate API key as before
		key, err := m.Validator.GetAPIKeyByDevKey(ctx, apiKey)
		if err != nil {
			if err == state.ErrNoAPIKey {
				m.Logger.DebugContext(ctx, "invalid API key attempted", "key", apiKey[:min(8, len(apiKey))]+"...")
				m.sendErrorResponse(w, http.StatusForbidden, "invalid API key")
				return
			}
			m.Logger.ErrorContext(ctx, "error validating API key", "err", err.Error())
			m.sendErrorResponse(w, http.StatusInternalServerError, "internal server error")
			return
		}

		// Check if key is active
		if !key.IsActive {
			m.Logger.DebugContext(ctx, "inactive API key used", "dev_id", key.DevID)
			m.sendErrorResponse(w, http.StatusForbidden, "API key is inactive")
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
			m.sendErrorResponse(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		// Update last used timestamp asynchronously
		go func() {
			if err := m.Validator.UpdateLastUsed(context.Background(), apiKey); err != nil {
				m.Logger.Error("failed to update last_used timestamp", "err", err.Error())
			}
		}()

		// Add API key info to context for use in handlers
		ctx = context.WithValue(ctx, ContextKeyAPIKey, key)
		ctx = context.WithValue(ctx, ContextKeyDevID, key.DevID)

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
