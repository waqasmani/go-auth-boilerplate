// Package middleware provides Gin middleware components for the application.
// This file implements per-key token-bucket rate limiting backed by an
// expirable LRU cache.  The "key" is determined by a pluggable KeyFunc so
// callers can throttle by IP address, authenticated user ID, API key, or any
// other dimension — or combine them (e.g. user ID when authenticated, IP
// otherwise).
package middleware

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/golang-lru/v2/expirable"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
	"golang.org/x/time/rate"
)

// ─── KeyFunc ─────────────────────────────────────────────────────────────────

// KeyFunc extracts a rate-limit bucket key from an incoming request.
// The returned string is used as the cache key; every distinct value gets its
// own independent token bucket.
//
// If the function returns a non-nil error the middleware falls back to the
// client IP address as the key, so a misbehaving or missing claim never
// hard-blocks a legitimate request.
type KeyFunc func(c *gin.Context) (string, error)

// ── Built-in KeyFuncs ────────────────────────────────────────────────────────

// KeyByIP derives the rate-limit key from the client IP address.
// This is the default KeyFunc used when none is specified in RateLimitConfig.
//
// Gin's c.ClientIP() honours the X-Forwarded-For / X-Real-IP headers when
// TrustedProxies are configured on the engine, and falls back to the TCP
// remote address otherwise.  Configure gin.Engine.SetTrustedProxies() to
// match your infrastructure so this value cannot be spoofed.
func KeyByIP(c *gin.Context) (string, error) {
	ip := c.ClientIP()
	if ip == "" {
		return "", fmt.Errorf("ratelimit: could not determine client IP")
	}
	return "ip:" + ip, nil
}

// KeyByUserID derives the rate-limit key from the authenticated user's ID,
// as stored in the Gin context by the Auth JWT middleware (UserIDKey).
//
// This key func is intended for routes that sit behind the Auth middleware.
// Every authenticated user gets their own independent token bucket regardless
// of which IP they connect from — useful for per-user API quota enforcement.
//
// Returns an error when no user ID is present (unauthenticated request).
// The middleware will automatically fall back to KeyByIP on error, so
// pairing this with KeyByUserIDWithIPFallback is usually more explicit.
func KeyByUserID(c *gin.Context) (string, error) {
	uid, exists := c.Get(UserIDKey)
	if !exists {
		return "", fmt.Errorf("ratelimit: UserIDKey not found in context (is Auth middleware applied?)")
	}
	userID, ok := uid.(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("ratelimit: UserIDKey is not a non-empty string")
	}
	return "user:" + userID, nil
}

// KeyByUserIDWithIPFallback is the most practical key func for auth-adjacent
// routes.  It uses the authenticated user's ID when available and gracefully
// degrades to the client IP address for unauthenticated requests.
//
// Typical usage:
//
//	POST /auth/login  → client is not yet authenticated → keyed by IP
//	GET  /api/v1/...  → client is authenticated         → keyed by user ID
//
// This prevents a single shared or compromised IP from exhausting the budget
// of unrelated legitimate users while still protecting anonymous endpoints.
func KeyByUserIDWithIPFallback(c *gin.Context) (string, error) {
	uid, exists := c.Get(UserIDKey)
	if exists {
		if userID, ok := uid.(string); ok && userID != "" {
			return "user:" + userID, nil
		}
	}
	return KeyByIP(c)
}

// KeyByHeader returns a KeyFunc that reads the rate-limit key from a specific
// HTTP request header (e.g. "X-API-Key").  An empty or absent header returns
// an error, which causes the middleware to fall back to the client IP.
//
// Example:
//
//	cfg := middleware.DefaultRateLimitConfig()
//	cfg.KeyFunc = middleware.KeyByHeader("X-API-Key")
//	apiGroup.Use(middleware.RateLimit(cfg))
func KeyByHeader(header string) KeyFunc {
	return func(c *gin.Context) (string, error) {
		v := c.GetHeader(header)
		if v == "" {
			return "", fmt.Errorf("ratelimit: header %q is absent or empty", header)
		}
		return "header:" + header + ":" + v, nil
	}
}

// ─── Configuration ────────────────────────────────────────────────────────────

// RateLimitConfig holds all tuneable parameters for the rate limiter.
// All fields are exported so callers can build configs from environment
// variables or application-level config structs.
type RateLimitConfig struct {
	// KeyFunc determines the rate-limit dimension (IP, user ID, API key, …).
	// Defaults to KeyByIP when nil.
	//
	// Built-in options:
	//   KeyByIP                      — per client IP (default)
	//   KeyByUserID                  — per authenticated user ID
	//   KeyByUserIDWithIPFallback    — user ID when authed, IP for anonymous
	//   KeyByHeader("X-API-Key")     — per arbitrary request header value
	KeyFunc KeyFunc

	// Rate is the steady-state token refill speed: N tokens added per second.
	// Each distinct key gets its own independent bucket at this rate.
	Rate rate.Limit

	// Burst is the token-bucket capacity — the maximum number of requests a
	// single key can fire instantly before being throttled.  Must be >= 1.
	// Setting Burst > Rate creates a "credit" window that absorbs short spikes.
	Burst int

	// TTL is how long an idle entry lives in the LRU cache before being
	// evicted.  After TTL with no traffic the entry is removed and the key
	// starts fresh with a full bucket on its next request.
	TTL time.Duration

	// MaxKeys caps the total number of live entries in the LRU cache.
	// The least-recently-used entry is evicted when this ceiling is reached.
	MaxKeys int
}

// DefaultRateLimitConfig returns conservative production-ready defaults.
//
//   - KeyFunc:  KeyByIP   (per client IP address)
//   - Rate:     5 req/s   — handles a busy login form with retries
//   - Burst:    10        — absorbs momentary spikes without false positives
//   - TTL:      10 min    — idle entries are cleaned up quickly
//   - MaxKeys:  10 000    — supports a large number of concurrent clients
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		KeyFunc: KeyByIP,
		Rate:    rate.Limit(5),
		Burst:   10,
		TTL:     10 * time.Minute,
		MaxKeys: 10_000,
	}
}

// AuthenticatedRateLimitConfig returns a config suited for protected API
// endpoints where clients carry a JWT.  It uses KeyByUserIDWithIPFallback so
// authenticated users each get their own bucket and anonymous callers are
// bucketed by IP.
//
//   - Rate:  10 req/s  — authenticated users may call more frequently
//   - Burst: 20        — generous burst for pages that fan out requests
func AuthenticatedRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		KeyFunc: KeyByUserIDWithIPFallback,
		Rate:    rate.Limit(10),
		Burst:   20,
		TTL:     10 * time.Minute,
		MaxKeys: 10_000,
	}
}

// resolveKeyFunc returns the configured KeyFunc or KeyByIP if none was set.
func (cfg RateLimitConfig) resolveKeyFunc() KeyFunc {
	if cfg.KeyFunc != nil {
		return cfg.KeyFunc
	}
	return KeyByIP
}

// ─── Limiter Store ────────────────────────────────────────────────────────────

// limiterStore holds the per-key token-bucket cache for a single middleware
// instance.  Safe for concurrent use: expirable.LRU uses an internal mutex
// and rate.Limiter.Allow() / Reserve() are goroutine-safe.
type limiterStore struct {
	cfg   RateLimitConfig
	cache *expirable.LRU[string, *rate.Limiter]
}

// newLimiterStore constructs a limiterStore with an expirable LRU cache.
func newLimiterStore(cfg RateLimitConfig) *limiterStore {
	cache := expirable.NewLRU[string, *rate.Limiter](cfg.MaxKeys, nil, cfg.TTL)
	return &limiterStore{cfg: cfg, cache: cache}
}

// getLimiter returns the rate.Limiter for key, creating one on a cache miss.
//
// Thread-safety note: there is a narrow TOCTOU gap between a cache miss and
// the subsequent Add where two goroutines may both create a limiter for the
// same key.  The second Add overwrites the first with an equivalent limiter,
// meaning at most Burst extra requests can slip through in that instant — an
// acceptable trade-off that avoids a heavier per-key lock.
func (s *limiterStore) getLimiter(key string) *rate.Limiter {
	if l, ok := s.cache.Get(key); ok {
		return l
	}
	l := rate.NewLimiter(s.cfg.Rate, s.cfg.Burst)
	s.cache.Add(key, l)
	return l
}

// ─── Gin Middleware ───────────────────────────────────────────────────────────

// RateLimit returns a Gin middleware function that enforces per-key token-
// bucket rate limiting.  The key is derived by cfg.KeyFunc on each request
// (defaults to KeyByIP when nil).
//
// When a request is allowed the handler chain continues normally with no extra
// headers written.
//
// When a request is rejected the middleware:
//   - Writes HTTP 429 with a standard JSON error envelope.
//   - Sets the Retry-After header (seconds until the next token is available).
//   - Calls c.Abort() so no downstream handler runs.
//
// Rate-limit by IP (default):
//
//	authGroup.Use(middleware.RateLimit(middleware.DefaultRateLimitConfig()))
//
// Per-user rate limiting on protected routes (run Auth middleware first):
//
//	apiGroup.Use(middleware.Auth(jwtHelper, log))
//	apiGroup.Use(middleware.RateLimit(middleware.AuthenticatedRateLimitConfig()))
//
// Custom key func — rate limit by API key header:
//
//	cfg := middleware.DefaultRateLimitConfig()
//	cfg.KeyFunc = middleware.KeyByHeader("X-API-Key")
//	apiGroup.Use(middleware.RateLimit(cfg))
func RateLimit(cfg RateLimitConfig) gin.HandlerFunc {
	store := newLimiterStore(cfg)
	keyFn := cfg.resolveKeyFunc()

	return func(c *gin.Context) {
		key, err := keyFn(c)
		if err != nil {
			// KeyFunc failed (e.g. no auth claims for KeyByUserID on an
			// anonymous endpoint).  Fall back to IP so the middleware degrades
			// gracefully rather than blocking or panicking.
			key, _ = KeyByIP(c)
		}

		limiter := store.getLimiter(key)

		if !limiter.Allow() {
			// Peek at how long the client must wait for the next token.
			// We call Reserve() only to read the delay and immediately cancel
			// so we do not consume a future token slot.
			reservation := limiter.Reserve()
			delay := reservation.Delay()
			reservation.Cancel()

			retrySeconds := int(delay.Seconds()) + 1
			if retrySeconds < 1 {
				retrySeconds = 1
			}

			c.Header("Retry-After", strconv.Itoa(retrySeconds))
			response.Error(c, apperrors.ErrRateLimitExceeded)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitWithDefaults is a zero-config convenience wrapper that applies
// DefaultRateLimitConfig (per-IP, 5 req/s, burst 10):
//
//	authGroup.Use(middleware.RateLimitWithDefaults())
func RateLimitWithDefaults() gin.HandlerFunc {
	return RateLimit(DefaultRateLimitConfig())
}
