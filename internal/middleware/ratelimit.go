// Package middleware provides Gin middleware components for the application.
// This file implements per-key token-bucket rate limiting with two backends:
//
//   - Redis (production): an atomic Lua token-bucket script executed via EVALSHA.
//     All pods share state, so limits are enforced across the entire fleet. This
//     replaces the previous fixed-window INCR/EXPIRE approach, which allowed a
//     2× burst at every window boundary (classic fixed-window double-burst).
//
//   - In-memory (tests / explicit use): golang.org/x/time/rate per-key limiter
//     stored in an expirable LRU. No cross-pod sharing; suitable only for
//     single-instance tooling and unit tests.
//
// # Token-bucket vs fixed window
//
// A fixed window resets its counter at a wall-clock boundary. An attacker who
// fires Burst requests at 11:59:59.9 and another Burst at 12:00:00.0 sees 2×Burst
// requests pass in ~100 ms — a well-known vulnerability. A token bucket refills
// continuously: after draining the bucket at 11:59:59.9, the bucket contains only
// Rate×0.1 new tokens at 12:00:00.0, capping the effective burst to exactly Rate×0.1.
//
// # Redis error policy
//
// The behaviour on a Redis error is controlled by RateLimitConfig.ErrorPolicy:
//
//   - PolicyFailClosed (zero value — default for all routes): reject with 429
//     and log. Without rate limiting an auth endpoint is exposed to brute-force
//     attacks; fail-closed is the secure default for all endpoints.
//
//   - PolicyFailOpen (must be set explicitly): allow the request and log.
//     A transient network blip should not block end-users on low-risk routes.
//     Never use this for routes under /auth/*.
//
// # Key function
//
// The "key" is determined by a pluggable KeyFunc so callers can throttle by
// IP address, authenticated user ID, API key, or any combination.
package middleware

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/golang-lru/v2/expirable"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
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
func KeyByIP(c *gin.Context) (string, error) {
	ip := c.ClientIP()
	if ip == "" {
		return "", fmt.Errorf("ratelimit: could not determine client IP")
	}
	return "ip:" + ip, nil
}

// KeyByUserID derives the rate-limit key from the authenticated user's ID.
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

// KeyByUserIDWithIPFallback uses user ID when authenticated, IP otherwise.
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
// HTTP request header (e.g. "X-API-Key").
func KeyByHeader(header string) KeyFunc {
	return func(c *gin.Context) (string, error) {
		v := c.GetHeader(header)
		if v == "" {
			return "", fmt.Errorf("ratelimit: header %q is absent or empty", header)
		}
		return "header:" + header + ":" + v, nil
	}
}

// ─── RateLimitStore interface ────────────────────────────────────────────────

// RateLimitStore is the backend interface for rate-limit state storage.
// Implementations must be safe for concurrent use from multiple goroutines.
//
// Allow returns (true, 0) when the request may proceed, or (false, retryAfter)
// when the bucket is exhausted.
type RateLimitStore interface {
	Allow(key string) (allowed bool, retryAfter time.Duration)
}

// ─── Redis error policy ───────────────────────────────────────────────────────

// RedisErrorPolicy controls how the Redis-backed rate limiter behaves when
// a Redis command returns an unexpected error (connection refused, timeout, etc.).
type RedisErrorPolicy int

const (
	// PolicyFailClosed rejects the request with 429 and logs an error when
	// Redis is unavailable. This is the correct policy for all authentication
	// endpoints (/auth/login, /auth/register, etc.): an outage should never
	// open the gate to brute-force attacks.
	//
	// This is the zero value of RedisErrorPolicy, so any RateLimitConfig
	// constructed without explicitly setting ErrorPolicy defaults to fail-closed.
	// Security is the safe default; callers must opt out explicitly.
	PolicyFailClosed RedisErrorPolicy = iota

	// PolicyFailOpen allows the request and logs a warning when Redis is
	// unavailable. Appropriate for non-security-critical routes where
	// availability is more important than strict throttling.
	//
	// Must be set explicitly — it is never the zero-value default.
	// Do NOT use this for any route under /auth/*.
	PolicyFailOpen
)

// ─── Configuration ────────────────────────────────────────────────────────────

// RateLimitConfig holds all tuneable parameters for the rate limiter.
type RateLimitConfig struct {
	// KeyFunc determines the rate-limit dimension. Defaults to KeyByIP when nil.
	KeyFunc KeyFunc

	// Rate is the steady-state token refill speed: N tokens added per second.
	Rate rate.Limit

	// Burst is the token-bucket capacity. Must be >= 1.
	Burst int

	// TTL is how long an idle entry lives in the LRU cache (in-memory) or
	// the Redis key expiry (Redis backend) before eviction.
	TTL time.Duration

	// MaxKeys caps the total number of live entries in the in-memory LRU cache.
	// Has no effect on the Redis backend (Redis manages its own memory).
	MaxKeys int

	// ErrorPolicy controls what happens when the Redis backend returns an
	// unexpected error. Defaults to PolicyFailClosed (zero value) so that
	// callers must explicitly opt into fail-open behaviour — security-critical
	// routes are protected by default.
	//
	// Use PolicyFailOpen for low-risk routes where availability matters more
	// than strict throttling. Always use PolicyFailClosed (or leave unset)
	// for /auth/* endpoints.
	ErrorPolicy RedisErrorPolicy
}

// DefaultRateLimitConfig returns conservative production-ready defaults.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		KeyFunc:     KeyByIP,
		Rate:        rate.Limit(5),
		Burst:       10,
		TTL:         10 * time.Minute,
		MaxKeys:     10_000,
		ErrorPolicy: PolicyFailClosed,
	}
}

// AuthenticatedRateLimitConfig returns a config suited for protected API endpoints.
func AuthenticatedRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		KeyFunc:     KeyByUserIDWithIPFallback,
		Rate:        rate.Limit(10),
		Burst:       20,
		TTL:         10 * time.Minute,
		MaxKeys:     10_000,
		ErrorPolicy: PolicyFailClosed,
	}
}

func (cfg RateLimitConfig) resolveKeyFunc() KeyFunc {
	if cfg.KeyFunc != nil {
		return cfg.KeyFunc
	}
	return KeyByIP
}

// ─── In-memory backend (test / explicit use only) ─────────────────────────────

type memoryStore struct {
	cfg   RateLimitConfig
	cache *expirable.LRU[string, *rate.Limiter]
	mu    sync.Mutex
}

func newMemoryStore(cfg RateLimitConfig) *memoryStore {
	cache := expirable.NewLRU[string, *rate.Limiter](cfg.MaxKeys, nil, cfg.TTL)
	return &memoryStore{cfg: cfg, cache: cache}
}

func (s *memoryStore) Allow(key string) (bool, time.Duration) {
	lim := s.getLimiter(key)
	if lim.Allow() {
		return true, 0
	}
	r := lim.Reserve()
	d := r.Delay()
	r.Cancel()
	if d < 0 {
		d = 0
	}
	return false, d
}

func (s *memoryStore) getLimiter(key string) *rate.Limiter {
	if l, ok := s.cache.Get(key); ok {
		return l
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.cache.Get(key); ok {
		return l
	}
	l := rate.NewLimiter(s.cfg.Rate, s.cfg.Burst)
	s.cache.Add(key, l)
	return l
}

// ─── Redis backend (token bucket via atomic Lua script) ───────────────────────

// tokenBucketScript is an atomic Lua token-bucket rate limiter executed with
// Redis EVALSHA (falling back to EVAL on NOSCRIPT automatically via go-redis).
//
// It stores two fields in a Redis hash at KEYS[1]:
//
//	tokens   — current available tokens (float, stored as a Lua string)
//	last_ms  — Unix timestamp in milliseconds of the last access
//
// On every invocation the script:
//  1. Reads the current state, or initialises a full bucket on first access.
//  2. Refills tokens proportional to the elapsed time since the last call,
//     capped at Burst (the bucket capacity).
//  3. Allows the request by subtracting one token, or rejects it and returns
//     the milliseconds until one token will have refilled.
//  4. Persists the updated state and refreshes the idle-expiry TTL.
//
// Because the entire read-modify-write executes inside a single EVAL, there are
// no race conditions between pods — this is the same guarantee as a Redis
// transaction but cheaper (no WATCH/MULTI/EXEC round-trips).
//
// Arguments:
//
//	KEYS[1]  — the rate-limit hash key (caller applies "rl:" prefix)
//	ARGV[1]  — token refill rate in tokens per second (float)
//	ARGV[2]  — bucket capacity / burst limit (integer)
//	ARGV[3]  — current Unix time in milliseconds (integer)
//	ARGV[4]  — key idle-expiry in whole seconds (integer ≥ 1)
//
// Returns: { allowed (0|1), retry_ms }
var tokenBucketScript = goredis.NewScript(`
local key      = KEYS[1]
local rate     = tonumber(ARGV[1])
local burst    = tonumber(ARGV[2])
local now_ms   = tonumber(ARGV[3])
local ttl_s    = tonumber(ARGV[4])

local data    = redis.call('HMGET', key, 'tokens', 'last_ms')
local tokens  = tonumber(data[1])
local last_ms = tonumber(data[2])

if tokens == nil then
    tokens  = burst
    last_ms = now_ms
end

local elapsed_ms = math.max(0, now_ms - last_ms)
tokens  = math.min(burst, tokens + elapsed_ms * rate / 1000.0)
last_ms = now_ms

local allowed  = 0
local retry_ms = 0

if tokens >= 1.0 then
    tokens  = tokens - 1.0
    allowed = 1
else
    retry_ms = math.ceil((1.0 - tokens) / rate * 1000.0)
end

redis.call('HMSET', key, 'tokens', tostring(tokens), 'last_ms', tostring(last_ms))
redis.call('EXPIRE', key, ttl_s)

return { allowed, retry_ms }
`)

type redisStore struct {
	rdb *goredis.Client
	cfg RateLimitConfig
	log *zap.Logger
}

func newRedisStore(rdb *goredis.Client, cfg RateLimitConfig, log *zap.Logger) *redisStore {
	return &redisStore{rdb: rdb, cfg: cfg, log: log}
}

const redisKeyPrefix = "rl:"

// Allow implements RateLimitStore using the Redis token-bucket Lua script.
// The entire check-and-update is atomic: no window-boundary double-burst is
// possible regardless of how many pods call Allow simultaneously.
func (s *redisStore) Allow(key string) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ttlS := int64(s.cfg.TTL.Seconds())
	if ttlS < 1 {
		ttlS = 1
	}

	raw, err := tokenBucketScript.Run(
		ctx,
		s.rdb,
		[]string{redisKeyPrefix + key},
		float64(s.cfg.Rate),
		s.cfg.Burst,
		time.Now().UnixMilli(),
		ttlS,
	).Result()
	if err != nil {
		return s.handleRedisError(key, err)
	}

	vals, ok := raw.([]interface{})
	if !ok || len(vals) < 2 {
		s.log.Error("ratelimit: unexpected Lua script result — rejecting (fail-closed)",
			zap.String("key", key),
			zap.Any("result", raw),
		)
		return false, s.cfg.TTL
	}

	if luaInt(vals[0]) == 1 {
		return true, 0
	}

	retryAfter := time.Duration(luaInt(vals[1])) * time.Millisecond
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return false, retryAfter
}

// handleRedisError applies the configured ErrorPolicy when the Lua script (or
// any Redis command) returns an unexpected error.
func (s *redisStore) handleRedisError(key string, err error) (bool, time.Duration) {
	switch s.cfg.ErrorPolicy {
	case PolicyFailOpen:
		s.log.Warn("ratelimit: redis error — allowing request (fail-open)",
			zap.String("key", key),
			zap.Error(err),
		)
		return true, 0

	default: // PolicyFailClosed
		s.log.Error("ratelimit: redis error — rejecting request (fail-closed) to prevent brute-force exposure",
			zap.String("key", key),
			zap.Error(err),
		)
		return false, s.cfg.TTL
	}
}

// luaInt safely converts the interface{} values returned by go-redis when
// evaluating a Lua script. Redis integers arrive as int64; Lua's tostring()
// produces bulk-string replies that need strconv parsing.
func luaInt(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case string:
		out, _ := strconv.ParseInt(n, 10, 64)
		return out
	default:
		return 0
	}
}

// ─── Limiter — imperative / programmatic use ──────────────────────────────────

// Limiter is an imperative rate-limiter for use in handler code when the
// bucket key cannot be derived from request headers alone (e.g. an email
// address only available after parsing the request body).
//
// Typical use:
//
//	if allowed, retryAfter := h.emailLimiter.Allow("login:email:" + email); !allowed {
//	    seconds := int(retryAfter.Seconds()) + 1
//	    c.Header("Retry-After", strconv.Itoa(seconds))
//	    response.Error(c, apperrors.ErrRateLimitExceeded)
//	    return
//	}
type Limiter struct {
	store RateLimitStore
}

// NewLimiterMemory constructs a Limiter backed by the in-memory store.
// Intended for tests and single-node tooling only. Use NewLimiter for all
// production code — Redis is required in production.
func NewLimiterMemory(cfg RateLimitConfig) *Limiter {
	return &Limiter{store: newMemoryStore(cfg)}
}

// NewLimiter constructs a Limiter backed by the Redis token-bucket script.
// Returns an error when rdb is nil so the module constructor (auth.NewModule)
// can propagate a structured startup error rather than crashing with a raw
// stack trace.
//
// This is the only Limiter constructor that can fail due to configuration;
// the inline RateLimit gin.HandlerFunc keeps its panic because by the time
// router.New is called the container has already verified Redis connectivity,
// making a nil rdb a true programmer error rather than a config mistake.
func NewLimiter(cfg RateLimitConfig, rdb *goredis.Client, log *zap.Logger) (*Limiter, error) {
	if rdb == nil {
		return nil, fmt.Errorf(
			"ratelimit: NewLimiter requires a non-nil Redis client — " +
				"Redis is mandatory; there is no in-memory fallback",
		)
	}
	return &Limiter{store: newRedisStore(rdb, cfg, log)}, nil
}

// Allow checks whether key has capacity remaining.
// Returns (true, 0) when allowed; (false, retryAfter) when exhausted.
func (l *Limiter) Allow(key string) (allowed bool, retryAfter time.Duration) {
	return l.store.Allow(key)
}

// ─── Gin Middleware ───────────────────────────────────────────────────────────

// RateLimitMemory returns a Gin middleware backed by the in-memory store.
// Intended for tests and single-node tooling only. Use RateLimit for all
// production routes — Redis is required in production.
func RateLimitMemory(cfg RateLimitConfig) gin.HandlerFunc {
	return rateLimitWith(newMemoryStore(cfg), cfg.resolveKeyFunc())
}

// RateLimit returns a Gin middleware backed by the Redis token-bucket script.
//
// Panics at startup when rdb is nil. This panic is intentional and appropriate
// here: RateLimit is called from router.New which runs after container.New has
// already verified Redis connectivity and returned a non-nil *goredis.Client.
// A nil rdb at this call site therefore represents a programmer error in wiring
// (e.g. accidentally passing the wrong variable), not a deployment config
// mistake — exactly the case where panic is the right signal.
func RateLimit(cfg RateLimitConfig, rdb *goredis.Client, log *zap.Logger) gin.HandlerFunc {
	if rdb == nil {
		panic("ratelimit: RateLimit requires a non-nil Redis client — Redis is mandatory; there is no in-memory fallback")
	}
	return rateLimitWith(newRedisStore(rdb, cfg, log), cfg.resolveKeyFunc())
}

// rateLimitWith is the shared middleware implementation used by both RateLimit
// and RateLimitMemory.
func rateLimitWith(store RateLimitStore, keyFn KeyFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		key, err := keyFn(c)
		if err != nil {
			key, _ = KeyByIP(c)
		}

		allowed, retryAfter := store.Allow(key)
		if !allowed {
			retrySeconds := int(retryAfter.Seconds()) + 1
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
