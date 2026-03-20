// Package auth — TOTP replay cache backed exclusively by Redis.
//
// TOTPReplayCache prevents a valid TOTP code from being reused within its
// validity window (±1 step = up to 90 seconds with the default 30-second
// period and skew=1).
//
// RFC 6238 §5.2 explicitly requires servers to reject a previously accepted
// OTP within its validity window. Without this cache an attacker who captures
// a valid code can replay it for up to 90 seconds.
//
// Redis is a hard dependency — there is no in-memory fallback. The application
// will not start unless a reachable Redis instance is configured.
//
// # Redis error policy
//
// When Redis returns an unexpected error during a TOTP replay check, the code
// is always rejected (fail-closed). This ensures RFC 6238 §5.2 compliance at
// all times: a Redis outage blocks 2FA login rather than silently reopening
// the replay window. If your deployment requires 2FA availability during Redis
// outages, address that at the infrastructure layer (Redis Sentinel, Cluster,
// ElastiCache Multi-AZ) rather than relaxing the application-level policy.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// ─── TOTPReplayCache ─────────────────────────────────────────────────────────

// TOTPReplayCache wraps the Redis-backed replay store and exposes the public
// API used by the TOTP verification handlers. Construct via
// NewTOTPReplayCache — the zero value is not usable.
type TOTPReplayCache struct {
	backend *redisReplayStore
}

// NewTOTPReplayCache returns a Redis-backed cache with a 90-second TTL.
// Returns an error when rdb is nil so the caller (module constructor) can
// propagate a structured startup error instead of crashing with a stack trace.
//
// On Redis error at runtime, TOTP codes are always rejected (fail-closed) to
// maintain RFC 6238 §5.2 compliance regardless of infrastructure state.
func NewTOTPReplayCache(rdb *goredis.Client, log *zap.Logger) (*TOTPReplayCache, error) {
	return NewTOTPReplayCacheWithTTL(rdb, log, 90*time.Second)
}

// NewTOTPReplayCacheWithTTL is like NewTOTPReplayCache but with an explicit
// TTL. Useful in integration tests with a real Redis instance.
func NewTOTPReplayCacheWithTTL(rdb *goredis.Client, log *zap.Logger, ttl time.Duration) (*TOTPReplayCache, error) {
	if rdb == nil {
		return nil, fmt.Errorf(
			"totp_replay: rdb must not be nil — Redis is a mandatory dependency; " +
				"there is no in-memory fallback for TOTP replay prevention",
		)
	}
	return &TOTPReplayCache{backend: newRedisReplayStore(rdb, log, ttl)}, nil
}

// CheckAndRecord atomically checks whether (userID, code) has been seen within
// the TTL window and, if not, records it.
//
// Returns true when the code is fresh (allowed); false when it has already been
// submitted (replay) or when Redis returns an error (fail-closed).
//
// Call immediately after ValidateTOTP returns (valid=true, err=nil):
//
//	valid, err := platformauth.ValidateTOTP(code, secret, period, digits)
//	if err != nil || !valid {
//	    return apperrors.ErrTokenInvalid
//	}
//	if !replayCache.CheckAndRecord(userID, code) {
//	    return apperrors.ErrTokenInvalid // replay or Redis error
//	}
func (c *TOTPReplayCache) CheckAndRecord(userID, code string) bool {
	return c.backend.CheckAndRecord(userID, code)
}

// ─── Redis backend ────────────────────────────────────────────────────────────

// redisReplayStore uses Redis SET key "" EX <ttl> NX for atomic distributed
// replay prevention.
//
// Algorithm:
//
//	SET totp_replay:<sha256(userID:code)> "" EX <ttlSeconds> NX
//	→ OK  (set=true)  : key was absent → fresh code → allow
//	→ nil (set=false) : key existed    → replay     → deny
//
// SET NX is a single atomic operation, so two concurrent pods racing on the
// same (userID, code) pair are correctly serialised: exactly one receives OK.
//
// On any Redis error the code is rejected (fail-closed) to maintain RFC 6238
// §5.2 compliance. Resolve availability via infrastructure-layer Redis HA.
const redisReplayKeyPrefix = "totp_replay:"

type redisReplayStore struct {
	rdb *goredis.Client
	log *zap.Logger
	ttl time.Duration
}

func newRedisReplayStore(rdb *goredis.Client, log *zap.Logger, ttl time.Duration) *redisReplayStore {
	return &redisReplayStore{rdb: rdb, log: log, ttl: ttl}
}

func (s *redisReplayStore) CheckAndRecord(userID, code string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	key := redisReplayKeyPrefix + replayCacheKey(userID, code)

	set, err := s.rdb.SetNX(ctx, key, "", s.ttl).Result()
	if err != nil {
		// Always fail-closed: reject the code and log. A Redis outage should
		// not silently reopen the TOTP replay window. Resolve availability at
		// the infrastructure layer (Sentinel, Cluster, ElastiCache Multi-AZ).
		s.log.Error(
			"totp_replay: redis unavailable — rejecting TOTP code (fail-closed) to prevent replay exposure; "+
				"resolve Redis availability at the infrastructure layer",
			zap.NamedError("redis_error", err),
		)
		return false
	}
	return set
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// replayCacheKey returns a SHA-256 hex digest of "userID:code". The userID
// prefix scopes the key so the same 6-digit code from different users never
// collides. SHA-256 without HMAC is acceptable here because the full input
// already carries a high-cardinality userID, making precomputation of the
// complete (user, code) space impractical even though the code alone has
// only 10^6 values.
func replayCacheKey(userID, code string) string {
	h := sha256.Sum256([]byte(userID + ":" + code))
	return hex.EncodeToString(h[:])
}
