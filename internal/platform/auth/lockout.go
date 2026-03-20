// Package auth — Redis-backed account lockout for login brute-force protection.
//
// Algorithm (two Redis keys per user):
//
//	lockout:fail:<userID>    INCR counter, TTL = LockoutWindowTTL
//	lockout:locked:<userID>  empty string,  TTL = LockoutDuration
//
// Flow:
//  1. IsLocked      — GET TTL of the locked key; positive TTL → account is locked.
//  2. RecordFailure — INCR fail counter; on first increment set EXPIRE to
//     LockoutWindowTTL. When the counter reaches MaxAttempts, SET the locked
//     key with LockoutDuration TTL and DEL the fail counter so the next
//     lockout window starts fresh.
//  3. ClearFailures — DEL fail counter on a successful credential check so the
//     attempt history does not bleed across separate login sessions.
//
// # Redis error policy
//
// Lockout is fail-open: when Redis is unavailable, IsLocked returns (false, 0)
// so a Redis outage never blocks every user's login simultaneously. This is the
// correct trade-off — a brief outage is less harmful than a global lockout.
// Rate limiting provides a complementary defence layer during the outage.
//
// Contrast with TOTP replay (fail-closed): replay prevention is a hard RFC 6238
// §5.2 requirement, whereas lockout is defence-in-depth complemented by
// per-IP and per-email rate limiting.
package auth

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	lockoutFailPrefix   = "lockout:fail:"
	lockoutLockedPrefix = "lockout:locked:"

	// lockoutRedisTimeout caps individual Redis commands so a slow Redis never
	// stalls a login handler goroutine for more than a fraction of a second.
	lockoutRedisTimeout = 300 * time.Millisecond
)

// AccountLocker is a Redis-backed, per-account brute-force lockout tracker.
// Construct via NewAccountLocker — the zero value is not usable.
type AccountLocker struct {
	rdb         *goredis.Client
	log         *zap.Logger
	maxAttempts int
	windowTTL   time.Duration
	lockoutDur  time.Duration
}

// NewAccountLocker returns a ready-to-use AccountLocker or a descriptive error.
// Returning an error (rather than panicking) lets module constructors surface
// the problem as a structured startup message via fmt.Errorf wrapping.
//
// Failure modes:
//   - rdb is nil: Redis is required for distributed lockout state; an
//     in-process counter resets on every pod restart.
//   - maxAttempts < 1: the lockout threshold must be at least 1.
func NewAccountLocker(
	rdb *goredis.Client,
	log *zap.Logger,
	maxAttempts int,
	windowTTL, lockoutDur time.Duration,
) (*AccountLocker, error) {
	if rdb == nil {
		return nil, fmt.Errorf(
			"auth: NewAccountLocker: rdb must not be nil — Redis is required for distributed account lockout",
		)
	}
	if maxAttempts < 1 {
		return nil, fmt.Errorf(
			"auth: NewAccountLocker: maxAttempts must be ≥1, got %d", maxAttempts,
		)
	}
	return &AccountLocker{
		rdb:         rdb,
		log:         log,
		maxAttempts: maxAttempts,
		windowTTL:   windowTTL,
		lockoutDur:  lockoutDur,
	}, nil
}

// IsLocked reports whether the account identified by userID is currently locked.
//
// Returns (true, retryAfter, nil) when the locked key exists in Redis.
// retryAfter is the remaining lock duration — pass it to apperrors.NewLockoutError
// so the handler can emit an accurate Retry-After response header.
//
// On Redis error the call fails-open: (false, 0, nil). A Redis outage must not
// lock all users out of their accounts; rate limiting remains active as a
// complementary defence layer during the outage.
func (l *AccountLocker) IsLocked(ctx context.Context, userID string) (locked bool, retryAfter time.Duration, err error) {
	rctx, cancel := context.WithTimeout(ctx, lockoutRedisTimeout)
	defer cancel()

	ttl, redisErr := l.rdb.TTL(rctx, lockoutLockedPrefix+userID).Result()
	if redisErr != nil {
		l.log.Error("lockout: IsLocked: redis TTL failed — failing open to avoid global lockout during Redis outage",
			zap.String("user_id", userID),
			zap.Error(redisErr),
		)
		return false, 0, nil
	}

	// TTL returns:
	//   -2  key does not exist  → account is not locked
	//   -1  key has no expiry   → should never occur (we always SET with EX)
	//   > 0 remaining TTL       → account is locked
	if ttl <= 0 {
		return false, 0, nil
	}
	return true, ttl, nil
}

// RecordFailure increments the per-account failure counter and, when the
// threshold is reached, writes the lockout sentinel key.
//
// Returns the updated failure count. On Redis error the count is returned as
// zero and the error is logged but not propagated — the caller must continue
// normally so that a transient Redis blip does not cause a successful login
// attempt to return an error.
func (l *AccountLocker) RecordFailure(ctx context.Context, userID string) (int, error) {
	rctx, cancel := context.WithTimeout(ctx, lockoutRedisTimeout)
	defer cancel()

	failKey := lockoutFailPrefix + userID

	count, incrErr := l.rdb.Incr(rctx, failKey).Result()
	if incrErr != nil {
		l.log.Error("lockout: RecordFailure: redis INCR failed",
			zap.String("user_id", userID),
			zap.Error(incrErr),
		)
		return 0, incrErr
	}

	// Set the sliding-window expiry only on the first increment so that
	// subsequent failures within the window do not reset the clock.
	if count == 1 {
		if expErr := l.rdb.Expire(rctx, failKey, l.windowTTL).Err(); expErr != nil {
			l.log.Warn("lockout: RecordFailure: redis EXPIRE failed for fail key — window may not reset automatically",
				zap.String("user_id", userID),
				zap.Error(expErr),
			)
		}
	}

	if int(count) >= l.maxAttempts {
		lockedKey := lockoutLockedPrefix + userID

		if setErr := l.rdb.Set(rctx, lockedKey, "", l.lockoutDur).Err(); setErr != nil {
			l.log.Error("lockout: RecordFailure: redis SET failed for locked key",
				zap.String("user_id", userID),
				zap.Error(setErr),
			)
		}

		// Reset the failure counter so the next lockout window starts from zero.
		if delErr := l.rdb.Del(rctx, failKey).Err(); delErr != nil {
			l.log.Warn("lockout: RecordFailure: redis DEL failed for fail key after lockout",
				zap.String("user_id", userID),
				zap.Error(delErr),
			)
		}

		l.log.Warn("lockout: account locked after repeated failures",
			zap.String("user_id", userID),
			zap.Int("threshold", l.maxAttempts),
			zap.Duration("lockout_duration", l.lockoutDur),
		)
	}

	return int(count), nil
}

// ClearFailures deletes the failure counter for userID. Call this immediately
// after a successful credential check so that the next incorrect attempt
// starts from a clean slate rather than inheriting the accumulated history
// of previous sessions.
//
// # Error policy
//
// Errors are logged at Warn level but never returned. A Redis failure here
// must not cause a successful login to surface an error to the user.
//
// # Operational implication
//
// If the DEL fails (Redis outage, network partition), the counter is not
// reset. The key expires on its own after LockoutWindowTTL (default 15 m),
// so no manual intervention is required. However, on a subsequent failed
// attempt within that window the user will reach the lockout threshold faster
// than the configured LockoutMaxAttempts, because the counter still reflects
// failures from the previous session. The worst case is LockoutMaxAttempts−1
// phantom failures carried forward.
//
// Alert on repeated "lockout: ClearFailures: redis DEL failed" warnings —
// they indicate a Redis connectivity problem that will degrade lockout
// accuracy until connectivity is restored.
func (l *AccountLocker) ClearFailures(ctx context.Context, userID string) {
	rctx, cancel := context.WithTimeout(ctx, lockoutRedisTimeout)
	defer cancel()

	if err := l.rdb.Del(rctx, lockoutFailPrefix+userID).Err(); err != nil {
		l.log.Warn("lockout: ClearFailures: redis DEL failed — counter will expire naturally via TTL",
			zap.String("user_id", userID),
			zap.Error(err),
		)
	}
}
