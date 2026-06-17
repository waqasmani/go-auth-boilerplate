// Package auth — Redis-backed immediate revocation of stateless access tokens.
//
// Access tokens are stateless JWTs: once signed they validate on any replica
// until they expire, so logging out or changing a credential cannot, by itself,
// invalidate an access token that is already in a client's hands. Refresh tokens
// are revoked in the database, but the short-lived access token would otherwise
// remain usable for up to JWT_ACCESS_TTL after the event.
//
// AccessRevoker closes that window across the whole fleet with a single Redis
// key per user — a "valid-after" epoch:
//
//	auth:revoke:<userID>  = unix seconds of the revocation instant
//	                        TTL = AccessTTL + buffer
//
// On every authenticated request the Auth middleware compares the token's iat
// against this epoch: a token issued strictly before the epoch is rejected. The
// key only needs to outlive the longest-lived access token issued just before
// the revocation, so it self-expires after AccessTTL + buffer.
//
// # Redis error policy
//
// Revocation is fail-OPEN: if Redis is unavailable, IsRevoked returns false so a
// Redis outage does not 401 every authenticated request across the fleet. This
// matches the account-lockout policy (auth/lockout.go) and is acceptable because
// access tokens are already short-lived and the refresh token is revoked durably
// in the database regardless. Contrast with rate limiting and TOTP-replay, which
// fail closed.
package auth

import (
	"context"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	accessRevokePrefix = "auth:revoke:"

	// revokeRedisTimeout caps individual Redis commands so a slow Redis never
	// stalls a request goroutine for more than a fraction of a second.
	revokeRedisTimeout = 300 * time.Millisecond

	// revokeTTLBuffer is added to AccessTTL when computing the key's TTL so the
	// epoch comfortably outlives any access token still within its validity
	// window (covering issuer/validator clock skew and JWT leeway).
	revokeTTLBuffer = 2 * time.Minute
)

// AccessRevoker records and checks per-user "valid-after" epochs in Redis so
// access tokens issued before a logout / credential change are rejected fleet
// wide. Construct via NewAccessRevoker.
//
// A nil *AccessRevoker is a valid "disabled" value: all methods are no-ops that
// report "not revoked". This lets the middleware and services hold an optional
// revoker without nil-checking at every call site (e.g. tests without Redis).
type AccessRevoker struct {
	rdb       *goredis.Client
	log       *zap.Logger
	accessTTL time.Duration
}

// NewAccessRevoker returns a ready-to-use AccessRevoker. rdb must be non-nil —
// Redis is required for distributed revocation state (an in-process set would
// not be shared across replicas, defeating the purpose).
func NewAccessRevoker(rdb *goredis.Client, log *zap.Logger, accessTTL time.Duration) *AccessRevoker {
	return &AccessRevoker{rdb: rdb, log: log, accessTTL: accessTTL}
}

// keyTTL is how long the valid-after epoch must live: long enough that every
// access token issued just before the revocation has already expired.
func (r *AccessRevoker) keyTTL() time.Duration {
	return r.accessTTL + revokeTTLBuffer
}

// RevokeBefore records that every access token issued before t is no longer
// valid for userID. Call it on logout, logout-all, password reset, and any other
// credential change that must terminate established sessions immediately.
//
// Errors are logged but not returned: a failure here must not break the
// user-facing operation (the refresh token is still revoked durably in the DB).
// The worst case of a Redis failure is that the access token remains valid until
// its natural expiry — the pre-existing behaviour.
func (r *AccessRevoker) RevokeBefore(ctx context.Context, userID string, t time.Time) {
	if r == nil || r.rdb == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, revokeRedisTimeout)
	defer cancel()

	val := strconv.FormatInt(t.UTC().Unix(), 10)
	if err := r.rdb.Set(rctx, accessRevokePrefix+userID, val, r.keyTTL()).Err(); err != nil {
		r.log.Error("revoke: RevokeBefore: redis SET failed — access token will remain valid until natural expiry",
			zap.String("user_id", userID),
			zap.Error(err),
		)
	}
}

// IsRevoked reports whether an access token issued at issuedAt for userID has
// been revoked. A token is revoked when its issue time is strictly before the
// stored epoch (strict "<" so a token minted in the same second as — but after —
// the revocation, e.g. an immediate re-login, is not caught; JWT iat has
// one-second granularity, so the residual window is at most one second).
//
// Fails open: on any Redis error it returns false and logs, so a Redis outage
// never blocks authenticated traffic fleet wide.
func (r *AccessRevoker) IsRevoked(ctx context.Context, userID string, issuedAt time.Time) bool {
	if r == nil || r.rdb == nil {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, revokeRedisTimeout)
	defer cancel()

	val, err := r.rdb.Get(rctx, accessRevokePrefix+userID).Result()
	if err == goredis.Nil {
		return false // no revocation recorded for this user
	}
	if err != nil {
		r.log.Error("revoke: IsRevoked: redis GET failed — failing open to avoid blocking authenticated traffic during Redis outage",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return false
	}

	epoch, parseErr := strconv.ParseInt(val, 10, 64)
	if parseErr != nil {
		r.log.Error("revoke: IsRevoked: malformed epoch value — ignoring",
			zap.String("user_id", userID),
			zap.String("value", val),
			zap.Error(parseErr),
		)
		return false
	}

	return issuedAt.UTC().Unix() < epoch
}
