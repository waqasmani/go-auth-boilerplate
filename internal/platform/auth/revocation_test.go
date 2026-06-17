package auth

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestAccessRevoker_RevokesTokensIssuedBeforeEpoch(t *testing.T) {
	rdb, _ := newTestRedis(t)
	r := NewAccessRevoker(rdb, zap.NewNop(), 5*time.Minute)
	ctx := context.Background()

	issued := time.Now().UTC()

	// Nothing revoked yet.
	if r.IsRevoked(ctx, "u1", issued) {
		t.Fatal("token should not be revoked before any RevokeBefore call")
	}

	// Revoke everything issued up to now+1s.
	r.RevokeBefore(ctx, "u1", issued.Add(time.Second))

	// A token issued before the epoch is rejected.
	if !r.IsRevoked(ctx, "u1", issued) {
		t.Fatal("token issued before the revocation epoch should be revoked")
	}

	// A token issued at/after the epoch (e.g. an immediate re-login) survives.
	if r.IsRevoked(ctx, "u1", issued.Add(2*time.Second)) {
		t.Fatal("token issued after the revocation epoch must remain valid")
	}

	// Revocation is per-user — another user is unaffected.
	if r.IsRevoked(ctx, "u2", issued) {
		t.Fatal("revocation must not leak across users")
	}
}

func TestAccessRevoker_KeyTTLBoundedByAccessTTL(t *testing.T) {
	rdb, mr := newTestRedis(t)
	r := NewAccessRevoker(rdb, zap.NewNop(), 5*time.Minute)
	ctx := context.Background()

	r.RevokeBefore(ctx, "u1", time.Now().UTC())

	ttl := mr.TTL(accessRevokePrefix + "u1")
	if ttl <= 0 {
		t.Fatalf("expected a positive TTL on the revocation key, got %v", ttl)
	}
	// TTL must be AccessTTL + buffer, never unbounded.
	if want := 5*time.Minute + revokeTTLBuffer; ttl > want+time.Second {
		t.Fatalf("revocation key TTL %v exceeds AccessTTL+buffer %v", ttl, want)
	}
}

func TestAccessRevoker_NilIsDisabled(t *testing.T) {
	var r *AccessRevoker // nil — revocation disabled
	ctx := context.Background()

	// Methods on a nil revoker must be safe no-ops.
	r.RevokeBefore(ctx, "u1", time.Now().UTC())
	if r.IsRevoked(ctx, "u1", time.Now().UTC()) {
		t.Fatal("nil AccessRevoker must report not-revoked")
	}
}

func TestAccessRevoker_FailsOpenOnRedisError(t *testing.T) {
	rdb, mr := newTestRedis(t)
	r := NewAccessRevoker(rdb, zap.NewNop(), 5*time.Minute)
	ctx := context.Background()

	issued := time.Now().UTC()
	r.RevokeBefore(ctx, "u1", issued.Add(time.Minute))
	if !r.IsRevoked(ctx, "u1", issued) {
		t.Fatal("precondition: token should be revoked while Redis is up")
	}

	// Simulate a Redis outage: IsRevoked must fail open (return false) rather
	// than block authenticated traffic fleet-wide.
	mr.Close()
	if r.IsRevoked(ctx, "u1", issued) {
		t.Fatal("IsRevoked must fail open (not revoked) when Redis is unavailable")
	}
}
