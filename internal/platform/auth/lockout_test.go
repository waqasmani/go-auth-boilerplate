package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// newTestRedis returns a go-redis client backed by an in-process miniredis.
// Shared by the lockout and TOTP-replay tests in this package.
func newTestRedis(t *testing.T) (*goredis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

func TestAccountLocker_LocksAfterMaxAttempts(t *testing.T) {
	rdb, _ := newTestRedis(t)
	locker, err := NewAccountLocker(rdb, zap.NewNop(), 3, time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("NewAccountLocker: %v", err)
	}
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := locker.RecordFailure(ctx, "u1"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	locked, retry, _ := locker.IsLocked(ctx, "u1")
	if !locked {
		t.Fatal("account should be locked after 3 failures")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry-after, got %v", retry)
	}
}

func TestAccountLocker_NotLockedBelowThreshold(t *testing.T) {
	rdb, _ := newTestRedis(t)
	locker, _ := NewAccountLocker(rdb, zap.NewNop(), 5, time.Minute, time.Minute)
	ctx := context.Background()
	_, _ = locker.RecordFailure(ctx, "u2")
	_, _ = locker.RecordFailure(ctx, "u2")
	if locked, _, _ := locker.IsLocked(ctx, "u2"); locked {
		t.Fatal("should not be locked after 2/5 failures")
	}
}

func TestAccountLocker_ClearFailuresResets(t *testing.T) {
	rdb, _ := newTestRedis(t)
	locker, _ := NewAccountLocker(rdb, zap.NewNop(), 3, time.Minute, time.Minute)
	ctx := context.Background()
	_, _ = locker.RecordFailure(ctx, "u3")
	_, _ = locker.RecordFailure(ctx, "u3")
	locker.ClearFailures(ctx, "u3")
	// Two more failures after a reset must not reach the threshold of 3.
	_, _ = locker.RecordFailure(ctx, "u3")
	_, _ = locker.RecordFailure(ctx, "u3")
	if locked, _, _ := locker.IsLocked(ctx, "u3"); locked {
		t.Fatal("ClearFailures did not reset the counter")
	}
}

func TestAccountLocker_FailsOpenOnRedisOutage(t *testing.T) {
	rdb, mr := newTestRedis(t)
	locker, _ := NewAccountLocker(rdb, zap.NewNop(), 3, time.Minute, time.Minute)
	mr.Close() // simulate a Redis outage
	if locked, _, _ := locker.IsLocked(context.Background(), "u4"); locked {
		t.Fatal("IsLocked must fail OPEN (report not-locked) during a Redis outage")
	}
}
