package auth

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestTOTPReplayCache_RejectsReuse(t *testing.T) {
	rdb, _ := newTestRedis(t)
	cache, err := NewTOTPReplayCacheWithTTL(rdb, zap.NewNop(), 90*time.Second)
	if err != nil {
		t.Fatalf("NewTOTPReplayCacheWithTTL: %v", err)
	}

	if !cache.CheckAndRecord("u1", "123456") {
		t.Fatal("first use of a code must be accepted")
	}
	if cache.CheckAndRecord("u1", "123456") {
		t.Fatal("replay of the same code within the window must be rejected")
	}
	// A different code for the same user, and the same code for a different user,
	// are both independent and allowed.
	if !cache.CheckAndRecord("u1", "654321") {
		t.Fatal("a different code for the same user should be accepted")
	}
	if !cache.CheckAndRecord("u2", "123456") {
		t.Fatal("the same code for a different user should be accepted")
	}
}

func TestTOTPReplayCache_FailsClosedOnOutage(t *testing.T) {
	rdb, mr := newTestRedis(t)
	cache, _ := NewTOTPReplayCacheWithTTL(rdb, zap.NewNop(), 90*time.Second)
	mr.Close() // simulate a Redis outage
	if cache.CheckAndRecord("u1", "123456") {
		t.Fatal("CheckAndRecord must fail CLOSED (reject) during a Redis outage (RFC 6238 §5.2)")
	}
}
