package auth

import (
	"strings"
	"testing"
)

func TestHashVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword("correct horse battery staple", hash); err != nil {
		t.Fatalf("VerifyPassword(correct) = %v, want nil", err)
	}
	if err := VerifyPassword("wrong password", hash); err == nil {
		t.Fatal("VerifyPassword(wrong) = nil, want error")
	}
}

// TestPassword72ByteRegression guards the bcrypt 72-byte truncation pitfall.
// Two passwords identical for the first 72 bytes but differing afterwards must
// NOT cross-verify. Without the SHA-256 prehash, bcrypt would treat them as the
// same password.
func TestPassword72ByteRegression(t *testing.T) {
	base := strings.Repeat("a", 72)
	p1 := base + "ENDING-ONE"
	p2 := base + "ENDING-TWO"

	hash, err := HashPassword(p1)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(p1, hash); err != nil {
		t.Fatalf("VerifyPassword(p1) = %v, want nil", err)
	}
	if err := VerifyPassword(p2, hash); err == nil {
		t.Fatal("VerifyPassword(p2) = nil — bcrypt 72-byte truncation is NOT mitigated")
	}
}

func TestHashPassword_DistinctHashesPerCall(t *testing.T) {
	// bcrypt salts each hash; the same password must produce different digests.
	h1, _ := HashPassword("samepassword123")
	h2, _ := HashPassword("samepassword123")
	if h1 == h2 {
		t.Fatal("expected distinct salted hashes for the same password")
	}
}
