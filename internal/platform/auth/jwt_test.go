package auth

import (
	"crypto/rsa"
	"testing"
	"time"

	"crypto/rand"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testSecret  = "test-secret-that-is-definitely-32-bytes-or-more-aaaa"
	testSecret2 = "second-test-secret-also-32-bytes-or-more-bbbbbbbbbbb"
)

func newTestJWT(t *testing.T) *JWT {
	t.Helper()
	j, err := NewJWT(JWTConfig{
		Keys:               []JWTKey{{ID: "v1", Secret: testSecret, Active: true}},
		Issuer:             "test-iss",
		Audience:           "test-aud",
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         24 * time.Hour,
		RefreshAbsoluteTTL: 72 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}
	return j
}

func TestNewJWT_ActiveKeyInvariant(t *testing.T) {
	cases := []struct {
		name    string
		keys    []JWTKey
		wantErr bool
	}{
		{"one active", []JWTKey{{ID: "v1", Secret: testSecret, Active: true}}, false},
		{"no active", []JWTKey{{ID: "v1", Secret: testSecret, Active: false}}, true},
		{"two active", []JWTKey{{ID: "v1", Secret: testSecret, Active: true}, {ID: "v2", Secret: testSecret2, Active: true}}, true},
		{"short secret", []JWTKey{{ID: "v1", Secret: "tooshort", Active: true}}, true},
		{"empty id", []JWTKey{{ID: "", Secret: testSecret, Active: true}}, true},
		{"dup id", []JWTKey{{ID: "v1", Secret: testSecret, Active: true}, {ID: "v1", Secret: testSecret2, Active: false}}, true},
		{"empty set", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewJWT(JWTConfig{Keys: tc.keys, Issuer: "i", Audience: "a", AccessTTL: time.Minute, RefreshTTL: time.Hour})
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewJWT err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestGenerateAndValidate_RoundTrip(t *testing.T) {
	j := newTestJWT(t)
	pair, err := j.GenerateTokenPair("user-1", "u@example.com", []string{"user", "admin"}, "", time.Time{})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	claims, err := j.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" || claims.Email != "u@example.com" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "user" {
		t.Fatalf("roles mismatch: %+v", claims.Roles)
	}
	if pair.RefreshTokenFamily == "" || pair.RefreshTokenHashed == "" {
		t.Fatalf("expected family + hashed refresh to be set")
	}
}

// TestAlgPinning is the most security-critical test: a token using "none",
// RS256, or any non-HMAC algorithm must be rejected regardless of kid.
func TestAlgPinning(t *testing.T) {
	j := newTestJWT(t)

	t.Run("alg none rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{
			UserID: "attacker",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-iss",
				Audience:  jwt.ClaimStrings{"test-aud"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})
		tok.Header["kid"] = "v1"
		s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("sign none: %v", err)
		}
		if _, err := j.ValidateAccessToken(s); err == nil {
			t.Fatal("alg=none token was ACCEPTED — alg pinning is broken")
		}
	})

	t.Run("RS256 rejected", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa gen: %v", err)
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
			UserID: "attacker",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-iss",
				Audience:  jwt.ClaimStrings{"test-aud"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})
		tok.Header["kid"] = "v1"
		s, err := tok.SignedString(rsaKey)
		if err != nil {
			t.Fatalf("sign rs256: %v", err)
		}
		if _, err := j.ValidateAccessToken(s); err == nil {
			t.Fatal("RS256 token was ACCEPTED — algorithm confusion is possible")
		}
	})

	t.Run("wrong HMAC secret rejected", func(t *testing.T) {
		s := signHS256(t, "v1", "totally-different-secret-but-also-32-bytes-xxxxxx", time.Now().Add(time.Hour))
		if _, err := j.ValidateAccessToken(s); err == nil {
			t.Fatal("token signed with the wrong secret was ACCEPTED")
		}
	})
}

func TestValidate_KidHandling(t *testing.T) {
	j := newTestJWT(t)

	t.Run("unknown kid rejected", func(t *testing.T) {
		s := signHS256(t, "unknown-kid", testSecret, time.Now().Add(time.Hour))
		if _, err := j.ValidateAccessToken(s); err == nil {
			t.Fatal("token with unknown kid was ACCEPTED")
		}
	})

	t.Run("missing kid rejected", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-iss",
				Audience:  jwt.ClaimStrings{"test-aud"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		})
		s, _ := tok.SignedString([]byte(testSecret))
		if _, err := j.ValidateAccessToken(s); err == nil {
			t.Fatal("token with no kid was ACCEPTED")
		}
	})
}

// TestKeyRotation verifies a token signed by a now-inactive (but still present)
// key continues to validate — the core zero-downtime rotation guarantee.
func TestKeyRotation(t *testing.T) {
	// Phase 1: v1 active. Issue a token.
	j1 := newTestJWT(t)
	pair, err := j1.GenerateTokenPair("u", "u@x.com", nil, "", time.Time{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Phase 2: v2 active, v1 retired but still in the set.
	j2, err := NewJWT(JWTConfig{
		Keys: []JWTKey{
			{ID: "v1", Secret: testSecret, Active: false},
			{ID: "v2", Secret: testSecret2, Active: true},
		},
		Issuer: "test-iss", Audience: "test-aud", AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWT phase2: %v", err)
	}
	if _, err := j2.ValidateAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("token signed by retired key v1 should still validate: %v", err)
	}

	// Phase 3: v1 removed entirely → old token must now fail.
	j3, err := NewJWT(JWTConfig{
		Keys:   []JWTKey{{ID: "v2", Secret: testSecret2, Active: true}},
		Issuer: "test-iss", Audience: "test-aud", AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWT phase3: %v", err)
	}
	if _, err := j3.ValidateAccessToken(pair.AccessToken); err == nil {
		t.Fatal("token signed by removed key v1 should NOT validate")
	}
}

func TestValidate_ExpiredRejected(t *testing.T) {
	j := newTestJWT(t)
	// Past expiry, well beyond the default 30s leeway.
	s := signHS256(t, "v1", testSecret, time.Now().Add(-time.Hour))
	if _, err := j.ValidateAccessToken(s); err == nil {
		t.Fatal("expired token was ACCEPTED")
	}
}

func TestGenerateTokenPair_AbsoluteFamilyDeadline(t *testing.T) {
	j := newTestJWT(t) // RefreshAbsoluteTTL = 72h

	// New family: deadline ≈ now + 72h.
	pair, err := j.GenerateTokenPair("u", "u@x.com", nil, "", time.Time{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	want := time.Now().Add(72 * time.Hour)
	if d := pair.FamilyExpiresAt.Sub(want); d > time.Minute || d < -time.Minute {
		t.Fatalf("new-family FamilyExpiresAt=%v, want ≈%v", pair.FamilyExpiresAt, want)
	}

	// Rotation: the existing family deadline must be preserved unchanged.
	fixed := time.Now().Add(5 * time.Hour).UTC().Truncate(time.Second)
	rotated, err := j.GenerateTokenPair("u", "u@x.com", nil, pair.RefreshTokenFamily, fixed)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !rotated.FamilyExpiresAt.Equal(fixed) {
		t.Fatalf("rotation changed family deadline: got %v want %v", rotated.FamilyExpiresAt, fixed)
	}
	if rotated.RefreshTokenFamily != pair.RefreshTokenFamily {
		t.Fatalf("rotation changed family id")
	}
}

// signHS256 hand-crafts an HS256 token with the given kid, secret and expiry.
func signHS256(t *testing.T, kid, secret string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		UserID: "u",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-iss",
			Audience:  jwt.ClaimStrings{"test-aud"},
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("signHS256: %v", err)
	}
	return s
}
