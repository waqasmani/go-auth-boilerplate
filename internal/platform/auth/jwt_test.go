package auth_test

import (
	"testing"
	"time"

	"github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

func newTestJWT() *auth.JWT {
	return auth.NewJWT(auth.JWTConfig{
		Secret:     "test-secret-at-least-32-characters-long",
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
}

func TestGenerateAndValidateTokenPair(t *testing.T) {
	j := newTestJWT()

	pair, err := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if pair.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
	if pair.RefreshTokenHashed == "" {
		t.Error("expected non-empty hashed refresh token")
	}
	if pair.RefreshTokenFamily == "" {
		t.Error("expected non-empty token family")
	}
	if pair.RefreshToken == pair.RefreshTokenHashed {
		t.Error("raw and hashed refresh tokens must differ")
	}

	claims, err := j.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("expected user_id=user-1, got %s", claims.UserID)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email=user@example.com, got %s", claims.Email)
	}
}

func TestTokenRotationPreservesFamily(t *testing.T) {
	j := newTestJWT()

	first, _ := j.GenerateTokenPair("u1", "u@example.com", []string{"user"}, "")
	second, err := j.GenerateTokenPair("u1", "u@example.com", []string{"user"}, first.RefreshTokenFamily)
	if err != nil {
		t.Fatalf("second GenerateTokenPair: %v", err)
	}
	if first.RefreshTokenFamily != second.RefreshTokenFamily {
		t.Errorf("family should be preserved across rotation: %s != %s",
			first.RefreshTokenFamily, second.RefreshTokenFamily)
	}
}

func TestValidateAccessToken_InvalidToken(t *testing.T) {
	j := newTestJWT()
	_, err := j.ValidateAccessToken("not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidateAccessToken_WrongSecret(t *testing.T) {
	j1 := newTestJWT()
	j2 := auth.NewJWT(auth.JWTConfig{
		Secret:     "different-secret-at-least-32-characters",
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})

	pair, _ := j1.GenerateTokenPair("u1", "u@example.com", []string{"user"}, "")
	_, err := j2.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected error when validating with wrong secret")
	}
}

func TestHashRefreshToken_Deterministic(t *testing.T) {
	raw := "some-opaque-token"
	h1 := auth.HashRefreshToken(raw)
	h2 := auth.HashRefreshToken(raw)
	if h1 != h2 {
		t.Error("hash must be deterministic")
	}
	if h1 == raw {
		t.Error("hash must differ from raw token")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got len=%d", len(h1))
	}
}

func TestHashPassword_And_Verify(t *testing.T) {
	plain := "my-secure-password"
	hash, err := auth.HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == plain {
		t.Error("hash must differ from plaintext")
	}

	if err = auth.VerifyPassword(plain, hash); err != nil {
		t.Errorf("VerifyPassword should succeed: %v", err)
	}
	if err = auth.VerifyPassword("wrong-password", hash); err == nil {
		t.Error("VerifyPassword should fail for wrong password")
	}
}
