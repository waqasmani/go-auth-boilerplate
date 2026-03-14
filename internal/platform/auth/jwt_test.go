package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// ─── Fixtures ─────────────────────────────────────────────────────────────────

// Secrets are 64-byte hex strings — acceptable for HS256 in tests.
// Never reuse test secrets in production.
const (
	secretV1 = "test-secret-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	secretV2 = "test-secret-v2-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
)

// singleKeyJWT is the common case: one active key, nothing in rotation.
func singleKeyJWT(t *testing.T) *platformauth.JWT {
	t.Helper()
	return platformauth.NewJWT(platformauth.JWTConfig{
		Keys:       []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
	})
}

// ─── GenerateTokenPair ────────────────────────────────────────────────────────

func TestGenerateTokenPair_ReturnsNonEmptyTokens(t *testing.T) {
	j := singleKeyJWT(t)

	pair, err := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}
	if pair.RefreshTokenHashed == "" {
		t.Error("RefreshTokenHashed is empty")
	}
	if pair.RefreshTokenFamily == "" {
		t.Error("RefreshTokenFamily is empty — should be auto-generated when empty family is passed")
	}
	if pair.RefreshExpiresAt.IsZero() {
		t.Error("RefreshExpiresAt is zero")
	}
}

func TestGenerateTokenPair_FamilyPreservedWhenProvided(t *testing.T) {
	j := singleKeyJWT(t)
	const family = "existing-family-uuid"

	pair, err := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, family)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pair.RefreshTokenFamily != family {
		t.Errorf("got family %q, want %q", pair.RefreshTokenFamily, family)
	}
}

func TestGenerateTokenPair_EmptyFamilyGeneratesNewUUID(t *testing.T) {
	j := singleKeyJWT(t)

	p1, _ := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")
	p2, _ := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	if p1.RefreshTokenFamily == p2.RefreshTokenFamily {
		t.Error("two calls with empty family produced the same family UUID — should be unique")
	}
}

func TestGenerateTokenPair_RefreshTokenIsOpaqueNotJWT(t *testing.T) {
	j := singleKeyJWT(t)

	pair, _ := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	// A JWT contains exactly two dots; a UUID/opaque token contains none.
	if strings.Count(pair.RefreshToken, ".") >= 2 {
		t.Error("RefreshToken looks like a JWT — it should be an opaque token")
	}
}

func TestGenerateTokenPair_HashIsDeterministic(t *testing.T) {
	j := singleKeyJWT(t)

	pair, _ := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	got := platformauth.HashRefreshToken(pair.RefreshToken)
	if got != pair.RefreshTokenHashed {
		t.Errorf("HashRefreshToken(%q) = %q, want %q", pair.RefreshToken, got, pair.RefreshTokenHashed)
	}
}

func TestGenerateTokenPair_AccessTokenCarriesKidHeader(t *testing.T) {
	j := singleKeyJWT(t)

	pair, _ := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	// Parse without verifying so we can inspect the header directly.
	tok, _, err := jwt.NewParser().ParseUnverified(pair.AccessToken, &platformauth.Claims{})
	if err != nil {
		t.Fatalf("could not parse token header: %v", err)
	}
	kid, ok := tok.Header["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("kid header absent or empty, got %v", tok.Header["kid"])
	}
	if kid != "v1" {
		t.Errorf("kid = %q, want %q", kid, "v1")
	}
}

// ─── ValidateAccessToken — happy path ─────────────────────────────────────────

func TestValidateAccessToken_ValidToken(t *testing.T) {
	j := singleKeyJWT(t)

	pair, _ := j.GenerateTokenPair("user-42", "alice@example.com", []string{"user", "admin"}, "")

	claims, err := j.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "user-42" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-42")
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "alice@example.com")
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "user" || claims.Roles[1] != "admin" {
		t.Errorf("Roles = %v, want [user admin]", claims.Roles)
	}
}

// ─── ValidateAccessToken — error cases ────────────────────────────────────────

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	j := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:       []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		AccessTTL:  -1 * time.Second, // already expired at issuance
		RefreshTTL: 720 * time.Hour,
	})

	pair, _ := j.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	_, err := j.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected TOKEN_EXPIRED error, got nil")
	}
	assertAppErrorCode(t, err, "TOKEN_EXPIRED")
}

func TestValidateAccessToken_Malformed(t *testing.T) {
	j := singleKeyJWT(t)

	_, err := j.ValidateAccessToken("this.is.not.a.jwt")
	if err == nil {
		t.Fatal("expected TOKEN_INVALID error, got nil")
	}
	assertAppErrorCode(t, err, "TOKEN_INVALID")
}

func TestValidateAccessToken_EmptyString(t *testing.T) {
	j := singleKeyJWT(t)

	_, err := j.ValidateAccessToken("")
	if err == nil {
		t.Fatal("expected TOKEN_INVALID error for empty string")
	}
	assertAppErrorCode(t, err, "TOKEN_INVALID")
}

func TestValidateAccessToken_WrongSecret(t *testing.T) {
	signer := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:       []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
	})
	validator := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:       []platformauth.JWTKey{{ID: "v1", Secret: secretV2, Active: true}}, // different secret, same kid
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
	})

	pair, _ := signer.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	_, err := validator.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected TOKEN_INVALID for wrong secret, got nil")
	}
	assertAppErrorCode(t, err, "TOKEN_INVALID")
}

func TestValidateAccessToken_WrongIssuer(t *testing.T) {
	signer := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:    "issuer-a",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})
	validator := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:    "issuer-b",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})

	pair, _ := signer.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	_, err := validator.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected TOKEN_INVALID for wrong issuer")
	}
	assertAppErrorCode(t, err, "TOKEN_INVALID")
}

func TestValidateAccessToken_WrongAudience(t *testing.T) {
	signer := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:    "test-issuer",
		Audience:  "audience-a",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})
	validator := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:    "test-issuer",
		Audience:  "audience-b",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})

	pair, _ := signer.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	_, err := validator.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected TOKEN_INVALID for wrong audience")
	}
	assertAppErrorCode(t, err, "TOKEN_INVALID")
}

func TestValidateAccessToken_UnknownKid(t *testing.T) {
	signer := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})
	// Validator only knows about v2 — v1 tokens are "unknown kid".
	validator := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v2", Secret: secretV2, Active: true}},
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})

	pair, _ := signer.GenerateTokenPair("user-1", "user@example.com", []string{"user"}, "")

	_, err := validator.ValidateAccessToken(pair.AccessToken)
	if err == nil {
		t.Fatal("expected TOKEN_INVALID for unknown kid")
	}
	assertAppErrorCode(t, err, "TOKEN_INVALID")
}

// ─── Key rotation ─────────────────────────────────────────────────────────────

// TestRotation_OldTokenValidDuringWindow simulates the middle of a rotation:
//   - v1 was the active key; tokens were issued with kid=v1
//   - v2 is now active; new tokens will carry kid=v2
//   - both keys are in the set so old (v1) tokens still validate
func TestRotation_OldTokenValidDuringWindow(t *testing.T) {
	// Step 1: issue a token with the old active key (v1).
	preRotation := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})
	oldPair, _ := preRotation.GenerateTokenPair("user-1", "u@example.com", []string{"user"}, "")

	// Step 2: rotate — v2 is now active, v1 kept for the validation window.
	postRotation := platformauth.NewJWT(platformauth.JWTConfig{
		Keys: []platformauth.JWTKey{
			{ID: "v1", Secret: secretV1, Active: false}, // old key: inactive but still validates
			{ID: "v2", Secret: secretV2, Active: true},  // new key: signs new tokens
		},
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})

	// Old token (kid=v1) must still be accepted.
	claims, err := postRotation.ValidateAccessToken(oldPair.AccessToken)
	if err != nil {
		t.Fatalf("old token rejected during rotation window: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-1")
	}
}

// TestRotation_NewTokenSignedWithNewKey confirms that after rotation, newly
// issued tokens carry kid=v2 and are verifiable with v2's secret.
func TestRotation_NewTokenSignedWithNewKey(t *testing.T) {
	postRotation := platformauth.NewJWT(platformauth.JWTConfig{
		Keys: []platformauth.JWTKey{
			{ID: "v1", Secret: secretV1, Active: false},
			{ID: "v2", Secret: secretV2, Active: true},
		},
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})

	newPair, _ := postRotation.GenerateTokenPair("user-2", "b@example.com", []string{"user"}, "")

	// Confirm kid is v2.
	tok, _, _ := jwt.NewParser().ParseUnverified(newPair.AccessToken, &platformauth.Claims{})
	if kid := tok.Header["kid"]; kid != "v2" {
		t.Errorf("new token kid = %v, want v2", kid)
	}

	// Confirm post-rotation validator accepts the new token.
	if _, err := postRotation.ValidateAccessToken(newPair.AccessToken); err != nil {
		t.Fatalf("new token rejected: %v", err)
	}
}

// TestRotation_OldTokenRejectedAfterKeyRemoval simulates step 4 of the rotation
// runbook: the old key has been removed because its max-TTL window has elapsed.
// Old tokens must now be rejected.
func TestRotation_OldTokenRejectedAfterKeyRemoval(t *testing.T) {
	preRotation := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: true}},
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})
	oldPair, _ := preRotation.GenerateTokenPair("user-1", "u@example.com", []string{"user"}, "")

	// v1 removed — only v2 remains.
	cleanedUp := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:      []platformauth.JWTKey{{ID: "v2", Secret: secretV2, Active: true}},
		Issuer:    "test-issuer",
		Audience:  "test-audience",
		AccessTTL: 15 * time.Minute, RefreshTTL: 720 * time.Hour,
	})

	_, err := cleanedUp.ValidateAccessToken(oldPair.AccessToken)
	if err == nil {
		t.Fatal("expected TOKEN_INVALID after key removal, got nil")
	}
	assertAppErrorCode(t, err, "TOKEN_INVALID")
}

// ─── NewJWT constructor panics ─────────────────────────────────────────────────

func TestNewJWT_PanicsOnEmptyKeys(t *testing.T) {
	assertPanics(t, "empty Keys slice", func() {
		platformauth.NewJWT(platformauth.JWTConfig{
			Issuer: "x", Audience: "x",
			AccessTTL: time.Minute, RefreshTTL: time.Hour,
		})
	})
}

func TestNewJWT_PanicsOnNoActiveKey(t *testing.T) {
	assertPanics(t, "no active key", func() {
		platformauth.NewJWT(platformauth.JWTConfig{
			Keys:      []platformauth.JWTKey{{ID: "v1", Secret: secretV1, Active: false}},
			Issuer:    "x",
			Audience:  "x",
			AccessTTL: time.Minute, RefreshTTL: time.Hour,
		})
	})
}

func TestNewJWT_PanicsOnMultipleActiveKeys(t *testing.T) {
	assertPanics(t, "two active keys", func() {
		platformauth.NewJWT(platformauth.JWTConfig{
			Keys: []platformauth.JWTKey{
				{ID: "v1", Secret: secretV1, Active: true},
				{ID: "v2", Secret: secretV2, Active: true},
			},
			Issuer:    "x",
			Audience:  "x",
			AccessTTL: time.Minute, RefreshTTL: time.Hour,
		})
	})
}

func TestNewJWT_PanicsOnDuplicateKeyID(t *testing.T) {
	assertPanics(t, "duplicate key ID", func() {
		platformauth.NewJWT(platformauth.JWTConfig{
			Keys: []platformauth.JWTKey{
				{ID: "v1", Secret: secretV1, Active: true},
				{ID: "v1", Secret: secretV2, Active: false}, // same ID
			},
			Issuer:    "x",
			Audience:  "x",
			AccessTTL: time.Minute, RefreshTTL: time.Hour,
		})
	})
}

func TestNewJWT_PanicsOnEmptyKeyID(t *testing.T) {
	assertPanics(t, "empty key ID", func() {
		platformauth.NewJWT(platformauth.JWTConfig{
			Keys:      []platformauth.JWTKey{{ID: "", Secret: secretV1, Active: true}},
			Issuer:    "x",
			Audience:  "x",
			AccessTTL: time.Minute, RefreshTTL: time.Hour,
		})
	})
}

func TestNewJWT_PanicsOnEmptySecret(t *testing.T) {
	assertPanics(t, "empty secret", func() {
		platformauth.NewJWT(platformauth.JWTConfig{
			Keys:      []platformauth.JWTKey{{ID: "v1", Secret: "", Active: true}},
			Issuer:    "x",
			Audience:  "x",
			AccessTTL: time.Minute, RefreshTTL: time.Hour,
		})
	})
}

// ─── HashRefreshToken ─────────────────────────────────────────────────────────

func TestHashRefreshToken_Deterministic(t *testing.T) {
	const raw = "some-opaque-refresh-token"
	if h1, h2 := platformauth.HashRefreshToken(raw), platformauth.HashRefreshToken(raw); h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
}

func TestHashRefreshToken_DifferentInputsDifferentHashes(t *testing.T) {
	h1 := platformauth.HashRefreshToken("token-a")
	h2 := platformauth.HashRefreshToken("token-b")
	if h1 == h2 {
		t.Error("different inputs produced the same hash")
	}
}

func TestHashRefreshToken_IsHex64Chars(t *testing.T) {
	// SHA-256 produces 32 bytes = 64 hex characters.
	h := platformauth.HashRefreshToken("any-token")
	if len(h) != 64 {
		t.Errorf("hash length = %d, want 64", len(h))
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("non-hex character %q in hash %q", c, h)
			break
		}
	}
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

// assertAppErrorCode checks that err is a non-nil *apperrors.AppError with the
// expected Code.  Imported inline to keep the test file self-contained.
func assertAppErrorCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected AppError with code %q, got nil", wantCode)
	}
	// Simplest portable approach: stringify and check prefix.
	// AppError.Error() returns "[CODE] message" so we can check the prefix.
	errStr := err.Error()
	wantPrefix := "[" + wantCode + "]"
	if !strings.HasPrefix(errStr, wantPrefix) {
		t.Errorf("error = %q, want code %q", errStr, wantCode)
	}
}

// assertPanics asserts that fn panics, failing the test if it does not.
func assertPanics(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for case %q, but did not panic", name)
		}
	}()
	fn()
}
