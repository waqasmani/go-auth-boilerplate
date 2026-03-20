package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

// JWTKey is a single HMAC-SHA256 signing key with a stable, opaque identifier.
//
// Key rotation workflow:
//  1. Generate a new key and append it with Active: false.
//  2. Deploy — old tokens (signed with the old kid) continue to validate
//     because the old key is still in the set.
//  3. Set the new key to Active: true and the old key to Active: false.
//     Deploy — new tokens are now signed with the new key; old tokens still
//     validate until they expire naturally.
//  4. Once the old key's maximum TTL has elapsed (RefreshTTL, typically 30 d),
//     remove the old key entirely and deploy.
//
// No downtime. No forced re-login.
type JWTKey struct {
	// ID is the value written into the JWT "kid" header and used to look up the
	// correct secret during validation. Must be unique across the key set.
	ID string

	// Secret is the raw HMAC signing secret. Minimum 32 bytes required;
	// 64 bytes is preferred for HS256. Never reuse a secret across key IDs.
	Secret string

	// Active marks the single key used to sign newly issued tokens.
	// Exactly one key in the set must have Active: true.
	Active bool
}

// Claims represents JWT claims for access tokens.
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// TokenPair holds an access and refresh token pair returned by GenerateTokenPair.
type TokenPair struct {
	AccessToken        string
	RefreshToken       string // raw token (returned to client)
	RefreshTokenHashed string // SHA-256 hash (stored in DB)
	RefreshTokenFamily string
	RefreshExpiresAt   time.Time
	AccessExpiresAt    time.Time
}

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	// Keys is the full key set. Must contain exactly one Active key.
	Keys       []JWTKey
	Issuer     string
	Audience   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// JWT provides token generation and validation with support for key rotation.
//
// Signing always uses the single Active key. Validation looks up the key by
// the "kid" header so tokens issued before a rotation continue to validate
// until they expire naturally.
type JWT struct {
	cfg       JWTConfig
	activeKey JWTKey
	keyByID   map[string]JWTKey
}

// NewJWT creates and validates a JWT helper. Returns an error describing the
// exact misconfiguration so container.New can surface it as a structured
// startup error rather than a raw stack trace. Common failure modes:
//   - JWT_KEYS / JWT_SECRET missing or malformed (caught by config.Load first,
//     but double-checked here in case the struct is built directly in tests).
//   - No key has Active: true, or more than one does.
//   - A key secret is shorter than 32 bytes (RFC 7518 §3.2 minimum for HS256).
func NewJWT(cfg JWTConfig) (*JWT, error) {
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("jwt: Keys is empty — provide at least one key")
	}

	keyByID := make(map[string]JWTKey, len(cfg.Keys))
	var activeKey JWTKey
	activeCount := 0

	for _, k := range cfg.Keys {
		if k.ID == "" {
			return nil, fmt.Errorf("jwt: a key has an empty ID — every key must have a unique non-empty ID")
		}
		if k.Secret == "" {
			return nil, fmt.Errorf("jwt: key %q has an empty Secret", k.ID)
		}
		if len(k.Secret) < 32 {
			return nil, fmt.Errorf(
				"jwt: key %q secret is %d bytes — minimum 32 bytes required for HS256 (RFC 7518 §3.2)",
				k.ID, len(k.Secret),
			)
		}
		if _, dup := keyByID[k.ID]; dup {
			return nil, fmt.Errorf("jwt: duplicate key ID %q — key IDs must be unique", k.ID)
		}
		keyByID[k.ID] = k
		if k.Active {
			activeKey = k
			activeCount++
		}
	}

	switch activeCount {
	case 0:
		return nil, fmt.Errorf("jwt: no active key — exactly one key must have Active: true")
	case 1:
		// correct
	default:
		return nil, fmt.Errorf("jwt: %d keys have Active: true — exactly one key must be active", activeCount)
	}

	return &JWT{cfg: cfg, activeKey: activeKey, keyByID: keyByID}, nil
}

// generateSecureToken creates a URL-safe base64-encoded string with 64 bytes
// (512 bits) of cryptographic entropy.
func generateSecureToken() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateTokenPair creates a new access + refresh token pair.
// The access token is signed with the active key and carries a "kid" header
// so ValidateAccessToken can look up the correct secret without ambiguity.
//
// family can be empty (new login — a fresh family UUID is generated) or
// provided (token rotation continues the existing session family).
func (j *JWT) GenerateTokenPair(userID, email string, roles []string, family string) (*TokenPair, error) {
	now := time.Now().UTC()

	accessClaims := Claims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.cfg.Issuer,
			Audience:  jwt.ClaimStrings{j.cfg.Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.cfg.AccessTTL)),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	token.Header["kid"] = j.activeKey.ID

	signedAccess, err := token.SignedString([]byte(j.activeKey.Secret))
	if err != nil {
		return nil, fmt.Errorf("jwt: sign access token: %w", err)
	}

	rawRefresh, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("jwt: generate refresh token: %w", err)
	}

	if family == "" {
		family = uuid.NewString()
	}

	return &TokenPair{
		AccessToken:        signedAccess,
		RefreshToken:       rawRefresh,
		RefreshTokenHashed: hashToken(rawRefresh),
		RefreshTokenFamily: family,
		RefreshExpiresAt:   now.Add(j.cfg.RefreshTTL),
		AccessExpiresAt:    now.Add(j.cfg.AccessTTL),
	}, nil
}

// ValidateAccessToken parses and validates a signed JWT access token.
//
// Validation order is intentional and must not be changed:
//  1. Signing algorithm is verified FIRST — this prevents algorithm-confusion
//     attacks where an attacker substitutes a public key as an HMAC secret.
//     Only HMAC variants (HS256/HS384/HS512) are accepted; any other method
//     causes immediate rejection before any key material is touched.
//  2. Key lookup by "kid" header — only reached when the algorithm is
//     confirmed safe. Tokens issued before a key rotation continue to validate
//     as long as their issuing key remains in the set.
func (j *JWT) ValidateAccessToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(t *jwt.Token) (interface{}, error) {
			// ── Step 1: algorithm check — MUST come before key lookup ──────────
			// Rejecting non-HMAC methods here prevents algorithm-confusion
			// attacks (e.g. RS256 / "none") regardless of the kid value.
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf(
					"jwt: algorithm %q is not accepted — only HMAC variants (HS256/HS384/HS512) are allowed",
					t.Header["alg"],
				)
			}

			// ── Step 2: kid lookup — only reached when algorithm is safe ───────
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, fmt.Errorf("jwt: missing or non-string kid header — token must be re-issued")
			}
			key, found := j.keyByID[kid]
			if !found {
				return nil, fmt.Errorf("jwt: unknown kid %q — token must be re-issued", kid)
			}
			return []byte(key.Secret), nil
		},
		jwt.WithIssuer(j.cfg.Issuer),
		jwt.WithAudience(j.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if isExpiredError(err) {
			return nil, apperrors.ErrTokenExpired
		}
		return nil, apperrors.ErrTokenInvalid
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, apperrors.ErrTokenInvalid
	}

	return claims, nil
}

// HashRefreshToken returns the SHA-256 hex hash of a raw refresh token.
//
// Only use this for high-entropy inputs such as the 64-byte opaque refresh
// tokens and URL-safe email tokens produced by generateSecureToken /
// generateURLToken. For low-entropy inputs such as 6-digit OTP codes use
// HMACToken — the full 1,000,000-value OTP space can be precomputed in
// milliseconds against a plain SHA-256 digest.
func HashRefreshToken(raw string) string {
	return hashToken(raw)
}

// HMACToken returns an HMAC-SHA256 hex digest of raw keyed with secret.
//
// Use this — not HashRefreshToken — for any low-entropy input such as a
// 6-digit numeric OTP. Without a server-side secret, all 1,000,000 possible
// SHA-256 digests can be precomputed in milliseconds, making any stored hash
// trivially reversible by anyone with read access to the database. Keying the
// digest with a secret known only to the server eliminates that attack
// regardless of input entropy.
//
// secret must be at least 32 bytes; enforced at startup by config.Load via
// the OTP_HMAC_SECRET minimum-length check.
func HMACToken(raw, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// ── internal helpers ──────────────────────────────────────────────────────────

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func isExpiredError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}
