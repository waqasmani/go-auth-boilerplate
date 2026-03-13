package auth

import (
	"crypto/sha256"
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
	// correct secret during validation.  Must be unique across the key set.
	// Use a short opaque string (e.g. "v1", "2024-01", a UUID fragment).
	ID string

	// Secret is the raw HMAC signing secret.  Minimum 32 bytes recommended;
	// 64 bytes is preferred for HS256.  Never reuse a secret across key IDs.
	Secret string

	// Active marks the single key used to sign newly issued tokens.
	// Exactly one key in the set must have Active: true.
	// Inactive keys are kept to validate tokens issued before the last rotation.
	Active bool
}

// Claims represents JWT claims for access tokens.
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// TokenPair holds an access and refresh token.
type TokenPair struct {
	AccessToken        string
	RefreshToken       string // raw token (returned to client)
	RefreshTokenHashed string // SHA-256 hash (stored in DB)
	RefreshTokenFamily string
	RefreshExpiresAt   time.Time
}

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	// Keys is the full key set.  Must contain exactly one Active key.
	// All other keys are kept for validation during rolling rotation.
	Keys []JWTKey

	Issuer     string
	Audience   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// JWT provides token generation and validation with support for key rotation.
//
// Signing always uses the single Active key.
// Validation looks up the key by the "kid" header so tokens issued before a
// rotation continue to validate until they expire naturally.
type JWT struct {
	cfg       JWTConfig
	activeKey JWTKey            // the one key with Active==true; selected at construction
	keyByID   map[string]JWTKey // O(1) lookup during validation
}

// NewJWT creates a new JWT helper.  It panics at startup — not at request time
// — when the key set is invalid so a misconfiguration is caught immediately
// rather than silently producing unverifiable tokens in production.
//
// Invariants enforced:
//   - at least one key must be present
//   - every key must have a non-empty ID and non-empty Secret
//   - no two keys may share the same ID
//   - exactly one key must have Active: true
func NewJWT(cfg JWTConfig) *JWT {
	if len(cfg.Keys) == 0 {
		panic("jwt: Keys is empty — provide at least one key")
	}

	keyByID := make(map[string]JWTKey, len(cfg.Keys))
	var activeKey JWTKey
	activeCount := 0

	for _, k := range cfg.Keys {
		if k.ID == "" {
			panic("jwt: a key has an empty ID — every key must have a unique non-empty ID")
		}
		if k.Secret == "" {
			panic(fmt.Sprintf("jwt: key %q has an empty Secret", k.ID))
		}
		if _, dup := keyByID[k.ID]; dup {
			panic(fmt.Sprintf("jwt: duplicate key ID %q — key IDs must be unique", k.ID))
		}
		keyByID[k.ID] = k
		if k.Active {
			activeKey = k
			activeCount++
		}
	}

	switch activeCount {
	case 0:
		panic("jwt: no active key — exactly one key must have Active: true")
	case 1:
		// correct
	default:
		panic(fmt.Sprintf("jwt: %d keys have Active: true — exactly one key must be active", activeCount))
	}

	return &JWT{cfg: cfg, activeKey: activeKey, keyByID: keyByID}
}

// GenerateTokenPair creates a new access + refresh token pair.
// The access token is signed with the active key and carries a "kid" header
// so ValidateAccessToken can look up the correct secret without ambiguity.
//
// family can be empty (new login, a fresh family UUID is generated) or
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

	// Set kid so ValidateAccessToken can select the right secret without
	// having to try every key in the set.  This is safe to include in the
	// header because it names the key, not the secret.
	token.Header["kid"] = j.activeKey.ID

	signedAccess, err := token.SignedString([]byte(j.activeKey.Secret))
	if err != nil {
		return nil, fmt.Errorf("jwt: sign access token: %w", err)
	}

	// Refresh token — opaque UUID (not a JWT).
	rawRefresh := uuid.NewString()
	hashedRefresh := hashToken(rawRefresh)
	refreshExp := now.Add(j.cfg.RefreshTTL)

	if family == "" {
		family = uuid.NewString()
	}

	return &TokenPair{
		AccessToken:        signedAccess,
		RefreshToken:       rawRefresh,
		RefreshTokenHashed: hashedRefresh,
		RefreshTokenFamily: family,
		RefreshExpiresAt:   refreshExp,
	}, nil
}

// ValidateAccessToken parses and validates a signed JWT access token.
//
// The "kid" header is read from the (unverified) token header, the
// corresponding key is looked up in the key set, and the signature is
// verified with that key's secret.  This means tokens issued before a key
// rotation continue to validate as long as their issuing key remains in the
// set — the active/inactive flag only governs signing.
func (j *JWT) ValidateAccessToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}

			// Extract kid from the parsed (but not yet verified) header.
			// The library guarantees the header is decoded before the keyfunc
			// is called, so this is always populated for well-formed tokens.
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				// Tokens without a kid were issued before this fix was deployed.
				// Reject them so we don't silently accept unidentified tokens
				// after a rotation removes the old secret from the key set.
				return nil, fmt.Errorf("jwt: missing kid header — token must be re-issued")
			}

			key, found := j.keyByID[kid]
			if !found {
				// The key was removed from the set (post-rotation cleanup) or
				// the token was forged with an unknown kid.
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
func HashRefreshToken(raw string) string {
	return hashToken(raw)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func isExpiredError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}
