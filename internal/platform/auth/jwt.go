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
	Secret     string
	Issuer     string
	Audience   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// JWT provides token generation and validation.
type JWT struct {
	cfg JWTConfig
}

// NewJWT creates a new JWT helper.
func NewJWT(cfg JWTConfig) *JWT {
	return &JWT{cfg: cfg}
}

// GenerateTokenPair creates a new access + refresh token pair.
// family can be empty (new login) or provided (token rotation keeps same family).
func (j *JWT) GenerateTokenPair(userID, email string, roles []string, family string) (*TokenPair, error) {
	now := time.Now().UTC()

	// Access token
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

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccess, err := accessToken.SignedString([]byte(j.cfg.Secret))
	if err != nil {
		return nil, fmt.Errorf("jwt: sign access token: %w", err)
	}

	// Refresh token — opaque UUID (not a JWT)
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
func (j *JWT) ValidateAccessToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(j.cfg.Secret), nil
	},
		jwt.WithIssuer(j.cfg.Issuer),
		jwt.WithAudience(j.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		switch {
		case isExpiredError(err):
			return nil, apperrors.ErrTokenExpired
		default:
			return nil, apperrors.ErrTokenInvalid
		}
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
