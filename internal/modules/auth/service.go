package auth

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

//go:generate mockgen -source=service.go -destination=mocks/service_mock.go -package=mocks

// Service defines auth business logic.
type Service interface {
	Register(ctx context.Context, req RegisterRequest) (*TokenResponse, error)
	Login(ctx context.Context, req LoginRequest) (*TokenResponse, error)
	Refresh(ctx context.Context, req RefreshRequest) (*TokenResponse, error)
	Logout(ctx context.Context, req LogoutRequest) error
}

type service struct {
	repo Repository
	jwt  *platformauth.JWT
	log  *zap.Logger
}

// NewService constructs the auth service.
func NewService(repo Repository, jwt *platformauth.JWT, log *zap.Logger) Service {
	return &service{repo: repo, jwt: jwt, log: log}
}

func (s *service) Register(ctx context.Context, req RegisterRequest) (*TokenResponse, error) {
	log := logger.FromContext(ctx).With(zap.String("email", req.Email))

	// Check email uniqueness.
	_, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err == nil {
		return nil, apperrors.ErrEmailAlreadyExists
	}
	if appErr, ok := apperrors.As(err); !ok || appErr.Code != apperrors.ErrNotFound.Code {
		return nil, err
	}

	hash, err := platformauth.HashPassword(req.Password)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	userID := uuid.NewString()
	if err = s.repo.CreateUser(ctx, db.CreateUserParams{
		ID:           userID,
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		PasswordHash: hash,
		Name:         strings.TrimSpace(req.Name),
	}); err != nil {
		return nil, err
	}

	log.Info("user registered", zap.String("user_id", userID))
	return s.issueTokenPair(ctx, userID, req.Email, []string{"user"}, "")
}

func (s *service) Login(ctx context.Context, req LoginRequest) (*TokenResponse, error) {
	user, err := s.repo.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil {
		if appErr, ok := apperrors.As(err); ok && appErr.Code == apperrors.ErrNotFound.Code {
			return nil, apperrors.ErrInvalidCredentials
		}
		return nil, err
	}

	if err = platformauth.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		return nil, apperrors.ErrInvalidCredentials
	}

	logger.FromContext(ctx).Info("user logged in", zap.String("user_id", user.ID))
	return s.issueTokenPair(ctx, user.ID, user.Email, []string{"user"}, "")
}

func (s *service) Refresh(ctx context.Context, req RefreshRequest) (*TokenResponse, error) {
	tokenHash := platformauth.HashRefreshToken(req.RefreshToken)

	// ── 1. Load token record ───────────────────────────────────────────────────
	token, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	// ── 2. Expiry check ───────────────────────────────────────────────────────
	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, apperrors.ErrTokenExpired
	}

	// ── 3. Revocation check (family-level logout) ─────────────────────────────
	// A revoked_at means the whole family was invalidated by a prior logout or
	// reuse event. Check this before the atomic consume so we never issue tokens
	// for a revoked session.
	if token.RevokedAt.Valid {
		return nil, apperrors.ErrTokenRevoked
	}

	// ── 4. Atomic consume — the ONLY place that marks used_at ─────────────────
	//
	// Previous pattern (VULNERABLE):
	//   if token.UsedAt.Valid { ... }   ← read
	//   repo.MarkRefreshTokenUsed(...)  ← write
	//
	// Two goroutines racing on the same token both read UsedAt = NULL, both
	// pass the guard, and both issue fresh token pairs — a full authentication
	// bypass.
	//
	// Fixed pattern:
	//   UPDATE ... SET used_at = NOW() WHERE id = ? AND used_at IS NULL
	//
	// The database serialises the two UPDATEs. Exactly one gets RowsAffected=1
	// (winner); the other gets RowsAffected=0. The loser is treated as reuse,
	// the entire family is revoked, and ErrTokenReuse is returned.
	consumed, err := s.repo.ConsumeRefreshToken(ctx, token.ID)
	if err != nil {
		return nil, err
	}
	if !consumed {
		// RowsAffected == 0: the token was consumed by a concurrent request
		// before this one reached the database. Treat it identically to a
		// detected reuse — revoke the whole session family so the legitimate
		// user is forced to re-authenticate.
		s.log.Warn("refresh token reuse detected (concurrent request) — revoking family",
			zap.String("family", token.TokenFamily),
			zap.String("user_id", token.UserID),
		)
		_ = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily)
		return nil, apperrors.ErrTokenReuse
	}

	// ── 5. Fetch user for up-to-date claims ──────────────────────────────────
	user, err := s.repo.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	logger.FromContext(ctx).Info("token refreshed", zap.String("user_id", user.ID))
	return s.issueTokenPair(ctx, user.ID, user.Email, []string{"user"}, token.TokenFamily)
}

func (s *service) Logout(ctx context.Context, req LogoutRequest) error {
	tokenHash := platformauth.HashRefreshToken(req.RefreshToken)

	token, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		// Idempotent: treat a missing token as already logged out.
		if appErr, ok := apperrors.As(err); ok && appErr.Code == apperrors.ErrTokenInvalid.Code {
			return nil
		}
		return err
	}

	// Revoke entire family — all tokens from this login session are invalidated.
	if err = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily); err != nil {
		return err
	}

	logger.FromContext(ctx).Info("user logged out",
		zap.String("user_id", token.UserID),
		zap.String("family", token.TokenFamily),
	)
	return nil
}

// issueTokenPair generates a token pair, persists the hashed refresh token,
// and returns the public response.
func (s *service) issueTokenPair(ctx context.Context, userID, email string, roles []string, family string) (*TokenResponse, error) {
	pair, err := s.jwt.GenerateTokenPair(userID, email, roles, family)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	if err = s.repo.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		ID:          uuid.NewString(),
		UserID:      userID,
		TokenHash:   pair.RefreshTokenHashed,
		TokenFamily: pair.RefreshTokenFamily,
		ExpiresAt:   pair.RefreshExpiresAt,
	}); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    pair.RefreshExpiresAt,
	}, nil
}
