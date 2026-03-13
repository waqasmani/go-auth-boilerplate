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

// Register creates a new user account and issues a token pair.
//
// The INSERT into users and the INSERT into refresh_tokens are wrapped in a
// single transaction: if the process dies or the token insert fails after the
// user row is written, both writes are rolled back together.  The caller
// receives a 500 with no partial state left in the database.
func (s *service) Register(ctx context.Context, req RegisterRequest) (*TokenResponse, error) {
	log := logger.FromContext(ctx).With(zap.String("email", req.Email))

	// Check email uniqueness before opening a transaction — avoids holding
	// locks during a read that is very likely to succeed on the hot path.
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
	userParams := db.CreateUserParams{
		ID:           userID,
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		PasswordHash: hash,
		Name:         strings.TrimSpace(req.Name),
	}

	// Atomically: INSERT user row + INSERT refresh token.
	// On any failure the transaction rolls back — no orphaned user with no session.
	var tokenResp *TokenResponse
	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		if err := tx.CreateUser(ctx, userParams); err != nil {
			return err
		}
		var txErr error
		tokenResp, txErr = s.issueTokenPair(ctx, tx, userID, req.Email, []string{"user"}, "")
		return txErr
	}); err != nil {
		return nil, err
	}

	log.Info("user registered", zap.String("user_id", userID))
	return tokenResp, nil
}

// Login verifies credentials and issues a token pair.
//
// Login only writes a single row (CreateRefreshToken), so no transaction is
// needed — a single INSERT is already atomic.
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

	tokenResp, err := s.issueTokenPair(ctx, s.repo, user.ID, user.Email, []string{"user"}, "")
	if err != nil {
		return nil, err
	}

	logger.FromContext(ctx).Info("user logged in", zap.String("user_id", user.ID))
	return tokenResp, nil
}

// Refresh rotates the token pair for an existing session.
//
// The ConsumeRefreshToken UPDATE and the CreateRefreshToken INSERT are wrapped
// in a single transaction so the two writes are atomic:
//
//   - If CreateRefreshToken fails after ConsumeRefreshToken succeeds, the
//     UPDATE is rolled back — the old token is NOT consumed and the client can
//     retry with the same refresh token.
//   - Concurrent requests racing on the same token: the database serialises
//     the ConsumeRefreshToken UPDATEs.  The loser gets RowsAffected == 0
//     inside the transaction, returns ErrTokenReuse, and the callback rolls
//     back.  Family revocation is fired outside the transaction (see below).
//
// Family revocation on reuse MUST happen outside the transaction so it commits
// regardless of the transaction outcome.  The callback returns ErrTokenReuse
// as a sentinel; WithTx rolls back (harmless — the UPDATE did nothing), and
// the caller fires RevokeRefreshTokenFamily unconditionally on that sentinel.
func (s *service) Refresh(ctx context.Context, req RefreshRequest) (*TokenResponse, error) {
	tokenHash := platformauth.HashRefreshToken(req.RefreshToken)

	// ── 1. Load token record (outside tx — read-only) ─────────────────────────
	token, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	// ── 2. Expiry check ───────────────────────────────────────────────────────
	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, apperrors.ErrTokenExpired
	}

	// ── 3. Revocation check (family-level logout) ─────────────────────────────
	if token.RevokedAt.Valid {
		return nil, apperrors.ErrTokenRevoked
	}

	// ── 4. Fetch user for up-to-date claims (outside tx — read-only) ──────────
	// If the user is deleted between this read and the transaction, the foreign
	// key constraint on refresh_tokens.user_id will cause CreateRefreshToken to
	// fail and the transaction to roll back cleanly.
	user, err := s.repo.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	// ── 5. Atomically: consume old token + issue new token pair ───────────────
	var tokenResp *TokenResponse
	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		consumed, err := tx.ConsumeRefreshToken(ctx, token.ID)
		if err != nil {
			return err
		}
		if !consumed {
			// RowsAffected == 0: a concurrent request already consumed this
			// token.  Return the reuse sentinel — WithTx rolls back, and the
			// caller below fires family revocation outside the transaction.
			return apperrors.ErrTokenReuse
		}

		tokenResp, err = s.issueTokenPair(ctx, tx, user.ID, user.Email, []string{"user"}, token.TokenFamily)
		return err
	}); err != nil {
		// Family revocation is a security action that must commit regardless of
		// whether anything else in the transaction succeeded.  Fire it outside
		// the rolled-back transaction on the main repo.
		if appErr, ok := apperrors.As(err); ok && appErr.Code == apperrors.ErrTokenReuse.Code {
			s.log.Warn("refresh token reuse detected — revoking family",
				zap.String("family", token.TokenFamily),
				zap.String("user_id", token.UserID),
			)
			_ = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily)
		}
		return nil, err
	}

	logger.FromContext(ctx).Info("token refreshed", zap.String("user_id", user.ID))
	return tokenResp, nil
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

// issueTokenPair generates a JWT access token + opaque refresh token, persists
// the hashed refresh token via repo, and returns the public response.
//
// repo is an explicit parameter (not s.repo) so callers can pass a
// transaction-scoped Repository when the token creation must be atomic with
// other writes in the same transaction (Register, Refresh).  Login passes
// s.repo directly since it only performs a single write.
func (s *service) issueTokenPair(ctx context.Context, repo Repository, userID, email string, roles []string, family string) (*TokenResponse, error) {
	pair, err := s.jwt.GenerateTokenPair(userID, email, roles, family)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	if err = repo.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
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
