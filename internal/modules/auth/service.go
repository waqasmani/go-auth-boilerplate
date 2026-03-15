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

// MFAChallenger is implemented by authemail.Service. Defined here so the auth
// package owns the contract without importing auth_email. Wired in app.go via
// SetMFAChallenger after both modules are constructed.
type MFAChallenger interface {
	// InitiateChallenge invalidates live OTPs for userID, generates a fresh OTP,
	// emails it, and returns an opaque challenge token the client must present
	// alongside the OTP code at POST /auth/otp/verify.
	InitiateChallenge(ctx context.Context, userID, email, name string) (challengeToken string, expiresAt time.Time, err error)
}

// Service defines the auth business-logic contract.
type Service interface {
	Register(ctx context.Context, req RegisterRequest) (*TokenResponse, error)
	// Login returns a LoginResult whose Token is set for normal logins and
	// whose Challenge is set when the user has two_fa_enabled = true.
	Login(ctx context.Context, req LoginRequest) (*LoginResult, error)
	Refresh(ctx context.Context, req RefreshRequest) (*TokenResponse, error)
	Logout(ctx context.Context, req LogoutRequest) error
	// SetMFAChallenger injects the auth_email dependency. Must be called once
	// in app.go after both modules are constructed.
	SetMFAChallenger(c MFAChallenger)
	// IssueTokensForUser is called by auth_email.Service to complete an MFA
	// login. It fetches fresh user data and issues a full token pair.
	IssueTokensForUser(ctx context.Context, userID string) (*platformauth.SessionTokens, error)
}

type service struct {
	repo          Repository
	jwt           *platformauth.JWT
	log           *zap.Logger
	mfaChallenger MFAChallenger // injected post-construction; nil until SetMFAChallenger is called
}

// NewService constructs the auth service.
func NewService(repo Repository, jwt *platformauth.JWT, log *zap.Logger) Service {
	return &service{repo: repo, jwt: jwt, log: log}
}

// SetMFAChallenger injects the MFA challenge initiator (auth_email.Service).
// Not safe to call concurrently with Login; call once during app startup.
func (s *service) SetMFAChallenger(c MFAChallenger) {
	s.mfaChallenger = c
}

// Register creates a new user account and issues a token pair.
// No email verification is required immediately after registration — the client
// receives a working token pair and the verification email is sent separately
// via POST /auth/send-verification (JWT-protected) or triggered automatically
// by the registration handler.
func (s *service) Register(ctx context.Context, req RegisterRequest) (*TokenResponse, error) {
	log := logger.FromContext(ctx).With(zap.String("email", req.Email))

	normalizedEmail := strings.ToLower(strings.TrimSpace(req.Email))
	hash, err := platformauth.HashPassword(req.Password)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	userID := uuid.NewString()
	userParams := db.CreateUserParams{
		ID:           userID,
		Email:        normalizedEmail,
		PasswordHash: hash,
		Name:         strings.TrimSpace(req.Name),
	}

	var tokenResp *TokenResponse
	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		if err := tx.CreateUser(ctx, userParams); err != nil {
			return err
		}
		if err := tx.AssignUserRole(ctx, userID, "user"); err != nil {
			return err
		}
		var txErr error
		tokenResp, txErr = s.issueTokenPair(ctx, tx, userID, normalizedEmail, []string{"user"}, "")
		return txErr
	}); err != nil {
		return nil, err
	}

	log.Info("user registered", zap.String("user_id", userID))
	return tokenResp, nil
}

// Login verifies credentials and either issues a token pair or initiates an
// MFA challenge, depending on the user's security settings.
//
// Gate order is intentional and must not be changed:
//
//  1. Credential check  — always first; timing must not reveal which gate
//     caused the rejection.
//  2. Email verification — checked before 2FA so an unverified-2FA-enabled
//     account cannot be used to probe the MFA flow.
//  3. 2FA gate          — only reached when credentials are valid and email
//     is verified.
func (s *service) Login(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	user, err := s.repo.GetUserByEmailWithRoles(ctx, strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil {
		if appErr, ok := apperrors.As(err); ok && appErr.Code == apperrors.ErrNotFound.Code {
			return nil, apperrors.ErrInvalidCredentials
		}
		return nil, err
	}

	// ── 1. Credential check ───────────────────────────────────────────────────
	if err = platformauth.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		return nil, apperrors.ErrInvalidCredentials
	}

	// ── 2. Email verification gate ────────────────────────────────────────────
	// Unverified accounts may not log in. The client should redirect to a
	// "check your inbox" page and offer POST /auth/resend-verification.
	if !user.EmailVerified {
		return nil, apperrors.ErrEmailNotVerified
	}

	// ── 3. 2FA gate ───────────────────────────────────────────────────────────
	if user.TwoFAEnabled {
		if s.mfaChallenger == nil {
			// 2FA is enabled in the DB but the challenger was never wired in
			// app.go. Fail closed — better to block login than silently bypass.
			s.log.Error("2FA enabled for user but MFAChallenger not configured — check app.go wiring",
				zap.String("user_id", user.ID),
			)
			return nil, apperrors.ErrInternalServer
		}

		challengeToken, expiresAt, err := s.mfaChallenger.InitiateChallenge(
			ctx, user.ID, user.Email, user.Name,
		)
		if err != nil {
			return nil, err
		}

		logger.FromContext(ctx).Info("2FA challenge issued", zap.String("user_id", user.ID))
		return &LoginResult{
			Challenge: &MFAChallengeResponse{
				RequiresMFA: true,
				MFAToken:    challengeToken,
				ExpiresAt:   expiresAt,
			},
		}, nil
	}

	// ── 4. Non-2FA: issue token pair directly ─────────────────────────────────
	tokenResp, err := s.issueTokenPair(ctx, s.repo, user.ID, user.Email, user.Roles, "")
	if err != nil {
		return nil, err
	}

	logger.FromContext(ctx).Info("user logged in", zap.String("user_id", user.ID))
	return &LoginResult{Token: tokenResp}, nil
}

// Refresh rotates the token pair for an existing session.
func (s *service) Refresh(ctx context.Context, req RefreshRequest) (*TokenResponse, error) {
	tokenHash := platformauth.HashRefreshToken(req.RefreshToken)

	token, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, apperrors.ErrTokenExpired
	}

	if token.RevokedAt.Valid {
		return nil, apperrors.ErrTokenRevoked
	}

	if token.UsedAt.Valid {
		s.log.Warn("used token presented — possible replay attack, revoking family",
			zap.String("family", token.TokenFamily),
			zap.String("user_id", token.UserID),
		)
		_ = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily)
		return nil, apperrors.ErrTokenReuse
	}

	user, err := s.repo.GetUserByIDWithRoles(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	var tokenResp *TokenResponse
	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		consumed, err := tx.ConsumeRefreshToken(ctx, token.ID)
		if err != nil {
			return err
		}
		if !consumed {
			return apperrors.ErrTokenReuse
		}
		tokenResp, err = s.issueTokenPair(ctx, tx, user.ID, user.Email, user.Roles, token.TokenFamily)
		return err
	}); err != nil {
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

// Logout revokes the session family associated with the supplied refresh token.
func (s *service) Logout(ctx context.Context, req LogoutRequest) error {
	tokenHash := platformauth.HashRefreshToken(req.RefreshToken)

	token, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if appErr, ok := apperrors.As(err); ok && appErr.Code == apperrors.ErrTokenInvalid.Code {
			return nil
		}
		return err
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil
	}
	if token.RevokedAt.Valid {
		return nil
	}
	if token.UsedAt.Valid {
		_ = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily)
		return nil
	}

	if err = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily); err != nil {
		return err
	}

	logger.FromContext(ctx).Info("user logged out",
		zap.String("user_id", token.UserID),
		zap.String("family", token.TokenFamily),
	)
	return nil
}

// IssueTokensForUser fetches fresh user data and issues a token pair.
// Called by auth_email.Service to complete an MFA login after both the
// challenge token and OTP have been consumed. The user data is re-fetched
// here rather than trusted from the challenge token payload so that role
// changes made between login-initiation and OTP-completion are reflected.
func (s *service) IssueTokensForUser(ctx context.Context, userID string) (*platformauth.SessionTokens, error) {
	user, err := s.repo.GetUserByIDWithRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	resp, err := s.issueTokenPair(ctx, s.repo, user.ID, user.Email, user.Roles, "")
	if err != nil {
		return nil, err
	}

	return &platformauth.SessionTokens{
		AccessToken:           resp.AccessToken,
		RefreshToken:          resp.RefreshToken,
		TokenType:             resp.TokenType,
		AccessTokenExpiresAt:  resp.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: resp.RefreshTokenExpiresAt,
	}, nil
}

// issueTokenPair generates a JWT access token + opaque refresh token, persists
// the hashed refresh token, and returns the public response.
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
		AccessToken:           pair.AccessToken,
		RefreshToken:          pair.RefreshToken,
		TokenType:             "Bearer",
		AccessTokenExpiresAt:  pair.AccessExpiresAt,
		RefreshTokenExpiresAt: pair.RefreshExpiresAt,
	}, nil
}
