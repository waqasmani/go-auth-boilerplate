package auth

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

//go:generate mockgen -source=service.go -destination=mocks/service_mock.go -package=mocks

// tokenCleanupOpTimeout is the per-tick deadline for DeleteExpiredRefreshTokens.
// It caps the time the cleanup goroutine will wait on a slow or locked table
// without blocking the next tick or preventing graceful shutdown.
const tokenCleanupOpTimeout = 30 * time.Second

// MFAChallenger is implemented by authemail.Service.
type MFAChallenger interface {
	InitiateChallenge(ctx context.Context, userID, email, name string) (challengeToken string, expiresAt time.Time, err error)
}

// VerificationSender is implemented by authemail.Service.
type VerificationSender interface {
	SendVerification(ctx context.Context, userID string) error
}

// Service defines the auth business-logic contract.
type Service interface {
	Register(ctx context.Context, req RegisterRequest) error
	Login(ctx context.Context, req LoginRequest) (*LoginResult, error)
	Refresh(ctx context.Context, req RefreshRequest) (*TokenResponse, error)
	Logout(ctx context.Context, req LogoutRequest) error
	SetMFAChallenger(c MFAChallenger)
	SetVerificationSender(v VerificationSender)
	// IssueTokensForUser fetches fresh user data and issues a full token pair
	// in a single self-contained operation (no surrounding transaction).
	// Use PrepareTokensForUser when the refresh token insertion must be part
	// of a larger atomic transaction (e.g. MFA login completion).
	IssueTokensForUser(ctx context.Context, userID string) (*platformauth.SessionTokens, error)
	// PrepareTokensForUser fetches the user's current claims and generates a
	// signed token pair without writing the refresh token to the database.
	// The caller must persist the returned pair.RefreshTokenHashed via
	// repo.CreateRefreshToken — typically inside the same transaction that
	// consumes an MFA challenge — so that token consumption and session
	// creation are fully atomic. Use IssueTokensForUser when no surrounding
	// transaction is needed.
	PrepareTokensForUser(ctx context.Context, userID string) (*platformauth.TokenPair, error)
	// StartTokenCleanup launches a background goroutine that purges expired
	// refresh tokens on the given interval. Call exactly once from app.Run
	// after the server starts listening. The goroutine exits when ctx is
	// cancelled (typically at the start of graceful shutdown).
	StartTokenCleanup(ctx context.Context, interval time.Duration)
}

type service struct {
	repo               Repository
	jwt                *platformauth.JWT
	log                *zap.Logger
	auditLog           *audit.Logger
	mfaChallenger      MFAChallenger
	verificationSender VerificationSender
	// locker enforces account-level lockout after repeated credential failures.
	// nil when Redis is not configured or in tests that do not require lockout;
	// all call sites guard with a nil check so the service degrades gracefully.
	locker *platformauth.AccountLocker
}

// NewService constructs the auth service.
// locker may be nil — the service operates without account lockout when it is,
// relying exclusively on rate limiting. Pass a non-nil AccountLocker in all
// production deployments.
func NewService(repo Repository, jwt *platformauth.JWT, log *zap.Logger, auditLog *audit.Logger, locker *platformauth.AccountLocker) Service {
	return &service{repo: repo, jwt: jwt, log: log, auditLog: auditLog, locker: locker}
}

func (s *service) SetMFAChallenger(c MFAChallenger)           { s.mfaChallenger = c }
func (s *service) SetVerificationSender(v VerificationSender) { s.verificationSender = v }

// StartTokenCleanup launches a background goroutine that calls
// DeleteExpiredRefreshTokens on the given interval. Call exactly once from
// app.Run after the server starts listening. The goroutine exits when ctx is
// cancelled (typically at the start of graceful shutdown).
//
// # Shutdown behaviour
//
// When ctx is cancelled the goroutine exits on whichever select branch fires
// first — either the ctx.Done() case directly, or the ticker.C case where
// ctx.Err() is detected. In the latter path we return immediately (not
// continue) so the goroutine does not re-enter the select and log a spurious
// "skipped" line on every subsequent tick before ctx.Done() is eventually
// chosen by the scheduler.
func (s *service) StartTokenCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		s.log.Info("token cleanup goroutine started", zap.Duration("interval", interval))

		for {
			select {
			case <-ticker.C:
				// If the context was already cancelled when this tick fired
				// (e.g. shutdown signal raced with the ticker), exit immediately
				// rather than continuing the loop. Using continue here would
				// re-enter the select, log another "skipped" line on the next
				// tick, and repeat until ctx.Done() happens to win the race —
				// flooding logs during slow shutdowns.
				if err := ctx.Err(); err != nil {
					s.log.Info("token cleanup goroutine stopped", zap.Error(err))
					return
				}

				opCtx, opCancel := context.WithTimeout(ctx, tokenCleanupOpTimeout)
				n, err := s.repo.DeleteExpiredRefreshTokens(opCtx)
				opCancel()

				switch {
				case err == nil && n > 0:
					s.log.Info("token cleanup: expired tokens removed", zap.Int64("count", n))
				case err == nil:
					s.log.Debug("token cleanup: no expired tokens found")
				default:
					if opCtx.Err() != nil {
						s.log.Warn("token cleanup: operation cancelled",
							zap.Error(opCtx.Err()),
							zap.NamedError("cause", err),
						)
					} else {
						s.log.Error("token cleanup: delete failed", zap.Error(err))
					}
				}

			case <-ctx.Done():
				s.log.Info("token cleanup goroutine stopped", zap.Error(ctx.Err()))
				return
			}
		}
	}()
}

// ── Register ──────────────────────────────────────────────────────────────────

func (s *service) Register(ctx context.Context, req RegisterRequest) error {
	log := logger.FromContext(ctx).With(zap.String("email", req.Email))

	normalizedEmail := strings.ToLower(strings.TrimSpace(req.Email))
	hash, err := platformauth.HashPassword(req.Password)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	userID := uuid.NewString()
	userParams := db.CreateUserParams{
		ID:           userID,
		Email:        normalizedEmail,
		PasswordHash: hash,
		Name:         strings.TrimSpace(req.Name),
	}

	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		if err := tx.CreateUser(ctx, userParams); err != nil {
			return err
		}
		return tx.AssignUserRole(ctx, userID, "user")
	}); err != nil {
		return err
	}

	s.auditLog.Log(ctx, audit.EventRegister, userID, zap.String("email", normalizedEmail))
	log.Info("user registered", zap.String("user_id", userID))

	if s.verificationSender != nil {
		if vErr := s.verificationSender.SendVerification(ctx, userID); vErr != nil {
			s.log.Warn("register: verification email failed — user must resend manually",
				zap.Error(vErr),
				zap.String("user_id", userID),
			)
		}
	}

	return nil
}

// ── Login ─────────────────────────────────────────────────────────────────────

// Login verifies credentials and either issues a token pair or initiates an
// MFA challenge.
//
// Gate order is intentional and must not be changed:
//
//  0. Lockout check     — before credential work so a locked account never
//     reveals password correctness via timing. Fail-open on Redis error so a
//     Redis outage does not lock out all users.
//  1. Credential check  — always first among security checks; timing must not
//     reveal which gate rejected. Increments the lockout counter on failure;
//     clears it on success.
//  2. Email verification — before 2FA so an unverified account cannot probe
//     the MFA flow.
//  3. 2FA gate          — only reached when credentials and email are valid.
func (s *service) Login(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	user, err := s.repo.GetUserByEmailWithRoles(ctx, strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil {
		if appErr, ok := apperrors.As(err); ok && appErr.Code == apperrors.ErrNotFound.Code {
			s.auditLog.Log(ctx, audit.EventLoginFailed, "",
				zap.String("reason", "user_not_found"),
				zap.String("email", req.Email),
			)
			return nil, apperrors.ErrInvalidCredentials
		}
		return nil, err
	}

	// ── 0. Lockout gate ───────────────────────────────────────────────────────
	// Checked before VerifyPassword so a locked account never reveals whether
	// the supplied password would have been correct (prevents timing oracles).
	// Fails-open on Redis error — see AccountLocker.IsLocked for rationale.
	if s.locker != nil {
		if locked, retryAfter, _ := s.locker.IsLocked(ctx, user.ID); locked {
			s.auditLog.Log(ctx, audit.EventLoginFailed, user.ID,
				zap.String("reason", "account_locked"),
			)
			return nil, apperrors.NewLockoutError(retryAfter)
		}
	}

	// ── 1. Credential check ───────────────────────────────────────────────────
	if err = platformauth.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		// Record the failure before returning so the counter is always
		// incremented even if the locker encounters a Redis error internally
		// (RecordFailure logs and continues rather than propagating the error).
		if s.locker != nil {
			if _, recErr := s.locker.RecordFailure(ctx, user.ID); recErr != nil {
				s.log.Warn("lockout: RecordFailure returned error — counter may be inaccurate",
					zap.Error(recErr),
					zap.String("user_id", user.ID),
				)
			}
		}
		s.auditLog.Log(ctx, audit.EventLoginFailed, user.ID,
			zap.String("reason", "invalid_password"),
		)
		return nil, apperrors.ErrInvalidCredentials
	}

	// Credential check passed — reset the failure counter so this login
	// session starts clean.
	//
	// ClearFailures is fire-and-forget by design (fail-open): a Redis outage
	// must never block a user who supplied correct credentials. The failure
	// counter will expire on its own via the LockoutWindowTTL (default 15 m).
	//
	// Operational implication: if ClearFailures fails silently, the counter
	// retains its current value. On a subsequent failed attempt the user will
	// reach the lockout threshold sooner than expected — by however many
	// failures were recorded before this successful login. The window is
	// bounded: at most LockoutMaxAttempts−1 phantom failures can accumulate,
	// and all expire after LockoutWindowTTL with no operator action required.
	// Monitor the "lockout: ClearFailures: redis DEL failed" warning log to
	// detect Redis connectivity issues before they affect real users.
	if s.locker != nil {
		s.locker.ClearFailures(ctx, user.ID)
	}

	// ── 2. Email verification gate ────────────────────────────────────────────
	if !user.EmailVerified {
		// Emit an audit event so failed logins due to unverified email are
		// visible in the security event stream. Without this, a credential-
		// stuffing run against unverified accounts produces no audit trail.
		s.auditLog.Log(ctx, audit.EventLoginFailed, user.ID,
			zap.String("reason", "email_not_verified"),
		)
		return nil, apperrors.ErrEmailNotVerified
	}

	// ── 3. 2FA gate ───────────────────────────────────────────────────────────
	if user.TwoFAEnabled {
		if s.mfaChallenger == nil {
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

	s.auditLog.Log(ctx, audit.EventLoginSuccess, user.ID)
	logger.FromContext(ctx).Info("user logged in", zap.String("user_id", user.ID))
	return &LoginResult{Token: tokenResp}, nil
}

// ── Refresh ───────────────────────────────────────────────────────────────────

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
		s.auditLog.Log(ctx, audit.EventTokenReuseDetected, token.UserID,
			zap.String("family", token.TokenFamily),
		)
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
			s.auditLog.Log(ctx, audit.EventTokenReuseDetected, token.UserID,
				zap.String("family", token.TokenFamily),
			)
		}
		return nil, err
	}

	s.auditLog.Log(ctx, audit.EventTokenRefreshed, user.ID)
	logger.FromContext(ctx).Info("token refreshed", zap.String("user_id", user.ID))
	return tokenResp, nil
}

// ── Logout ────────────────────────────────────────────────────────────────────

// Logout revokes the session family associated with the supplied refresh token.
//
// A used (spent) token at Logout signals either a client that rotated its
// token and is calling logout with an old value, or an attacker probing
// session state with a stolen spent token. In both cases the family is revoked:
// the legitimate user re-authenticates, and the attacker's goal of leaving a
// live family intact is thwarted. The handler clears the cookie before calling
// this method, so there is no user-visible regression on the normal path.
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
		s.log.Warn("logout: used token presented — revoking family as precaution",
			zap.String("family", token.TokenFamily),
			zap.String("user_id", token.UserID),
		)
		_ = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily)
		s.auditLog.Log(ctx, audit.EventSessionsRevoked, token.UserID,
			zap.String("trigger", "logout_used_token"),
			zap.String("family", token.TokenFamily),
		)
		return nil
	}

	if err = s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily); err != nil {
		return err
	}

	s.auditLog.Log(ctx, audit.EventLogout, token.UserID,
		zap.String("family", token.TokenFamily),
	)
	logger.FromContext(ctx).Info("user logged out",
		zap.String("user_id", token.UserID),
		zap.String("family", token.TokenFamily),
	)
	return nil
}

// ── IssueTokensForUser ────────────────────────────────────────────────────────

// IssueTokensForUser fetches fresh user data and issues a token pair in a
// single self-contained operation (no surrounding transaction required).
// Use PrepareTokensForUser when the refresh token insertion must be part of a
// larger atomic transaction (e.g. MFA login completion via auth_email).
func (s *service) IssueTokensForUser(ctx context.Context, userID string) (*platformauth.SessionTokens, error) {
	user, err := s.repo.GetUserByIDWithRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !user.EmailVerified {
		return nil, apperrors.ErrEmailNotVerified
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

// ── PrepareTokensForUser ──────────────────────────────────────────────────────

// PrepareTokensForUser fetches the user's current roles and generates a signed
// token pair without inserting the refresh token row. The caller is responsible
// for persisting pair.RefreshTokenHashed via repo.CreateRefreshToken, typically
// inside the same transaction that consumes an MFA challenge token.
//
// This separation exists because MFA login completion must atomically:
//  1. Consume the challenge token
//  2. Consume the OTP token
//  3. Insert the new refresh token
//
// All three must succeed or none must. Putting the DB write here would require
// enrolling this method in the caller's transaction, which would couple the
// auth and auth_email modules. Instead, the caller pre-generates the pair here
// (pure crypto + one read) and inserts the row itself inside its transaction.
func (s *service) PrepareTokensForUser(ctx context.Context, userID string) (*platformauth.TokenPair, error) {
	user, err := s.repo.GetUserByIDWithRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !user.EmailVerified {
		return nil, apperrors.ErrEmailNotVerified
	}

	pair, err := s.jwt.GenerateTokenPair(user.ID, user.Email, user.Roles, "")
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	return pair, nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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
