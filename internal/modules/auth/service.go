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

// concurrentUseGrace is the window within which a second /refresh request
// presenting an already-consumed token is treated as a benign concurrent
// duplicate rather than a deliberate replay of a rotated-away token.
//
// Why this exists: two legitimate /refresh requests racing on the same token
// (double-click, network retry, client-side race) are serialised by the FOR
// UPDATE row lock. The first request wins and consumes the token; the second
// acquires the lock and finds used_at IS NOT NULL. Without this grace window
// the second request triggers family revocation, invalidating the new token
// the first request just issued and silently logging the user out.
//
// Security trade-off: an attacker who steals token T and replays it within
// 10 seconds of the legitimate use receives 401 (no access) but does NOT
// trigger family revocation. Outside the window, replay correctly revokes the
// entire family. Real-world token theft (cookie exfiltration, XSS, log
// scraping) is almost never synchronised within a 10-second window of
// legitimate use. TLS prevents the only synchronised-replay vector (active
// MitM) before the token even reaches this code.
const concurrentUseGrace = 10 * time.Second

func (s *service) Refresh(ctx context.Context, req RefreshRequest) (*TokenResponse, error) {
	tokenHash := platformauth.HashRefreshToken(req.RefreshToken)

	// capturedFamily and capturedUserID are set inside the transaction closure
	// so the post-transaction family-revocation path has the values it needs
	// without a second database round-trip. ErrTokenReuse is only returned
	// after the FOR UPDATE succeeds, so both variables are always populated
	// when the revocation branch runs.
	var capturedFamily string
	var capturedUserID string

	var tokenResp *TokenResponse
	txErr := s.repo.WithTx(ctx, func(tx Repository) error {
		// Acquire an exclusive row lock as the very first operation.
		//
		// Previous design: a non-locking GetRefreshTokenByHash read outside the
		// transaction served as a "fast-reject" for unknown tokens. That created
		// a TOCTOU window: both requests in a concurrent pair could pass the
		// fast-reject (token looks valid), the first would consume the token
		// inside the transaction, and the second would acquire the FOR UPDATE
		// lock, see used_at IS NOT NULL, and trigger a false-positive family
		// revocation — invalidating the new token the first request had just
		// issued and logging the user out.
		//
		// Current design: the FOR UPDATE is the single authoritative read.
		// Unknown tokens are rejected here (repository maps sql.ErrNoRows →
		// ErrTokenInvalid) with no preceding non-locking read, eliminating the
		// TOCTOU window entirely.
		locked, err := tx.GetRefreshTokenByHashForUpdate(ctx, tokenHash)
		if err != nil {
			return err
		}

		capturedFamily = locked.TokenFamily
		capturedUserID = locked.UserID

		// ── Authoritative state checks (race-free under FOR UPDATE lock) ─────

		if time.Now().UTC().After(locked.ExpiresAt) {
			return apperrors.ErrTokenExpired
		}

		// Token was revoked by a concurrent Logout, an admin action, or a
		// previous replay detection. Return ErrTokenRevoked (not ErrTokenReuse)
		// so the caller receives the correct error code and no spurious second
		// family revocation is triggered.
		if locked.RevokedAt.Valid {
			return apperrors.ErrTokenRevoked
		}

		if locked.UsedAt.Valid {
			// Distinguish between a concurrent duplicate request (benign race)
			// and deliberate replay of a token that was rotated away some time ago.
			//
			// Concurrent duplicate: used_at was stamped moments ago by the
			// winning sibling request. The legitimate client already received the
			// new token from that sibling; this 401 is safely ignorable. Do NOT
			// revoke the family — that would invalidate the sibling's new token.
			//
			// Deliberate replay: used_at is old. Revoke the entire family so any
			// session the attacker may have established is terminated.
			// ErrTokenReuse is handled in the outer scope.
			if time.Since(locked.UsedAt.Time) <= concurrentUseGrace {
				return apperrors.ErrTokenInvalid // 401, no family revocation
			}
			return apperrors.ErrTokenReuse // triggers family revocation below
		}

		// ── Fetch user data ───────────────────────────────────────────────────
		// Uses the outer (non-transactional) repository so the user JOIN query
		// does not extend the refresh_token row-lock duration. If the user is
		// deleted between here and issueTokenPair's CreateRefreshToken, the FK
		// constraint surfaces the error correctly.
		user, err := s.repo.GetUserByIDWithRoles(ctx, locked.UserID)
		if err != nil {
			return err
		}

		// ── Consume ───────────────────────────────────────────────────────────

		consumed, err := tx.ConsumeRefreshToken(ctx, locked.ID)
		if err != nil {
			return err
		}
		if !consumed {
			// Should be unreachable: the FOR UPDATE lock guarantees used_at IS
			// NULL and revoked_at IS NULL at this point. This branch fires only
			// if ConsumeRefreshToken's WHERE clause diverges from the checks
			// above (schema drift, manual DB edit, or query mismatch).
			s.log.Error(
				"refresh: ConsumeRefreshToken returned consumed=false after FOR UPDATE "+
					"confirmed used_at IS NULL and revoked_at IS NULL — possible schema drift",
				zap.String("token_id", locked.ID),
				zap.String("user_id", locked.UserID),
				zap.String("family", locked.TokenFamily),
			)
			return apperrors.ErrTokenReuse
		}

		tokenResp, err = s.issueTokenPair(ctx, tx, user.ID, user.Email, user.Roles, locked.TokenFamily)
		return err
	})

	if txErr != nil {
		if appErr, ok := apperrors.As(txErr); ok && appErr.Code == apperrors.ErrTokenReuse.Code {
			s.log.Warn("refresh: token reuse detected — revoking family",
				zap.String("family", capturedFamily),
				zap.String("user_id", capturedUserID),
			)
			if revokeErr := s.repo.RevokeRefreshTokenFamily(ctx, capturedFamily); revokeErr != nil {
				s.log.Error("refresh: family revocation failed after reuse detection — family may still be active",
					zap.String("family", capturedFamily),
					zap.String("user_id", capturedUserID),
					zap.Error(revokeErr),
				)
				s.auditLog.Log(ctx, audit.EventTokenReuseDetected, capturedUserID,
					zap.String("family", capturedFamily),
				)
				return nil, revokeErr
			}
			s.auditLog.Log(ctx, audit.EventTokenReuseDetected, capturedUserID,
				zap.String("family", capturedFamily),
			)
		}
		return nil, txErr
	}

	s.auditLog.Log(ctx, audit.EventTokenRefreshed, capturedUserID)
	logger.FromContext(ctx).Info("token refreshed", zap.String("user_id", capturedUserID))
	return tokenResp, nil
}

// ── Logout ────────────────────────────────────────────────────────────────────

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
		if err := s.repo.RevokeRefreshTokenFamily(ctx, token.TokenFamily); err != nil {
			// A failure here leaves the token family live. Return the error so
			// the client receives 500 and retries rather than a 204 that falsely
			// implies all sessions were terminated. The audit event is
			// intentionally withheld: logging "sessions revoked" when revocation
			// failed would produce a misleading security record.
			s.log.Error("logout: family revocation failed — sessions may still be active",
				zap.String("family", token.TokenFamily),
				zap.String("user_id", token.UserID),
				zap.Error(err),
			)
			return err
		}
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
