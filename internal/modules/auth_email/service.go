package authemail

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

// ── Token type constants ──────────────────────────────────────────────────────

const (
	tokenTypeVerify    = "verify"
	tokenTypeReset     = "reset"
	tokenTypeOTP       = "otp"
	tokenTypeChallenge = "challenge"
)

// ResetPasswordResult carries the outcome of a password reset so the handler
// can inform the client whether a verification email was dispatched.
type ResetPasswordResult struct {
	EmailVerificationSent bool
}

// ── Token TTLs ────────────────────────────────────────────────────────────────

const (
	verifyTokenTTL    = 24 * time.Hour
	resetTokenTTL     = 1 * time.Hour
	otpTokenTTL       = 10 * time.Minute
	challengeTokenTTL = 5 * time.Minute
)

// TokenIssuer is satisfied by auth.Service.
type TokenIssuer interface {
	PrepareTokensForUser(ctx context.Context, userID string) (*platformauth.TokenPair, error)
}

//go:generate mockgen -source=service.go -destination=mocks/service_mock.go -package=mocks

// Service defines the email-auth business-logic contract.
type Service interface {
	ForgotPassword(ctx context.Context, req ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResult, error)
	VerifyEmail(ctx context.Context, req VerifyEmailRequest) error
	VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*platformauth.SessionTokens, error)
	SendVerification(ctx context.Context, userID string) error
	SendOTP(ctx context.Context, userID string) error
	ResendVerification(ctx context.Context, req ResendVerificationRequest) error
	InitiateChallenge(ctx context.Context, userID, email, name string) (string, time.Time, error)
	SetupTOTP(ctx context.Context, userID string) (secret, uri, qrBase64 string, err error)
	EnableTOTP(ctx context.Context, userID, code string) error
	DisableTOTP(ctx context.Context, userID, code, password string) error
}

type service struct {
	repo           Repository
	mailer         *mailer.Mailer
	log            *zap.Logger
	frontEndDomain string
	tokenIssuer    TokenIssuer
	auditLog       *audit.Logger
	otpSecret      string
	otpMaxAttempts int

	// rdb backs the global standalone-OTP brute-force breaker. May be nil
	// (breaker disabled, fails open) — see standaloneOTPBreakerTripped.
	rdb *goredis.Client

	totpKeySet  *platformauth.TOTPKeySet
	totpIssuer  string
	totpPeriod  uint
	totpDigits  otp.Digits
	replayCache *platformauth.TOTPReplayCache
}

// NewService constructs the email-auth service. Returns an error when
// replayCache is nil so that NewModule can propagate a structured startup
// message rather than crashing with a raw stack trace. The replayCache is
// always required — omitting it would leave the TOTP replay window open,
// violating RFC 6238 §5.2.
func NewService(
	repo Repository,
	m *mailer.Mailer,
	log *zap.Logger,
	frontEndDomain string,
	tokenIssuer TokenIssuer,
	otpSecret string,
	otpMaxAttempts int,
	auditLog *audit.Logger,
	totpKeySet *platformauth.TOTPKeySet,
	totpIssuer string,
	totpPeriod int,
	totpDigits int,
	replayCache *platformauth.TOTPReplayCache,
	rdb *goredis.Client,
) (Service, error) {
	if replayCache == nil {
		return nil, fmt.Errorf(
			"authemail: NewService: replayCache must not be nil — " +
				"pass platformauth.NewTOTPReplayCache(); " +
				"omitting it leaves the TOTP replay window open (RFC 6238 §5.2 violation)",
		)
	}
	digits := otp.DigitsSix
	if totpDigits == 8 {
		digits = otp.DigitsEight
	}
	period := uint(30)
	if totpPeriod > 0 {
		period = uint(totpPeriod)
	}
	return &service{
		repo:           repo,
		mailer:         m,
		log:            log,
		frontEndDomain: frontEndDomain,
		tokenIssuer:    tokenIssuer,
		otpSecret:      otpSecret,
		otpMaxAttempts: otpMaxAttempts,
		auditLog:       auditLog,
		totpKeySet:     totpKeySet,
		totpIssuer:     totpIssuer,
		totpPeriod:     period,
		totpDigits:     digits,
		replayCache:    replayCache,
		rdb:            rdb,
	}, nil
}

// ── Standalone-OTP brute-force breaker ─────────────────────────────────────────
//
// The standalone POST /auth/otp/verify path accepts an unauthenticated 6-digit
// code with no account identifier. A wrong guess resolves to no token row, so a
// per-account attempt cap (as used on the MFA login path) is structurally
// impossible here, and a per-IP limiter alone cannot stop a *distributed*
// attacker grinding the 10^6 code space across many source IPs.
//
// This global, fixed-window counter caps the total number of FAILED standalone
// verifications across all clients. It is defence-in-depth, not the primary
// control: a successful standalone verification grants no credential (it only
// marks the OTP consumed), and the credential-issuing MFA login flow is a
// separate code path with its own per-challenge burn, so tripping this breaker
// never blocks login. It fails OPEN on any Redis error or when no client is
// configured, so it can never become an availability risk.
const (
	standaloneOTPFailWindow   = time.Minute
	standaloneOTPFailMax      = 100
	standaloneOTPRedisTimeout = 2 * time.Second
	standaloneOTPFailKey      = "otp:standalone:fails"
)

func (s *service) standaloneOTPBreakerTripped(ctx context.Context) bool {
	if s.rdb == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, standaloneOTPRedisTimeout)
	defer cancel()
	n, err := s.rdb.Get(cctx, standaloneOTPFailKey).Int()
	if err != nil {
		// redis.Nil (no failures yet) or any transient error → fail open.
		return false
	}
	return n >= standaloneOTPFailMax
}

func (s *service) recordStandaloneOTPFailure(ctx context.Context) {
	if s.rdb == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, standaloneOTPRedisTimeout)
	defer cancel()
	n, err := s.rdb.Incr(cctx, standaloneOTPFailKey).Result()
	if err != nil {
		s.log.Warn("standalone OTP breaker: record failure failed", zap.Error(err))
		return
	}
	// Set the fixed-window TTL only when the key is first created so the window
	// rolls over cleanly every standaloneOTPFailWindow.
	if n == 1 {
		if err := s.rdb.Expire(cctx, standaloneOTPFailKey, standaloneOTPFailWindow).Err(); err != nil {
			s.log.Warn("standalone OTP breaker: set window TTL failed", zap.Error(err))
		}
	}
}

// ── ForgotPassword ────────────────────────────────────────────────────────────

func (s *service) ForgotPassword(ctx context.Context, req ForgotPasswordRequest) error {
	log := logger.FromContext(ctx)
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Debug("forgot-password: user not found, returning early", zap.String("email", audit.MaskEmail(email)))
		return nil
	}

	raw, hash, err := generateURLToken()
	if err != nil {
		log.Error("forgot-password: generate token", zap.Error(err))
		return nil
	}

	if err = s.repo.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
		UserID:    user.ID,
		TokenType: tokenTypeReset,
	}); err != nil {
		log.Error("forgot-password: invalidate old tokens", zap.Error(err), zap.String("user_id", user.ID))
		return nil
	}

	if err = s.repo.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: hash,
		TokenType: tokenTypeReset,
		ExpiresAt: time.Now().UTC().Add(resetTokenTTL),
	}); err != nil {
		log.Error("forgot-password: persist token", zap.Error(err), zap.String("user_id", user.ID))
		return nil
	}

	link := fmt.Sprintf("%s/auth/reset-password?token=%s", s.frontEndDomain, raw)
	// Enqueue (async) rather than send synchronously: a synchronous SMTP round
	// trip on the account-exists branch, against an instant return on the
	// unknown-account branch, is a user-enumeration timing oracle.
	s.sendEmail(ctx, user.Email, "Reset your password", func() (string, error) {
		return mailer.ResetPassword(user.Name, link)
	}, "forgot-password", user.ID)

	s.auditLog.Log(ctx, audit.EventPasswordResetRequested, user.ID)
	log.Info("forgot-password: reset token issued", zap.String("user_id", user.ID))
	return nil
}

// ── ResetPassword ─────────────────────────────────────────────────────────────

func (s *service) ResetPassword(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResult, error) {
	log := logger.FromContext(ctx)

	hash := platformauth.HashRefreshToken(req.Token)
	token, err := s.repo.GetEmailTokenByHash(ctx, hash)
	if err != nil {
		return nil, apperrors.ErrTokenInvalid
	}
	if token.TokenType != tokenTypeReset || token.UsedAt.Valid || time.Now().UTC().After(token.ExpiresAt) {
		return nil, apperrors.ErrTokenInvalid
	}

	newHash, err := platformauth.HashPassword(req.NewPassword)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	userID := token.UserID
	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		consumed, err := tx.ConsumeEmailToken(ctx, token.ID)
		if err != nil {
			return err
		}
		if !consumed {
			return apperrors.ErrTokenInvalid
		}
		if err = tx.UpdateUserPasswordHash(ctx, db.UpdateUserPasswordHashParams{
			PasswordHash: newHash,
			ID:           userID,
		}); err != nil {
			return err
		}
		if err = tx.ClearEmailVerified(ctx, userID); err != nil {
			return err
		}
		if err = tx.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
			UserID:    userID,
			TokenType: tokenTypeChallenge,
		}); err != nil {
			return err
		}
		return tx.RevokeUserRefreshTokens(ctx, userID)
	}); err != nil {
		return nil, err
	}

	s.auditLog.Log(ctx, audit.EventPasswordReset, userID)
	log.Info("reset-password: password updated, all sessions and challenges revoked",
		zap.String("user_id", userID),
	)

	result := &ResetPasswordResult{}
	if vErr := s.SendVerification(ctx, userID); vErr != nil {
		s.log.Warn("reset-password: re-verification email failed — user must resend manually",
			zap.Error(vErr),
			zap.String("user_id", userID),
		)
		result.EmailVerificationSent = false
	} else {
		result.EmailVerificationSent = true
	}

	return result, nil
}

// ── VerifyEmail ───────────────────────────────────────────────────────────────

func (s *service) VerifyEmail(ctx context.Context, req VerifyEmailRequest) error {
	log := logger.FromContext(ctx)

	hash := platformauth.HashRefreshToken(req.Token)
	token, err := s.repo.GetEmailTokenByHash(ctx, hash)
	if err != nil {
		return apperrors.ErrTokenInvalid
	}
	if token.TokenType != tokenTypeVerify || token.UsedAt.Valid || time.Now().UTC().After(token.ExpiresAt) {
		return apperrors.ErrTokenInvalid
	}

	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		consumed, err := tx.ConsumeEmailToken(ctx, token.ID)
		if err != nil {
			return err
		}
		if !consumed {
			return apperrors.ErrTokenInvalid
		}
		return tx.MarkEmailVerified(ctx, token.UserID)
	}); err != nil {
		return err
	}

	s.auditLog.Log(ctx, audit.EventEmailVerified, token.UserID)
	log.Info("verify-email: address verified", zap.String("user_id", token.UserID))
	return nil
}

// ── VerifyOTP ─────────────────────────────────────────────────────────────────

func (s *service) VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*platformauth.SessionTokens, error) {
	if req.MFAToken != "" {
		return s.completeMFALoginDispatch(ctx, req.MFAToken, req.Code)
	}
	if err := s.consumeStandaloneEmailOTP(ctx, req.Code); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *service) consumeStandaloneEmailOTP(ctx context.Context, code string) error {
	log := logger.FromContext(ctx)

	// Defence-in-depth against distributed brute-forcing of the 6-digit code
	// space (see standaloneOTPBreakerTripped). Checked before any DB work.
	if s.standaloneOTPBreakerTripped(ctx) {
		s.auditLog.Log(ctx, audit.EventOTPFailed, "", zap.String("reason", "standalone_breaker_open"))
		return apperrors.ErrRateLimitExceeded
	}

	otpHash := platformauth.HMACToken(code, s.otpSecret)
	otpToken, err := s.repo.GetEmailTokenByHash(ctx, otpHash)
	if err != nil {
		// A failed lookup is the brute-force signal — count it toward the global
		// window so the breaker trips before the code space can be ground down.
		s.recordStandaloneOTPFailure(ctx)
		s.auditLog.Log(ctx, audit.EventOTPFailed, "", zap.String("reason", "invalid_code"))
		return apperrors.ErrTokenInvalid
	}
	if otpToken.TokenType != tokenTypeOTP {
		s.auditLog.Log(ctx, audit.EventOTPFailed, otpToken.UserID, zap.String("reason", "wrong_token_type"))
		return apperrors.ErrTokenInvalid
	}
	if otpToken.UsedAt.Valid {
		s.auditLog.Log(ctx, audit.EventOTPFailed, otpToken.UserID, zap.String("reason", "replay_attempt"))
		return apperrors.ErrTokenInvalid
	}
	if time.Now().UTC().After(otpToken.ExpiresAt) {
		s.auditLog.Log(ctx, audit.EventOTPFailed, otpToken.UserID, zap.String("reason", "expired"))
		return apperrors.ErrTokenInvalid
	}

	consumed, err := s.repo.ConsumeEmailToken(ctx, otpToken.ID)
	if err != nil {
		return err
	}
	if !consumed {
		s.auditLog.Log(ctx, audit.EventOTPFailed, otpToken.UserID, zap.String("reason", "replay_attempt"))
		return apperrors.ErrTokenInvalid
	}

	log.Info("verify-otp: OTP consumed (standalone)", zap.String("user_id", otpToken.UserID))
	return nil
}

func (s *service) completeMFALoginDispatch(ctx context.Context, rawChallenge, code string) (*platformauth.SessionTokens, error) {
	challengeHash := platformauth.HashRefreshToken(rawChallenge)
	challengeToken, err := s.repo.GetEmailTokenByHash(ctx, challengeHash)
	if err != nil {
		s.auditLog.Log(ctx, audit.EventOTPFailed, "", zap.String("reason", "invalid_challenge_token"))
		return nil, apperrors.ErrTokenInvalid
	}

	if challengeToken.TokenType != tokenTypeChallenge {
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID,
			zap.String("reason", "wrong_challenge_token_type"))
		return nil, apperrors.ErrTokenInvalid
	}
	if challengeToken.UsedAt.Valid {
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID,
			zap.String("reason", "challenge_replay_attempt"))
		return nil, apperrors.ErrTokenInvalid
	}
	if time.Now().UTC().After(challengeToken.ExpiresAt) {
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID,
			zap.String("reason", "challenge_expired"))
		return nil, apperrors.ErrTokenInvalid
	}

	mfaMethod, err := s.repo.GetUserMFAMethod(ctx, challengeToken.UserID)
	if err != nil {
		s.log.Error("completeMFALoginDispatch: GetUserMFAMethod failed, falling back to email",
			zap.Error(err), zap.String("user_id", challengeToken.UserID))
		mfaMethod = "email"
	}

	if mfaMethod == "totp" {
		return s.completeMFALoginTOTP(ctx, challengeToken, code)
	}
	return s.completeMFALoginEmail(ctx, challengeToken, code)
}

func (s *service) completeMFALoginEmail(ctx context.Context, challengeToken *db.EmailToken, code string) (*platformauth.SessionTokens, error) {
	log := logger.FromContext(ctx)

	if s.tokenIssuer == nil {
		s.log.Error("MFA email login: TokenIssuer not configured — check app.go wiring",
			zap.String("user_id", challengeToken.UserID))
		return nil, apperrors.ErrInternalServer
	}

	otpToken, err := s.validateEmailOTP(ctx, challengeToken, code)
	if err != nil {
		// Count the failed guess against the challenge and burn it once the
		// per-challenge limit is reached, so a 6-digit OTP cannot be brute-forced.
		s.registerMFAFailure(ctx, challengeToken)
		return nil, err
	}

	userID := challengeToken.UserID
	pair, err := s.tokenIssuer.PrepareTokensForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		consumed, err := tx.ConsumeEmailToken(ctx, challengeToken.ID)
		if err != nil {
			return err
		}
		if !consumed {
			s.auditLog.Log(ctx, audit.EventOTPFailed, userID, zap.String("reason", "challenge_replay_attempt"))
			return apperrors.ErrTokenInvalid
		}
		consumed, err = tx.ConsumeEmailToken(ctx, otpToken.ID)
		if err != nil {
			return err
		}
		if !consumed {
			s.auditLog.Log(ctx, audit.EventOTPFailed, userID, zap.String("reason", "replay_attempt"))
			return apperrors.ErrTokenInvalid
		}
		return tx.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
			ID:              uuid.NewString(),
			UserID:          userID,
			TokenHash:       pair.RefreshTokenHashed,
			TokenFamily:     pair.RefreshTokenFamily,
			ExpiresAt:       pair.RefreshExpiresAt,
			FamilyExpiresAt: pair.FamilyExpiresAt,
		})
	}); err != nil {
		return nil, err
	}

	tokens := &platformauth.SessionTokens{
		AccessToken:           pair.AccessToken,
		RefreshToken:          pair.RefreshToken,
		TokenType:             "Bearer",
		AccessTokenExpiresAt:  pair.AccessExpiresAt,
		RefreshTokenExpiresAt: pair.RefreshExpiresAt,
	}
	s.auditLog.Log(ctx, audit.EventMFACompleted, userID,
		zap.String("method", "email"), zap.String("result", "success"))
	log.Info("mfa email login completed", zap.String("user_id", userID))
	return tokens, nil
}

// validateEmailOTP looks up and validates the email OTP for an MFA challenge,
// returning the matching OTP token on success. Every failure maps to
// ErrTokenInvalid and emits an audit event; the caller is responsible for
// incrementing the challenge's failed-attempt counter via registerMFAFailure.
func (s *service) validateEmailOTP(ctx context.Context, challengeToken *db.EmailToken, code string) (*db.EmailToken, error) {
	otpHash := platformauth.HMACToken(code, s.otpSecret)
	otpToken, err := s.repo.GetEmailTokenByHash(ctx, otpHash)
	if err != nil {
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID, zap.String("reason", "invalid_code"))
		return nil, apperrors.ErrTokenInvalid
	}
	if otpToken.TokenType != tokenTypeOTP {
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID, zap.String("reason", "wrong_token_type"))
		return nil, apperrors.ErrTokenInvalid
	}
	if otpToken.UsedAt.Valid {
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID, zap.String("reason", "replay_attempt"))
		return nil, apperrors.ErrTokenInvalid
	}
	if time.Now().UTC().After(otpToken.ExpiresAt) {
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID, zap.String("reason", "expired"))
		return nil, apperrors.ErrTokenInvalid
	}
	if challengeToken.UserID != otpToken.UserID {
		logger.FromContext(ctx).Warn("completeMFALoginEmail: challenge/OTP user mismatch",
			zap.String("challenge_user", challengeToken.UserID),
			zap.String("otp_user", otpToken.UserID))
		s.auditLog.Log(ctx, audit.EventOTPFailed, challengeToken.UserID,
			zap.String("reason", "user_mismatch"))
		return nil, apperrors.ErrTokenInvalid
	}
	return otpToken, nil
}

// registerMFAFailure increments the failed-attempt counter on an MFA challenge
// and burns the challenge once otpMaxAttempts is reached, capping brute-force
// guesses against a 6-digit OTP/TOTP code per challenge. Best-effort: a counter
// error is logged but never converts the caller's 401 into a 500.
func (s *service) registerMFAFailure(ctx context.Context, challenge *db.EmailToken) {
	if s.otpMaxAttempts <= 0 {
		return
	}
	attempts, err := s.repo.RecordChallengeAttempt(ctx, challenge.ID)
	if err != nil {
		s.log.Warn("mfa: record challenge attempt failed",
			zap.Error(err), zap.String("user_id", challenge.UserID))
		return
	}
	if attempts >= s.otpMaxAttempts {
		// Burn the challenge so further guesses against this mfa_token are
		// rejected up-front (completeMFALoginDispatch sees used_at IS NOT NULL).
		if _, cErr := s.repo.ConsumeEmailToken(ctx, challenge.ID); cErr != nil {
			s.log.Error("mfa: burn challenge after max attempts failed",
				zap.Error(cErr), zap.String("user_id", challenge.UserID))
		}
		s.auditLog.Log(ctx, audit.EventMFAChallengeLocked, challenge.UserID,
			zap.Int("attempts", attempts))
	}
}

func (s *service) completeMFALoginTOTP(ctx context.Context, challengeToken *db.EmailToken, code string) (*platformauth.SessionTokens, error) {
	log := logger.FromContext(ctx)

	if s.tokenIssuer == nil {
		s.log.Error("MFA TOTP login: TokenIssuer not configured — check app.go wiring",
			zap.String("user_id", challengeToken.UserID))
		return nil, apperrors.ErrInternalServer
	}

	userID := challengeToken.UserID

	encrypted, err := s.repo.GetUserTOTPSecretEncrypted(ctx, userID)
	if err != nil {
		s.log.Error("completeMFALoginTOTP: fetch encrypted secret",
			zap.Error(err), zap.String("user_id", userID))
		return nil, apperrors.ErrInternalServer
	}
	plainSecret, err := s.totpKeySet.Decrypt(encrypted)
	if err != nil {
		s.log.Error("completeMFALoginTOTP: decrypt secret",
			zap.Error(err), zap.String("user_id", userID))
		return nil, apperrors.ErrInternalServer
	}

	valid, err := platformauth.ValidateTOTP(code, plainSecret, s.totpPeriod, s.totpDigits)
	if err != nil || !valid {
		s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "invalid_code"))
		s.registerMFAFailure(ctx, challengeToken)
		return nil, apperrors.ErrTokenInvalid
	}

	if !s.replayCache.CheckAndRecord(userID, code) {
		s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "replay_detected"))
		s.registerMFAFailure(ctx, challengeToken)
		return nil, apperrors.ErrTokenInvalid
	}

	pair, err := s.tokenIssuer.PrepareTokensForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if err = s.repo.WithTx(ctx, func(tx Repository) error {
		consumed, err := tx.ConsumeEmailToken(ctx, challengeToken.ID)
		if err != nil {
			return err
		}
		if !consumed {
			s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "challenge_replay_attempt"))
			return apperrors.ErrTokenInvalid
		}
		return tx.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
			ID:              uuid.NewString(),
			UserID:          userID,
			TokenHash:       pair.RefreshTokenHashed,
			TokenFamily:     pair.RefreshTokenFamily,
			ExpiresAt:       pair.RefreshExpiresAt,
			FamilyExpiresAt: pair.FamilyExpiresAt,
		})
	}); err != nil {
		return nil, err
	}

	tokens := &platformauth.SessionTokens{
		AccessToken:           pair.AccessToken,
		RefreshToken:          pair.RefreshToken,
		TokenType:             "Bearer",
		AccessTokenExpiresAt:  pair.AccessExpiresAt,
		RefreshTokenExpiresAt: pair.RefreshExpiresAt,
	}
	s.auditLog.Log(ctx, audit.EventMFACompleted, userID,
		zap.String("method", "totp"), zap.String("result", "success"))
	log.Info("mfa totp login completed", zap.String("user_id", userID))
	return tokens, nil
}

// ── ResendVerification ────────────────────────────────────────────────────────

func (s *service) ResendVerification(ctx context.Context, req ResendVerificationRequest) error {
	log := logger.FromContext(ctx)
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Debug("resend-verification: user not found", zap.String("email", audit.MaskEmail(email)))
		return nil
	}
	if user.EmailVerifiedAt.Valid {
		log.Debug("resend-verification: already verified", zap.String("user_id", user.ID))
		return nil
	}

	raw, hash, err := generateURLToken()
	if err != nil {
		log.Error("resend-verification: generate token", zap.Error(err), zap.String("user_id", user.ID))
		return nil
	}
	if err = s.repo.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
		UserID:    user.ID,
		TokenType: tokenTypeVerify,
	}); err != nil {
		log.Error("resend-verification: invalidate old tokens", zap.Error(err))
		return nil
	}
	if err = s.repo.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: hash,
		TokenType: tokenTypeVerify,
		ExpiresAt: time.Now().UTC().Add(verifyTokenTTL),
	}); err != nil {
		log.Error("resend-verification: persist token", zap.Error(err))
		return nil
	}

	link := fmt.Sprintf("%s/auth/verify-email?token=%s", s.frontEndDomain, raw)
	// Async enqueue to avoid a user-enumeration timing oracle (see ForgotPassword).
	s.sendEmail(ctx, user.Email, "Verify your email address", func() (string, error) {
		return mailer.VerifyEmail(user.Name, link)
	}, "resend-verification", user.ID)

	s.auditLog.Log(ctx, audit.EventVerificationSent, user.ID, zap.String("trigger", "resend_unauthenticated"))
	log.Info("resend-verification: token issued", zap.String("user_id", user.ID))
	return nil
}

// ── InitiateChallenge ─────────────────────────────────────────────────────────

func (s *service) InitiateChallenge(ctx context.Context, userID, email, name string) (string, time.Time, error) {
	mfaMethod, err := s.repo.GetUserMFAMethod(ctx, userID)
	if err != nil {
		s.log.Warn("InitiateChallenge: GetUserMFAMethod failed, using email OTP",
			zap.Error(err), zap.String("user_id", userID))
		mfaMethod = "email"
	}

	if mfaMethod != "totp" {
		if err = s.repo.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
			UserID:    userID,
			TokenType: tokenTypeOTP,
		}); err != nil {
			return "", time.Time{}, err
		}
		code, otpHash, err := generateOTP(s.otpSecret)
		if err != nil {
			return "", time.Time{}, apperrors.Wrap(apperrors.ErrInternalServer, err)
		}
		if err = s.repo.CreateEmailToken(ctx, db.CreateEmailTokenParams{
			ID:        uuid.NewString(),
			UserID:    userID,
			TokenHash: otpHash,
			TokenType: tokenTypeOTP,
			ExpiresAt: time.Now().UTC().Add(otpTokenTTL),
		}); err != nil {
			return "", time.Time{}, err
		}
		secureURL := fmt.Sprintf("%s/account/security", s.frontEndDomain)
		s.sendEmail(ctx, email, "Your login code", func() (string, error) {
			return mailer.TwoFactorOTP(name, code, secureURL)
		}, "initiate-challenge", userID)
	}

	raw, challengeHash, err := generateURLToken()
	if err != nil {
		return "", time.Time{}, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	expiresAt := time.Now().UTC().Add(challengeTokenTTL)
	if err = s.repo.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: challengeHash,
		TokenType: tokenTypeChallenge,
		ExpiresAt: expiresAt,
	}); err != nil {
		return "", time.Time{}, err
	}

	s.auditLog.Log(ctx, audit.EventMFAChallenged, userID, zap.String("method", mfaMethod))
	s.log.Info("mfa challenge initiated", zap.String("user_id", userID), zap.String("method", mfaMethod))
	return raw, expiresAt, nil
}

// ── SendVerification ──────────────────────────────────────────────────────────

func (s *service) SendVerification(ctx context.Context, userID string) error {
	log := logger.FromContext(ctx)

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.EmailVerifiedAt.Valid {
		log.Debug("send-verification: already verified", zap.String("user_id", userID))
		return nil
	}

	raw, hash, err := generateURLToken()
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	if err = s.repo.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
		UserID:    userID,
		TokenType: tokenTypeVerify,
	}); err != nil {
		return err
	}
	if err = s.repo.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hash,
		TokenType: tokenTypeVerify,
		ExpiresAt: time.Now().UTC().Add(verifyTokenTTL),
	}); err != nil {
		return err
	}

	link := fmt.Sprintf("%s/auth/verify-email?token=%s", s.frontEndDomain, raw)
	s.sendEmailSync(ctx, user.Email, "Verify your email address", func() (string, error) {
		return mailer.VerifyEmail(user.Name, link)
	}, "send-verification", userID)

	s.auditLog.Log(ctx, audit.EventVerificationSent, userID, zap.String("trigger", "authenticated"))
	log.Info("send-verification: email sent", zap.String("user_id", userID))
	return nil
}

// ── SendOTP ───────────────────────────────────────────────────────────────────

func (s *service) SendOTP(ctx context.Context, userID string) error {
	log := logger.FromContext(ctx)

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.TwoFaEnabled {
		return apperrors.New(
			"TWO_FA_NOT_ENABLED",
			"two-factor authentication is not enabled on this account",
			http.StatusForbidden, nil,
		)
	}

	code, hash, err := generateOTP(s.otpSecret)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	if err = s.repo.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
		UserID:    userID,
		TokenType: tokenTypeOTP,
	}); err != nil {
		return err
	}
	if err = s.repo.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hash,
		TokenType: tokenTypeOTP,
		ExpiresAt: time.Now().UTC().Add(otpTokenTTL),
	}); err != nil {
		return err
	}

	secureURL := fmt.Sprintf("%s/account/security", s.frontEndDomain)
	s.sendEmail(ctx, user.Email, "Your login code", func() (string, error) {
		return mailer.TwoFactorOTP(user.Name, code, secureURL)
	}, "send-otp", userID)

	s.auditLog.Log(ctx, audit.EventOTPSent, userID)
	log.Info("send-otp: OTP queued", zap.String("user_id", userID))
	return nil
}

// ── TOTP lifecycle ────────────────────────────────────────────────────────────

func (s *service) SetupTOTP(ctx context.Context, userID string) (secret, uri, qrBase64 string, err error) {
	log := logger.FromContext(ctx)

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return "", "", "", err
	}

	// Refuse to overwrite a live secret. Re-running setup while TOTP is already
	// enabled would clobber the active secret and could lock the user out if the
	// new enrollment is never confirmed. They must disable first.
	if user.TwoFaEnabled {
		return "", "", "", apperrors.New(
			"TOTP_ALREADY_ENABLED",
			"TOTP is already enabled on this account — disable it before enrolling a new authenticator",
			http.StatusConflict, nil,
		)
	}

	result, err := platformauth.GenerateTOTPSecret(platformauth.TOTPGenerateConfig{
		Issuer: s.totpIssuer,
		Period: s.totpPeriod,
		Digits: s.totpDigits,
		KeySet: s.totpKeySet,
	}, user.Email)
	if err != nil {
		return "", "", "", apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	if err = s.repo.SetUserTOTPSecret(ctx, userID, result.EncryptedSecret); err != nil {
		return "", "", "", err
	}

	s.auditLog.Log(ctx, audit.EventTOTPSetup, userID)
	log.Info("totp-setup: pending secret stored", zap.String("user_id", userID))
	return result.Secret, result.URI, result.QRCodeBase64, nil
}

func (s *service) EnableTOTP(ctx context.Context, userID, code string) error {
	log := logger.FromContext(ctx)

	encrypted, err := s.repo.GetUserTOTPSecretEncrypted(ctx, userID)
	if err != nil {
		return err
	}
	plainSecret, err := s.totpKeySet.Decrypt(encrypted)
	if err != nil {
		s.log.Error("enable-totp: decrypt secret", zap.Error(err), zap.String("user_id", userID))
		return apperrors.ErrInternalServer
	}

	valid, err := platformauth.ValidateTOTP(code, plainSecret, s.totpPeriod, s.totpDigits)
	if err != nil || !valid {
		s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "invalid_code_during_enable"))
		return apperrors.New("TOTP_CODE_INVALID",
			"the provided TOTP code is incorrect — confirm your authenticator app is synced",
			http.StatusUnprocessableEntity, nil)
	}

	if !s.replayCache.CheckAndRecord(userID, code) {
		s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "replay_during_enable"))
		return apperrors.New("TOTP_CODE_INVALID",
			"the provided TOTP code is incorrect — confirm your authenticator app is synced",
			http.StatusUnprocessableEntity, nil)
	}

	if err = s.repo.EnableUserTOTP(ctx, userID); err != nil {
		return err
	}

	s.auditLog.Log(ctx, audit.EventTOTPEnabled, userID)
	log.Info("totp-enable: TOTP activated", zap.String("user_id", userID))
	return nil
}

func (s *service) DisableTOTP(ctx context.Context, userID, code, password string) error {
	log := logger.FromContext(ctx)

	// Require password re-auth (in addition to the TOTP code) before stepping
	// down a security control, so an attacker with only a stolen access token —
	// and a glimpse of one code — cannot silently downgrade MFA. OAuth-only
	// accounts have no password and are gated by the TOTP code alone.
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash != "" {
		if vErr := platformauth.VerifyPassword(password, user.PasswordHash); vErr != nil {
			s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "invalid_password_during_disable"))
			return apperrors.ErrInvalidCredentials
		}
	}

	encrypted, err := s.repo.GetUserTOTPSecretEncrypted(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrTOTPNotSetup) {
			return ErrTOTPNotSetup
		}
		s.log.Error("disable-totp: missing secret", zap.Error(err), zap.String("user_id", userID))
		return apperrors.ErrInternalServer
	}

	plainSecret, err := s.totpKeySet.Decrypt(encrypted)
	if err != nil {
		s.log.Error("disable-totp: decrypt secret", zap.Error(err), zap.String("user_id", userID))
		return apperrors.ErrInternalServer
	}

	valid, err := platformauth.ValidateTOTP(code, plainSecret, s.totpPeriod, s.totpDigits)
	if err != nil || !valid {
		s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "invalid_code_during_disable"))
		return apperrors.New("TOTP_CODE_INVALID",
			"the provided TOTP code is incorrect — confirm your authenticator app is synced",
			http.StatusUnprocessableEntity, nil)
	}

	if !s.replayCache.CheckAndRecord(userID, code) {
		s.auditLog.Log(ctx, audit.EventTOTPFailed, userID, zap.String("reason", "replay_during_disable"))
		return apperrors.New("TOTP_CODE_INVALID",
			"the provided TOTP code is incorrect — confirm your authenticator app is synced",
			http.StatusUnprocessableEntity, nil)
	}

	if err := s.repo.WithTx(ctx, func(tx Repository) error {
		if err := tx.DisableUserTOTP(ctx, userID); err != nil {
			return err
		}
		// Invalidate any in-flight MFA challenge tokens so a concurrent TOTP
		// login that is mid-flow cannot complete after TOTP has been disabled.
		// ResetPassword performs the same invalidation for the same reason:
		// a credential change must atomically terminate all pending auth flows,
		// not just established sessions.
		if err := tx.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
			UserID:    userID,
			TokenType: tokenTypeChallenge,
		}); err != nil {
			return err
		}
		return tx.RevokeUserRefreshTokens(ctx, userID)
	}); err != nil {
		return err
	}

	s.auditLog.Log(ctx, audit.EventTOTPDisabled, userID)
	log.Info("totp-disable: reverted to email OTP", zap.String("user_id", userID))
	return nil
}

// ── Email dispatch helpers ────────────────────────────────────────────────────

func (s *service) sendEmailSync(ctx context.Context, to, subject string, renderFn func() (string, error), op, userID string) {
	if s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	html, err := renderFn()
	if err != nil {
		s.log.Error(op+": render email template", zap.Error(err), zap.String("user_id", userID))
		return
	}
	if err = s.mailer.Send(ctx, mailer.Message{To: to, Subject: subject, HTML: html}); err != nil {
		s.log.Error(op+": send email (sync)", zap.Error(err), zap.String("user_id", userID))
	}
}

func (s *service) sendEmail(ctx context.Context, to, subject string, renderFn func() (string, error), op, userID string) {
	if s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	html, err := renderFn()
	if err != nil {
		s.log.Error(op+": render email template", zap.Error(err), zap.String("user_id", userID))
		return
	}
	// Detach from the request context before enqueuing. The router's timeout
	// middleware cancels the request context via `defer cancel()` the instant
	// the handler returns, which almost always happens before a background
	// worker dequeues the message — causing the send to be silently dropped
	// (the worker bails on item.ctx.Err()). context.WithoutCancel severs
	// cancellation/deadline propagation while preserving request-scoped values
	// (e.g. request_id) for logging; the mailer worker applies its own
	// workerMsgTimeout to bound the actual send.
	if err = s.mailer.Enqueue(context.WithoutCancel(ctx), mailer.Message{To: to, Subject: subject, HTML: html}); err != nil {
		s.log.Warn(op+": enqueue email failed", zap.Error(err), zap.String("user_id", userID))
	}
}

// ── Token generation helpers ──────────────────────────────────────────────────

func generateURLToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("authemail: generate url token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = platformauth.HashRefreshToken(raw)
	return raw, hash, nil
}

func generateOTP(secret string) (code, hash string, err error) {
	max := big.NewInt(1_000_000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", "", fmt.Errorf("authemail: generate otp: %w", err)
	}
	code = fmt.Sprintf("%06d", n.Int64())
	hash = platformauth.HMACToken(code, secret)
	return code, hash, nil
}
