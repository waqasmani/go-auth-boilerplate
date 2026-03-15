package authemail

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

// ── Token type constants ──────────────────────────────────────────────────────

const (
	tokenTypeVerify    = "verify"
	tokenTypeReset     = "reset"
	tokenTypeOTP       = "otp"
	tokenTypeChallenge = "challenge" // pre-auth MFA challenge; consumed at /otp/verify
)

// ── Token TTLs ────────────────────────────────────────────────────────────────

const (
	verifyTokenTTL    = 24 * time.Hour
	resetTokenTTL     = 1 * time.Hour
	otpTokenTTL       = 10 * time.Minute
	challengeTokenTTL = 5 * time.Minute // short — credentials were just verified
)

// TokenIssuer is satisfied by auth.Service. Defined here to avoid an import
// cycle — auth_email never imports auth.
type TokenIssuer interface {
	IssueTokensForUser(ctx context.Context, userID string) (*platformauth.SessionTokens, error)
}

//go:generate mockgen -source=service.go -destination=mocks/service_mock.go -package=mocks

// Service defines the email-auth business-logic contract.
type Service interface {
	ForgotPassword(ctx context.Context, req ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, req ResetPasswordRequest) error
	VerifyEmail(ctx context.Context, req VerifyEmailRequest) error
	// VerifyOTP returns a *SessionTokens when completing an MFA login
	// (mfa_token present in the request) and nil for standalone OTP checks.
	VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*platformauth.SessionTokens, error)
	SendVerification(ctx context.Context, userID string) error
	SendOTP(ctx context.Context, userID string) error
	// ResendVerification is the unauthenticated equivalent of SendVerification.
	// Takes an email address; always returns nil (anti-enumeration guarantee).
	ResendVerification(ctx context.Context, req ResendVerificationRequest) error
	// InitiateChallenge satisfies auth.MFAChallenger. Invalidates live OTPs,
	// generates a new OTP + challenge token pair, and sends the OTP by email.
	InitiateChallenge(ctx context.Context, userID, email, name string) (string, time.Time, error)
}

type service struct {
	repo           Repository
	mailer         *mailer.Mailer
	log            *zap.Logger
	frontEndDomain string
	tokenIssuer    TokenIssuer // auth.Service — injected via ModuleConfig
}

// NewService constructs the email-auth service.
func NewService(repo Repository, m *mailer.Mailer, log *zap.Logger, frontEndDomain string, tokenIssuer TokenIssuer) Service {
	return &service{
		repo:           repo,
		mailer:         m,
		log:            log,
		frontEndDomain: frontEndDomain,
		tokenIssuer:    tokenIssuer,
	}
}

// ── ForgotPassword ────────────────────────────────────────────────────────────

func (s *service) ForgotPassword(ctx context.Context, req ForgotPasswordRequest) error {
	log := logger.FromContext(ctx)
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Debug("forgot-password: user not found, returning early", zap.String("email", email))
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
	s.sendEmail(ctx, user.Email, "Reset your password", func() (string, error) {
		return mailer.ResetPassword(user.Name, link)
	}, "forgot-password", user.ID)

	log.Info("forgot-password: reset token issued", zap.String("user_id", user.ID))
	return nil
}

// ── ResetPassword ─────────────────────────────────────────────────────────────

func (s *service) ResetPassword(ctx context.Context, req ResetPasswordRequest) error {
	log := logger.FromContext(ctx)

	hash := platformauth.HashRefreshToken(req.Token)
	token, err := s.repo.GetEmailTokenByHash(ctx, hash)
	if err != nil {
		return apperrors.ErrTokenInvalid
	}

	if token.TokenType != tokenTypeReset || token.UsedAt.Valid || time.Now().UTC().After(token.ExpiresAt) {
		return apperrors.ErrTokenInvalid
	}

	consumed, err := s.repo.ConsumeEmailToken(ctx, token.ID)
	if err != nil {
		return err
	}
	if !consumed {
		return apperrors.ErrTokenInvalid
	}

	newHash, err := platformauth.HashPassword(req.NewPassword)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	if err = s.repo.UpdateUserPasswordHash(ctx, db.UpdateUserPasswordHashParams{
		PasswordHash: newHash,
		ID:           token.UserID,
	}); err != nil {
		return err
	}

	// Revoke all active sessions — an attacker holding a stolen refresh token
	// must not survive the credential change. Best-effort: a failure here is
	// logged but does not roll back the password update.
	if rErr := s.repo.RevokeUserRefreshTokens(ctx, token.UserID); rErr != nil {
		log.Error("reset-password: revoke sessions failed — sessions may survive credential change",
			zap.Error(rErr), zap.String("user_id", token.UserID),
		)
	}

	log.Info("reset-password: password updated and sessions revoked", zap.String("user_id", token.UserID))
	return nil
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

	consumed, err := s.repo.ConsumeEmailToken(ctx, token.ID)
	if err != nil {
		return err
	}
	if !consumed {
		return apperrors.ErrTokenInvalid
	}

	if err = s.repo.MarkEmailVerified(ctx, token.UserID); err != nil {
		return err
	}

	log.Info("verify-email: address verified", zap.String("user_id", token.UserID))
	return nil
}

// ── VerifyOTP ─────────────────────────────────────────────────────────────────

// VerifyOTP handles two distinct paths:
//
//  1. MFA login completion (mfa_token present): validates both the challenge
//     token and the OTP, consumes both atomically, and issues a token pair.
//
//  2. Standalone OTP check (mfa_token absent): validates and consumes the OTP
//     only. Returns nil tokens. Used for step-up auth flows.
func (s *service) VerifyOTP(ctx context.Context, req VerifyOTPRequest) (*platformauth.SessionTokens, error) {
	log := logger.FromContext(ctx)

	otpHash := platformauth.HashRefreshToken(req.Code)
	otpToken, err := s.repo.GetEmailTokenByHash(ctx, otpHash)
	if err != nil {
		return nil, apperrors.ErrTokenInvalid
	}

	if otpToken.TokenType != tokenTypeOTP || otpToken.UsedAt.Valid || time.Now().UTC().After(otpToken.ExpiresAt) {
		return nil, apperrors.ErrTokenInvalid
	}

	// ── MFA login completion ──────────────────────────────────────────────────
	if req.MFAToken != "" {
		return s.completeMFALogin(ctx, req.MFAToken, otpToken)
	}

	// ── Standalone OTP verification ───────────────────────────────────────────
	consumed, err := s.repo.ConsumeEmailToken(ctx, otpToken.ID)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, apperrors.ErrTokenInvalid
	}

	log.Info("verify-otp: OTP consumed (standalone)", zap.String("user_id", otpToken.UserID))
	return nil, nil
}

// completeMFALogin validates the challenge token, cross-checks user ownership,
// consumes both tokens, and issues a full session via the TokenIssuer.
//
// Consumption order: challenge first, OTP second. If OTP consumption fails the
// challenge is already spent, forcing the user to re-authenticate — the safe
// failure mode (no partial login state).
func (s *service) completeMFALogin(ctx context.Context, rawChallenge string, otpToken *db.EmailToken) (*platformauth.SessionTokens, error) {
	log := logger.FromContext(ctx)

	challengeHash := platformauth.HashRefreshToken(rawChallenge)
	challengeToken, err := s.repo.GetEmailTokenByHash(ctx, challengeHash)
	if err != nil {
		return nil, apperrors.ErrTokenInvalid
	}

	// Validate challenge state.
	if challengeToken.TokenType != tokenTypeChallenge ||
		challengeToken.UsedAt.Valid ||
		time.Now().UTC().After(challengeToken.ExpiresAt) {
		return nil, apperrors.ErrTokenInvalid
	}

	// Cross-check: challenge and OTP must belong to the same user.
	// Prevents one user from using another's OTP against their own challenge.
	if challengeToken.UserID != otpToken.UserID {
		log.Warn("completeMFALogin: challenge/OTP user mismatch — possible cross-user attack",
			zap.String("challenge_user", challengeToken.UserID),
			zap.String("otp_user", otpToken.UserID),
		)
		return nil, apperrors.ErrTokenInvalid
	}

	// Consume challenge first.
	consumed, err := s.repo.ConsumeEmailToken(ctx, challengeToken.ID)
	if err != nil {
		return nil, err
	}
	if !consumed {
		// Concurrent request already consumed — this is a replay attempt.
		return nil, apperrors.ErrTokenInvalid
	}

	// Consume OTP second.
	consumed, err = s.repo.ConsumeEmailToken(ctx, otpToken.ID)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, apperrors.ErrTokenInvalid
	}

	if s.tokenIssuer == nil {
		log.Error("MFA login: TokenIssuer not configured — check app.go wiring",
			zap.String("user_id", challengeToken.UserID),
		)
		return nil, apperrors.New(
			"MFA_MISCONFIGURED",
			"an unexpected error occurred",
			http.StatusInternalServerError,
			nil,
		)
	}

	tokens, err := s.tokenIssuer.IssueTokensForUser(ctx, challengeToken.UserID)
	if err != nil {
		return nil, err
	}

	log.Info("mfa login completed", zap.String("user_id", challengeToken.UserID))
	return tokens, nil
}

// ── ResendVerification ────────────────────────────────────────────────────────

// ResendVerification is the unauthenticated equivalent of SendVerification.
// It accepts an email address, looks up the user, and (if the address is
// unverified) issues a new verification token and sends the link.
//
// Always returns nil — callers must not reveal whether the address is
// registered or already verified.
func (s *service) ResendVerification(ctx context.Context, req ResendVerificationRequest) error {
	log := logger.FromContext(ctx)
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Debug("resend-verification: user not found, returning early", zap.String("email", email))
		return nil
	}

	if user.EmailVerifiedAt.Valid {
		log.Debug("resend-verification: address already verified, skipping",
			zap.String("user_id", user.ID),
		)
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
		log.Error("resend-verification: invalidate old tokens", zap.Error(err), zap.String("user_id", user.ID))
		return nil
	}

	if err = s.repo.CreateEmailToken(ctx, db.CreateEmailTokenParams{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: hash,
		TokenType: tokenTypeVerify,
		ExpiresAt: time.Now().UTC().Add(verifyTokenTTL),
	}); err != nil {
		log.Error("resend-verification: persist token", zap.Error(err), zap.String("user_id", user.ID))
		return nil
	}

	link := fmt.Sprintf("%s/auth/verify-email?token=%s", s.frontEndDomain, raw)
	s.sendEmail(ctx, user.Email, "Verify your email address", func() (string, error) {
		return mailer.VerifyEmail(user.Name, link)
	}, "resend-verification", user.ID)

	log.Info("resend-verification: token issued", zap.String("user_id", user.ID))
	return nil
}

// ── InitiateChallenge (satisfies auth.MFAChallenger) ─────────────────────────

// InitiateChallenge is the MFA login entry point. It:
//  1. Invalidates any live OTPs for the user.
//  2. Generates a fresh OTP, stores its hash, and emails the code.
//  3. Generates an opaque challenge token, stores its hash, and returns
//     the raw token to auth.Service.Login, which passes it to the client.
//
// The client holds the challenge token and OTP code. It must present both at
// POST /auth/otp/verify to receive a session token pair. The challenge proves
// credentials were verified; the OTP proves inbox access.
func (s *service) InitiateChallenge(ctx context.Context, userID, email, name string) (string, time.Time, error) {
	// Step 1: invalidate live OTPs.
	if err := s.repo.InvalidateUserTokensByType(ctx, db.InvalidateUserTokensByTypeParams{
		UserID:    userID,
		TokenType: tokenTypeOTP,
	}); err != nil {
		return "", time.Time{}, err
	}

	// Step 2: generate OTP, store hash, email code.
	code, otpHash, err := generateOTP()
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

	// Step 3: generate challenge token, store hash.
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

	s.log.Info("mfa challenge initiated", zap.String("user_id", userID))
	return raw, expiresAt, nil
}

// ── SendVerification (JWT-protected) ─────────────────────────────────────────

func (s *service) SendVerification(ctx context.Context, userID string) error {
	log := logger.FromContext(ctx)

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if user.EmailVerifiedAt.Valid {
		log.Debug("send-verification: address already verified, skipping", zap.String("user_id", userID))
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
	s.sendEmail(ctx, user.Email, "Verify your email address", func() (string, error) {
		return mailer.VerifyEmail(user.Name, link)
	}, "send-verification", userID)

	log.Info("send-verification: verification email queued", zap.String("user_id", userID))
	return nil
}

// ── SendOTP (JWT-protected) ───────────────────────────────────────────────────

func (s *service) SendOTP(ctx context.Context, userID string) error {
	log := logger.FromContext(ctx)

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	code, hash, err := generateOTP()
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

	log.Info("send-otp: OTP queued", zap.String("user_id", userID))
	return nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (s *service) sendEmail(ctx context.Context, to, subject string, renderFn func() (string, error), op, userID string) {
	if s.mailer == nil || !s.mailer.Enabled() {
		return
	}
	html, err := renderFn()
	if err != nil {
		s.log.Error(op+": render email template", zap.Error(err), zap.String("user_id", userID))
		return
	}
	if err = s.mailer.Send(ctx, mailer.Message{To: to, Subject: subject, HTML: html}); err != nil {
		s.log.Error(op+": send email", zap.Error(err), zap.String("user_id", userID))
	}
}

func generateURLToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("authemail: generate url token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = platformauth.HashRefreshToken(raw)
	return raw, hash, nil
}

func generateOTP() (code, hash string, err error) {
	max := big.NewInt(1_000_000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", "", fmt.Errorf("authemail: generate otp: %w", err)
	}
	code = fmt.Sprintf("%06d", n.Int64())
	hash = platformauth.HashRefreshToken(code)
	return code, hash, nil
}
