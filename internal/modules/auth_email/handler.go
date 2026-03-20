package authemail

import (
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/cookieutil"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// ── DTOs ──────────────────────────────────────────────────────────────────────

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"        validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=12,max=128"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

type VerifyOTPRequest struct {
	Code     string `json:"code"      validate:"required,len=6,numeric"`
	MFAToken string `json:"mfa_token"`
}

type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type EnableTOTPRequest struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

type TOTPSetupResponse struct {
	Secret   string `json:"secret"`
	URI      string `json:"uri"`
	QRBase64 string `json:"qr_base64"`
}

type OTPTokenResponse struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	AccessTokenExpiresAt  string `json:"access_token_expires_at"`
	RefreshTokenExpiresAt string `json:"refresh_token_expires_at"`
}

type DisableTOTPRequest struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

type Handler struct {
	svc      Service
	validate *validator.Validate
	cfg      *config.Config
}

func NewHandler(svc Service, cfg *config.Config) *Handler {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" || name == "" {
			return fld.Name
		}
		return name
	})
	return &Handler{svc: svc, validate: v, cfg: cfg}
}

// ── Public handlers ───────────────────────────────────────────────────────────

// ForgotPassword godoc
// @Summary      Request a password-reset email
// @Description  Looks up the account by email and sends a one-time reset link valid for 1 hour.
// @Description  Always returns 200 regardless of whether the email is registered, to prevent
// @Description  user-enumeration attacks.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body ForgotPasswordRequest true "Email address to send the reset link to"
// @Success      200 {object} response.Response{data=object{message=string}}
// @Failure      415 {object} response.Response "Content-Type must be application/json"
// @Failure      422 {object} response.Response "Validation error"
// @Failure      429 {object} response.Response "Rate limit exceeded"
// @Router       /auth/forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	_ = h.svc.ForgotPassword(c.Request.Context(), req)
	response.OK(c, gin.H{"message": "if that email is registered, a reset link has been sent"})
}

// ResetPassword godoc
// @Summary      Reset password using a one-time token
// @Description  Validates the token from the password-reset email, updates the password,
// @Description  revokes all active refresh tokens, and clears email verification so the user
// @Description  must re-confirm inbox ownership before signing in again.
// @Description  A new verification email is dispatched automatically; the response body
// @Description  reports whether dispatch succeeded via `email_verification_sent`.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body ResetPasswordRequest true "Reset token and new password"
// @Success      200 {object} response.Response{data=object{message=string,email_verification_sent=bool}}
// @Failure      401 {object} response.Response "Token invalid or expired"
// @Failure      415 {object} response.Response "Content-Type must be application/json"
// @Failure      422 {object} response.Response "Validation error"
// @Failure      429 {object} response.Response "Rate limit exceeded"
// @Router       /auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	result, err := h.svc.ResetPassword(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{
		"message":                 "password has been reset successfully",
		"email_verification_sent": result.EmailVerificationSent,
	})
}

// VerifyEmail godoc
// @Summary      Verify email address using a one-time token
// @Description  Marks the account as email-verified once the user clicks the link sent
// @Description  during registration or by the resend-verification endpoint.
// @Description  The token is valid for 24 hours and is single-use.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body VerifyEmailRequest true "One-time verification token"
// @Success      200 {object} response.Response{data=object{message=string}}
// @Failure      401 {object} response.Response "Token invalid or expired"
// @Failure      415 {object} response.Response "Content-Type must be application/json"
// @Failure      422 {object} response.Response "Validation error"
// @Failure      429 {object} response.Response "Rate limit exceeded"
// @Router       /auth/verify-email [post]
func (h *Handler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	if err := h.svc.VerifyEmail(c.Request.Context(), req); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "email address verified successfully"})
}

// VerifyOTP godoc
// @Summary      Verify a one-time passcode (OTP or TOTP)
// @Description  Two distinct flows share this endpoint:
// @Description
// @Description  **MFA login completion** — supply `mfa_token` (from the login challenge response)
// @Description  together with the 6-digit `code` from the authenticator app (TOTP) or email (OTP).
// @Description  On success a full token pair is returned and the `refresh_token` HttpOnly cookie
// @Description  is set.
// @Description
// @Description  **Standalone OTP verification** — omit `mfa_token` to consume a one-off OTP
// @Description  that was sent via `POST /auth/otp/send`. Returns 200 with no token pair.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body VerifyOTPRequest true "6-digit code, and optionally the MFA challenge token"
// @Success      200 {object} response.Response{data=OTPTokenResponse} "MFA login completed — token pair returned"
// @Success      200 {object} response.Response{data=object{message=string}} "Standalone OTP consumed"
// @Failure      401 {object} response.Response "Code or MFA token invalid or expired"
// @Failure      415 {object} response.Response "Content-Type must be application/json"
// @Failure      422 {object} response.Response "Validation error"
// @Failure      429 {object} response.Response "Rate limit exceeded"
// @Router       /auth/otp/verify [post]
func (h *Handler) VerifyOTP(c *gin.Context) {
	var req VerifyOTPRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	tokens, err := h.svc.VerifyOTP(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}
	if tokens != nil {
		h.setCookie(c, tokens.RefreshToken)
		response.OK(c, tokens)
		return
	}
	response.OK(c, gin.H{"message": "OTP verified successfully"})
}

// ResendVerification godoc
// @Summary      Resend the email-verification link
// @Description  Issues a new verification token and dispatches the confirmation email.
// @Description  No-ops silently when the email is unknown or already verified, to prevent
// @Description  user-enumeration attacks. Always returns 200.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body ResendVerificationRequest true "Email address to resend the link to"
// @Success      200 {object} response.Response{data=object{message=string}}
// @Failure      415 {object} response.Response "Content-Type must be application/json"
// @Failure      422 {object} response.Response "Validation error"
// @Failure      429 {object} response.Response "Rate limit exceeded"
// @Router       /auth/resend-verification [post]
func (h *Handler) ResendVerification(c *gin.Context) {
	var req ResendVerificationRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	_ = h.svc.ResendVerification(c.Request.Context(), req)
	response.OK(c, gin.H{"message": "if that email is registered and unverified, a new link has been sent"})
}

// ── JWT-protected handlers ────────────────────────────────────────────────────

// SendVerification godoc
// @Summary      Send a verification email (authenticated)
// @Description  Dispatches a new email-verification link to the signed-in user's address.
// @Description  No-ops silently when the address is already verified.
// @Tags         auth
// @Security     BearerAuth
// @Produce      json
// @Success      200 {object} response.Response{data=object{message=string}}
// @Failure      401 {object} response.Response "Missing or invalid access token"
// @Router       /auth/send-verification [post]
func (h *Handler) SendVerification(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Error(c, apperrors.ErrUnauthorized)
		c.Abort()
		return
	}
	if err := h.svc.SendVerification(c.Request.Context(), claims.UserID); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "verification email sent"})
}

// SendOTP godoc
// @Summary      Send a 2FA OTP to the signed-in user (authenticated)
// @Description  Generates a 6-digit one-time passcode, stores its HMAC hash, and dispatches
// @Description  it by email. The code is valid for 10 minutes and is single-use.
// @Description  Requires `two_fa_enabled = true` on the account; returns 403 otherwise.
// @Tags         auth
// @Security     BearerAuth
// @Produce      json
// @Success      200 {object} response.Response{data=object{message=string}}
// @Failure      401 {object} response.Response "Missing or invalid access token"
// @Failure      403 {object} response.Response "Two-factor authentication is not enabled"
// @Router       /auth/otp/send [post]
func (h *Handler) SendOTP(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Error(c, apperrors.ErrUnauthorized)
		c.Abort()
		return
	}
	if err := h.svc.SendOTP(c.Request.Context(), claims.UserID); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "OTP sent"})
}

// ── TOTP lifecycle handlers ───────────────────────────────────────────────────

// SetupTOTP godoc
// @Summary      Begin TOTP setup (authenticated)
// @Description  Generates a new TOTP secret, encrypts it, stores it as pending (not yet active),
// @Description  and returns the plaintext secret, the `otpauth://` provisioning URI, and a
// @Description  base64-encoded QR-code PNG for display in the UI.
// @Description
// @Description  The secret is not activated until the user calls `POST /auth/mfa/totp/enable`
// @Description  with a valid code, proving possession of the authenticator. Calling this endpoint
// @Description  again before enabling overwrites the pending secret.
// @Tags         auth
// @Security     BearerAuth
// @Produce      json
// @Success      200 {object} response.Response{data=TOTPSetupResponse}
// @Failure      401 {object} response.Response "Missing or invalid access token"
// @Failure      500 {object} response.Response "Internal error generating the secret"
// @Router       /auth/mfa/totp/setup [post]
func (h *Handler) SetupTOTP(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Error(c, apperrors.ErrUnauthorized)
		c.Abort()
		return
	}
	secret, uri, qrBase64, err := h.svc.SetupTOTP(c.Request.Context(), claims.UserID)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, TOTPSetupResponse{Secret: secret, URI: uri, QRBase64: qrBase64})
}

// EnableTOTP godoc
// @Summary      Confirm TOTP setup and activate (authenticated)
// @Description  Validates the 6-digit code from the authenticator app against the pending secret
// @Description  stored by `POST /auth/mfa/totp/setup`. On success, sets `mfa_method = totp` and
// @Description  `two_fa_enabled = true`; future logins will require a TOTP code.
// @Description
// @Description  The same code cannot be reused within its 90-second validity window (replay
// @Description  prevention is backed by Redis).
// @Tags         auth
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body EnableTOTPRequest true "Current 6-digit TOTP code from the authenticator app"
// @Success      200 {object} response.Response{data=object{message=string}}
// @Failure      401 {object} response.Response "Missing or invalid access token"
// @Failure      422 {object} response.Response "Code incorrect, replayed, or TOTP not yet set up"
// @Failure      429 {object} response.Response "Rate limit exceeded"
// @Router       /auth/mfa/totp/enable [post]
func (h *Handler) EnableTOTP(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Error(c, apperrors.ErrUnauthorized)
		c.Abort()
		return
	}
	var req EnableTOTPRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	if err := h.svc.EnableTOTP(c.Request.Context(), claims.UserID, req.Code); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "TOTP enabled — future logins will require your authenticator app"})
}

// DisableTOTP godoc
// @Summary      Disable TOTP and revert to email OTP (authenticated)
// @Description  Validates the supplied TOTP code, then atomically:
// @Description  - Reverts `mfa_method` to `email` and clears `two_fa_enabled`.
// @Description  - Invalidates all in-flight MFA challenge tokens so any concurrent
// @Description    TOTP login cannot complete after this call.
// @Description  - Revokes all active refresh tokens, forcing a fresh login.
// @Description
// @Description  Requires the current TOTP code to prevent an attacker with a stolen
// @Description  access token from silently downgrading the account's MFA method.
// @Tags         auth
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        body body DisableTOTPRequest true "Current 6-digit TOTP code confirming possession"
// @Success      200 {object} response.Response{data=object{message=string}}
// @Failure      400 {object} response.Response "TOTP not configured on this account"
// @Failure      401 {object} response.Response "Missing or invalid access token"
// @Failure      422 {object} response.Response "Code incorrect or replayed"
// @Router       /auth/mfa/totp/disable [post]
func (h *Handler) DisableTOTP(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Error(c, apperrors.ErrUnauthorized)
		c.Abort()
		return
	}

	// Require request body with current TOTP code to prevent unauthorized disablement
	var req DisableTOTPRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	if err := h.svc.DisableTOTP(c.Request.Context(), claims.UserID, req.Code); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "TOTP disabled — email OTP is now active for this account"})
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

// setCookie writes the HttpOnly refresh-token cookie. Domain, SameSite, and
// Secure are all driven by config via cookieutil so they are identical to the
// cookies set by auth/handler.go and oauth/handler.go.
func (h *Handler) setCookie(c *gin.Context, token string) {
	c.SetSameSite(cookieutil.ParseSameSite(h.cfg.CookieSameSite))
	c.SetCookie(
		"refresh_token",
		token,
		int(h.cfg.RefreshTTL.Seconds()),
		"/",
		cookieutil.ResolveCookieDomain(h.cfg),
		h.cfg.CookieSecure, // config-driven — not derived from AppEnv
		true,               // HttpOnly — always
	)
}
