package authemail

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// ── DTOs ─────────────────────────────────────────────────────────────────────

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"        validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=12,max=72"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// VerifyOTPRequest handles both standalone OTP checks and MFA login completion.
// When MFAToken is present the service completes the MFA login flow and returns
// a full token pair. When absent it performs a standalone OTP verification.
type VerifyOTPRequest struct {
	// Code is the 6-digit numeric OTP exactly as received in the email.
	Code string `json:"code" validate:"required,len=6"`
	// MFAToken is the opaque challenge token returned by POST /auth/login when
	// two_fa_enabled is true. Required for MFA login completion; omit for
	// standalone OTP checks (step-up auth, etc.).
	MFAToken string `json:"mfa_token"`
}

// ResendVerificationRequest is the payload for POST /auth/resend-verification.
// Unauthenticated — intended for users who cannot log in because their email
// is not yet verified.
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ── Handler ───────────────────────────────────────────────────────────────────

// Handler exposes email-auth HTTP endpoints.
type Handler struct {
	svc      Service
	validate *validator.Validate
	cfg      *config.Config // needed to set the refresh cookie on MFA login completion
}

// NewHandler constructs an email-auth handler.
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
// @Tags         auth-email
// @Accept       json
// @Produce      json
// @Param        body body ForgotPasswordRequest true "Email address"
// @Success      200 {object} response.Response
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
// @Tags         auth-email
// @Accept       json
// @Produce      json
// @Param        body body ResetPasswordRequest true "Reset token and new password"
// @Success      200 {object} response.Response
// @Failure      401 {object} response.Response
// @Router       /auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), req); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "password has been reset successfully"})
}

// VerifyEmail godoc
// @Summary      Verify email address using a one-time token
// @Tags         auth-email
// @Accept       json
// @Produce      json
// @Param        body body VerifyEmailRequest true "Verification token"
// @Success      200 {object} response.Response
// @Failure      401 {object} response.Response
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
// @Summary      Verify OTP — standalone check or MFA login completion
// @Description  When mfa_token is present: validates both the challenge token and the OTP,
// @Description  consumes both, and returns a full token pair (completing the MFA login).
// @Description  When mfa_token is absent: validates and consumes the OTP only (step-up auth).
// @Tags         auth-email
// @Accept       json
// @Produce      json
// @Param        body body VerifyOTPRequest true "OTP code and optional MFA challenge token"
// @Success      200 {object} response.Response{data=auth.TokenResponse} "MFA login completed"
// @Success      200 {object} response.Response "Standalone OTP verified"
// @Failure      401 {object} response.Response
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

	// MFA login completion: set the refresh cookie and return the token pair.
	if tokens != nil {
		h.setCookie(c, tokens.RefreshToken)
		response.OK(c, tokens)
		return
	}

	// Standalone OTP check: no tokens to return.
	response.OK(c, gin.H{"message": "OTP verified successfully"})
}

// ResendVerification godoc
// @Summary      Resend email-verification link (unauthenticated)
// @Description  Accepts an email address and, if it belongs to an unverified account,
// @Description  sends a new verification link. Always returns 200 to prevent enumeration.
// @Tags         auth-email
// @Accept       json
// @Produce      json
// @Param        body body ResendVerificationRequest true "Email address"
// @Success      200 {object} response.Response
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
// @Summary      Send or resend the email-verification link (authenticated)
// @Tags         auth-email
// @Security     BearerAuth
// @Produce      json
// @Success      200 {object} response.Response
// @Failure      401 {object} response.Response
// @Router       /auth/send-verification [post]
func (h *Handler) SendVerification(c *gin.Context) {
	claims := middleware.MustGetClaims(c)
	if err := h.svc.SendVerification(c.Request.Context(), claims.UserID); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "verification email sent"})
}

// SendOTP godoc
// @Summary      Send a 2FA one-time passcode (authenticated)
// @Tags         auth-email
// @Security     BearerAuth
// @Produce      json
// @Success      200 {object} response.Response
// @Failure      401 {object} response.Response
// @Router       /auth/otp/send [post]
func (h *Handler) SendOTP(c *gin.Context) {
	claims := middleware.MustGetClaims(c)
	if err := h.svc.SendOTP(c.Request.Context(), claims.UserID); err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, gin.H{"message": "OTP sent"})
}

// ── Cookie helpers ────────────────────────────────────────────────────────────
// Replicated from auth.Handler intentionally — the two handlers have different
// dependency graphs and sharing a utility would introduce unnecessary coupling.

func (h *Handler) setCookie(c *gin.Context, token string) {
	u, err := url.Parse(h.cfg.FrontEndDomain)
	domain := ""
	if err == nil {
		domain = u.Hostname()
	}
	secure := h.cfg.AppEnv == "production"
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("refresh_token", token, int(h.cfg.RefreshTTL.Seconds()), "/", domain, secure, true)
}
