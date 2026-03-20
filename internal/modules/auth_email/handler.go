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

func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	_ = h.svc.ForgotPassword(c.Request.Context(), req)
	response.OK(c, gin.H{"message": "if that email is registered, a reset link has been sent"})
}

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

func (h *Handler) ResendVerification(c *gin.Context) {
	var req ResendVerificationRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}
	_ = h.svc.ResendVerification(c.Request.Context(), req)
	response.OK(c, gin.H{"message": "if that email is registered and unverified, a new link has been sent"})
}

// ── JWT-protected handlers ────────────────────────────────────────────────────

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
