// auth/handler.go — cookie domain uses cfg.CookieDomain with FrontEndDomain fallback

package auth

import (
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/cookieutil"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// Handler exposes auth HTTP endpoints.
type Handler struct {
	svc          Service
	validate     *validator.Validate
	cfg          *config.Config
	emailLimiter *middleware.Limiter
}

// NewHandler constructs an auth handler.
func NewHandler(svc Service, cfg *config.Config, emailLimiter *middleware.Limiter) *Handler {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" || name == "" {
			return fld.Name
		}
		return name
	})
	return &Handler{svc: svc, validate: v, cfg: cfg, emailLimiter: emailLimiter}
}

// Register godoc
// @Summary      Register a new user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body RegisterRequest true "Registration payload"
// @Success      202 {object} response.Response
// @Failure      409 {object} response.Response "Email already registered"
// @Failure      422 {object} response.Response "Validation error"
// @Router       /auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	log := logger.FromContext(c.Request.Context())
	log.Debug("register request", zap.String("email", req.Email))

	if err := h.svc.Register(c.Request.Context(), req); err != nil {
		response.Error(c, err)
		return
	}

	c.JSON(http.StatusAccepted, response.Response{
		Success: true,
		Data:    gin.H{"message": "registration successful — please check your inbox to verify your email address"},
	})
}

// Login godoc
// @Summary      Login
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body LoginRequest true "Login payload"
// @Success      200 {object} response.Response{data=TokenResponse}
// @Success      200 {object} response.Response{data=MFAChallengeResponse}
// @Failure      401 {object} response.Response
// @Failure      403 {object} response.Response
// @Failure      429 {object} response.Response "Account locked or rate limit exceeded"
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if allowed, retryAfter := h.emailLimiter.Allow("login:email:" + email); !allowed {
		seconds := max(int(retryAfter.Seconds())+1, 1)
		c.Header("Retry-After", strconv.Itoa(seconds))
		response.Error(c, apperrors.ErrRateLimitExceeded)
		return
	}

	result, err := h.svc.Login(c.Request.Context(), req)
	if err != nil {
		// Account lockout: service returns *apperrors.LockoutError which embeds
		// *AppError (HTTP 429, code ACCOUNT_LOCKED). Extract the remaining lock
		// duration and emit a standard Retry-After header so well-behaved clients
		// and API gateways can back off without polling.
		//
		// errors.As traverses the error chain — LockoutError.Unwrap returns the
		// embedded *AppError, so response.Error below still uses the correct
		// HTTP status and error code from the AppError.
		var lockErr *apperrors.LockoutError
		if errors.As(err, &lockErr) {
			seconds := max(int(lockErr.RetryAfter.Seconds())+1, 1)
			c.Header("Retry-After", strconv.Itoa(seconds))
		}
		response.Error(c, err)
		return
	}

	if result.Challenge != nil {
		response.OK(c, result.Challenge)
		return
	}

	h.setCookie(c, result.Token.RefreshToken)
	response.OK(c, result.Token)
}

// Refresh godoc
// @Summary      Refresh token pair
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body RefreshRequest true "Refresh payload"
// @Success      200 {object} response.Response{data=TokenResponse}
// @Router       /auth/refresh [post]
func (h *Handler) Refresh(c *gin.Context) {
	var req RefreshRequest

	refreshToken, err := c.Cookie("refresh_token")
	if err == nil {
		req.RefreshToken = refreshToken
	} else if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	tokenResp, err := h.svc.Refresh(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}

	h.setCookie(c, tokenResp.RefreshToken)
	response.OK(c, tokenResp)
}

// Logout godoc
// @Summary      Logout (revoke refresh token family)
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body LogoutRequest true "Logout payload"
// @Success      204
// @Router       /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	var req LogoutRequest

	refreshToken, err := c.Cookie("refresh_token")
	if err == nil {
		req.RefreshToken = refreshToken
	} else if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	h.clearCookie(c)

	if err := h.svc.Logout(c.Request.Context(), req); err != nil {
		response.Error(c, err)
		return
	}

	response.NoContent(c)
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

// setCookie writes the HttpOnly refresh-token cookie.
//
// Domain resolution and SameSite parsing are handled by cookieutil so the
// behaviour is identical to auth_email/handler.go and oauth/handler.go.
// See cookieutil.ResolveCookieDomain and cookieutil.ParseSameSite for the
// full resolution rules.
func (h *Handler) setCookie(c *gin.Context, token string) {
	c.SetSameSite(cookieutil.ParseSameSite(h.cfg.CookieSameSite))
	c.SetCookie(
		"refresh_token",
		token,
		int(h.cfg.RefreshTTL.Seconds()),
		"/",
		cookieutil.ResolveCookieDomain(h.cfg),
		h.cfg.CookieSecure,
		true, // HttpOnly — always
	)
}

func (h *Handler) clearCookie(c *gin.Context) {
	c.SetSameSite(cookieutil.ParseSameSite(h.cfg.CookieSameSite))
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		cookieutil.ResolveCookieDomain(h.cfg),
		h.cfg.CookieSecure,
		true,
	)
}
