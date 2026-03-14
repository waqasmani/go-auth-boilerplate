package auth

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// Handler exposes auth HTTP endpoints.
type Handler struct {
	svc      Service
	validate *validator.Validate
	cfg      *config.Config
}

// NewHandler constructs an auth handler.
func NewHandler(svc Service, cfg *config.Config) *Handler {
	v := validator.New()

	// Register json tag names so validation errors report "password" not "Password".
	// This closes the struct naming leak and aligns error keys with request fields.
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" || name == "" {
			return fld.Name
		}
		return name
	})

	return &Handler{svc: svc, validate: v, cfg: cfg}
}

// Register godoc
// @Summary      Register a new user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body RegisterRequest true "Registration payload"
// @Success      201 {object} response.Response{data=TokenResponse}
// @Router       /auth/register [post]
func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	log := logger.FromContext(c.Request.Context())
	log.Debug("register request", zap.String("email", req.Email))

	tokenResp, err := h.svc.Register(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}
	h.setCookie(c, tokenResp.RefreshToken)
	response.Created(c, tokenResp)
}

// Login godoc
// @Summary      Login
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body body LoginRequest true "Login payload"
// @Success      200 {object} response.Response{data=TokenResponse}
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	tokenResp, err := h.svc.Login(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}
	h.setCookie(c, tokenResp.RefreshToken)
	response.OK(c, tokenResp)
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

	// Try cookie first (web)
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

	// Set cookie for web clients
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

	// Try cookie first (web)
	refreshToken, err := c.Cookie("refresh_token")
	if err == nil {
		req.RefreshToken = refreshToken
	} else if !response.BindAndValidate(c, &req, h.validate) {
		return
	}

	if err := h.svc.Logout(c.Request.Context(), req); err != nil {
		response.Error(c, err)
		return
	}

	if refreshToken != "" {
		c.SetSameSite(http.SameSiteLaxMode)
		h.clearCookie(c)
	}
	response.NoContent(c)
}

// Cookie helper func
func (h *Handler) setCookie(c *gin.Context, token string) {
	u, err := url.Parse(h.cfg.FrontEndDomain)
	domain := ""
	if err == nil {
		domain = u.Hostname()
	}

	secure := h.cfg.AppEnv == "production"

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"refresh_token",
		token,
		int(h.cfg.RefreshTTL.Seconds()),
		"/",
		domain,
		secure, // Secure only in production
		true,   // HttpOnly ALWAYS true
	)
}

func (h *Handler) clearCookie(c *gin.Context) {
	u, err := url.Parse(h.cfg.FrontEndDomain)
	domain := ""
	if err == nil {
		domain = u.Hostname()
	}

	secure := h.cfg.AppEnv == "production"
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		domain,
		secure, // Secure only in production
		true,   // HttpOnly ALWAYS true
	)
}
