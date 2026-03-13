package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// Handler exposes auth HTTP endpoints.
type Handler struct {
	svc      Service
	validate *validator.Validate
}

// NewHandler constructs an auth handler.
func NewHandler(svc Service) *Handler {
	return &Handler{
		svc:      svc,
		validate: validator.New(),
	}
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
	if !bindAndValidate(c, &req, h.validate) {
		return
	}

	log := logger.FromContext(c.Request.Context())
	log.Debug("register request", zap.String("email", req.Email))

	tokenResp, err := h.svc.Register(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}
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
	if !bindAndValidate(c, &req, h.validate) {
		return
	}

	tokenResp, err := h.svc.Login(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}
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
	if !bindAndValidate(c, &req, h.validate) {
		return
	}

	tokenResp, err := h.svc.Refresh(c.Request.Context(), req)
	if err != nil {
		response.Error(c, err)
		return
	}
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
	if !bindAndValidate(c, &req, h.validate) {
		return
	}

	if err := h.svc.Logout(c.Request.Context(), req); err != nil {
		response.Error(c, err)
		return
	}
	response.NoContent(c)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// bindAndValidate binds JSON and runs struct validation.
// Returns false and writes an error response when binding or validation fails.
func bindAndValidate(c *gin.Context, req interface{}, v *validator.Validate) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		response.ValidationError(c, map[string]string{"body": err.Error()})
		return false
	}
	if err := v.Struct(req); err != nil {
		fields := make(map[string]string)
		for _, fe := range err.(validator.ValidationErrors) {
			fields[fe.Field()] = fe.Tag()
		}
		response.ValidationError(c, fields)
		return false
	}
	return true
}
