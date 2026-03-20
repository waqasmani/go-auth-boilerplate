package users

import (
	"github.com/gin-gonic/gin"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// Handler exposes user HTTP endpoints.
type Handler struct {
	svc Service
}

// NewHandler constructs a users handler.
func NewHandler(svc Service) *Handler {
	return &Handler{svc: svc}
}

// Me godoc
// @Summary      Get current user profile
// @Tags         users
// @Security     BearerAuth
// @Produce      json
// @Success      200 {object} response.Response{data=UserResponse}
// @Router       /users/me [get]
func (h *Handler) Me(c *gin.Context) {
	claims, ok := middleware.GetClaims(c)
	if !ok {
		response.Error(c, apperrors.ErrUnauthorized)
		c.Abort()
		return
	}
	userResp, err := h.svc.GetMe(c.Request.Context(), claims.UserID)
	if err != nil {
		response.Error(c, err)
		return
	}
	response.OK(c, userResp)
}
