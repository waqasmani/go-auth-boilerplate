package users

import (
	"github.com/gin-gonic/gin"

	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"go.uber.org/zap"
)

// RegisterRoutes attaches user endpoints to a RouterGroup.
func RegisterRoutes(rg *gin.RouterGroup, h *Handler, jwt *platformauth.JWT, revoker *platformauth.AccessRevoker, log *zap.Logger) {
	protected := rg.Group("")
	protected.Use(middleware.Auth(jwt, revoker, log))
	{
		protected.GET("/me", h.Me)
	}
}
