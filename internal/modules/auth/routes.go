package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
)

// RegisterRoutes attaches auth endpoints to a RouterGroup.
//
// Rate limiting is applied selectively:
//   - POST /login    ← throttled  (brute-force target)
//   - POST /register ← throttled  (account-creation spam target)
//   - POST /refresh  ← unrestricted (requires valid refresh token)
//   - POST /logout   ← unrestricted (requires valid refresh token)
func RegisterRoutes(rg *gin.RouterGroup, h *Handler, rlCfg middleware.RateLimitConfig) {
	// Build a single shared limiter instance for the protected sub-group.
	// Both login and register share the same per-IP bucket so a flood of
	// register attempts counts against the same quota as login attempts.
	rateLimiter := middleware.RateLimit(rlCfg)

	// Protected routes — rate limited.
	protected := rg.Group("")
	protected.Use(rateLimiter)
	{
		protected.POST("/login", h.Login)
		protected.POST("/register", h.Register)
	}

	// Unrestricted routes — no rate limiting.
	rg.POST("/refresh", h.Refresh)
	rg.POST("/logout", h.Logout)
}
