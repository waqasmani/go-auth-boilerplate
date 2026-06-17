package auth

import (
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// RegisterRoutes attaches auth endpoints to a RouterGroup.
//
// Rate limiting is applied selectively:
//   - POST /login    ← throttled per-IP (brute-force target) via Redis
//   - POST /register ← throttled per-IP via Redis
//   - POST /refresh  ← independently throttled + CSRF-checked (cookie path)
//   - POST /logout   ← CSRF-checked (cookie path)
func RegisterRoutes(
	rg *gin.RouterGroup,
	h *Handler,
	jwt *platformauth.JWT,
	revoker *platformauth.AccessRevoker,
	rlCfg middleware.RateLimitConfig,
	refreshRlCfg middleware.RateLimitConfig,
	csrfCfg middleware.CookieCSRFConfig,
	rdb *goredis.Client,
	log *zap.Logger,
) {
	csrfCheck := middleware.CookieCSRF(csrfCfg)

	// ── Rate-limited routes ────────────────────────────────────────────────────
	protected := rg.Group("")
	protected.Use(middleware.RateLimit(rlCfg, rdb, log))
	{
		protected.POST("/login", h.Login)
		protected.POST("/register", h.Register)
	}

	// ── Cookie-consuming routes — rate-limited + CSRF-checked ─────────────────
	rg.POST("/refresh",
		middleware.RateLimit(refreshRlCfg, rdb, log),
		csrfCheck,
		h.Refresh,
	)
	rg.POST("/logout", csrfCheck, h.Logout)

	// ── Authenticated session management ──────────────────────────────────────
	// logout-all is bearer-authenticated (it acts on the caller's own account)
	// and terminates every session fleet-wide.
	rg.POST("/logout-all", middleware.Auth(jwt, revoker, log), h.LogoutAll)
}
