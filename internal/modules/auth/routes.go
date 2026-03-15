package auth

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"golang.org/x/time/rate"
)

// RegisterRoutes attaches auth endpoints to a RouterGroup.
//
// Rate limiting is applied selectively:
//   - POST /login    ← throttled  (brute-force target)
//   - POST /register ← throttled  (account-creation spam target)
//   - POST /refresh  ← lightly throttled + CSRF-checked (cookie path)
//   - POST /logout   ← CSRF-checked (cookie path)
//
// The csrfCfg is applied only to /refresh and /logout because those are the
// two endpoints that accept the refresh token via the HttpOnly cookie.
// /login and /register never read the cookie, so the CSRF check is not needed
// there — and adding it would break the JSON-only flow unnecessarily.
func RegisterRoutes(rg *gin.RouterGroup, h *Handler, rlCfg middleware.RateLimitConfig, csrfCfg middleware.CookieCSRFConfig) {
	csrfCheck := middleware.CookieCSRF(csrfCfg)

	// ── Rate-limited routes ────────────────────────────────────────────────────
	// Both login and register share one per-IP bucket so a flood of register
	// attempts counts against the same quota as login attempts.
	protected := rg.Group("")
	protected.Use(middleware.RateLimit(rlCfg))
	{
		protected.POST("/login", h.Login)
		protected.POST("/register", h.Register)
	}

	// ── Cookie-consuming routes — rate-limited + CSRF-checked ─────────────────
	// csrfCheck runs before the handler so a CSRF-rejected request never
	// touches the token database.
	rg.POST("/refresh",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate:    rate.Limit(1),
			Burst:   5,
			TTL:     1 * time.Minute,
			MaxKeys: 10_000,
		}),
		csrfCheck,
		h.Refresh,
	)
	rg.POST("/logout", csrfCheck, h.Logout)
}
