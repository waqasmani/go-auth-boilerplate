package router

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	authmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	usersmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/users"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// Options carries optional router-level configuration.
// Using a struct keeps New()'s signature stable as new options are added.
type Options struct {
	// RateLimit configures IP-based throttling applied to the auth endpoints
	// that are most exposed to brute-force / credential-stuffing attacks.
	// Pass middleware.DefaultRateLimitConfig() for sensible production defaults.
	RateLimit middleware.RateLimitConfig

	// CORS configures the Cross-Origin Resource Sharing policy applied globally
	// before any route handler runs. Preflight OPTIONS requests are answered
	// immediately — they never reach auth or rate-limit middleware.
	// Pass middleware.DefaultCORSConfig() for local-development defaults.
	CORS middleware.CORSConfig

	// SecureHeaders configures the defensive HTTP response headers written on
	// every response (X-Content-Type-Options, X-Frame-Options, etc.).
	// HSTS is disabled by default and must be opted into in production.
	// Pass middleware.DefaultSecureHeadersConfig() for safe development defaults.
	SecureHeaders middleware.SecureHeadersConfig
}

// DefaultOptions returns router options with production-appropriate rate limits
// and local-development CORS defaults (localhost:3000 only).
func DefaultOptions() Options {
	return Options{
		RateLimit:     middleware.DefaultRateLimitConfig(),
		CORS:          middleware.DefaultCORSConfig(),
		SecureHeaders: middleware.DefaultSecureHeadersConfig(),
	}
}

// New builds and returns a configured *gin.Engine.
//
// Middleware is applied in the following order, which matters:
//
//  1. CORS — must be first so preflight OPTIONS responses are returned before
//     any auth check or rate limiter runs. A 401 on a preflight request means
//     the browser never sends the real request, silently breaking the frontend.
//  2. SecureHeaders — writes defensive headers on every response including
//     preflight replies; placed before RequestID so headers are present even
//     if a later middleware short-circuits the chain.
//  3. RequestID — injects / propagates X-Request-ID for tracing.
//  4. Logger — structured request logging (reads RequestID set above).
//  5. Recovery — panic → 500 with no stack leak (reads RequestID set above).
//
// Rate limiting is applied selectively inside route groups rather than
// globally; see authmodule.RegisterRoutes for details.
func New(
	env string,
	log *zap.Logger,
	jwtHelper *platformauth.JWT,
	authMod *authmodule.Module,
	usersMod *usersmodule.Module,
	opts Options,
) *gin.Engine {
	if env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// ─── Global Middleware ─────────────────────────────────────────────────────
	// Order is intentional — see godoc above.
	r.Use(middleware.CORS(opts.CORS))
	r.Use(middleware.SecureHeaders(opts.SecureHeaders))
	r.Use(middleware.RequestID())
	r.Use(middleware.Logger(log))
	r.Use(middleware.Recovery(log))

	// ─── Health Check ──────────────────────────────────────────────────────────
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// ─── API v1 ────────────────────────────────────────────────────────────────
	v1 := r.Group("/api/v1")

	// ── Auth ───────────────────────────────────────────────────────────────────
	authGroup := v1.Group("/auth")
	authmodule.RegisterRoutes(authGroup, authMod.Handler, opts.RateLimit)

	// ── Users ──────────────────────────────────────────────────────────────────
	usersGroup := v1.Group("/users")
	usersmodule.RegisterRoutes(usersGroup, usersMod.Handler, jwtHelper, log)

	return r
}

// RateLimitConfigFromValues constructs a middleware.RateLimitConfig from scalar
// values — useful when building Options from config package fields without
// importing the middleware package at the call site.
func RateLimitConfigFromValues(r float64, burst int, ttl time.Duration, maxKeys int) middleware.RateLimitConfig {
	return middleware.RateLimitConfig{
		Rate:    rate.Limit(r),
		Burst:   burst,
		TTL:     ttl,
		MaxKeys: maxKeys,
	}
}

// CORSConfigFromValues constructs a middleware.CORSConfig from scalar config
// values — mirrors RateLimitConfigFromValues so app.go never imports middleware
// directly.
func CORSConfigFromValues(origins, headers []string, allowCredentials bool, maxAge int) middleware.CORSConfig {
	return middleware.CORSConfig{
		AllowedOrigins:   origins,
		AllowedHeaders:   headers,
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}
}

// SecureHeadersConfigFromValues constructs a middleware.SecureHeadersConfig
// from scalar config values — mirrors the other ConfigFromValues helpers so
// app.go can bridge config package fields into router.Options without
// importing the middleware package directly.
func SecureHeadersConfigFromValues(hstsEnabled bool, hstsMaxAge int) middleware.SecureHeadersConfig {
	return middleware.SecureHeadersConfig{
		HSTSEnabled:           hstsEnabled,
		HSTSMaxAge:            hstsMaxAge,
		HSTSIncludeSubDomains: true, // safe default; matches ProductionSecureHeadersConfig
	}
}
