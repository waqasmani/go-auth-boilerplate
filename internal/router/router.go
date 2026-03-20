package router

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/waqasmani/go-auth-boilerplate/docs"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	authmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	emailmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth_email"
	oauthmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/oauth"
	usersmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/users"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	redispkg "github.com/waqasmani/go-auth-boilerplate/internal/platform/redis"
)

const requestTimeout = 25 * time.Second

// Options carries optional router-level configuration.
type Options struct {
	RateLimit         middleware.RateLimitConfig
	RefreshRateLimit  middleware.RateLimitConfig
	EmailRateLimit    emailmodule.EmailRateLimits
	OAuthRateLimits   oauthmodule.RateLimits
	CORS              middleware.CORSConfig
	SecureHeaders     middleware.SecureHeadersConfig
	TrustedProxyCIDRs []string
	CookieCSRF        middleware.CookieCSRFConfig
	SqlDB             *sql.DB
	ShutdownCh        <-chan struct{}

	// RedisClient is the optional Redis wrapper used by the /health endpoint.
	RedisClient *redispkg.Client

	// RDB is the raw go-redis client passed to per-route rate-limit middleware.
	RDB *goredis.Client

	// Log is forwarded to all middleware constructors that emit structured logs.
	Log *zap.Logger
}

// DefaultOptions returns router options with production-appropriate defaults.
func DefaultOptions() Options {
	return Options{
		RateLimit:        middleware.DefaultRateLimitConfig(),
		RefreshRateLimit: defaultRefreshRateLimit(),
		EmailRateLimit:   emailmodule.DefaultEmailRateLimits(),
		OAuthRateLimits:  oauthmodule.DefaultRateLimits(),
		CORS:             middleware.DefaultCORSConfig(),
		SecureHeaders:    middleware.DefaultSecureHeadersConfig(),
	}
}

func defaultRefreshRateLimit() middleware.RateLimitConfig {
	return middleware.RateLimitConfig{
		Rate:    rate.Limit(1),
		Burst:   5,
		TTL:     1 * time.Minute,
		MaxKeys: 10_000,
	}
}

// New builds and returns a configured *gin.Engine.
func New(
	env string,
	log *zap.Logger,
	jwtHelper *platformauth.JWT,
	authMod *authmodule.Module,
	usersMod *usersmodule.Module,
	opts Options,
	emailMod *emailmodule.Module,
	oauthMod *oauthmodule.Module,
) *gin.Engine {
	if env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// ── Trusted Proxies ────────────────────────────────────────────────────────
	if env == "production" {
		if err := r.SetTrustedProxies(opts.TrustedProxyCIDRs); err != nil {
			panic(fmt.Sprintf("router: invalid trusted proxy CIDRs: %v", err))
		}
	} else {
		_ = r.SetTrustedProxies(nil)
	}

	// ─── Global Middleware ─────────────────────────────────────────────────────
	//
	// Size guards must be registered first so that oversized input is rejected
	// before any other middleware — logging, rate limiting, CSRF — processes it.
	//
	// Order matters:
	//   1. Body cap     — MaxBytesReader on the request body (POST/PUT/PATCH).
	//   2. Query cap    — QuerySizeLimit on the raw URL query string (GET params).
	//
	// Without (2), an attacker could supply an arbitrarily-long `state=` or
	// `code=` query parameter on the OAuth callback endpoint and bypass the body
	// cap entirely, because query strings are never read through the body reader.
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024)
		c.Next()
	})
	r.Use(middleware.QuerySizeLimit(middleware.DefaultQuerySizeLimit))

	r.Use(middleware.CORS(opts.CORS))

	if opts.ShutdownCh != nil {
		r.Use(middleware.Shutdown(opts.ShutdownCh))
	}

	r.Use(middleware.SecureHeaders(opts.SecureHeaders))

	r.Use(func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), requestTimeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})

	r.Use(middleware.RequestID())
	r.Use(middleware.Logger(log))
	r.Use(middleware.Recovery(log))

	// ─── Health endpoint ───────────────────────────────────────────────────────
	r.GET("/health", buildHealthHandler(opts))

	// ─── Swagger UI (non-production only) ─────────────────────────────────────
	if env != "production" {
		r.GET("/swagger", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
		})
		swaggerGroup := r.Group("/swagger")
		swaggerGroup.GET("/*any",
			func(c *gin.Context) {
				if c.Param("any") == "/index.html" {
					c.Header("Content-Security-Policy",
						"default-src 'self'; "+
							"script-src 'self' 'unsafe-inline'; "+
							"style-src 'self' 'unsafe-inline'; "+
							"img-src 'self' data:; "+
							"connect-src 'self';",
					)
				}
				c.Next()
			},
			ginSwagger.WrapHandler(swaggerFiles.Handler),
		)
	}

	// ─── API v1 ────────────────────────────────────────────────────────────────
	v1 := r.Group("/api/v1")

	// ── Auth ───────────────────────────────────────────────────────────────────
	authGroup := v1.Group("/auth")
	emailmodule.RegisterRoutes(authGroup, emailMod.Handler, jwtHelper, log, opts.EmailRateLimit, opts.RDB)
	authmodule.RegisterRoutes(authGroup, authMod.Handler, opts.RateLimit, opts.RefreshRateLimit, opts.CookieCSRF, opts.RDB, log)

	// ── OAuth Social Login ─────────────────────────────────────────────────────
	if oauthMod != nil {
		oauthGroup := v1.Group("/oauth")
		oauthmodule.RegisterRoutes(oauthGroup, oauthMod.Handler, jwtHelper, log, opts.OAuthRateLimits, opts.RDB)
	}

	// ── Users ──────────────────────────────────────────────────────────────────
	usersGroup := v1.Group("/users")
	usersmodule.RegisterRoutes(usersGroup, usersMod.Handler, jwtHelper, log)

	return r
}

// buildHealthHandler returns the /health gin.HandlerFunc.
func buildHealthHandler(opts Options) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		log := opts.Log
		healthy := true

		if err := opts.SqlDB.PingContext(ctx); err != nil {
			healthy = false
			if log != nil {
				log.Error("health: database unreachable", zap.Error(err))
			}
		}

		if opts.RedisClient != nil {
			if err := opts.RedisClient.Ping(ctx); err != nil {
				healthy = false
				if log != nil {
					log.Error("health: redis unreachable", zap.Error(err))
				}
			}
		}

		if !healthy {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

// ─── Config helpers ───────────────────────────────────────────────────────────

func RateLimitConfigFromValues(r float64, burst int, ttl time.Duration, maxKeys int) middleware.RateLimitConfig {
	return middleware.RateLimitConfig{
		Rate:    rate.Limit(r),
		Burst:   burst,
		TTL:     ttl,
		MaxKeys: maxKeys,
	}
}

func RefreshRateLimitFromValues(r float64) middleware.RateLimitConfig {
	return middleware.RateLimitConfig{
		Rate:    rate.Limit(r),
		Burst:   5,
		TTL:     1 * time.Minute,
		MaxKeys: 10_000,
	}
}

func EmailRateLimitsFromValues(forgotPwd, resendVerify, resetPwd, verifyEmail, otpVerify float64) emailmodule.EmailRateLimits {
	return emailmodule.EmailRateLimits{
		ForgotPassword: forgotPwd,
		ResendVerify:   resendVerify,
		ResetPassword:  resetPwd,
		VerifyEmail:    verifyEmail,
		OTPVerify:      otpVerify,
	}
}

func CORSConfigFromValues(origins, headers []string, allowCredentials bool, maxAge int) middleware.CORSConfig {
	return middleware.CORSConfig{
		AllowedOrigins:   origins,
		AllowedHeaders:   headers,
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}
}

func SecureHeadersConfigFromValues(hstsEnabled bool, hstsMaxAge int) middleware.SecureHeadersConfig {
	return middleware.SecureHeadersConfig{
		HSTSEnabled:           hstsEnabled,
		HSTSMaxAge:            hstsMaxAge,
		HSTSIncludeSubDomains: true,
	}
}

// CookieCSRFConfigFromValues builds a CookieCSRFConfig from the explicit
// trusted-origin list. trustedOrigins should come from cfg.CSRFTrustedOrigins,
// which already falls back to []string{cfg.FrontEndDomain} when
// CSRF_TRUSTED_ORIGINS is not set — no further defaulting is needed here.
func CookieCSRFConfigFromValues(trustedOrigins []string) middleware.CookieCSRFConfig {
	return middleware.CookieCSRFConfig{
		TrustedOrigins: trustedOrigins,
	}
}
