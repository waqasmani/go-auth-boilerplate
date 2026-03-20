package authemail

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
)

// ── Module wiring ─────────────────────────────────────────────────────────────

// Module wires the handler and service for email-auth flows.
type Module struct {
	Handler *Handler
	Service Service
}

// ModuleConfig carries every external dependency needed to build the module.
type ModuleConfig struct {
	SqlDB          *sql.DB
	Queries        *db.Queries
	Mailer         *mailer.Mailer
	Log            *zap.Logger
	AuditLog       *audit.Logger
	FrontEndDomain string
	TokenIssuer    TokenIssuer
	Cfg            *config.Config
	OTPSecret      string

	// TOTP configuration — sourced directly from config.Config fields.
	TOTPKeys   []config.TOTPKeyConfig
	TOTPIssuer string
	TOTPPeriod int
	TOTPDigits int

	// RDB is the raw go-redis client used for the TOTP replay cache.
	// Redis is a mandatory dependency; NewModule returns an error if RDB is nil.
	RDB *goredis.Client
}

// totpEncKeysFromConfig converts config key structs to platform types.
func totpEncKeysFromConfig(keys []config.TOTPKeyConfig) []platformauth.TOTPEncKey {
	out := make([]platformauth.TOTPEncKey, len(keys))
	for i, k := range keys {
		out[i] = platformauth.TOTPEncKey{ID: k.ID, Key: k.Key, Active: k.Active}
	}
	return out
}

// NewModule constructs the email-auth module. Returns an error on any
// misconfiguration so that app.New can surface a structured startup message
// rather than crashing with a raw stack trace. Failure modes:
//   - RDB is nil (Redis is mandatory for TOTP replay prevention).
//   - TOTP key set is empty or has no active key.
//   - NewService returns an error (e.g. nil replayCache, which should not
//     occur once the above checks pass, but is guarded defensively).
//
// The TOTP replay cache is always backed by Redis (fail-closed on errors) to
// maintain RFC 6238 §5.2 compliance across all pods. There is no in-memory
// fallback — resolve availability at the infrastructure layer (Redis Sentinel,
// Cluster, ElastiCache Multi-AZ).
func NewModule(cfg ModuleConfig) (*Module, error) {
	repo := NewRepository(cfg.SqlDB, cfg.Queries)

	totpKeySet, err := platformauth.NewTOTPKeySet(totpEncKeysFromConfig(cfg.TOTPKeys))
	if err != nil {
		return nil, fmt.Errorf("authemail: init TOTP key set: %w", err)
	}

	replayCache, err := platformauth.NewTOTPReplayCache(cfg.RDB, cfg.Log)
	if err != nil {
		return nil, fmt.Errorf("authemail: init TOTP replay cache: %w", err)
	}

	svc, err := NewService(
		repo,
		cfg.Mailer,
		cfg.Log,
		cfg.FrontEndDomain,
		cfg.TokenIssuer,
		cfg.OTPSecret,
		cfg.AuditLog,
		totpKeySet,
		cfg.TOTPIssuer,
		cfg.TOTPPeriod,
		cfg.TOTPDigits,
		replayCache,
	)
	if err != nil {
		return nil, fmt.Errorf("authemail: init service: %w", err)
	}

	h := NewHandler(svc, cfg.Cfg)
	return &Module{Handler: h, Service: svc}, nil
}

// ── EmailRateLimits ───────────────────────────────────────────────────────────

// EmailRateLimits holds per-endpoint token-bucket rate values (tokens/s).
type EmailRateLimits struct {
	ForgotPassword float64
	ResendVerify   float64
	ResetPassword  float64
	VerifyEmail    float64
	OTPVerify      float64
}

// DefaultEmailRateLimits returns conservative production defaults.
func DefaultEmailRateLimits() EmailRateLimits {
	return EmailRateLimits{
		ForgotPassword: 3.0 / 60.0,
		ResendVerify:   3.0 / 60.0,
		ResetPassword:  5.0 / 60.0,
		VerifyEmail:    10.0 / 60.0,
		OTPVerify:      5.0 / 60.0,
	}
}

// ── Route registration ────────────────────────────────────────────────────────

// RegisterRoutes attaches email-auth endpoints to a RouterGroup.
func RegisterRoutes(
	rg *gin.RouterGroup,
	h *Handler,
	jwt *platformauth.JWT,
	log *zap.Logger,
	rl EmailRateLimits,
	rdb *goredis.Client,
) {
	rg.POST("/forgot-password",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(rl.ForgotPassword), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}, rdb, log),
		h.ForgotPassword,
	)
	rg.POST("/resend-verification",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(rl.ResendVerify), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}, rdb, log),
		h.ResendVerification,
	)
	rg.POST("/reset-password",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(rl.ResetPassword), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}, rdb, log),
		h.ResetPassword,
	)
	rg.POST("/verify-email",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(rl.VerifyEmail), Burst: 10, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}, rdb, log),
		h.VerifyEmail,
	)
	rg.POST("/otp/verify",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(rl.OTPVerify), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}, rdb, log),
		h.VerifyOTP,
	)

	// JWT-protected routes — authenticated users only.
	protected := rg.Group("")
	protected.Use(middleware.Auth(jwt, log))
	{
		protected.POST("/send-verification", h.SendVerification)
		protected.POST("/otp/send", h.SendOTP)

		mfa := protected.Group("/mfa/totp")
		{
			mfa.POST("/setup", h.SetupTOTP)
			mfa.POST("/enable",
				middleware.RateLimit(middleware.RateLimitConfig{
					KeyFunc: middleware.KeyByUserIDWithIPFallback,
					Rate:    rate.Limit(5.0 / 60.0),
					Burst:   5,
					TTL:     5 * time.Minute,
					MaxKeys: 100_000,
				}, rdb, log),
				h.EnableTOTP,
			)
			mfa.POST("/disable", h.DisableTOTP)
		}
	}
}
