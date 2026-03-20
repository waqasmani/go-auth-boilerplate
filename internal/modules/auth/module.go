package auth

import (
	"database/sql"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// defaultLoginEmailRate is the fallback token-refill speed for the per-email
// login limiter when ModuleConfig.LoginEmailRateLimitRate is zero.
const defaultLoginEmailRate = 0.1

// Module wires together all auth dependencies.
type Module struct {
	Handler *Handler
	Service Service
}

// ModuleConfig carries every dependency needed to construct the auth module.
type ModuleConfig struct {
	SqlDB    *sql.DB
	Queries  *db.Queries
	Jwt      *platformauth.JWT
	Log      *zap.Logger
	AuditLog *audit.Logger
	Cfg      *config.Config
	// RDB is the raw go-redis client used to back the per-email login rate
	// limiter and the account lockout tracker with a distributed Redis store.
	// Redis is a mandatory dependency; NewModule returns an error if RDB is nil.
	RDB                     *goredis.Client
	LoginEmailRateLimitRate float64
}

// NewModule constructs the auth module. Returns an error on any
// misconfiguration so that app.New can surface a structured startup message
// rather than crashing with a raw stack trace. Failure modes:
//   - RDB is nil (Redis is mandatory for distributed rate limiting and lockout).
//   - LockoutMaxAttempts < 1 (validated by config.Load, double-checked here).
//
// Three complementary brute-force defences are wired here:
//
//  1. Per-IP rate limiter (route middleware in routes.go).
//  2. Per-email rate limiter (emailLimiter, inside the Login handler).
//  3. Account lockout (AccountLocker, inside service.Login).
func NewModule(m ModuleConfig) (*Module, error) {
	repo := NewRepository(m.SqlDB, m.Queries)

	emailRate := m.LoginEmailRateLimitRate
	if emailRate <= 0 {
		emailRate = defaultLoginEmailRate
	}

	emailLimiter, err := middleware.NewLimiter(middleware.RateLimitConfig{
		Rate:    rate.Limit(emailRate),
		Burst:   5,
		TTL:     15 * time.Minute,
		MaxKeys: 100_000,
	}, m.RDB, m.Log)
	if err != nil {
		return nil, fmt.Errorf("auth: init email rate limiter: %w", err)
	}

	locker, err := platformauth.NewAccountLocker(
		m.RDB,
		m.Log,
		m.Cfg.LockoutMaxAttempts,
		m.Cfg.LockoutWindowTTL,
		m.Cfg.LockoutDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: init account locker: %w", err)
	}

	svc := NewService(repo, m.Jwt, m.Log, m.AuditLog, locker)
	h := NewHandler(svc, m.Cfg, emailLimiter)

	return &Module{Handler: h, Service: svc}, nil
}
