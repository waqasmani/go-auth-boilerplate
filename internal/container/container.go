// Package container provides a dependency injection container for the application.
// It centralizes the wiring of dependencies, making testing and substitution easier.
package container

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
	redispkg "github.com/waqasmani/go-auth-boilerplate/internal/platform/redis"
)

// Container holds all application dependencies.
type Container struct {
	Config     *config.Config
	DB         *sql.DB
	Queries    *dbpkg.Queries
	Redis      *redispkg.Client
	RawRedis   *goredis.Client
	Logger     *zap.Logger
	AuditLog   *audit.Logger
	Mailer     *mailer.Mailer
	JWT        *platformauth.JWT
	OAuthKeys  *platformauth.SymmetricKeySet
	TOTPKeys   *platformauth.TOTPKeySet
	ShutdownCh chan struct{}
}

// New initializes the container and wires all dependencies.
func New(migrationsFS fs.FS) (*Container, error) {
	c := &Container{}

	// ─── Config ────────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("container: load config: %w", err)
	}
	c.Config = cfg

	// ─── Logger ────────────────────────────────────────────────────────────────
	log, err := logger.New(cfg.AppEnv)
	if err != nil {
		return nil, fmt.Errorf("container: init logger: %w", err)
	}
	c.Logger = log

	// ─── Audit Logger ──────────────────────────────────────────────────────────
	c.AuditLog = audit.New(log)

	// ─── Database ──────────────────────────────────────────────────────────────
	dbCfg := database.DefaultConfig(cfg.DBDSN)
	sqlDB, err := database.New(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("container: connect database: %w", err)
	}
	c.DB = sqlDB
	log.Info("connected to database")

	// ─── Migrations ────────────────────────────────────────────────────────────
	if !cfg.SkipMigrations {
		if err = database.RunMigrations(sqlDB, migrationsFS, log); err != nil {
			return nil, fmt.Errorf("container: run migrations: %w", err)
		}
	}

	// ─── Prepared Statements ───────────────────────────────────────────────────
	prepCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	queries, err := dbpkg.Prepare(prepCtx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("container: prepare statements: %w", err)
	}
	c.Queries = queries
	log.Info("prepared statements ready")

	// ─── Redis (always required) ───────────────────────────────────────────────
	redisClient, err := redispkg.New(redispkg.Config{
		DSN:      cfg.RedisDSN,
		PoolSize: cfg.RedisPoolSize,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("container: init redis: %w", err)
	}
	c.Redis = redisClient
	c.RawRedis = redisClient.RDB()

	// ─── JWT ───────────────────────────────────────────────────────────────────
	// NewJWT returns an error instead of panicking so a bad JWT_KEYS value
	// (wrong format, no active key, key too short) produces a structured startup
	// message rather than a raw stack trace in container logs.
	jwtHelper, err := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:       jwtKeysFromConfig(cfg.JWTKeys),
		Issuer:     cfg.JWTIssuer,
		Audience:   cfg.JWTAudience,
		AccessTTL:  cfg.AccessTTL,
		RefreshTTL: cfg.RefreshTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("container: init jwt: %w", err)
	}
	c.JWT = jwtHelper

	// ─── OAuth Keys ────────────────────────────────────────────────────────────
	// NewSymmetricKeySet returns an error instead of panicking so a bad
	// OAUTH_TOKEN_KEYS value produces a structured message at startup.
	if len(cfg.OAuthTokenKeys) > 0 {
		oauthKeys, err := platformauth.NewSymmetricKeySet(oauthKeysFromConfig(cfg.OAuthTokenKeys))
		if err != nil {
			return nil, fmt.Errorf("container: init oauth token keys: %w", err)
		}
		c.OAuthKeys = oauthKeys
	}

	// ─── TOTP Keys ─────────────────────────────────────────────────────────────
	// NewTOTPKeySet returns an error instead of panicking so a bad TOTP_KEYS
	// value produces a structured message at startup.
	if len(cfg.TOTPKeys) > 0 {
		totpKeys, err := platformauth.NewTOTPKeySet(totpKeysFromConfig(cfg.TOTPKeys))
		if err != nil {
			return nil, fmt.Errorf("container: init totp keys: %w", err)
		}
		c.TOTPKeys = totpKeys
	}

	// ─── Mailer (always required) ──────────────────────────────────────────────
	// EMAIL_SMTP_HOST is validated as required by config.Load(); this call will
	// always produce an enabled Mailer — the disabled-stub path no longer exists.
	m, err := mailer.New(mailer.Config{
		Host:     cfg.EmailSMTPHost,
		Port:     cfg.EmailSMTPPort,
		Username: cfg.EmailSMTPUser,
		Password: cfg.EmailSMTPPass,
		UseTLS:   cfg.EmailSMTPUseTLS,
		From:     cfg.EmailFrom,
	})
	if err != nil {
		return nil, fmt.Errorf("container: init mailer: %w", err)
	}
	c.Mailer = m
	log.Info("mailer ready", zap.String("smtp_host", cfg.EmailSMTPHost), zap.Int("smtp_port", cfg.EmailSMTPPort))

	// ─── Shutdown Channel ──────────────────────────────────────────────────────
	c.ShutdownCh = make(chan struct{})

	return c, nil
}

// Close gracefully shuts down all resources.
func (c *Container) Close() error {
	var errs []error
	if c.Queries != nil {
		if err := c.Queries.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.DB != nil {
		if err := c.DB.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Redis != nil {
		if err := c.Redis.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Logger != nil {
		_ = c.Logger.Sync()
	}
	return nil
}

func jwtKeysFromConfig(keys []config.JWTKeyConfig) []platformauth.JWTKey {
	out := make([]platformauth.JWTKey, len(keys))
	for i, k := range keys {
		out[i] = platformauth.JWTKey{ID: k.ID, Secret: k.Secret, Active: k.Active}
	}
	return out
}

func oauthKeysFromConfig(keys []config.OAuthTokenKeyConfig) []platformauth.SymmetricKeyConfig {
	out := make([]platformauth.SymmetricKeyConfig, len(keys))
	for i, k := range keys {
		out[i] = platformauth.SymmetricKeyConfig{ID: k.ID, Key: k.Key, Active: k.Active}
	}
	return out
}

func totpKeysFromConfig(keys []config.TOTPKeyConfig) []platformauth.TOTPEncKey {
	out := make([]platformauth.TOTPEncKey, len(keys))
	for i, k := range keys {
		out[i] = platformauth.TOTPEncKey{ID: k.ID, Key: k.Key, Active: k.Active}
	}
	return out
}
