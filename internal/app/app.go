// Package app orchestrates application startup, dependency wiring, and lifecycle management.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	authmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	usersmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/users"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
	"github.com/waqasmani/go-auth-boilerplate/internal/router"
)

// App encapsulates the entire application.
type App struct {
	cfg     *config.Config
	db      *sql.DB
	queries *dbpkg.Queries
	log     *zap.Logger
	server  *http.Server
}

// New builds and wires the application.
func New(migrationsFS fs.FS) (*App, error) {
	// ─── Config ────────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("app: load config: %w", err)
	}

	// ─── Logger ────────────────────────────────────────────────────────────────
	log, err := logger.New(cfg.AppEnv)
	if err != nil {
		return nil, fmt.Errorf("app: init logger: %w", err)
	}

	// ─── Database ──────────────────────────────────────────────────────────────
	dbCfg := database.DefaultConfig(cfg.DBDSN)
	sqlDB, err := database.New(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("app: connect database: %w", err)
	}
	log.Info("connected to database")

	// ─── Migrations ────────────────────────────────────────────────────────────
	if err = database.RunMigrations(sqlDB, migrationsFS, log); err != nil {
		return nil, fmt.Errorf("app: run migrations: %w", err)
	}

	// ─── Prepared Statements ───────────────────────────────────────────────────
	prepCtx, prepCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer prepCancel()

	queries, err := dbpkg.Prepare(prepCtx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("app: prepare statements: %w", err)
	}
	log.Info("prepared statements ready")

	// ─── JWT ───────────────────────────────────────────────────────────────────
	// config.JWTKeyConfig and platformauth.JWTKey are structurally identical but
	// live in separate packages to prevent an import cycle (platform/auth must
	// not import config).  The conversion is a one-liner per key.
	//
	// NewJWT panics on an invalid key set (no active key, duplicate IDs, etc.).
	// config.Load already validates the same invariants and returns a clean
	// error, so a panic here means a programming error in Load, not an operator
	// mistake.
	jwtHelper := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:       jwtKeysFromConfig(cfg.JWTKeys),
		Issuer:     cfg.JWTIssuer,
		Audience:   cfg.JWTAudience,
		AccessTTL:  cfg.AccessTTL,
		RefreshTTL: cfg.RefreshTTL,
	})

	logJWTKeySet(log, cfg.JWTKeys)

	// ─── Modules ───────────────────────────────────────────────────────────────
	authMod := authmodule.NewModule(authmodule.ModuleConfig{
		SqlDB:   sqlDB,
		Queries: queries,
		Jwt:     jwtHelper,
		Log:     log,
		Cfg:     cfg,
	})
	usersMod := usersmodule.NewModule(queries, log)

	// ─── Router ────────────────────────────────────────────────────────────────
	routerOpts := router.Options{
		RateLimit: router.RateLimitConfigFromValues(
			cfg.RateLimitRate,
			cfg.RateLimitBurst,
			cfg.RateLimitTTL,
			cfg.RateLimitMaxKeys,
		),
		CORS: router.CORSConfigFromValues(
			cfg.CORSAllowedOrigins,
			cfg.CORSAllowedHeaders,
			cfg.CORSAllowCredentials,
			cfg.CORSMaxAge,
		),
		SecureHeaders: router.SecureHeadersConfigFromValues(
			cfg.SecHSTSEnabled,
			cfg.SecHSTSMaxAge,
		),
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
	}
	engine := router.New(cfg.AppEnv, log, jwtHelper, authMod, usersMod, routerOpts)

	server := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      engine,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &App{
		cfg:     cfg,
		db:      sqlDB,
		queries: queries,
		log:     log,
		server:  server,
	}, nil
}

// Run starts the HTTP server and blocks until a shutdown signal is received.
func (a *App) Run() error {
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		a.log.Info("server starting", zap.String("addr", a.server.Addr))
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdownCh:
		a.log.Info("shutdown signal received", zap.String("signal", sig.String()))
	}

	return a.Shutdown()
}

// Shutdown gracefully stops the server, closes prepared statements, then
// closes the connection pool.
func (a *App) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var errs []error
	if err := a.server.Shutdown(ctx); err != nil {
		a.log.Error("server shutdown error", zap.Error(err))
		errs = append(errs, err)
	}
	if err := a.queries.Close(); err != nil {
		a.log.Error("prepared statements close error", zap.Error(err))
		errs = append(errs, err)
	}
	if err := a.db.Close(); err != nil {
		a.log.Error("database close error", zap.Error(err))
		errs = append(errs, err)
	}
	a.log.Info("server stopped")
	_ = a.log.Sync()
	return errors.Join(errs...)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// jwtKeysFromConfig converts the config-package key slice to the platform/auth
// key slice.  The two types are structurally identical; the conversion exists
// only to break the config → platform/auth import that would create a cycle.
func jwtKeysFromConfig(keys []config.JWTKeyConfig) []platformauth.JWTKey {
	out := make([]platformauth.JWTKey, len(keys))
	for i, k := range keys {
		out[i] = platformauth.JWTKey{
			ID:     k.ID,
			Secret: k.Secret,
			Active: k.Active,
		}
	}
	return out
}

// logJWTKeySet logs the key IDs and their active/inactive status at startup
// without ever logging secrets.  Useful for confirming which keys are loaded
// after a rotation.
func logJWTKeySet(log *zap.Logger, keys []config.JWTKeyConfig) {
	ids := make([]string, len(keys))
	for i, k := range keys {
		status := "inactive"
		if k.Active {
			status = "active"
		}
		ids[i] = k.ID + "(" + status + ")"
	}
	log.Info("JWT key set loaded", zap.Strings("keys", ids))
}
