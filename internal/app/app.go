package app

import (
	"context"
	"database/sql"
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
	queries *dbpkg.Queries // prepared statements — closed before db in Shutdown
	log     *zap.Logger
	server  *http.Server
}

// New builds and wires the application.
//
// migrationsFS must be the embed.FS exported by the sql/migrations package.
// Passing it as a parameter (rather than embedding it here) is necessary
// because Go's embed package forbids ".." in paths, so the only file that can
// embed sql/migrations/*.sql is one that lives inside that directory.
//
// Startup sequence:
//  1. Load config
//  2. Init logger
//  3. Connect to database (Ping)
//  4. Run migrations  ← schema is current before any query executes
//  5. Prepare statements  ← one round-trip; all eight statements cached
//  6. Wire modules (auth, users) with the prepared *db.Queries
//  7. Build HTTP server
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
	// Run before Prepare so statements are compiled against the current schema.
	// golang-migrate is idempotent: if the schema is already at the latest
	// version it logs "no change" and returns nil.
	if err = database.RunMigrations(sqlDB, migrationsFS, log); err != nil {
		return nil, fmt.Errorf("app: run migrations: %w", err)
	}

	// ─── Prepared Statements ───────────────────────────────────────────────────
	// db.Prepare sends all eight SQL statements to the server in one batch and
	// caches the resulting prepared-statement handles.  Every subsequent query
	// reuses the handle, skipping the parse/plan phase on the server and saving
	// one network round-trip per query.
	//
	// A 10-second timeout prevents startup from hanging if the DB is
	// temporarily overloaded; the context is not stored — it is only used
	// during the Prepare call itself.
	prepCtx, prepCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer prepCancel()

	queries, err := dbpkg.Prepare(prepCtx, sqlDB)
	if err != nil {
		return nil, fmt.Errorf("app: prepare statements: %w", err)
	}
	log.Info("prepared statements ready")

	// ─── JWT ───────────────────────────────────────────────────────────────────
	jwtHelper := platformauth.NewJWT(platformauth.JWTConfig{
		Secret:     cfg.JWTSecret,
		Issuer:     cfg.JWTIssuer,
		Audience:   cfg.JWTAudience,
		AccessTTL:  cfg.AccessTTL,
		RefreshTTL: cfg.RefreshTTL,
	})

	// ─── Modules ───────────────────────────────────────────────────────────────
	// Both modules receive the shared *db.Queries so all queries in a request
	// flow through the same prepared handles.  Ownership of queries stays here;
	// Shutdown closes it after the HTTP server drains.
	authMod := authmodule.NewModule(queries, jwtHelper, log)
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
//
// Order matters: the HTTP server must drain first so in-flight handlers can
// finish their queries.  Prepared statements are closed before the pool
// because each statement holds an implicit reference to a connection.
func (a *App) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Stop accepting new requests; wait for in-flight handlers to finish.
	if err := a.server.Shutdown(ctx); err != nil {
		a.log.Error("server shutdown error", zap.Error(err))
	}

	// 2. Release prepared-statement handles on the server side.
	if err := a.queries.Close(); err != nil {
		a.log.Error("prepared statements close error", zap.Error(err))
	}

	// 3. Close the connection pool last.
	if err := a.db.Close(); err != nil {
		a.log.Error("database close error", zap.Error(err))
	}

	a.log.Info("server stopped")
	_ = a.log.Sync()
	return nil
}
