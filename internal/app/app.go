// Package app orchestrates application startup and lifecycle management.
// Dependencies are wired via the container package.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/container"
	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	authmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	emailmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth_email"
	oauthmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/oauth"
	usersmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/users"
	"github.com/waqasmani/go-auth-boilerplate/internal/router"
)

const (
	tokenCleanupInterval  = 1 * time.Hour
	serverShutdownTimeout = 15 * time.Second
	mailerDrainTimeout    = 10 * time.Second
)

// App encapsulates the entire application.
type App struct {
	cfg        *config.Config
	log        *zap.Logger
	server     *http.Server
	shutdownCh chan struct{}
	container  *container.Container
}

// New builds and wires the application using the dependency container.
func New(migrationsFS fs.FS) (*App, error) {
	// ─── Initialize Container ──────────────────────────────────────────────────
	cont, err := container.New(migrationsFS)
	if err != nil {
		return nil, fmt.Errorf("app: init container: %w", err)
	}

	// ─── Health Check ──────────────────────────────────────────────────────────
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer checkCancel()
	if err = verifyRolesSeeded(checkCtx, cont.Queries); err != nil {
		return nil, fmt.Errorf("app: startup health-check: %w", err)
	}

	// ─── Modules ───────────────────────────────────────────────────────────────
	// Each NewModule now returns (*Module, error) so misconfiguration (bad key
	// sets, missing Redis, empty StateSecret, unknown provider names) surfaces
	// here as a structured fmt.Errorf chain rather than a raw panic stack trace.

	authMod, err := authmodule.NewModule(authmodule.ModuleConfig{
		SqlDB:                   cont.DB,
		Queries:                 cont.Queries,
		Jwt:                     cont.JWT,
		Log:                     cont.Logger,
		AuditLog:                cont.AuditLog,
		Cfg:                     cont.Config,
		RDB:                     cont.RawRedis,
		LoginEmailRateLimitRate: cont.Config.RateLimitLoginEmail,
	})
	if err != nil {
		return nil, fmt.Errorf("app: init auth module: %w", err)
	}

	emailAuthMod, err := emailmodule.NewModule(emailmodule.ModuleConfig{
		SqlDB:          cont.DB,
		Queries:        cont.Queries,
		Mailer:         cont.Mailer,
		Log:            cont.Logger,
		AuditLog:       cont.AuditLog,
		FrontEndDomain: cont.Config.FrontEndDomain,
		TokenIssuer:    authMod.Service,
		Cfg:            cont.Config,
		OTPSecret:      cont.Config.OTPSecret,
		TOTPKeys:       cont.Config.TOTPKeys,
		TOTPIssuer:     cont.Config.TOTPIssuer,
		TOTPPeriod:     cont.Config.TOTPPeriod,
		TOTPDigits:     cont.Config.TOTPDigits,
		RDB:            cont.RawRedis,
	})
	if err != nil {
		return nil, fmt.Errorf("app: init email auth module: %w", err)
	}

	authMod.Service.SetMFAChallenger(emailAuthMod.Service)
	authMod.Service.SetVerificationSender(emailAuthMod.Service)

	usersMod := usersmodule.NewModule(cont.Queries, cont.Logger)

	oauthMod, err := oauthmodule.NewModule(oauthmodule.ModuleConfig{
		SqlDB:       cont.DB,
		Queries:     cont.Queries,
		Cfg:         cont.Config,
		Log:         cont.Logger,
		AuditLog:    cont.AuditLog,
		TokenIssuer: authMod.Service,
		TokenKeySet: cont.OAuthKeys,
		StateSecret: cont.Config.OAuthStateSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("app: init oauth module: %w", err)
	}

	// ─── Router ────────────────────────────────────────────────────────────────
	routerOpts := router.Options{
		RateLimit: router.RateLimitConfigFromValues(
			cont.Config.RateLimitRate,
			cont.Config.RateLimitBurst,
			cont.Config.RateLimitTTL,
			cont.Config.RateLimitMaxKeys,
		),
		RefreshRateLimit: router.RefreshRateLimitFromValues(cont.Config.RateLimitAuthRefresh),
		EmailRateLimit: router.EmailRateLimitsFromValues(
			cont.Config.RateLimitForgotPassword,
			cont.Config.RateLimitResendVerify,
			cont.Config.RateLimitResetPassword,
			cont.Config.RateLimitVerifyEmail,
			cont.Config.RateLimitOTPVerify,
		),
		OAuthRateLimits: oauthmodule.RateLimits{
			Login:    cont.Config.RateLimitOAuthLogin,
			Callback: cont.Config.RateLimitOAuthCallback,
			Link:     cont.Config.RateLimitOAuthLink,
			Exchange: cont.Config.RateLimitOAuthExchange,
		},
		CORS: router.CORSConfigFromValues(
			cont.Config.CORSAllowedOrigins,
			cont.Config.CORSAllowedHeaders,
			cont.Config.CORSAllowCredentials,
			cont.Config.CORSMaxAge,
		),
		SecureHeaders: router.SecureHeadersConfigFromValues(
			cont.Config.SecHSTSEnabled,
			cont.Config.SecHSTSMaxAge,
		),
		SqlDB:             cont.DB,
		TrustedProxyCIDRs: cont.Config.TrustedProxyCIDRs,
		CookieCSRF:        router.CookieCSRFConfigFromValues(cont.Config.CSRFTrustedOrigins),
		ShutdownCh:        cont.ShutdownCh,
		RedisClient:       cont.Redis,
		RDB:               cont.RawRedis,
		Log:               cont.Logger,
	}

	engine := router.New(cont.Config.AppEnv, cont.Logger, cont.JWT, authMod, usersMod, routerOpts, emailAuthMod, oauthMod)

	server := &http.Server{
		Addr:         ":" + cont.Config.AppPort,
		Handler:      engine,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &App{
		cfg:        cont.Config,
		log:        cont.Logger,
		server:     server,
		shutdownCh: cont.ShutdownCh,
		container:  cont,
	}, nil
}

// Run starts the HTTP server and blocks until a shutdown signal is received.
func (a *App) Run() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

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
	case sig := <-sigCh:
		a.log.Info("shutdown signal received", zap.String("signal", sig.String()))
	}

	close(a.shutdownCh)
	return a.Shutdown()
}

// Shutdown gracefully stops the server.
func (a *App) Shutdown() error {
	var errs []error

	// Server drain — capped independently. Exhausting this budget must not
	// steal time from the mailer drain: queued emails are real user-facing
	// work that deserves its full window regardless of how long HTTP draining
	// takes.
	serverCtx, serverCancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer serverCancel()

	if err := a.server.Shutdown(serverCtx); err != nil {
		a.log.Error("server shutdown error", zap.Error(err))
		errs = append(errs, err)
	}

	// Mailer drain — derived from context.Background(), not from serverCtx.
	// This guarantees the full mailerDrainTimeout budget even when server
	// drain consumes its entire 15 s window before returning.
	if a.container.Mailer != nil {
		mailerCtx, mailerCancel := context.WithTimeout(context.Background(), mailerDrainTimeout)
		defer mailerCancel()
		if err := a.container.Mailer.Shutdown(mailerCtx); err != nil {
			a.log.Error("mailer shutdown error", zap.Error(err))
			errs = append(errs, err)
		}
	}

	if err := a.container.Close(); err != nil {
		a.log.Error("container close error", zap.Error(err))
		errs = append(errs, err)
	}

	a.log.Info("server stopped")
	return errors.Join(errs...)
}

func verifyRolesSeeded(ctx context.Context, queries *db.Queries) error {
	requiredRoles := []string{"user", "admin"}
	var missing []string
	for _, role := range requiredRoles {
		count, err := queries.CountRoleByName(ctx, role)
		if err != nil {
			return fmt.Errorf("roles health-check failed for role %q: %w", role, err)
		}
		if count == 0 {
			missing = append(missing, role)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required role(s) [%s] not found in roles table", joinStrings(missing))
	}
	return nil
}

func joinStrings(s []string) string {
	if len(s) == 0 {
		return ""
	}
	if len(s) == 1 {
		return s[0]
	}
	var result strings.Builder
	result.WriteString(s[0])
	for _, v := range s[1:] {
		result.WriteString(", " + v)
	}
	return result.String()
}
