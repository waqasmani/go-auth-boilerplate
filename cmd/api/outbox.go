package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/outbox"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

const (
	defaultOutboxPollInterval = 5 * time.Second
	outboxMailerDrainTimeout  = 10 * time.Second
)

// runOutboxWorker is the long-running process that drains the email_outbox table
// and delivers each message over SMTP. It is safe to run as multiple replicas
// (rows are claimed per-worker; see internal/outbox). Run it as its own
// Deployment, separate from the API pods. Returns a process exit code.
func runOutboxWorker() int {
	// The worker never owns DDL — the dedicated migrate step does.
	if err := os.Setenv("SKIP_MIGRATIONS", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "outbox-worker: set SKIP_MIGRATIONS: %v\n", err)
		return 1
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "outbox-worker: load config: %v\n", err)
		return 1
	}
	log, err := logger.New(cfg.AppEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "outbox-worker: init logger: %v\n", err)
		return 1
	}
	defer func() { _ = log.Sync() }()

	sqlDB, err := database.New(database.Config{
		DSN:             cfg.DBDSN,
		MaxOpenConns:    cfg.DBMaxOpenConns,
		MaxIdleConns:    cfg.DBMaxIdleConns,
		ConnMaxLifetime: cfg.DBConnMaxLifetime,
		ConnMaxIdleTime: cfg.DBConnMaxIdleTime,
	})
	if err != nil {
		log.Error("outbox-worker: connect database", zap.Error(err))
		return 1
	}
	defer func() { _ = sqlDB.Close() }()

	m, err := mailer.New(mailer.Config{
		Host:     cfg.EmailSMTPHost,
		Port:     cfg.EmailSMTPPort,
		Username: cfg.EmailSMTPUser,
		Password: cfg.EmailSMTPPass,
		UseTLS:   cfg.EmailSMTPUseTLS,
		From:     cfg.EmailFrom,
	})
	if err != nil {
		log.Error("outbox-worker: init mailer", zap.Error(err))
		return 1
	}
	defer func() {
		drainCtx, cancel := context.WithTimeout(context.Background(), outboxMailerDrainTimeout)
		defer cancel()
		_ = m.Shutdown(drainCtx)
	}()

	pollInterval := defaultOutboxPollInterval
	if raw := os.Getenv("OUTBOX_POLL_INTERVAL"); raw != "" {
		if d, perr := time.ParseDuration(raw); perr == nil && d > 0 {
			pollInterval = d
		} else {
			log.Warn("outbox-worker: invalid OUTBOX_POLL_INTERVAL — using default",
				zap.String("raw", raw),
				zap.Duration("default", defaultOutboxPollInterval),
			)
		}
	}

	worker := outbox.NewWorker(outbox.NewSQLStore(sqlDB), m, log, outbox.ConfigFromEnv(log))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := worker.Run(ctx, pollInterval); err != nil && err != context.Canceled {
		log.Error("outbox-worker: stopped with error", zap.Error(err))
		return 1
	}
	return 0
}
