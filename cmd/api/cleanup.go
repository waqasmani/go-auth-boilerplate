package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/cleanup"
	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

const cleanupDefaultTimeout = 5 * time.Minute

// runCleanup purges expired token rows and old email_outbox rows in a single
// pass, then exits. Exposed as the `/api cleanup` subcommand so the same image
// that serves the API can back a Kubernetes CronJob (the standalone cmd/cleanup
// binary remains for non-container schedulers). Migrations are skipped — the
// dedicated migrate step owns DDL. Returns a process exit code.
func runCleanup() int {
	if err := os.Setenv("SKIP_MIGRATIONS", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: set SKIP_MIGRATIONS: %v\n", err)
		return 1
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: load config: %v\n", err)
		return 1
	}
	log, err := logger.New(cfg.AppEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: init logger: %v\n", err)
		return 1
	}
	defer func() { _ = log.Sync() }()

	sqlDB, err := database.New(database.DefaultConfig(cfg.DBDSN))
	if err != nil {
		log.Error("cleanup: connect database", zap.Error(err))
		return 1
	}
	defer func() { _ = sqlDB.Close() }()

	timeout := cleanupDefaultTimeout
	if raw := os.Getenv("CLEANUP_TIMEOUT"); raw != "" {
		if d, perr := time.ParseDuration(raw); perr == nil && d > 0 {
			timeout = d
		} else {
			log.Warn("cleanup: invalid CLEANUP_TIMEOUT — using default",
				zap.String("raw", raw),
				zap.Duration("default", cleanupDefaultTimeout),
			)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := cleanup.NewJob(sqlDB, log).Run(ctx); err != nil {
		log.Error("cleanup: finished with errors", zap.Error(err))
		return 1
	}
	log.Info("cleanup: finished successfully")
	return 0
}
