// Command cleanup purges expired rows from token tables in a single run and
// exits. Run it as a Kubernetes CronJob or Unix cron entry rather than as a
// background goroutine inside an HTTP pod.
//
// Exit codes:
//
//	0 — all passes completed without error
//	1 — configuration, database, or one-or-more pass errors
//
// Environment: identical to the main API binary. Migrations are skipped
// (SKIP_MIGRATIONS is forced true) so the job never blocks waiting to acquire
// a DDL lock during a schema upgrade.
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

// jobTimeout is the maximum wall-clock time the entire cleanup run may take.
// Override via CLEANUP_TIMEOUT env var if tables are very large; use a value
// that safely fits within the CronJob's activeDeadlineSeconds.
const defaultJobTimeout = 5 * time.Minute

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "cleanup: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Force migrations off — the cleanup job has no business acquiring a DDL
	// lock, and running against a schema it did not migrate is correct: the
	// API pods own migration on startup.
	if err := os.Setenv("SKIP_MIGRATIONS", "true"); err != nil {
		return fmt.Errorf("set SKIP_MIGRATIONS: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log, err := logger.New(cfg.AppEnv)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer func() { _ = log.Sync() }()

	dbCfg := database.DefaultConfig(cfg.DBDSN)
	sqlDB, err := database.New(dbCfg)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	timeout := defaultJobTimeout
	if raw := os.Getenv("CLEANUP_TIMEOUT"); raw != "" {
		if d, parseErr := time.ParseDuration(raw); parseErr == nil && d > 0 {
			timeout = d
		} else {
			log.Warn("cleanup: invalid CLEANUP_TIMEOUT — using default",
				zap.String("raw", raw),
				zap.Duration("default", defaultJobTimeout),
			)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	log.Info("cleanup: starting",
		zap.Duration("timeout", timeout),
		zap.String("env", cfg.AppEnv),
	)

	job := cleanup.NewJob(sqlDB, log)
	if err = job.Run(ctx); err != nil {
		log.Error("cleanup: finished with errors", zap.Error(err))
		return err
	}

	log.Info("cleanup: finished successfully")
	return nil
}
