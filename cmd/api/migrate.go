package main

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
	"github.com/waqasmani/go-auth-boilerplate/sql/migrations"
)

// runMigrate applies all pending schema migrations in a single run and returns
// a process exit code (0 success, 1 failure).
//
// It exists so migrations can be driven as a dedicated deployment step — a
// Kubernetes init-container / Job (`/api migrate`) or a CI stage — rather than
// by every API replica on boot. App replicas should then run with
// SKIP_MIGRATIONS=true so they never contend for the golang-migrate advisory
// lock during a rolling deploy or scale-from-zero. The migration logic itself
// is exactly the function container.New uses on startup, so the two paths can
// never diverge.
func runMigrate() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("migrate: load config: %v\n", err)
		return 1
	}

	log, err := logger.New(cfg.AppEnv)
	if err != nil {
		fmt.Printf("migrate: init logger: %v\n", err)
		return 1
	}
	defer func() { _ = log.Sync() }()

	sqlDB, err := database.New(database.DefaultConfig(cfg.DBDSN))
	if err != nil {
		log.Error("migrate: connect database", zap.Error(err))
		return 1
	}
	defer func() { _ = sqlDB.Close() }()

	if err = database.RunMigrations(sqlDB, migrations.FS, log); err != nil {
		log.Error("migrate: apply migrations", zap.Error(err))
		return 1
	}
	return 0
}
