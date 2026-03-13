// Package database provides helpers for opening and managing the SQL
// connection pool. This file adds a migration runner on top of golang-migrate
// so schema changes are applied atomically on every startup before the
// application begins serving traffic.
package database

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	mysqldrv "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"go.uber.org/zap"

	"database/sql"
)

// RunMigrations applies every pending migration in migrationsFS to db and
// returns nil when the schema is already at the latest version (ErrNoChange).
//
// It is safe to call on every startup: golang-migrate tracks applied versions
// in a schema_migrations table and is idempotent when the schema is current.
//
// Call this immediately after the connection pool passes its Ping check and
// before any application query executes, so the schema and the code are always
// in sync:
//
//	sqlDB, _ := database.New(cfg)
//	database.RunMigrations(sqlDB, migrations.FS, log)
//	queries, _ := db.Prepare(ctx, sqlDB)
//
// The migrationsFS must contain sequentially-numbered *.up.sql / *.down.sql
// pairs at its root (e.g. 000001_init.up.sql).  Use the embed.FS exported by
// the sql/migrations package so the files are always bundled with the binary.
func RunMigrations(sqlDB *sql.DB, migrationsFS fs.FS, log *zap.Logger) error {
	m, err := newMigrator(sqlDB, migrationsFS)
	if err != nil {
		return err
	}
	return runMigrator(m, log)
}

// ─── Internal seam ───────────────────────────────────────────────────────────

// migrator is a narrow interface over *migrate.Migrate.  The single method
// matches migrate.Migrate.Up exactly, which lets tests inject a fake without
// standing up a real MySQL instance.
type migrator interface {
	Up() error
}

// newMigrator wires the iofs source driver to the MySQL database driver and
// returns a ready-to-use *migrate.Migrate.  Separated from RunMigrations so
// the hot path (runMigrator) is testable with a fake.
func newMigrator(sqlDB *sql.DB, migrationsFS fs.FS) (migrator, error) {
	// Source: read migration files from the embedded FS.
	// "." means the files live at the root of the provided FS, which is what
	// //go:embed *.sql produces — no subdirectory to traverse.
	src, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: create iofs source: %w", err)
	}

	// Database driver: wraps the existing *sql.DB so golang-migrate uses the
	// same connection pool as the rest of the application.  DatabaseName is
	// left empty — the driver infers it from the DSN.
	drv, err := mysqldrv.WithInstance(sqlDB, &mysqldrv.Config{})
	if err != nil {
		return nil, fmt.Errorf("migrate: create mysql driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "mysql", drv)
	if err != nil {
		return nil, fmt.Errorf("migrate: init migrator: %w", err)
	}

	return m, nil
}

// runMigrator calls m.Up() and converts the result into a clean error contract:
//
//   - nil            → migrations applied; schema is now current
//   - ErrNoChange    → schema was already at the latest version; not an error
//   - anything else  → wrapped and returned so the caller can abort startup
func runMigrator(m migrator, log *zap.Logger) error {
	err := m.Up()
	switch {
	case err == nil:
		log.Info("database migrations applied successfully")
		return nil
	case errors.Is(err, migrate.ErrNoChange):
		log.Info("database schema is already up to date — no migrations to run")
		return nil
	default:
		return fmt.Errorf("migrate: apply: %w", err)
	}
}
