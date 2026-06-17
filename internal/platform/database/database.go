package database

import (
	"database/sql"
	"fmt"
	"time"

	// Registers the MySQL driver for database/sql; also used directly to parse
	// and re-format the DSN for the migration connection below.
	"github.com/go-sql-driver/mysql"
)

// Config holds database configuration.
type Config struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig(dsn string) Config {
	return Config{
		DSN:             dsn,
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 2 * time.Minute,
	}
}

// New opens and configures a *sql.DB connection pool.
func New(cfg Config) (*sql.DB, error) {
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("database: open: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("database: ping: %w", err)
	}

	return db, nil
}

// NewMigrationDB opens a dedicated, short-lived connection for running schema
// migrations. It forces multiStatements=true so a single migration file may
// contain more than one statement (e.g. a CREATE TABLE followed by a seed
// INSERT) — without it the MySQL driver rejects the second statement with a
// syntax error.
//
// multiStatements is deliberately NOT enabled on the application pool (New):
// allowing several ';'-separated statements per query widens the SQL-injection
// blast radius of every query the app runs, so it is confined to this isolated
// migration handle, which the caller closes as soon as migrations finish. The
// pool is capped at a single connection because golang-migrate runs migrations
// serially under an advisory lock.
func NewMigrationDB(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: parse dsn for migration: %w", err)
	}
	cfg.MultiStatements = true

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("database: open migration connection: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: ping migration connection: %w", err)
	}
	return db, nil
}
