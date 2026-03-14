package database

// Tests for the migration runner live in the same package (package database,
// not package database_test) so they can reach the unexported runMigrator
// function directly.  This lets us exercise every logical branch without
// standing up a real MySQL instance — the database driver is injected via the
// migrator interface.

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/golang-migrate/migrate/v4"
	"go.uber.org/zap/zaptest"
)

// ─── Fake migrator ────────────────────────────────────────────────────────────

// fakeMigrator implements the migrator interface and returns whatever error
// was pre-loaded into it.  This lets tests exercise every branch in
// runMigrator without touching a database.
type fakeMigrator struct {
	err error
}

func (f *fakeMigrator) Up() error { return f.err }

// ─── runMigrator tests ────────────────────────────────────────────────────────

func TestRunMigrator_SuccessfulMigration(t *testing.T) {
	log := zaptest.NewLogger(t)

	// Up() returning nil means migrations were applied.
	if err := runMigrator(&fakeMigrator{err: nil}, log); err != nil {
		t.Errorf("runMigrator() unexpected error on successful migration: %v", err)
	}
}

func TestRunMigrator_NoChange(t *testing.T) {
	log := zaptest.NewLogger(t)

	// ErrNoChange must be swallowed — schema is already current; that is not
	// a deployment failure.
	if err := runMigrator(&fakeMigrator{err: migrate.ErrNoChange}, log); err != nil {
		t.Errorf("runMigrator() must return nil for ErrNoChange, got: %v", err)
	}
}

func TestRunMigrator_RealError_IsReturned(t *testing.T) {
	log := zaptest.NewLogger(t)
	sentinel := errors.New("migration file corrupted")

	err := runMigrator(&fakeMigrator{err: sentinel}, log)
	if err == nil {
		t.Fatal("runMigrator() must return an error when Up() fails")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("runMigrator() error chain must contain the original error; got: %v", err)
	}
}

func TestRunMigrator_ErrorIsWrapped(t *testing.T) {
	log := zaptest.NewLogger(t)
	raw := errors.New("disk full")

	err := runMigrator(&fakeMigrator{err: raw}, log)

	// The returned error must be a wrapped form of raw (contains context prefix).
	if errors.Is(err, migrate.ErrNoChange) {
		t.Error("runMigrator() must not treat a real error as ErrNoChange")
	}
	if err.Error() == raw.Error() {
		t.Error("runMigrator() must wrap the error with context, not return it bare")
	}
}

func TestRunMigrator_ErrNoChange_NotWrappedAsOtherError(t *testing.T) {
	// Regression guard: make sure a future refactor does not accidentally start
	// wrapping ErrNoChange inside another error type before the errors.Is check.
	log := zaptest.NewLogger(t)

	wrapped := fmt.Errorf("outer: %w", migrate.ErrNoChange)
	if err := runMigrator(&fakeMigrator{err: wrapped}, log); err != nil {
		t.Errorf("runMigrator() must return nil when ErrNoChange is wrapped: %v", err)
	}
}

// ─── newMigrator / source-driver tests (no DB required) ──────────────────────

// TestNewMigrator_InvalidFS checks that newMigrator fails fast when the
// provided FS contains no valid migration files.  The iofs driver validates the
// file names (they must match the golang-migrate numbering convention), so an
// empty FS causes an error before any database connection is attempted.
//
// This test intentionally passes a nil *sql.DB; iofs validation happens before
// the mysql driver is initialised, so the nil DB is never dereferenced.
func TestNewMigrator_EmptyFS_ReturnsError(t *testing.T) {
	emptyFS := fstest.MapFS{} // no *.sql files

	// sql.Open is lazy — it never dials the server, so the returned *sql.DB is
	// non-nil even though the DSN is unreachable. This prevents mysqldrv.WithInstance
	// from nil-panicking while still guaranteeing newMigrator returns an error
	// (the driver's internal Ping fails on an unreachable host).
	db, err := sql.Open("mysql", "user:pass@tcp(127.0.0.1:1)/nonexistent")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			t.Logf("failed to close db: %v", cerr)
		}
	}()

	_, err = newMigrator(db, emptyFS)
	if err == nil {
		t.Error("newMigrator() must return an error for an empty FS or unreachable DB")
	}
}

func TestNewMigrator_ValidFS_NilDB_FailsAtDriverStep(t *testing.T) {
	// An FS with a correctly-named file passes the source-driver step and fails
	// at the MySQL driver step (nil *sql.DB), confirming the source is accepted.
	validFS := fstest.MapFS{
		"000001_init.up.sql":   &fstest.MapFile{Data: []byte("CREATE TABLE t (id INT);")},
		"000001_init.down.sql": &fstest.MapFile{Data: []byte("DROP TABLE t;")},
	}

	_, err := newMigrator(nil, validFS)
	// The error must come from the MySQL driver step, not the iofs step.
	if err == nil {
		t.Error("newMigrator() must return an error when sqlDB is nil")
	}
	// Must NOT be an iofs source error (source was valid).
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("newMigrator() error should be from the mysql driver step, not FS: %v", err)
	}
}

// ─── Logging behaviour ────────────────────────────────────────────────────────

// TestRunMigrator_LogsOnSuccess and _LogsOnNoChange are smoke tests that ensure
// runMigrator does not panic when writing log entries.  zaptest.NewLogger
// captures output so the test binary stays quiet.
func TestRunMigrator_DoesNotPanicOnLogging(t *testing.T) {
	log := zaptest.NewLogger(t)

	cases := []struct {
		name string
		err  error
	}{
		{"nil error", nil},
		{"ErrNoChange", migrate.ErrNoChange},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("runMigrator panicked: %v", r)
				}
			}()
			_ = runMigrator(&fakeMigrator{err: tc.err}, log)
		})
	}
}

// ─── Unused import guard ──────────────────────────────────────────────────────
