//go:build integration

// Package integration holds DB-backed end-to-end tests. They are gated behind
// the `integration` build tag (so the default `go test ./...` never compiles
// them) and skip cleanly when DB_DSN is unset.
//
// Run with a live MariaDB/MySQL:
//
//	make docker-db && sleep 5 && make migrate && make test-integration
//
// or directly:
//
//	DB_DSN="root:rootpassword@tcp(127.0.0.1:3306)/auth_db?parseTime=true&loc=UTC" \
//	  go test -race -tags=integration ./tests/integration/...
package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	authmod "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	emailmod "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth_email"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	"github.com/waqasmani/go-auth-boilerplate/sql/migrations"
)

func setup(t *testing.T) (*sql.DB, *dbpkg.Queries) {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB integration test")
	}
	db, err := database.New(database.DefaultConfig(dsn))
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Idempotent: ErrNoChange is treated as success by RunMigrations.
	if err := database.RunMigrations(db, migrations.FS, zap.NewNop()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q, err := dbpkg.Prepare(ctx, db)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return db, q
}

func newJWT(t *testing.T) *platformauth.JWT {
	t.Helper()
	j, err := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:               []platformauth.JWTKey{{ID: "v1", Secret: "integration-jwt-secret-32-bytes-or-more-xx", Active: true}},
		Issuer:             "itest",
		Audience:           "itest",
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         24 * time.Hour,
		RefreshAbsoluteTTL: 72 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}
	return j
}

func createUser(t *testing.T, repo authmod.Repository) string {
	t.Helper()
	id := uuid.NewString()
	hash, _ := platformauth.HashPassword("integration-password-123")
	ctx := context.Background()
	if err := repo.CreateUser(ctx, dbpkg.CreateUserParams{
		ID: id, Email: id + "@itest.local", PasswordHash: hash, Name: "itest",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := repo.AssignUserRole(ctx, id, "user"); err != nil {
		t.Fatalf("AssignUserRole (roles must be seeded by migration 0003): %v", err)
	}
	return id
}

// TestRefreshReuseRevokesFamily_DB exercises rotation + reuse detection +
// family-wide revocation against a real database (the FOR UPDATE path).
func TestRefreshReuseRevokesFamily_DB(t *testing.T) {
	db, q := setup(t)
	repo := authmod.NewRepository(db, q)
	svc := authmod.NewService(repo, newJWT(t), zap.NewNop(), audit.New(zap.NewNop()), nil)
	ctx := context.Background()

	userID := createUser(t, repo)

	// Seed a refresh token via the JWT + repo (mimicking issuance at login).
	j := newJWT(t)
	pair, err := j.GenerateTokenPair(userID, userID+"@itest.local", []string{"user"}, "", time.Time{})
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	if err := repo.CreateRefreshToken(ctx, dbpkg.CreateRefreshTokenParams{
		ID: uuid.NewString(), UserID: userID, TokenHash: pair.RefreshTokenHashed,
		TokenFamily: pair.RefreshTokenFamily, ExpiresAt: pair.RefreshExpiresAt,
		FamilyExpiresAt: pair.FamilyExpiresAt,
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	// First refresh rotates successfully.
	if _, err := svc.Refresh(ctx, authmod.RefreshRequest{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	// Backdate used_at beyond the 10s concurrent-use grace so the replay counts
	// as deliberate reuse rather than a benign race.
	if _, err := db.ExecContext(ctx,
		"UPDATE refresh_tokens SET used_at = UTC_TIMESTAMP() - INTERVAL 30 SECOND WHERE token_hash = ?",
		pair.RefreshTokenHashed); err != nil {
		t.Fatalf("backdate used_at: %v", err)
	}

	// Replay the rotated-away token → reuse detected → family revoked.
	_, err = svc.Refresh(ctx, authmod.RefreshRequest{RefreshToken: pair.RefreshToken})
	if appErr, ok := apperrors.As(err); !ok || appErr.Code != apperrors.ErrTokenReuse.Code {
		t.Fatalf("replay error = %v, want ErrTokenReuse", err)
	}

	// Every row in the family must now be revoked.
	var live int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM refresh_tokens WHERE token_family = ? AND revoked_at IS NULL",
		pair.RefreshTokenFamily).Scan(&live); err != nil {
		t.Fatalf("count live family rows: %v", err)
	}
	if live != 0 {
		t.Fatalf("expected entire family revoked, found %d live rows", live)
	}
}

// TestChallengeAttemptCounter_DB validates the new email_tokens.attempts column
// and the atomic increment used to cap OTP brute-force (C3).
func TestChallengeAttemptCounter_DB(t *testing.T) {
	db, q := setup(t)
	authRepo := authmod.NewRepository(db, q)
	emailRepo := emailmod.NewRepository(db, q)
	ctx := context.Background()

	userID := createUser(t, authRepo)

	challengeID := uuid.NewString()
	if err := emailRepo.CreateEmailToken(ctx, dbpkg.CreateEmailTokenParams{
		ID: challengeID, UserID: userID, TokenHash: uuid.NewString(),
		TokenType: "challenge", ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateEmailToken: %v", err)
	}

	for want := 1; want <= 3; want++ {
		got, err := emailRepo.RecordChallengeAttempt(ctx, challengeID)
		if err != nil {
			t.Fatalf("RecordChallengeAttempt: %v", err)
		}
		if got != want {
			t.Fatalf("attempt count = %d, want %d", got, want)
		}
	}
}
