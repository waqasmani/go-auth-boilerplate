package auth

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// ── In-memory fake repository ───────────────────────────────────────────────

type fakeRepo struct {
	mu     sync.Mutex
	tokens map[string]*db.RefreshToken // keyed by id
	user   *UserWithRoles
}

func newFakeRepo(user *UserWithRoles) *fakeRepo {
	return &fakeRepo{tokens: map[string]*db.RefreshToken{}, user: user}
}

func (f *fakeRepo) byHash(hash string) *db.RefreshToken {
	for _, t := range f.tokens {
		if t.TokenHash == hash {
			return t
		}
	}
	return nil
}

func (f *fakeRepo) WithTx(ctx context.Context, fn func(tx Repository) error) error {
	// The fake mutates in place; the only path that mutates inside the tx
	// (successful rotation) commits, and the reuse path returns before mutating.
	return fn(f)
}

func (f *fakeRepo) CreateRefreshToken(ctx context.Context, p db.CreateRefreshTokenParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[p.ID] = &db.RefreshToken{
		ID:              p.ID,
		UserID:          p.UserID,
		TokenHash:       p.TokenHash,
		TokenFamily:     p.TokenFamily,
		ExpiresAt:       p.ExpiresAt,
		FamilyExpiresAt: sql.NullTime{Time: p.FamilyExpiresAt, Valid: true},
		CreatedAt:       time.Now().UTC(),
	}
	return nil
}

func (f *fakeRepo) GetRefreshTokenByHashForUpdate(ctx context.Context, hash string) (*db.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t := f.byHash(hash); t != nil {
		return t, nil
	}
	return nil, apperrors.ErrTokenInvalid
}

func (f *fakeRepo) GetRefreshTokenByHash(ctx context.Context, hash string) (*db.RefreshToken, error) {
	return f.GetRefreshTokenByHashForUpdate(ctx, hash)
}

func (f *fakeRepo) ConsumeRefreshToken(ctx context.Context, id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tokens[id]
	if t == nil || t.UsedAt.Valid || t.RevokedAt.Valid {
		return false, nil
	}
	t.UsedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	return true, nil
}

func (f *fakeRepo) RevokeRefreshTokenFamily(ctx context.Context, family string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.TokenFamily == family {
			t.RevokedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		}
	}
	return nil
}

func (f *fakeRepo) GetUserByIDWithRoles(ctx context.Context, id string) (*UserWithRoles, error) {
	return f.user, nil
}

// Unused by the refresh path — present to satisfy the interface.
func (f *fakeRepo) GetUserByEmail(ctx context.Context, e string) (*db.User, error) { return nil, nil }
func (f *fakeRepo) GetUserByID(ctx context.Context, id string) (*db.User, error)   { return nil, nil }
func (f *fakeRepo) GetUserByEmailWithRoles(ctx context.Context, e string) (*UserWithRoles, error) {
	return f.user, nil
}
func (f *fakeRepo) CreateUser(ctx context.Context, p db.CreateUserParams) error { return nil }
func (f *fakeRepo) AssignUserRole(ctx context.Context, u, r string) error       { return nil }

// ── Test harness ────────────────────────────────────────────────────────────

func newTestService(t *testing.T, repo Repository) *service {
	t.Helper()
	j, err := platformauth.NewJWT(platformauth.JWTConfig{
		Keys:               []platformauth.JWTKey{{ID: "v1", Secret: "unit-test-jwt-secret-32-bytes-or-more-xxxx", Active: true}},
		Issuer:             "test",
		Audience:           "test",
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         24 * time.Hour,
		RefreshAbsoluteTTL: 72 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}
	return &service{repo: repo, jwt: j, log: zap.NewNop(), auditLog: audit.New(zap.NewNop())}
}

// seedToken issues a fresh token pair and stores it in the fake repo, returning
// the raw refresh token the client would hold.
func seedToken(t *testing.T, s *service, repo *fakeRepo, familyExpiresAt time.Time) string {
	t.Helper()
	resp, err := s.issueTokenPair(context.Background(), repo, repo.user.ID, repo.user.Email, repo.user.Roles, "", familyExpiresAt)
	if err != nil {
		t.Fatalf("seed issueTokenPair: %v", err)
	}
	return resp.RefreshToken
}

func isCode(err error, code string) bool {
	appErr, ok := apperrors.As(err)
	return ok && appErr.Code == code
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestRefresh_RotatesSuccessfully(t *testing.T) {
	repo := newFakeRepo(&UserWithRoles{ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true})
	s := newTestService(t, repo)
	raw := seedToken(t, s, repo, time.Time{})

	resp, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: raw})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if resp.RefreshToken == "" || resp.RefreshToken == raw {
		t.Fatal("expected a rotated (new, different) refresh token")
	}
	if resp.AccessToken == "" {
		t.Fatal("expected an access token")
	}
}

// TestRefresh_ReuseRevokesFamily is the headline reuse-detection test: replaying
// a previously-rotated token (outside the concurrent-use grace window) must
// return ErrTokenReuse AND revoke every token in the family.
func TestRefresh_ReuseRevokesFamily(t *testing.T) {
	repo := newFakeRepo(&UserWithRoles{ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true})
	s := newTestService(t, repo)
	raw := seedToken(t, s, repo, time.Time{})

	// First refresh: succeeds, consumes the original token, issues a new one.
	if _, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: raw}); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	// Backdate the consumed token's used_at beyond the 10s grace window so the
	// replay is treated as deliberate reuse rather than a benign concurrent race.
	original := repo.byHash(platformauth.HashRefreshToken(raw))
	if original == nil {
		t.Fatal("original token vanished")
	}
	original.UsedAt = sql.NullTime{Time: time.Now().UTC().Add(-30 * time.Second), Valid: true}
	family := original.TokenFamily

	// Replay the original (already-rotated) token.
	_, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: raw})
	if !isCode(err, apperrors.ErrTokenReuse.Code) {
		t.Fatalf("replay error = %v, want ErrTokenReuse", err)
	}

	// Every token in the family must now be revoked.
	for _, tk := range repo.tokens {
		if tk.TokenFamily == family && !tk.RevokedAt.Valid {
			t.Fatalf("token %s in reused family is NOT revoked", tk.ID)
		}
	}
}

func TestRefresh_GraceWindowDoesNotRevoke(t *testing.T) {
	repo := newFakeRepo(&UserWithRoles{ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true})
	s := newTestService(t, repo)
	raw := seedToken(t, s, repo, time.Time{})

	if _, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: raw}); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	// Immediate replay: used_at is ~now (well within the 10s grace) → benign
	// concurrent duplicate, returns invalid WITHOUT family revocation.
	_, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: raw})
	if !isCode(err, apperrors.ErrTokenInvalid.Code) {
		t.Fatalf("grace-window replay error = %v, want ErrTokenInvalid", err)
	}
	original := repo.byHash(platformauth.HashRefreshToken(raw))
	if original.RevokedAt.Valid {
		t.Fatal("grace-window replay must NOT revoke the family")
	}
}

func TestRefresh_AbsoluteFamilyDeadlineRejected(t *testing.T) {
	repo := newFakeRepo(&UserWithRoles{ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true})
	s := newTestService(t, repo)
	raw := seedToken(t, s, repo, time.Time{})

	// A new family always gets a fresh deadline (now + RefreshAbsoluteTTL), so
	// backdate the stored family deadline to simulate a long-lived, continuously
	// rotated session that has hit its absolute cap.
	repo.byHash(platformauth.HashRefreshToken(raw)).FamilyExpiresAt =
		sql.NullTime{Time: time.Now().UTC().Add(-time.Minute), Valid: true}

	_, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: raw})
	if !isCode(err, apperrors.ErrTokenExpired.Code) {
		t.Fatalf("past-absolute-deadline error = %v, want ErrTokenExpired", err)
	}
}

func TestRefresh_UnknownTokenRejected(t *testing.T) {
	repo := newFakeRepo(&UserWithRoles{ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true})
	s := newTestService(t, repo)
	_, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: "never-issued-token"})
	if !isCode(err, apperrors.ErrTokenInvalid.Code) {
		t.Fatalf("unknown token error = %v, want ErrTokenInvalid", err)
	}
}
