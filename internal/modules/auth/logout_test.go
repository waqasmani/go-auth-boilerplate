package auth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// logoutRepo extends the existing fakeRepo so RevokeRefreshTokenFamily can be
// forced to fail, exercising the "revocation failure must surface as an error,
// not a false success" path in Logout.
type logoutRepo struct {
	*fakeRepo
	revokeErr   error
	revokeCalls int
}

func (r *logoutRepo) RevokeRefreshTokenFamily(ctx context.Context, family string) error {
	r.revokeCalls++
	if r.revokeErr != nil {
		return r.revokeErr
	}
	return r.fakeRepo.RevokeRefreshTokenFamily(ctx, family)
}

// ── Test 3: Logout ──────────────────────────────────────────────────────────

// TestLogout_RevokesWholeFamily asserts that presenting a valid, unused refresh
// token revokes the entire token family (all sibling tokens), not just the one
// presented.
func TestLogout_RevokesWholeFamily(t *testing.T) {
	t.Parallel()

	repo := &logoutRepo{fakeRepo: newFakeRepo(&UserWithRoles{
		ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true,
	})}
	s := newTestService(t, repo)

	raw := seedToken(t, s, repo.fakeRepo, time.Time{})
	family := repo.byHash(platformauth.HashRefreshToken(raw)).TokenFamily

	// Add a SECOND token in the SAME family (as a rotation would) to prove the
	// whole family is revoked, not merely the presented token.
	sibling := seedToken(t, s, repo.fakeRepo, time.Time{})
	siblingTok := repo.byHash(platformauth.HashRefreshToken(sibling))
	siblingTok.TokenFamily = family

	if err := s.Logout(context.Background(), LogoutRequest{RefreshToken: raw}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if repo.revokeCalls != 1 {
		t.Fatalf("expected exactly 1 revoke call, got %d", repo.revokeCalls)
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	for _, tk := range repo.tokens {
		if tk.TokenFamily == family && !tk.RevokedAt.Valid {
			t.Fatalf("token %s in family %s was NOT revoked by logout", tk.ID, family)
		}
	}
}

// TestLogout_RevocationFailureSurfacesError asserts that when the underlying
// family revocation fails, Logout returns the error rather than a false
// "success" (which would mislead the client into believing all sessions were
// terminated).
func TestLogout_RevocationFailureSurfacesError(t *testing.T) {
	t.Parallel()

	dbErr := errors.New("db down")
	repo := &logoutRepo{
		fakeRepo: newFakeRepo(&UserWithRoles{
			ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true,
		}),
		revokeErr: dbErr,
	}
	s := newTestService(t, repo)

	raw := seedToken(t, s, repo.fakeRepo, time.Time{})

	err := s.Logout(context.Background(), LogoutRequest{RefreshToken: raw})
	if err == nil {
		t.Fatal("expected Logout to surface the revocation error, got nil (false success)")
	}
	if !errors.Is(err, dbErr) {
		t.Fatalf("expected the underlying revoke error to surface, got %v", err)
	}
	if repo.revokeCalls != 1 {
		t.Fatalf("expected exactly 1 revoke attempt, got %d", repo.revokeCalls)
	}
}

// TestLogout_UsedTokenRevokesFamilyAsPrecaution asserts that presenting an
// already-USED (rotated-away) but not-yet-expired token still revokes the whole
// family as a precaution, and that a revoke failure there ALSO surfaces an error
// rather than a 204-style false success.
func TestLogout_UsedTokenRevocationFailureSurfacesError(t *testing.T) {
	t.Parallel()

	dbErr := errors.New("db down")
	repo := &logoutRepo{
		fakeRepo: newFakeRepo(&UserWithRoles{
			ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true,
		}),
		revokeErr: dbErr,
	}
	s := newTestService(t, repo)

	raw := seedToken(t, s, repo.fakeRepo, time.Time{})
	// Mark the token as already used (as a successful rotation would have).
	repo.byHash(platformauth.HashRefreshToken(raw)).UsedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	err := s.Logout(context.Background(), LogoutRequest{RefreshToken: raw})
	if err == nil {
		t.Fatal("expected used-token logout revoke failure to surface, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Fatalf("expected the underlying revoke error to surface, got %v", err)
	}
}

// TestLogout_UnknownTokenIsNoOp asserts that logging out with a token that was
// never issued succeeds silently (idempotent logout — no error, no revoke).
func TestLogout_UnknownTokenIsNoOp(t *testing.T) {
	t.Parallel()

	repo := &logoutRepo{fakeRepo: newFakeRepo(&UserWithRoles{
		ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true,
	})}
	s := newTestService(t, repo)

	if err := s.Logout(context.Background(), LogoutRequest{RefreshToken: "never-issued"}); err != nil {
		t.Fatalf("logout with unknown token should be a no-op, got %v", err)
	}
	if repo.revokeCalls != 0 {
		t.Fatalf("unknown-token logout must not attempt revocation, got %d calls", repo.revokeCalls)
	}
}

// TestLogout_ExpiredTokenIsNoOp asserts that an expired token logout is a no-op
// (the family naturally died; no revoke needed, no error).
func TestLogout_ExpiredTokenIsNoOp(t *testing.T) {
	t.Parallel()

	repo := &logoutRepo{fakeRepo: newFakeRepo(&UserWithRoles{
		ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true,
	})}
	s := newTestService(t, repo)

	raw := seedToken(t, s, repo.fakeRepo, time.Time{})
	repo.byHash(platformauth.HashRefreshToken(raw)).ExpiresAt = time.Now().UTC().Add(-time.Hour)

	if err := s.Logout(context.Background(), LogoutRequest{RefreshToken: raw}); err != nil {
		t.Fatalf("expired-token logout should be a no-op, got %v", err)
	}
	if repo.revokeCalls != 0 {
		t.Fatalf("expired-token logout must not attempt revocation, got %d calls", repo.revokeCalls)
	}
}
