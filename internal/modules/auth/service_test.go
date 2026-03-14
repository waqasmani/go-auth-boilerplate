package auth_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// ─── Stub Repository ──────────────────────────────────────────────────────────

type stubRepo struct {
	mu              sync.Mutex
	users           map[string]*db.User
	tokens          map[string]*db.RefreshToken // keyed by token_hash
	revokedFamilies map[string]bool
}

func newStubRepo() *stubRepo {
	return &stubRepo{
		users:           make(map[string]*db.User),
		tokens:          make(map[string]*db.RefreshToken),
		revokedFamilies: make(map[string]bool),
	}
}

// WithTx satisfies auth.Repository.  The stub has no real transaction
// semantics — it calls fn with itself so the callback operates on the same
// in-memory state.  This is correct for unit tests: we want to verify service
// logic (correct sequencing, error propagation, reuse detection) without
// standing up a real database.  True atomicity is covered by integration tests
// against a live MySQL instance.
//
// If fn returns an error the stub does nothing (mirrors rollback).
// If fn returns nil the stub does nothing (mirrors commit).
// Either way the in-memory state reflects every write fn performed, which is
// what the test assertions need to inspect.
func (r *stubRepo) WithTx(_ context.Context, fn func(tx auth.Repository) error) error {
	return fn(r)
}

func (r *stubRepo) GetUserByEmailWithRoles(_ context.Context, email string) (*auth.UserWithRoles, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Email == email {
			return &auth.UserWithRoles{
				ID:           u.ID,
				Name:         u.Name,
				Email:        u.Email,
				PasswordHash: u.PasswordHash,
				Roles:        []string{},
				CreatedAt:    u.CreatedAt,
				UpdatedAt:    u.UpdatedAt,
			}, nil
		}
	}
	return nil, apperrors.ErrNotFound
}

func (r *stubRepo) GetUserByIDWithRoles(_ context.Context, id string) (*auth.UserWithRoles, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok {
		return nil, apperrors.ErrNotFound
	}
	return &auth.UserWithRoles{
		ID:           u.ID,
		Name:         u.Name,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		Roles:        []string{},
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}, nil
}
func (r *stubRepo) GetUserByEmail(_ context.Context, email string) (*db.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, apperrors.ErrNotFound
}

func (r *stubRepo) GetUserByID(_ context.Context, id string) (*db.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, apperrors.ErrNotFound
}

func (r *stubRepo) AssignUserRole(_ context.Context, _, _ string) error {
	return nil
}

func (r *stubRepo) CreateUser(_ context.Context, params db.CreateUserParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Mirror the MySQL UNIQUE KEY uq_users_email constraint.
	// The real repo gets this for free from error 1062; the stub must enforce it explicitly.
	for _, u := range r.users {
		if u.Email == params.Email {
			return apperrors.ErrEmailAlreadyExists
		}
	}

	r.users[params.ID] = &db.User{
		ID:           params.ID,
		Email:        params.Email,
		PasswordHash: params.PasswordHash,
		Name:         params.Name,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	return nil
}

func (r *stubRepo) CreateRefreshToken(_ context.Context, params db.CreateRefreshTokenParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[params.TokenHash] = &db.RefreshToken{
		ID:          params.ID,
		UserID:      params.UserID,
		TokenHash:   params.TokenHash,
		TokenFamily: params.TokenFamily,
		ExpiresAt:   params.ExpiresAt,
	}
	return nil
}

func (r *stubRepo) GetRefreshTokenByHash(_ context.Context, hash string) (*db.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tokens[hash]
	if !ok {
		return nil, apperrors.ErrTokenInvalid
	}
	// Reflect family-level revocations into the returned record.
	if r.revokedFamilies[t.TokenFamily] {
		t.RevokedAt = sql.NullTime{Time: time.Now(), Valid: true}
	}
	return t, nil
}

// ConsumeRefreshToken mirrors the atomic DB behaviour:
// it sets used_at only when the token is currently unconsumed and unrevoked,
// returning false (no-op) when another caller already consumed it.
func (r *stubRepo) ConsumeRefreshToken(_ context.Context, id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Find by ID (tokens map is keyed by hash; scan for the matching ID).
	for _, t := range r.tokens {
		if t.ID == id {
			if t.UsedAt.Valid || t.RevokedAt.Valid {
				return false, nil // already consumed or revoked
			}
			t.UsedAt = sql.NullTime{Time: time.Now(), Valid: true}
			return true, nil
		}
	}
	return false, nil
}

func (r *stubRepo) RevokeRefreshTokenFamily(_ context.Context, family string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokedFamilies[family] = true
	return nil
}

func (r *stubRepo) RevokeRefreshToken(_ context.Context, _ string) error {
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newTestService(repo auth.Repository) auth.Service {
	jwt := platformauth.NewJWT(platformauth.JWTConfig{
		Keys: []platformauth.JWTKey{
			{ID: "test-v1", Secret: "test-secret-at-least-32-characters-long", Active: true},
		},
		Issuer:     "test",
		Audience:   "test-audience",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
	})
	return auth.NewService(repo, jwt, zap.NewNop())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	resp, err := svc.Register(context.Background(), auth.RegisterRequest{
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "securepassword",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh token")
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	_, _ = svc.Register(context.Background(), auth.RegisterRequest{
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "securepassword",
	})

	_, err := svc.Register(context.Background(), auth.RegisterRequest{
		Name:     "Alice2",
		Email:    "alice@example.com",
		Password: "securepassword",
	})
	fmt.Println(err)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.ErrEmailAlreadyExists.Code {
		t.Errorf("expected EMAIL_ALREADY_EXISTS, got %v", err)
	}
}

func TestLogin_InvalidPassword(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	_, _ = svc.Register(context.Background(), auth.RegisterRequest{
		Name:     "Bob",
		Email:    "bob@example.com",
		Password: "correctpassword",
	})

	_, err := svc.Login(context.Background(), auth.LoginRequest{
		Email:    "bob@example.com",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.ErrInvalidCredentials.Code {
		t.Errorf("expected INVALID_CREDENTIALS, got %v", err)
	}
}

func TestRefresh_TokenReuse_Sequential(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	loginResp, _ := svc.Register(context.Background(), auth.RegisterRequest{
		Name:     "Carol",
		Email:    "carol@example.com",
		Password: "password123",
	})

	// First refresh (valid).
	_, err := svc.Refresh(context.Background(), auth.RefreshRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}

	// Second refresh with the same (now consumed) token → reuse detected.
	_, err = svc.Refresh(context.Background(), auth.RefreshRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	if err == nil {
		t.Fatal("expected reuse error on sequential replay")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.ErrTokenReuse.Code {
		t.Errorf("expected TOKEN_REUSE_DETECTED, got %v", err)
	}
}

// TestRefresh_TokenReuse_Concurrent is the regression test for the race
// condition. It fires N goroutines simultaneously against the same refresh
// token and asserts that exactly one succeeds and all others receive
// ErrTokenReuse (or ErrTokenRevoked once the family is revoked).
func TestRefresh_TokenReuse_Concurrent(t *testing.T) {
	const concurrency = 20

	repo := newStubRepo()
	svc := newTestService(repo)

	loginResp, err := svc.Register(context.Background(), auth.RegisterRequest{
		Name:     "Dave",
		Email:    "dave@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	type result struct {
		resp *auth.TokenResponse
		err  error
	}

	results := make([]result, concurrency)
	var wg sync.WaitGroup
	// start gate keeps all goroutines blocked until we release them together.
	start := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := svc.Refresh(context.Background(), auth.RefreshRequest{
				RefreshToken: loginResp.RefreshToken,
			})
			results[i] = result{resp, err}
		}()
	}

	close(start) // release all goroutines simultaneously
	wg.Wait()

	successes := 0
	for _, r := range results {
		if r.err == nil {
			successes++
		} else {
			appErr, ok := apperrors.As(r.err)
			if !ok {
				t.Errorf("unexpected non-AppError: %v", r.err)
				continue
			}
			// Acceptable outcomes for losers: TOKEN_REUSE_DETECTED or
			// TOKEN_REVOKED (if the family was already revoked by the winner's
			// reuse handling before this goroutine even read the token).
			switch appErr.Code {
			case apperrors.ErrTokenReuse.Code, apperrors.ErrTokenRevoked.Code:
				// expected
			default:
				t.Errorf("unexpected error code %q: %v", appErr.Code, r.err)
			}
		}
	}

	if successes != 1 {
		t.Errorf("expected exactly 1 successful refresh, got %d", successes)
	}
}

// seedToken inserts a token record directly into the stub, bypassing the
// normal issue flow.  Used by logout tests that need pre-expired or
// pre-revoked tokens that could never arrive via the service itself.
func (r *stubRepo) seedToken(tok *db.RefreshToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[tok.TokenHash] = tok
}

// ─── Logout tests ─────────────────────────────────────────────────────────────

// TestLogout_ValidToken_RevokesFamily is the happy path: a live token causes
// its entire session family to be revoked.
func TestLogout_ValidToken_RevokesFamily(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	loginResp, _ := svc.Register(context.Background(), auth.RegisterRequest{
		Name: "Eve", Email: "eve@example.com", Password: "password123",
	})

	if err := svc.Logout(context.Background(), auth.LogoutRequest{
		RefreshToken: loginResp.RefreshToken,
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// A subsequent refresh must fail because the family is now revoked.
	_, err := svc.Refresh(context.Background(), auth.RefreshRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	if err == nil {
		t.Fatal("expected error after logout, got nil")
	}
}

// TestLogout_MissingToken_IsIdempotent confirms that presenting a token that
// does not exist in the database is silently accepted — the session was
// already gone.
func TestLogout_MissingToken_IsIdempotent(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	err := svc.Logout(context.Background(), auth.LogoutRequest{
		RefreshToken: "token-that-was-never-issued",
	})
	if err != nil {
		t.Fatalf("missing token should be treated as already logged out, got %v", err)
	}
}

// TestLogout_ExpiredToken_IsIdempotent is the key regression test for the
// oracle bug.  An attacker holding a stolen-but-expired token must get the
// same silent 200/204 as any other no-op logout, not an error that reveals
// the token's history.
func TestLogout_ExpiredToken_IsIdempotent(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	// Seed an expired token directly — it can never be issued through the
	// normal service flow because ExpiresAt is always set to now+RefreshTTL.
	const rawToken = "expired-raw-token-value"
	repo.seedToken(&db.RefreshToken{
		ID:          "expired-id",
		UserID:      "some-user",
		TokenHash:   platformauth.HashRefreshToken(rawToken),
		TokenFamily: "some-family",
		ExpiresAt:   time.Now().Add(-24 * time.Hour), // expired yesterday
	})

	err := svc.Logout(context.Background(), auth.LogoutRequest{
		RefreshToken: rawToken,
	})
	if err != nil {
		t.Fatalf("expired token should be silently accepted, got %v", err)
	}

	// The family must NOT have been touched — revoking an expired family leaks
	// information and is a no-op from a security perspective.
	repo.mu.Lock()
	revoked := repo.revokedFamilies["some-family"]
	repo.mu.Unlock()
	if revoked {
		t.Error("logout with expired token should not revoke the family")
	}
}

// TestLogout_RevokedToken_IsIdempotent ensures that presenting a token whose
// family was already revoked (e.g. a prior logout or reuse event) returns
// success with no state change, not an error that reveals revocation status.
func TestLogout_RevokedToken_IsIdempotent(t *testing.T) {
	repo := newStubRepo()
	svc := newTestService(repo)

	loginResp, _ := svc.Register(context.Background(), auth.RegisterRequest{
		Name: "Frank", Email: "frank@example.com", Password: "password123",
	})

	// First logout: revokes the family.
	_ = svc.Logout(context.Background(), auth.LogoutRequest{
		RefreshToken: loginResp.RefreshToken,
	})

	// Second logout with the same token: family is already revoked.
	// Must return nil, not an error that distinguishes "revoked" from "missing".
	err := svc.Logout(context.Background(), auth.LogoutRequest{
		RefreshToken: loginResp.RefreshToken,
	})
	if err != nil {
		t.Fatalf("second logout with revoked token should be silently accepted, got %v", err)
	}
}
