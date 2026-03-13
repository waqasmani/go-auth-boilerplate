package auth_test

import (
	"context"
	"database/sql"
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

func (r *stubRepo) CreateUser(_ context.Context, params db.CreateUserParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
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
		Secret:     "test-secret-at-least-32-characters-long",
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
