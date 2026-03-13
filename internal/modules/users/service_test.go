package users_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/modules/users"
)

// ─── Stub Repository ──────────────────────────────────────────────────────────

type stubUsersRepo struct {
	users map[string]*db.User
}

func newStubUsersRepo() *stubUsersRepo {
	return &stubUsersRepo{users: make(map[string]*db.User)}
}

func (r *stubUsersRepo) GetUserByID(_ context.Context, id string) (*db.User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, apperrors.ErrNotFound
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestGetMe_Success(t *testing.T) {
	repo := newStubUsersRepo()
	repo.users["user-123"] = &db.User{
		ID:        "user-123",
		Name:      "Alice",
		Email:     "alice@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	svc := users.NewService(repo, zap.NewNop())
	resp, err := svc.GetMe(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", resp.Email)
	}
	if resp.Name != "Alice" {
		t.Errorf("expected name Alice, got %s", resp.Name)
	}
}

func TestGetMe_NotFound(t *testing.T) {
	repo := newStubUsersRepo()
	svc := users.NewService(repo, zap.NewNop())

	_, err := svc.GetMe(context.Background(), "nonexistent-id")
	if err == nil {
		t.Fatal("expected not found error")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.ErrNotFound.Code {
		t.Errorf("expected NOT_FOUND, got %v", err)
	}
}

func TestGetMe_EmptyUserID(t *testing.T) {
	repo := newStubUsersRepo()
	svc := users.NewService(repo, zap.NewNop())

	_, err := svc.GetMe(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty user ID")
	}
	appErr, ok := apperrors.As(err)
	if !ok || appErr.Code != apperrors.ErrUnauthorized.Code {
		t.Errorf("expected UNAUTHORIZED, got %v", err)
	}
}
