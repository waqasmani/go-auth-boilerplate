package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

//go:generate mockgen -source=repository.go -destination=mocks/repository_mock.go -package=mocks

// Repository defines the data-access contract for auth.
type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*db.User, error)
	GetUserByID(ctx context.Context, id string) (*db.User, error)
	CreateUser(ctx context.Context, params db.CreateUserParams) error
	CreateRefreshToken(ctx context.Context, params db.CreateRefreshTokenParams) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*db.RefreshToken, error)

	// ConsumeRefreshToken atomically marks the token as used in a single UPDATE
	// that includes a "used_at IS NULL" guard. It returns true when this caller
	// won the race (RowsAffected == 1) and false when another request already
	// consumed the token (RowsAffected == 0), which the service treats as reuse.
	ConsumeRefreshToken(ctx context.Context, id string) (bool, error)

	RevokeRefreshTokenFamily(ctx context.Context, family string) error
	RevokeRefreshToken(ctx context.Context, id string) error
}

type repository struct {
	queries *db.Queries
}

// NewRepository constructs an auth repository backed by sqlc Queries.
func NewRepository(queries *db.Queries) Repository {
	return &repository{queries: queries}
}

func (r *repository) GetUserByEmail(ctx context.Context, email string) (*db.User, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return &user, nil
}

func (r *repository) GetUserByID(ctx context.Context, id string) (*db.User, error) {
	user, err := r.queries.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return &user, nil
}

func (r *repository) CreateUser(ctx context.Context, params db.CreateUserParams) error {
	if err := r.queries.CreateUser(ctx, params); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) CreateRefreshToken(ctx context.Context, params db.CreateRefreshTokenParams) error {
	if err := r.queries.CreateRefreshToken(ctx, params); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*db.RefreshToken, error) {
	token, err := r.queries.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return &token, nil
}

// ConsumeRefreshToken calls the atomic UPDATE and converts sql.Result →
// bool. RowsAffected == 1 means this caller won the race; 0 means the
// token was already consumed or revoked by a concurrent request.
func (r *repository) ConsumeRefreshToken(ctx context.Context, id string) (bool, error) {
	result, err := r.queries.ConsumeRefreshToken(ctx, id)
	if err != nil {
		return false, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return affected == 1, nil
}

func (r *repository) RevokeRefreshTokenFamily(ctx context.Context, family string) error {
	if err := r.queries.RevokeRefreshTokenFamily(ctx, family); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) RevokeRefreshToken(ctx context.Context, id string) error {
	if err := r.queries.RevokeRefreshToken(ctx, id); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}
