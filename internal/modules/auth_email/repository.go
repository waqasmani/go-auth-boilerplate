// Package authemail implements email-based authentication flows: password
// reset, email verification, and 2FA OTP delivery and verification.
package authemail

import (
	"context"
	"database/sql"
	"errors"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

//go:generate mockgen -source=repository.go -destination=mocks/repository_mock.go -package=mocks

// Repository defines the data-access contract for email-auth flows.
//
// GetUserByEmail and GetUserByID reuse the same prepared statements that the
// auth module uses — there is one *db.Queries instance shared across modules,
// so we are not opening additional connections or re-preparing statements.
type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*db.User, error)
	GetUserByID(ctx context.Context, id string) (*db.User, error)
	CreateEmailToken(ctx context.Context, params db.CreateEmailTokenParams) error
	GetEmailTokenByHash(ctx context.Context, hash string) (*db.EmailToken, error)
	ConsumeEmailToken(ctx context.Context, id string) (bool, error)
	InvalidateUserTokensByType(ctx context.Context, params db.InvalidateUserTokensByTypeParams) error
	UpdateUserPasswordHash(ctx context.Context, params db.UpdateUserPasswordHashParams) error
	MarkEmailVerified(ctx context.Context, id string) error
	RevokeUserRefreshTokens(ctx context.Context, userID string) error
}

type repository struct {
	queries *db.Queries
}

// NewRepository constructs an email-auth repository backed by sqlc Queries.
// queries must be the prepared-statement handle returned by db.Prepare in app.go;
// this type never closes it.
func NewRepository(queries *db.Queries) Repository {
	return &repository{queries: queries}
}

func (r *repository) RevokeUserRefreshTokens(ctx context.Context, userID string) error {
	if err := r.queries.RevokeUserRefreshTokens(ctx, userID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
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

func (r *repository) CreateEmailToken(ctx context.Context, params db.CreateEmailTokenParams) error {
	if err := r.queries.CreateEmailToken(ctx, params); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) GetEmailTokenByHash(ctx context.Context, hash string) (*db.EmailToken, error) {
	token, err := r.queries.GetEmailTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Return ErrTokenInvalid — not ErrNotFound — so the HTTP layer
			// returns 401 rather than 404, which would confirm token existence.
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return &token, nil
}

// ConsumeEmailToken atomically marks a token as used and returns whether this
// caller won the race. RowsAffected == 0 means the token was already consumed
// by a concurrent request — the service must treat that as a replay attempt.
func (r *repository) ConsumeEmailToken(ctx context.Context, id string) (bool, error) {
	result, err := r.queries.ConsumeEmailToken(ctx, id)
	if err != nil {
		return false, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return affected == 1, nil
}

func (r *repository) InvalidateUserTokensByType(ctx context.Context, params db.InvalidateUserTokensByTypeParams) error {
	if err := r.queries.InvalidateUserTokensByType(ctx, params); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) UpdateUserPasswordHash(ctx context.Context, params db.UpdateUserPasswordHashParams) error {
	if err := r.queries.UpdateUserPasswordHash(ctx, params); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) MarkEmailVerified(ctx context.Context, id string) error {
	if err := r.queries.MarkEmailVerified(ctx, id); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}
