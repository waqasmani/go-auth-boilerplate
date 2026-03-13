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

	// WithTx executes fn inside a single database transaction.
	//
	// The Repository passed to fn is backed by a transaction-scoped *db.Queries
	// (via queries.WithTx), so every call inside fn participates in the same
	// transaction.  WithTx commits when fn returns nil and rolls back otherwise.
	//
	// Callers should never pass the outer Repository into fn — always use the
	// tx-scoped one provided as the argument so the atomicity guarantee holds.
	//
	// Example — register user + issue first refresh token atomically:
	//
	//	var tokenResp *TokenResponse
	//	err = s.repo.WithTx(ctx, func(tx Repository) error {
	//	    if err := tx.CreateUser(ctx, userParams); err != nil {
	//	        return err
	//	    }
	//	    tokenResp, err = s.issueTokenPair(ctx, tx, userID, email, roles, "")
	//	    return err
	//	})
	WithTx(ctx context.Context, fn func(tx Repository) error) error
}

// repository is the concrete implementation backed by sqlc Queries.
//
// Both sqlDB and queries are stored so WithTx can open a real *sql.Tx
// and wrap the existing prepared statements via queries.WithTx(tx).
// Ownership of both belongs to the caller (app.go); this type never closes them.
type repository struct {
	sqlDB   *sql.DB
	queries *db.Queries
}

// NewRepository constructs an auth repository backed by sqlc Queries.
//
// sqlDB is required for WithTx — it is used only to call BeginTx; all normal
// queries go through the prepared-statement handles in queries.
func NewRepository(sqlDB *sql.DB, queries *db.Queries) Repository {
	return &repository{sqlDB: sqlDB, queries: queries}
}

// WithTx opens a transaction, builds a tx-scoped repository, runs fn, and
// commits or rolls back depending on fn's return value.
func (r *repository) WithTx(ctx context.Context, fn func(tx Repository) error) error {
	tx, err := r.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	txRepo := &repository{
		sqlDB:   r.sqlDB,
		queries: r.queries.WithTx(tx),
	}

	if err = fn(txRepo); err != nil {
		// Best-effort rollback: the original fn error is what matters to the caller.
		_ = tx.Rollback()
		return err
	}

	if err = tx.Commit(); err != nil {
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
