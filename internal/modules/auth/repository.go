package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-sql-driver/mysql"
	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

//go:generate mockgen -source=repository.go -destination=mocks/repository_mock.go -package=mocks

// Repository defines the data-access contract for auth.
type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*db.User, error)
	GetUserByID(ctx context.Context, id string) (*db.User, error)
	GetUserByIDWithRoles(ctx context.Context, id string) (*UserWithRoles, error)
	GetUserByEmailWithRoles(ctx context.Context, email string) (*UserWithRoles, error)
	CreateUser(ctx context.Context, params db.CreateUserParams) error
	CreateRefreshToken(ctx context.Context, params db.CreateRefreshTokenParams) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*db.RefreshToken, error)
	AssignUserRole(ctx context.Context, userID, roleName string) error
	ConsumeRefreshToken(ctx context.Context, id string) (bool, error)
	RevokeRefreshTokenFamily(ctx context.Context, family string) error
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

func (r *repository) GetUserByEmailWithRoles(ctx context.Context, email string) (*UserWithRoles, error) {
	rows, err := r.queries.GetUserByEmailWithRoles(ctx, email)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	if len(rows) == 0 {
		return nil, apperrors.ErrNotFound
	}

	result := &UserWithRoles{
		ID:           rows[0].ID,
		Name:         rows[0].Name,
		Email:        rows[0].Email,
		Roles:        []string{},
		PasswordHash: rows[0].PasswordHash,
		CreatedAt:    rows[0].CreatedAt,
		UpdatedAt:    rows[0].UpdatedAt,
	}

	for _, row := range rows {
		if row.RoleName.Valid {
			result.Roles = append(result.Roles, row.RoleName.String)
		}
	}

	return result, nil
}

func (r *repository) AssignUserRole(ctx context.Context, userID, roleName string) error {
	result, err := r.queries.AssignUserRoleByName(ctx, db.AssignUserRoleByNameParams{
		UserID: userID,
		Name:   roleName,
	})
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	if affected == 0 {
		return apperrors.New("ROLE_NOT_FOUND",
			fmt.Sprintf("role %q does not exist", roleName),
			http.StatusInternalServerError, nil)
	}
	return nil
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

func (r *repository) GetUserByIDWithRoles(ctx context.Context, id string) (*UserWithRoles, error) {
	rows, err := r.queries.GetUserByIDWithRoles(ctx, id)
	if err != nil {
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	if len(rows) == 0 {
		return nil, apperrors.ErrNotFound
	}

	result := &UserWithRoles{
		ID:           rows[0].ID,
		Name:         rows[0].Name,
		Email:        rows[0].Email,
		Roles:        []string{},
		PasswordHash: rows[0].PasswordHash,
		CreatedAt:    rows[0].CreatedAt,
		UpdatedAt:    rows[0].UpdatedAt,
	}

	for _, row := range rows {
		if row.RoleName.Valid {
			result.Roles = append(result.Roles, row.RoleName.String)
		}
	}
	return result, nil
}

func (r *repository) CreateUser(ctx context.Context, params db.CreateUserParams) error {
	if err := r.queries.CreateUser(ctx, params); err != nil {
		// Check for MySQL duplicate entry error (unique constraint violation on email)
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return apperrors.ErrEmailAlreadyExists
		}
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) CreateRefreshToken(ctx context.Context, params db.CreateRefreshTokenParams) error {
	if err := r.queries.CreateRefreshToken(ctx, params); err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1452 {
			// The user was deleted between the read and this write.
			// Surfacing ErrNotFound lets the service return a 404/401
			// rather than an opaque 500.
			return apperrors.Wrap(apperrors.ErrNotFound, err)
		}
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
