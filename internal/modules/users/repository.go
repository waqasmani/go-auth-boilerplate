package users

import (
	"context"
	"database/sql"
	"errors"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

//go:generate mockgen -source=repository.go -destination=mocks/repository_mock.go -package=mocks

// Repository defines data-access for the users module.
type Repository interface {
	GetUserByID(ctx context.Context, id string) (*db.User, error)
}

type repository struct {
	queries *db.Queries
}

// NewRepository constructs a users repository.
func NewRepository(queries *db.Queries) Repository {
	return &repository{queries: queries}
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
