package users

import (
	"context"

	"go.uber.org/zap"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

//go:generate mockgen -source=service.go -destination=mocks/service_mock.go -package=mocks

// Service defines the users business-logic contract.
type Service interface {
	GetMe(ctx context.Context, userID string) (*UserResponse, error)
}

type service struct {
	repo Repository
	log  *zap.Logger
}

// NewService constructs a users service.
func NewService(repo Repository, log *zap.Logger) Service {
	return &service{repo: repo, log: log}
}

// AFTER
func (s *service) GetMe(ctx context.Context, userID string) (*UserResponse, error) {
	if userID == "" {
		return nil, apperrors.ErrUnauthorized
	}

	resp, err := s.repo.GetUserByIDWithRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	logger.FromContext(ctx).Debug("fetched user profile", zap.String("user_id", userID))
	return resp, nil
}
