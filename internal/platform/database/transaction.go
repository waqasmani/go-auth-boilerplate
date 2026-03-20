// Package database provides helpers for opening and managing the SQL
// connection pool. This file adds a transaction manager for consistent TX handling.
package database

import (
	"context"
	"database/sql"
	"fmt"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

// TxManager handles database transactions with consistent error handling.
type TxManager interface {
	WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error
}

type txManager struct {
	db *sql.DB
}

// NewTxManager creates a new transaction manager.
func NewTxManager(db *sql.DB) TxManager {
	return &txManager{db: db}
}

// WithTx opens a transaction, executes fn, and commits or rolls back.
func (m *txManager) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, fmt.Errorf("db.begin_tx: %w", err))
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return apperrors.Wrap(apperrors.ErrInternalServer, fmt.Errorf("tx.rollback: %w; original err: %v", rbErr, err))
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, fmt.Errorf("tx.commit: %w", err))
	}

	return nil
}
