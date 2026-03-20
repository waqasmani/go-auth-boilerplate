// Package authemail implements email-based authentication flows: password
// reset, email verification, 2FA OTP delivery/verification, and TOTP setup.
package authemail

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/go-sql-driver/mysql"
	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

// Repository defines the data-access contract for email-auth flows.
type Repository interface {
	WithTx(ctx context.Context, fn func(tx Repository) error) error

	GetUserByEmail(ctx context.Context, email string) (*db.User, error)
	GetUserByID(ctx context.Context, id string) (*db.User, error)
	CreateEmailToken(ctx context.Context, params db.CreateEmailTokenParams) error
	GetEmailTokenByHash(ctx context.Context, hash string) (*db.EmailToken, error)
	ConsumeEmailToken(ctx context.Context, id string) (bool, error)
	InvalidateUserTokensByType(ctx context.Context, params db.InvalidateUserTokensByTypeParams) error
	UpdateUserPasswordHash(ctx context.Context, params db.UpdateUserPasswordHashParams) error
	MarkEmailVerified(ctx context.Context, id string) error
	ClearEmailVerified(ctx context.Context, id string) error
	RevokeUserRefreshTokens(ctx context.Context, userID string) error
	CreateRefreshToken(ctx context.Context, params db.CreateRefreshTokenParams) error

	// ── TOTP ──────────────────────────────────────────────────────────────────

	// GetUserMFAMethod returns the user's current mfa_method ('email'|'totp'|'none').
	// Returns ("email", nil) when the user does not exist — degrades gracefully
	// on schemas that predate the TOTP migration.
	GetUserMFAMethod(ctx context.Context, userID string) (string, error)

	// GetUserTOTPSecretEncrypted returns the AES-GCM ciphertext blob.
	// Returns ErrTOTPNotSetup when the column is NULL (user has not called
	// SetupTOTP yet, or DisableTOTP cleared the secret).
	GetUserTOTPSecretEncrypted(ctx context.Context, userID string) ([]byte, error)

	// SetUserTOTPSecret persists the encrypted secret (pending; not yet active).
	// Called by SetupTOTP before the user confirms with a valid code.
	SetUserTOTPSecret(ctx context.Context, userID string, encryptedSecret []byte) error

	// EnableUserTOTP sets mfa_method='totp', two_fa_enabled=1, and records
	// totp_enabled_at. Called only after the user proves possession.
	EnableUserTOTP(ctx context.Context, userID string) error

	// DisableUserTOTP reverts mfa_method to 'email' and clears the secret.
	DisableUserTOTP(ctx context.Context, userID string) error
}

// ErrTOTPNotSetup is returned when a TOTP operation requires a stored secret
// but none is present. The user must call POST /auth/mfa/totp/setup first.
var ErrTOTPNotSetup = apperrors.New(
	"TOTP_NOT_SETUP",
	"TOTP is not configured on this account — call POST /auth/mfa/totp/setup first",
	http.StatusBadRequest,
	nil,
)

// repository is the concrete implementation backed by sqlc Queries.
type repository struct {
	sqlDB   *sql.DB
	queries *db.Queries
}

// NewRepository constructs an email-auth repository.
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
		_ = tx.Rollback()
		return err
	}
	if err = tx.Commit(); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
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
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return &token, nil
}

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

func (r *repository) ClearEmailVerified(ctx context.Context, id string) error {
	if err := r.queries.ClearEmailVerified(ctx, id); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) CreateRefreshToken(ctx context.Context, params db.CreateRefreshTokenParams) error {
	if err := r.queries.CreateRefreshToken(ctx, params); err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1452 {
			return apperrors.Wrap(apperrors.ErrNotFound, err)
		}
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

// ── TOTP repository methods ───────────────────────────────────────────────────
//
// All methods delegate to r.queries (sqlc-generated) via totp.sql.go.
// No raw r.sqlDB calls — the query layer and transaction scope are consistent
// with every other method in this file.

func (r *repository) GetUserMFAMethod(ctx context.Context, userID string) (string, error) {
	method, err := r.queries.GetUserMFAMethod(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// User does not exist or column is missing (pre-migration schema).
			// Degrade gracefully to "email" so InitiateChallenge always has a
			// safe fallback without a hard dependency on the migration version.
			return "email", nil
		}
		return "email", apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return string(method), nil
}

func (r *repository) GetUserTOTPSecretEncrypted(ctx context.Context, userID string) ([]byte, error) {
	encrypted, err := r.queries.GetUserTOTPSecretEncrypted(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	// Column is NULL → TOTP not setup
	if !encrypted.Valid {
		return nil, ErrTOTPNotSetup
	}

	return []byte(encrypted.String), nil
}

func (r *repository) SetUserTOTPSecret(ctx context.Context, userID string, encryptedSecret []byte) error {
	err := r.queries.SetUserTOTPSecret(ctx, db.SetUserTOTPSecretParams{
		TotpSecretEncrypted: sql.NullString{
			String: string(encryptedSecret),
			Valid:  true,
		},
		ID: userID,
	})
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}

	return nil
}

func (r *repository) EnableUserTOTP(ctx context.Context, userID string) error {
	if err := r.queries.EnableUserTOTP(ctx, userID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) DisableUserTOTP(ctx context.Context, userID string) error {
	if err := r.queries.DisableUserTOTP(ctx, userID); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}
