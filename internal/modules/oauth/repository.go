package oauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-sql-driver/mysql"

	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

//go:generate mockgen -source=repository.go -destination=mocks/repository_mock.go -package=mocks

// Repository defines the data-access contract for the OAuth module.
type Repository interface {
	// CreateOAuthAccount inserts a new OAuth identity row.
	CreateOAuthAccount(ctx context.Context, params CreateOAuthAccountParams) error
	// GetOAuthAccountByProviderID is the primary callback lookup.
	GetOAuthAccountByProviderID(ctx context.Context, provider, providerID string) (*OAuthAccount, error)
	// GetOAuthAccountByUserIDAndProvider checks whether a user already has a
	// specific provider linked.
	GetOAuthAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*OAuthAccount, error)
	// UpdateOAuthTokens refreshes the encrypted token blob after re-auth.
	UpdateOAuthTokens(ctx context.Context, params UpdateOAuthTokensParams) error
	// LinkOAuthAccountToUser is the transactional write for explicit account linking.
	LinkOAuthAccountToUser(ctx context.Context, params CreateOAuthAccountParams) error
	// WithTx opens a transaction and runs fn. Rolls back on fn error.
	WithTx(ctx context.Context, fn func(tx Repository) error) error

	// CreateOAuthOnlyUser inserts a new local user record for an OAuth sign-in.
	//
	// emailVerified controls which SQL query is used:
	//
	//   true  — the provider has confirmed the email address (e.g. Google with
	//           email_verified=true). The real email is stored and
	//           email_verified_at is stamped NOW() so the Login gate allows
	//           this user without an additional verification step.
	//
	//   false — the provider does NOT guarantee email ownership (e.g. Facebook
	//           public-app tier). A UUID-based placeholder
	//           ("<userID>@oauth.invalid") is stored instead of the unverified
	//           address, and email_verified_at is left NULL. The caller passes
	//           the real provider email only as a display value stored in
	//           user_oauth_accounts.provider_email.
	//
	// The placeholder format "<userID>@oauth.invalid" satisfies the NOT NULL +
	// UNIQUE constraint on users.email (the UUID is globally unique) and uses
	// the RFC 2606 reserved .invalid TLD to make the synthetic nature explicit.
	CreateOAuthOnlyUser(ctx context.Context, id, email, name string, emailVerified bool) error

	GetUserNameAndEmail(ctx context.Context, userID string) (name, email string, err error)
	GetUserByEmail(ctx context.Context, email string) (userID string, exists bool, err error)

	// ── Server-side linking state ──────────────────────────────────────────────

	// StoreLinkingState persists the encrypted provider identity payload keyed
	// by a random nonce. Only the HMAC-signed nonce travels to the browser.
	StoreLinkingState(ctx context.Context, nonce string, payload []byte, expiresAt time.Time) error

	// ConsumeLinkingState atomically reads and deletes the payload for nonce.
	// Returns ErrInvalidLinkingToken when the nonce is unknown, consumed, or expired.
	ConsumeLinkingState(ctx context.Context, nonce string) ([]byte, error)

	// ── Mobile one-time codes ──────────────────────────────────────────────────

	// StoreOneTimeCode persists the SHA-256 hash of a mobile one-time code.
	StoreOneTimeCode(ctx context.Context, params dbpkg.StoreOneTimeCodeParams) error

	// ConsumeOneTimeCode atomically validates and marks the code as used.
	// Returns ErrInvalidOneTimeCode when the code is unknown, expired, or already used.
	ConsumeOneTimeCode(ctx context.Context, codeHash string) (userID string, err error)
}

// repository is the concrete implementation.
type repository struct {
	db      *sql.DB
	queries *dbpkg.Queries
}

// NewRepository constructs an OAuth repository.
func NewRepository(db *sql.DB, queries *dbpkg.Queries) Repository {
	return &repository{db: db, queries: queries}
}

// WithTx opens a transaction, binds a transaction-scoped *Queries via
// queries.WithTx, runs fn, then commits or rolls back.
//
// Returning a value from the closure: because fn's signature is
// func(tx Repository) error, callers that need to surface a result should
// capture it through a local variable declared in the outer scope:
//
//	var result SomeType
//	err := r.WithTx(ctx, func(tx Repository) error {
//	    txRepo := tx.(*repository)          // safe: WithTx always passes *repository
//	    val, err := txRepo.queries.SomeQuery(ctx, ...)
//	    if err != nil { return err }
//	    result = val
//	    return nil
//	})
//	if err != nil { return nil, err }
//	return result, nil
//
// The type assertion tx.(*repository) is the only way to reach txRepo.queries
// from inside the closure without widening the Repository interface. It is safe
// because WithTx always constructs and passes a *repository — never any other
// implementation.
func (r *repository) WithTx(ctx context.Context, fn func(tx Repository) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	txRepo := &repository{
		db:      r.db,
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

// ── OAuth account operations ──────────────────────────────────────────────────

func (r *repository) CreateOAuthAccount(ctx context.Context, p CreateOAuthAccountParams) error {
	err := r.queries.CreateOAuthAccount(ctx, toDBCreateParams(p))
	return mapOAuthInsertErr(err)
}

func (r *repository) GetOAuthAccountByProviderID(ctx context.Context, provider, providerID string) (*OAuthAccount, error) {
	row, err := r.queries.GetOAuthAccountByProviderID(ctx, dbpkg.GetOAuthAccountByProviderIDParams{
		Provider:   provider,
		ProviderID: providerID,
	})
	if err != nil {
		return nil, mapOAuthSelectErr(err)
	}
	return fromDBRow(&row), nil
}

func (r *repository) GetOAuthAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*OAuthAccount, error) {
	row, err := r.queries.GetOAuthAccountByUserIDAndProvider(ctx, dbpkg.GetOAuthAccountByUserIDAndProviderParams{
		UserID:   userID,
		Provider: provider,
	})
	if err != nil {
		return nil, mapOAuthSelectErr(err)
	}
	return fromDBRow(&row), nil
}

func (r *repository) UpdateOAuthTokens(ctx context.Context, p UpdateOAuthTokensParams) error {
	err := r.queries.UpdateOAuthTokens(ctx, dbpkg.UpdateOAuthTokensParams{
		AccessTokenEncrypted:  bytesToNullString(p.AccessTokenEncrypted),
		RefreshTokenEncrypted: bytesToNullString(p.RefreshTokenEncrypted),
		TokenExpiresAt:        timeToNullTime(p.TokenExpiresAt),
		EncKeyID:              p.EncKeyID,
		Provider:              p.Provider,
		ProviderID:            p.ProviderID,
	})
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) LinkOAuthAccountToUser(ctx context.Context, p CreateOAuthAccountParams) error {
	err := r.queries.LinkOAuthAccountToUser(ctx, dbpkg.LinkOAuthAccountToUserParams{
		ID:                    p.ID,
		UserID:                p.UserID,
		Provider:              p.Provider,
		ProviderID:            p.ProviderID,
		ProviderEmail:         p.ProviderEmail,
		ProviderName:          p.ProviderName,
		AccessTokenEncrypted:  bytesToNullString(p.AccessTokenEncrypted),
		RefreshTokenEncrypted: bytesToNullString(p.RefreshTokenEncrypted),
		TokenExpiresAt:        timeToNullTime(p.TokenExpiresAt),
		EncKeyID:              p.EncKeyID,
	})
	return mapOAuthInsertErr(err)
}

// ── Server-side linking state ─────────────────────────────────────────────────

func (r *repository) StoreLinkingState(ctx context.Context, nonce string, payload []byte, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO oauth_linking_states (nonce, payload, expires_at) VALUES (?, ?, ?)`,
		nonce, payload, expiresAt.UTC(),
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) ConsumeLinkingState(ctx context.Context, nonce string) ([]byte, error) {
	var payload []byte
	err := r.WithTx(ctx, func(tx Repository) error {
		txRepo := tx.(*repository)

		// SELECT … FOR UPDATE via the sqlc-generated query so the row lock
		// is held for the duration of this transaction. Raw tx.QueryRowContext
		// was used previously; the generated query is identical in SQL but
		// goes through the same prepared-statement path as every other query.
		row, err := txRepo.queries.ConsumeLinkingState(ctx, nonce)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidLinkingToken
			}
			return apperrors.Wrap(apperrors.ErrInternalServer, err)
		}

		if time.Now().UTC().After(row.ExpiresAt.UTC()) {
			return ErrInvalidLinkingToken
		}

		if err := txRepo.queries.DeleteLinkingState(ctx, nonce); err != nil {
			return apperrors.Wrap(apperrors.ErrInternalServer, err)
		}

		// Best-effort lazy expiry sweep; errors intentionally discarded.
		// A failure here must not roll back a valid consume.
		_ = txRepo.queries.PurgeExpiredLinkingStates(ctx)

		payload = row.Payload
		return nil
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// ── Mobile one-time codes ─────────────────────────────────────────────────────

func (r *repository) StoreOneTimeCode(ctx context.Context, params dbpkg.StoreOneTimeCodeParams) error {
	if err := r.queries.StoreOneTimeCode(ctx, params); err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return nil
}

func (r *repository) ConsumeOneTimeCode(ctx context.Context, codeHash string) (string, error) {
	var userID string
	err := r.WithTx(ctx, func(tx Repository) error {
		txRepo := tx.(*repository)

		row, err := txRepo.queries.GetOneTimeCodeForUpdate(ctx, codeHash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidOneTimeCode
			}
			return apperrors.Wrap(apperrors.ErrInternalServer, err)
		}

		if time.Now().UTC().After(row.ExpiresAt.UTC()) {
			return ErrInvalidOneTimeCode
		}

		if row.UsedAt.Valid {
			return ErrInvalidOneTimeCode
		}

		result, err := txRepo.queries.MarkOneTimeCodeUsed(ctx, codeHash)
		if err != nil {
			return apperrors.Wrap(apperrors.ErrInternalServer, err)
		}
		if n, _ := result.RowsAffected(); n == 0 {
			return ErrInvalidOneTimeCode
		}

		// Best-effort lazy expiry sweep; errors intentionally discarded.
		_ = txRepo.queries.PurgeExpiredOneTimeCodes(ctx)

		userID = row.UserID
		return nil
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}

// ── CreateOAuthOnlyUser ───────────────────────────────────────────────────────

// CreateOAuthOnlyUser inserts a local user record and assigns the "user" role.
//
// emailVerified=true  → calls CreateOAuthUser:          stores the real email,
//
//	stamps email_verified_at=NOW().
//
// emailVerified=false → calls CreateOAuthUserUnverified: stores a synthetic
//
//	placeholder ("<id>@oauth.invalid") as the email and
//	leaves email_verified_at=NULL.
//
// The placeholder satisfies the NOT NULL + UNIQUE constraint on users.email
// (the user UUID is globally unique) and the RFC 2606 .invalid TLD makes the
// synthetic nature unambiguous. The real provider email, when present, is
// stored only in user_oauth_accounts.provider_email for display purposes.
//
// Leaving email_verified_at NULL for unverified providers is critical: the
// service.Login gate checks user.EmailVerified before issuing a session. If
// we stamped NOW() unconditionally, a Facebook user whose unverified email
// matches no existing account would silently receive a pre-verified local
// account tied to an address they may not own.
func (r *repository) CreateOAuthOnlyUser(ctx context.Context, id, email, name string, emailVerified bool) error {
	var insertErr error

	if emailVerified {
		// Provider confirmed email ownership — store the real address and mark
		// email as verified so the user can log in immediately after OAuth.
		insertErr = r.queries.CreateOAuthUser(ctx, dbpkg.CreateOAuthUserParams{
			ID:    id,
			Email: email,
			Name:  name,
		})
	} else {
		// Provider does NOT guarantee email ownership (e.g. Facebook public
		// tier). Store a deterministic placeholder so the schema constraints are
		// met without implying confirmation. The Login gate will require email
		// verification before granting a session.
		placeholder := fmt.Sprintf("%s@oauth.invalid", id)
		insertErr = r.queries.CreateOAuthUserUnverified(ctx, dbpkg.CreateOAuthUserUnverifiedParams{
			ID:    id,
			Email: placeholder,
			Name:  name,
		})
	}

	if insertErr != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(insertErr, &mysqlErr) && mysqlErr.Number == 1062 {
			return apperrors.ErrEmailAlreadyExists
		}
		return apperrors.Wrap(apperrors.ErrInternalServer, insertErr)
	}

	result, err := r.queries.AssignUserRoleByName(ctx, dbpkg.AssignUserRoleByNameParams{
		UserID: id,
		Name:   "user",
	})
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	if affected == 0 {
		return apperrors.New("ROLE_NOT_FOUND", `role "user" does not exist`, http.StatusInternalServerError, nil)
	}
	return nil
}

// ── User-table helpers via sqlc ───────────────────────────────────────────────

func (r *repository) GetUserByEmail(ctx context.Context, email string) (userID string, exists bool, err error) {
	id, err := r.queries.GetUserIDByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return id, true, nil
}

func (r *repository) GetUserNameAndEmail(ctx context.Context, userID string) (name, email string, err error) {
	info, err := r.queries.GetUserDisplayInfo(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", apperrors.ErrNotFound
		}
		return "", "", apperrors.Wrap(apperrors.ErrInternalServer, err)
	}
	return info.Name, info.Email, nil
}

// ── Domain ↔ DB mapping ────────────────────────────────────────────────────────

func toDBCreateParams(p CreateOAuthAccountParams) dbpkg.CreateOAuthAccountParams {
	return dbpkg.CreateOAuthAccountParams{
		ID:                    p.ID,
		UserID:                p.UserID,
		Provider:              p.Provider,
		ProviderID:            p.ProviderID,
		ProviderEmail:         p.ProviderEmail,
		ProviderName:          p.ProviderName,
		AccessTokenEncrypted:  bytesToNullString(p.AccessTokenEncrypted),
		RefreshTokenEncrypted: bytesToNullString(p.RefreshTokenEncrypted),
		TokenExpiresAt:        timeToNullTime(p.TokenExpiresAt),
		EncKeyID:              p.EncKeyID,
	}
}

func fromDBRow(r *dbpkg.UserOauthAccount) *OAuthAccount {
	a := &OAuthAccount{
		ID:            r.ID,
		UserID:        r.UserID,
		Provider:      r.Provider,
		ProviderID:    r.ProviderID,
		ProviderEmail: r.ProviderEmail,
		ProviderName:  r.ProviderName,
		EncKeyID:      r.EncKeyID,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
	if r.AccessTokenEncrypted.Valid && len(r.AccessTokenEncrypted.String) > 0 {
		a.AccessTokenEncrypted = []byte(r.AccessTokenEncrypted.String)
	}
	if r.RefreshTokenEncrypted.Valid && len(r.RefreshTokenEncrypted.String) > 0 {
		a.RefreshTokenEncrypted = []byte(r.RefreshTokenEncrypted.String)
	}
	if r.TokenExpiresAt.Valid {
		t := r.TokenExpiresAt.Time
		a.TokenExpiresAt = &t
	}
	return a
}

// ── Nullable type helpers ─────────────────────────────────────────────────────

func bytesToNullString(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

func timeToNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// ── Error mapping ─────────────────────────────────────────────────────────────

func mapOAuthInsertErr(err error) error {
	if err == nil {
		return nil
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return ErrOAuthAccountExists
	}
	return apperrors.Wrap(apperrors.ErrInternalServer, err)
}

func mapOAuthSelectErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return apperrors.ErrNotFound
	}
	return apperrors.Wrap(apperrors.ErrInternalServer, err)
}

// ── Module-specific errors ─────────────────────────────────────────────────────

var (
	ErrOAuthAccountExists = apperrors.New(
		"OAUTH_ACCOUNT_EXISTS",
		"this provider account is already linked to a user",
		409, nil,
	)
	ErrOAuthEmailConflict = apperrors.New(
		"OAUTH_EMAIL_CONFLICT",
		"an account with this email already exists — please log in and link your account in settings",
		409, nil,
	)
	ErrProviderNotEnabled = apperrors.New(
		"OAUTH_PROVIDER_NOT_ENABLED",
		"this OAuth provider is not enabled",
		400, nil,
	)
	ErrInvalidState = apperrors.New(
		"OAUTH_INVALID_STATE",
		"request origin could not be verified — please restart the login process",
		403, nil,
	)
	ErrInvalidLinkingToken = apperrors.New(
		"OAUTH_INVALID_LINKING_TOKEN",
		"linking token is invalid or expired — please restart the login process",
		403, nil,
	)
	ErrUnverifiedEmail = apperrors.New(
		"OAUTH_UNVERIFIED_EMAIL",
		"provider did not confirm a verified email address — cannot create or link account",
		400, nil,
	)
	ErrRedirectNotAllowed = apperrors.New(
		"OAUTH_REDIRECT_NOT_ALLOWED",
		"redirect URL is not in the allowed list for this provider",
		400, nil,
	)
)

// ErrInvalidOneTimeCode is returned for unknown, expired, or already-used codes.
var ErrInvalidOneTimeCode = apperrors.New(
	"OAUTH_INVALID_CODE",
	"code is invalid or expired — please restart the login process",
	403, nil,
)
