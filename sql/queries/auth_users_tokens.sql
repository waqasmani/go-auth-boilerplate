-- name: CreateUser :exec
INSERT INTO
    users (
        id,
        email,
        password_hash,
        name,
        created_at,
        updated_at
    )
VALUES (?, ?, ?, ?, NOW(), NOW());

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ? LIMIT 1;

-- name: GetUserByEmailWithRoles :many
SELECT
    u.id,
    u.email,
    u.password_hash,
    u.name,
    u.email_verified_at,
    u.two_fa_enabled,
    u.created_at,
    u.updated_at,
    r.id AS role_id,
    r.name AS role_name,
    r.description AS role_description
FROM
    users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
WHERE
    u.email = ?;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ? LIMIT 1;

-- name: GetUserByIDWithRoles :many
SELECT
    u.id,
    u.email,
    u.password_hash,
    u.name,
    u.email_verified_at,
    u.two_fa_enabled,
    u.created_at,
    u.updated_at,
    r.id AS role_id,
    r.name AS role_name,
    r.description AS role_description
FROM
    users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
WHERE
    u.id = ?;

-- name: AssignUserRoleByName :execresult
-- Assigns a role to a user by role name rather than by hard-coded role_id.
-- The LIMIT 1 is defensive — role names are UNIQUE but this makes the intent
-- explicit and prevents a runaway insert if that constraint were ever dropped.
INSERT INTO
    user_roles (user_id, role_id)
SELECT ?, r.id
FROM roles r
WHERE
    r.name = ?
LIMIT 1;

-- name: CreateRefreshToken :exec
INSERT INTO
    refresh_tokens (
        id,
        user_id,
        token_hash,
        token_family,
        expires_at,
        created_at
    )
VALUES (?, ?, ?, ?, ?, NOW());

-- name: GetRefreshTokenByHash :one
SELECT
    id,
    user_id,
    token_hash,
    token_family,
    expires_at,
    used_at,
    revoked_at,
    created_at
FROM refresh_tokens
WHERE
    token_hash = ?
LIMIT 1;

-- name: GetRefreshTokenByHashForUpdate :one
-- Retrieves the token row and acquires an InnoDB row-level write lock (FOR
-- UPDATE) for the duration of the calling transaction. The lock prevents any
-- concurrent transaction from modifying used_at or revoked_at between this
-- SELECT and the subsequent ConsumeRefreshToken UPDATE, closing the TOCTOU
-- window that existed when state checks happened on the pre-transaction
-- non-locking read.
--
-- MUST be called inside an explicit transaction (i.e. on a *Queries value
-- returned by Queries.WithTx). Calling outside a transaction acquires a lock
-- that is released immediately, providing no serialisation guarantee.
SELECT
    id,
    user_id,
    token_hash,
    token_family,
    expires_at,
    used_at,
    revoked_at,
    created_at
FROM refresh_tokens
WHERE
    token_hash = ?
LIMIT 1
FOR UPDATE;

-- name: ConsumeRefreshToken :execresult
-- Atomically marks a refresh token as used in a single UPDATE.
-- The WHERE used_at IS NULL guard means exactly one concurrent caller
-- will get RowsAffected = 1; every other caller racing on the same token
-- gets RowsAffected = 0, which the service layer treats as token reuse.
UPDATE refresh_tokens
SET
    used_at = NOW()
WHERE
    id = ?
    AND used_at IS NULL
    AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens
SET
    revoked_at = NOW()
WHERE
    token_family = ?;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = ?;

-- name: GetUserIDByEmail :one
-- Looks up a user ID by email address. Returns sql.ErrNoRows when not found.
SELECT id FROM users WHERE email = ? LIMIT 1;

-- name: CreateOAuthUser :exec
-- Creates a new OAuth-only user whose email address has been confirmed by the
-- provider (e.g. Google with email_verified=true). email_verified_at is
-- stamped NOW() so the Login gate allows this user without a verification step.
-- password_hash is empty because OAuth users never authenticate with a password.
INSERT INTO users (
    id,
    email,
    password_hash,
    name,
    email_verified_at,
    created_at,
    updated_at
) VALUES (?, ?, '', ?, NOW(), NOW(), NOW());

-- name: CreateOAuthUserUnverified :exec
-- Creates a new OAuth-only user for providers that do NOT guarantee email
-- ownership (e.g. Facebook public-app tier, where VerifiesEmail()=false).
--
-- Security design:
--   - email stores a UUID-based placeholder ("<userID>@oauth.invalid") rather
--     than the provider's unverified address. The .invalid TLD is reserved by
--     RFC 2606 and can never resolve or collide with a real address. This
--     satisfies the NOT NULL + UNIQUE constraint on users.email without
--     implying the address was confirmed.
--   - email_verified_at is omitted (defaults to NULL) so the Login gate
--     (service.Login checks user.EmailVerified) routes this user through the
--     email-verification flow before granting a session. Without this, an
--     attacker who creates a Facebook account with an email they do not own
--     would receive a pre-verified local account.
--   - The actual provider email, if any, is stored in
--     user_oauth_accounts.provider_email for display purposes only. It must
--     never be used for identity matching or treated as verified.
INSERT INTO users (
    id,
    email,
    password_hash,
    name,
    created_at,
    updated_at
) VALUES (?, ?, '', ?, NOW(), NOW());

-- name: GetUserDisplayInfo :one
-- Fetches the display name and email for a user by ID.
-- Used for audit logging during OAuth account linking.
SELECT name, email FROM users WHERE id = ? LIMIT 1;

-- name: CountRoleByName :one
-- Used by the startup health-check in app.go to verify that required roles
-- have been seeded before the server begins accepting traffic.
-- Returns 0 when the role is absent, 1 when it exists.
SELECT COUNT(*) FROM roles WHERE name = ? LIMIT 1;