-- name: CreateUser :exec
INSERT INTO users (id, email, password_hash, name, created_at, updated_at)
VALUES (?, ?, ?, ?, NOW(), NOW());

-- name: GetUserByEmail :one
SELECT id, email, password_hash, name, created_at, updated_at
FROM users
WHERE email = ?
LIMIT 1;

-- name: GetUserByEmailWithRoles :many
SELECT
    u.id,
    u.email,
    u.password_hash,
    u.name,
    u.created_at,
    u.updated_at,
    r.id          AS role_id,
    r.name        AS role_name,
    r.description AS role_description
FROM users u
LEFT JOIN user_roles ur ON ur.user_id = u.id
LEFT JOIN roles r       ON r.id       = ur.role_id
WHERE u.email = ?;

-- name: GetUserByID :one
SELECT id, email, password_hash, name, created_at, updated_at
FROM users
WHERE id = ?
LIMIT 1;

-- name: GetUserByIDWithRoles :many
SELECT
    u.id,
    u.email,
    u.password_hash,
    u.name,
    u.created_at,
    u.updated_at,
    r.id          AS role_id,
    r.name        AS role_name,
    r.description AS role_description
FROM users u
LEFT JOIN user_roles ur ON ur.user_id = u.id
LEFT JOIN roles r       ON r.id       = ur.role_id
WHERE u.id = ?;

-- name: AssignUserRoleByName :execresult
-- Assigns a role to a user by role name rather than by hard-coded role_id.
-- The LIMIT 1 is defensive — role names are UNIQUE but this makes the intent
-- explicit and prevents a runaway insert if that constraint were ever dropped.
INSERT INTO user_roles (user_id, role_id)
SELECT ?, r.id
FROM roles r
WHERE r.name = ?
LIMIT 1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, token_hash, token_family, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, NOW());

-- name: GetRefreshTokenByHash :one
SELECT id, user_id, token_hash, token_family, expires_at, used_at, revoked_at, created_at
FROM refresh_tokens
WHERE token_hash = ?
AND revoked_at IS NULL
LIMIT 1;

-- name: ConsumeRefreshToken :execresult
-- Atomically marks a refresh token as used in a single UPDATE.
-- The WHERE used_at IS NULL guard means exactly one concurrent caller
-- will get RowsAffected = 1; every other caller racing on the same token
-- gets RowsAffected = 0, which the service layer treats as token reuse.
UPDATE refresh_tokens
SET used_at = NOW()
WHERE id = ?
  AND used_at   IS NULL
  AND revoked_at IS NULL;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE token_family = ?;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE id = ?;