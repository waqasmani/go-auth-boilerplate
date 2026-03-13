-- name: CreateUser :exec
INSERT INTO users (id, email, password_hash, name, created_at, updated_at)
VALUES (?, ?, ?, ?, NOW(), NOW());

-- name: GetUserByEmail :one
SELECT id, email, password_hash, name, created_at, updated_at
FROM users
WHERE email = ?
LIMIT 1;

-- name: GetUserByID :one
SELECT id, email, password_hash, name, created_at, updated_at
FROM users
WHERE id = ?
LIMIT 1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, token_hash, token_family, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, NOW());

-- name: GetRefreshTokenByHash :one
SELECT id, user_id, token_hash, token_family, expires_at, used_at, revoked_at, created_at
FROM refresh_tokens
WHERE token_hash = ?
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