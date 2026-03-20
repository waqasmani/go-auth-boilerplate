-- name: CreateEmailToken :exec
-- Inserts a new email token record. The raw token is never stored;
-- only the SHA-256 hex hash (CHAR(64)) is persisted, matching the
-- same pattern as refresh_tokens.
INSERT INTO
    email_tokens (id, user_id, token_hash, token_type, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, NOW());

-- name: GetEmailTokenByHash :one
-- Retrieves the full token record by its SHA-256 hex hash so the
-- service layer can inspect used_at / expires_at before consuming it.
-- No WHERE used_at IS NULL filter — the service layer decides which
-- state transitions are valid for each token_type.
SELECT
    id,
    user_id,
    token_hash,
    token_type,
    used_at,
    expires_at,
    created_at
FROM email_tokens
WHERE
    token_hash = ?
LIMIT 1;

-- name: ConsumeEmailToken :execresult
-- Atomically marks a token as used. The WHERE guard ensures exactly
-- one concurrent caller gets RowsAffected = 1; any racing caller gets
-- 0, which the service treats as a replay attempt.
UPDATE email_tokens
SET
    used_at = NOW()
WHERE
    id = ?
    AND used_at IS NULL;

-- name: InvalidateUserTokensByType :exec
-- Soft-deletes (marks used) all live tokens of a given type for a
-- user before issuing a new one. Prevents a user from holding multiple
-- valid reset/verify tokens simultaneously.
UPDATE email_tokens
SET
    used_at = NOW()
WHERE
    user_id = ?
    AND token_type = ?
    AND used_at IS NULL;

-- name: UpdateUserPasswordHash :exec
-- Replaces the bcrypt hash after a successful password reset.
-- updated_at is refreshed so cache-busting strategies based on that
-- column work correctly.
UPDATE users
SET
    password_hash = ?,
    updated_at    = NOW()
WHERE
    id = ?;

-- name: MarkEmailVerified :exec
-- Stamps email_verified_at once the user clicks the verification link.
-- Idempotent: calling it on an already-verified user is a safe no-op
-- (the column will simply be updated to NOW() again).
UPDATE users
SET
    email_verified_at = NOW(),
    updated_at        = NOW()
WHERE
    id = ?;

-- name: ClearEmailVerified :exec
-- Clears email_verified_at after a password reset so the account must
-- re-confirm inbox ownership before logging in again. This closes the
-- window where an attacker who hijacked the victim's inbox resets the
-- password and immediately inherits a verified, session-capable account.
-- Idempotent: safe to call when the column is already NULL.
UPDATE users
SET
    email_verified_at = NULL,
    updated_at        = NOW()
WHERE
    id = ?;

-- name: RevokeUserRefreshTokens :exec
-- Called after a successful password reset to invalidate every active
-- session for the user. Any attacker holding a stolen refresh token
-- will get ErrTokenRevoked on their next /refresh call.
UPDATE refresh_tokens
SET    revoked_at = NOW()
WHERE  user_id    = ?
  AND  revoked_at IS NULL;