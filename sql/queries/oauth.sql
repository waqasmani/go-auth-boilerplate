-- OAuth queries for user_oauth_accounts and oauth_linking_states.
--
-- After any change to this file, regenerate the Go data-access layer with:
--
--   sqlc generate
--
-- from the repository root (requires sqlc ≥ 1.25 and a running MySQL instance
-- or the mysql8 engine in sqlc Cloud).

-- name: CreateOAuthAccount :exec
INSERT INTO user_oauth_accounts (
    id,
    user_id,
    provider,
    provider_id,
    provider_email,
    provider_name,
    access_token_encrypted,
    refresh_token_encrypted,
    token_expires_at,
    enc_key_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetOAuthAccountByProviderID :one
SELECT
    id,
    user_id,
    provider,
    provider_id,
    provider_email,
    provider_name,
    access_token_encrypted,
    refresh_token_encrypted,
    token_expires_at,
    enc_key_id,
    created_at,
    updated_at
FROM user_oauth_accounts
WHERE provider    = ?
  AND provider_id = ?
LIMIT 1;

-- name: GetOAuthAccountByUserIDAndProvider :one
SELECT
    id,
    user_id,
    provider,
    provider_id,
    provider_email,
    provider_name,
    access_token_encrypted,
    refresh_token_encrypted,
    token_expires_at,
    enc_key_id,
    created_at,
    updated_at
FROM user_oauth_accounts
WHERE user_id  = ?
  AND provider = ?
LIMIT 1;

-- name: ListOAuthAccountsByUserID :many
SELECT
    id,
    provider,
    provider_id,
    provider_email,
    provider_name,
    token_expires_at,
    enc_key_id,
    created_at,
    updated_at
FROM user_oauth_accounts
WHERE user_id = ?
ORDER BY provider;

-- name: UpdateOAuthTokens :exec
UPDATE user_oauth_accounts
SET
    access_token_encrypted  = ?,
    refresh_token_encrypted = ?,
    token_expires_at        = ?,
    enc_key_id              = ?,
    updated_at              = NOW()
WHERE provider    = ?
  AND provider_id = ?;

-- name: LinkOAuthAccountToUser :exec
-- Called during the explicit linking flow when an authenticated user
-- intentionally connects a provider identity to their existing local account.
INSERT INTO user_oauth_accounts (
    id,
    user_id,
    provider,
    provider_id,
    provider_email,
    provider_name,
    access_token_encrypted,
    refresh_token_encrypted,
    token_expires_at,
    enc_key_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UnlinkOAuthAccount :exec
DELETE FROM user_oauth_accounts
WHERE user_id  = ?
  AND provider = ?;

-- ── oauth_linking_states ───────────────────────────────────────────────────────
-- Server-side storage for the email-collision linking flow.
-- The nonce (HMAC-signed) travels to the client; the payload stays on the server.
-- These queries replace the previous approach of embedding encrypted token blobs
-- in the client-visible linking_token. Run `sqlc generate` after adding these.

-- name: StoreLinkingState :exec
-- Persists a linking payload keyed by a 32-byte random nonce (hex-encoded).
-- Called when an OAuth callback detects an email collision with an existing
-- local account. expiresAt mirrors the 15-minute linkingTokenTTL.
INSERT INTO oauth_linking_states (nonce, payload, expires_at)
VALUES (?, ?, ?);

-- name: ConsumeLinkingState :one
-- Atomically reads and deletes a linking state row. The FOR UPDATE lock
-- serialises concurrent requests on the same nonce; only the first caller
-- gets a row — all others get sql.ErrNoRows (→ ErrInvalidLinkingToken).
-- This query must be executed inside a transaction by the caller.
SELECT payload, expires_at
FROM oauth_linking_states
WHERE nonce = ?
FOR UPDATE;

-- name: DeleteLinkingState :exec
-- Deletes the consumed nonce. Must be called in the same transaction as
-- ConsumeLinkingState immediately after a successful SELECT … FOR UPDATE.
DELETE FROM oauth_linking_states
WHERE nonce = ?;

-- name: PurgeExpiredLinkingStates :exec
-- Lazy cleanup of abandoned linking states (user closed the tab, etc.).
-- Called opportunistically inside ConsumeLinkingState; also suitable for a
-- scheduled maintenance job in high-traffic deployments.
DELETE FROM oauth_linking_states
WHERE expires_at < NOW()
LIMIT 50;

-- oauth_one_time_codes queries — mobile OAuth exchange flow.
--
-- Table added in migration 0008. Run `sqlc generate` after editing this file.
--
-- Naming conventions mirror oauth.sql patterns:
--   :exec        — INSERT / DELETE with no return value
--   :execresult  — UPDATE where RowsAffected is checked (single-use guard)
--   :one         — SELECT returning a single row (used inside a transaction)
--
-- Query naming rationale:
--   StoreOneTimeCode        — symmetric with StoreLinkingState in oauth.sql
--   GetOneTimeCodeForUpdate — explicit "ForUpdate" suffix signals the caller
--                             MUST wrap this in a transaction; see ConsumeOneTimeCode
--   MarkOneTimeCodeUsed     — mirrors ConsumeEmailToken / ConsumeRefreshToken patterns
--   PurgeExpiredOneTimeCodes— mirrors PurgeExpiredLinkingStates in oauth.sql

-- name: StoreOneTimeCode :exec
-- Persists the SHA-256 hex hash of the 64-char random plaintext code.
-- The plaintext is never written to any store — only SHA-256(plaintext) is here.
-- Called immediately after code generation in service.IssueOneTimeCode.
INSERT INTO oauth_one_time_codes (id, user_id, code_hash, expires_at)
VALUES (?, ?, ?, ?);

-- name: GetOneTimeCodeForUpdate :one
-- Retrieves and row-locks the code record for the duration of the surrounding
-- transaction. Must be called from within an explicit BEGIN transaction.
-- Returns sql.ErrNoRows when no matching code exists, which the repository
-- maps to ErrInvalidOneTimeCode (unknown / expired / already used are all
-- collapsed into one error to prevent oracle attacks).
SELECT
    id,
    user_id,
    code_hash,
    expires_at,
    used_at,
    created_at
FROM oauth_one_time_codes
WHERE code_hash = ?
FOR UPDATE;

-- name: MarkOneTimeCodeUsed :execresult
-- Atomically stamps used_at on the locked row.
-- The WHERE used_at IS NULL guard is belt-and-suspenders after the FOR UPDATE
-- lock: exactly one concurrent caller gets RowsAffected = 1; any racing caller
-- (possible on DBs without strict row-level locking) gets 0 and is rejected.
-- Must be called inside the same transaction as GetOneTimeCodeForUpdate.
UPDATE oauth_one_time_codes
SET    used_at   = NOW()
WHERE  code_hash = ?
AND    used_at   IS NULL;

-- name: PurgeExpiredOneTimeCodes :exec
-- Lazy cleanup of rows whose TTL has passed and have already been consumed.
-- Called opportunistically inside ConsumeOneTimeCode (best-effort; errors ignored).
-- For high-traffic deployments supplement with a scheduled job:
--   DELETE FROM oauth_one_time_codes
--   WHERE expires_at < NOW() AND used_at IS NOT NULL LIMIT 500;
DELETE FROM oauth_one_time_codes
WHERE expires_at < NOW()
AND   used_at    IS NOT NULL
LIMIT 50;