-- user_oauth_accounts stores OAuth 2.0 provider identities linked to local
-- users. One row per (provider, provider_id) pair.
--
-- Security design notes:
--   - access_token_encrypted / refresh_token_encrypted: tokens are never
--     stored in plaintext. AES-256-GCM ciphertext with an embedded key-id
--     prefix (same wire format as totp_secret_encrypted in users) allows key
--     rotation without re-migration. The key_id column is redundant with the
--     embedded prefix but is kept for operational visibility (e.g. "which
--     rows need re-encryption after key rotation") without requiring full
--     decryption of every row.
--   - provider_id is the opaque identifier assigned by the provider (Google
--     sub, Facebook id). It is the authoritative identity key, not email —
--     a user can change their provider email without breaking the link.
--   - email is stored here for display purposes only. It MUST NOT be used
--     to auto-link OAuth accounts to local accounts; explicit user-initiated
--     linking is required (see oauth.account_link_attempt_conflict audit event).

CREATE TABLE IF NOT EXISTS user_oauth_accounts (
    id                      CHAR(36)        NOT NULL,
    user_id                 CHAR(36)        NOT NULL,

    -- Provider identity
    provider                VARCHAR(50)     NOT NULL,   -- 'google' | 'facebook'
    provider_id             VARCHAR(255)    NOT NULL,   -- provider-assigned user id
    provider_email          VARCHAR(255)    NOT NULL,   -- email at provider (display only)
    provider_name           VARCHAR(255)    NOT NULL DEFAULT '',

    -- Encrypted OAuth tokens (AES-256-GCM blobs)
    -- NULL means the provider did not return a value or the token expired and
    -- was intentionally cleared.
    access_token_encrypted  VARBINARY(1024) NULL,
    refresh_token_encrypted VARBINARY(512)  NULL,
    token_expires_at        TIMESTAMP       NULL,

    -- key_id of the SymmetricKeySet entry that was active when these tokens
    -- were last written. Allows operators to identify rows that need
    -- re-encryption after key rotation without decrypting every row.
    -- Mirrors the embedded key-id in the ciphertext blob; kept for query-ability.
    enc_key_id              VARCHAR(255)    NOT NULL DEFAULT '',

    created_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    -- Guarantees one local user per provider account.
    UNIQUE KEY uq_oauth_provider_identity (provider, provider_id),

    -- Allows fast lookup of all providers linked to a user.
    KEY idx_oauth_user_id (user_id),

    -- Allows checking whether a user already has a given provider linked.
    KEY idx_oauth_user_provider (user_id, provider),

    CONSTRAINT fk_oauth_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;