-- email_tokens stores short-lived tokens for email verification,
-- password reset, and 2FA OTP. One table, one SELECT, zero confusion.
--
-- token_type:
--   'verify'  — email address verification link (24h)
--   'reset'   — password reset link (1h)
--   'otp'     — 2FA numeric code (10m)
--
-- The raw token is NEVER stored. Only the SHA-256 hex hash is persisted
-- (same pattern as refresh_tokens) so a DB leak cannot be replayed.

CREATE TABLE IF NOT EXISTS email_tokens (
    id          CHAR(36)     NOT NULL,
    user_id     CHAR(36)     NOT NULL,
    token_hash  CHAR(64)     NOT NULL,
    token_type  ENUM('verify','reset','otp','challenge') NOT NULL,
    used_at     TIMESTAMP    NULL DEFAULT NULL,
    expires_at  TIMESTAMP    NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE  KEY uq_email_tokens_hash (token_hash),
    KEY         idx_email_tokens_user_type (user_id, token_type),
    KEY         idx_email_tokens_expires (expires_at),
    CONSTRAINT  fk_email_tokens_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;