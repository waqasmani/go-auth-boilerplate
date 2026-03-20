-- oauth_one_time_codes stores short-lived tokens for the mobile OAuth exchange flow.
--
-- Security design:
--   - code_hash is the SHA-256 hex digest of the 64-char random plaintext code
--     (32 random bytes = 256-bit entropy). Only the hash is stored; a database
--     dump cannot be replayed because SHA-256 is a one-way function.
--   - TTL is 90 seconds, enforced application-side in ConsumeOneTimeCode. Short
--     window limits exposure in case of interception (deep-link sniffing, logs).
--   - Codes are single-use: used_at is set atomically inside a FOR UPDATE
--     transaction; concurrent callers on the same code serialise and only the
--     first caller wins. The used_at IS NULL guard in the UPDATE is belt-and-
--     suspenders for DB engines that do not support row-level locking.
--   - Rows are purged lazily (up to 50 per ConsumeOneTimeCode call). Supplement
--     with a scheduled job for high-traffic deployments:
--       DELETE FROM oauth_one_time_codes
--       WHERE expires_at < NOW() AND used_at IS NOT NULL
--       LIMIT 500;
--
-- Rate-limiting at the /oauth/exchange endpoint (default 0.1 req/s, burst 2)
-- further reduces the already-negligible brute-force surface.

CREATE TABLE IF NOT EXISTS oauth_one_time_codes (
    id         CHAR(36)   NOT NULL,
    user_id    CHAR(36)   NOT NULL,

    -- SHA-256 hex digest of the 64-char plaintext code (hex(rand(32))).
    -- CHAR(64) is fixed-width for efficient index storage.
    code_hash  CHAR(64)   NOT NULL,

    expires_at TIMESTAMP  NOT NULL,

    -- used_at is NULL while the code is unconsumed. Set atomically to NOW()
    -- by ConsumeOneTimeCode; serves as the single-use guard.
    used_at    TIMESTAMP  NULL DEFAULT NULL,

    created_at TIMESTAMP  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    -- Primary lookup path: code_hash → row. UNIQUE enforces one row per code.
    UNIQUE KEY uq_oauth_one_time_codes_hash (code_hash),

    -- Allows administrative revocation by user_id (e.g. on logout or password change).
    KEY idx_oauth_one_time_codes_user (user_id),

    -- Speeds up the lazy expiry-cleanup DELETE in ConsumeOneTimeCode.
    KEY idx_oauth_one_time_codes_expires (expires_at),

    -- Cascade-delete codes when the owning user is deleted.
    CONSTRAINT fk_oauth_one_time_codes_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;