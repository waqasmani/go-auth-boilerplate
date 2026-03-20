-- oauth_linking_states persists the server-side payload for the OAuth
-- email-collision linking flow. When a provider email collides with an
-- existing local account, the service stores the encrypted provider tokens
-- and identity claims here, keyed by a random nonce, and returns only the
-- nonce (signed with HMAC) to the client. The client never sees ciphertext.
--
-- Security design:
--   - nonce is a 32-byte cryptographically random value (hex-encoded = 64 chars).
--     Only the HMAC-signed nonce is transmitted to the browser; the payload
--     is never sent over the wire.
--   - payload holds the JSON-encoded linkingState (provider identity + encrypted
--     provider tokens). It is opaque to the client.
--   - expires_at mirrors the 15-minute linking token window. Rows older than
--     this are invalid and can be purged.
--   - ConsumeLinkingState reads and deletes atomically inside a transaction
--     so each nonce is single-use even under concurrent requests.
--
-- Maintenance:
--   Expired rows that were never consumed (e.g. user abandoned the flow) are
--   cleaned up lazily on each ConsumeLinkingState call (up to 50 rows per call).
--   For high-traffic deployments, consider a dedicated scheduled job that runs:
--     DELETE FROM oauth_linking_states WHERE expires_at < NOW() LIMIT 500;

CREATE TABLE IF NOT EXISTS oauth_linking_states (
    -- nonce is the CHAR(64) hex-encoded 32-byte random value generated at
    -- issuance. It is the lookup key and is single-use.
    nonce       CHAR(64)    NOT NULL,

    -- payload is the JSON-encoded linkingState blob (provider identity +
    -- AES-GCM encrypted provider tokens). Never transmitted to the client.
    payload     BLOB        NOT NULL,

    -- expires_at mirrors the 15-minute linking token TTL. Rows whose
    -- expires_at is in the past are logically expired and rejected on lookup.
    expires_at  TIMESTAMP   NOT NULL,

    created_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (nonce),

    -- Allows fast bulk expiry cleanup.
    KEY idx_linking_states_expires (expires_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;