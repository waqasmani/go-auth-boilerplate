-- Adds an absolute lifetime cap to refresh-token families. The deadline is set
-- when a family is created (login) and copied unchanged across every rotation,
-- so a continuously-rotated session cannot extend its lifetime indefinitely
-- (defence against silently-refreshed stolen sessions). Nullable so rows created
-- before this migration are unaffected until they next rotate or expire.
ALTER TABLE refresh_tokens
    ADD COLUMN family_expires_at TIMESTAMP NULL DEFAULT NULL AFTER expires_at;
