-- email_outbox is a durable, transactional outbox for outbound transactional
-- email (verification, password-reset, login OTP). Producers INSERT a row in the
-- request path; a separate worker process drains the table and performs the SMTP
-- send. This replaces the previous in-memory, at-most-once send queue: rows
-- survive a process crash and are delivered exactly once across any number of
-- worker replicas.
--
-- Multi-instance claim protocol (see internal/outbox):
--   1. A worker stamps a batch of due 'pending' rows with its own locked_by
--      token, flipping them to 'sending' in a single atomic UPDATE. The
--      status='pending' guard plus InnoDB row locks guarantee no two workers
--      claim the same row.
--   2. The worker SELECTs the rows bearing its token and sends each via SMTP.
--   3. On success the row becomes 'sent'; on a transient failure it is
--      rescheduled ('pending' with a back-off available_at); after max attempts
--      it becomes 'failed'.
--   4. Rows stuck in 'sending' (worker crashed mid-send) are reclaimed once
--      their locked_at is older than the stale threshold.

CREATE TABLE IF NOT EXISTS email_outbox (
    id           CHAR(36)     NOT NULL,
    to_addr      VARCHAR(320) NOT NULL,
    subject      VARCHAR(1024) NOT NULL,
    body_html    MEDIUMTEXT   NOT NULL,
    -- No DEFAULT on a TEXT column: nullable columns default to NULL implicitly,
    -- and an explicit `TEXT DEFAULT NULL` is rejected by MySQL (< 8.0.13). This
    -- matches the existing migrations' convention (see 0003 description TEXT).
    body_text    MEDIUMTEXT   NULL,
    status       ENUM('pending','sending','sent','failed') NOT NULL DEFAULT 'pending',
    attempts     INT          NOT NULL DEFAULT 0,
    available_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_by    CHAR(36)     NULL DEFAULT NULL,
    locked_at    TIMESTAMP    NULL DEFAULT NULL,
    last_error   VARCHAR(1024) NULL DEFAULT NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at      TIMESTAMP    NULL DEFAULT NULL,
    PRIMARY KEY (id),
    -- Drives the claim query: find due 'pending' rows quickly.
    KEY idx_email_outbox_due (status, available_at),
    -- Drives the post-claim SELECT by worker token.
    KEY idx_email_outbox_locked_by (locked_by),
    -- Drives stale-row recovery and retention cleanup.
    KEY idx_email_outbox_status_locked (status, locked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
