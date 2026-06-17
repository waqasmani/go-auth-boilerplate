package outbox

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Outbox row statuses. Kept as plain strings (matching the email_outbox ENUM)
// rather than a sqlc-generated type so this package stays independent of the
// generated layer.
const (
	statusPending = "pending"
	statusSending = "sending"
	statusSent    = "sent"
	statusFailed  = "failed"
)

// SQLStore is the production Store, backed by the shared *sql.DB. The queries
// are hand-written database/sql (not sqlc) — the same raw-SQL approach the
// cleanup job uses — so adding the outbox never touches generated code.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore wraps a *sql.DB as a Store.
func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

const resetStaleSQL = `
UPDATE email_outbox
SET status = 'pending', locked_by = NULL, locked_at = NULL
WHERE status = 'sending' AND locked_at < ?`

func (s *SQLStore) ResetStale(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, resetStaleSQL, cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("outbox: reset stale: %w", err)
	}
	return res.RowsAffected()
}

// claimSQL atomically stamps up to ? due 'pending' rows with this worker's
// token. The status='pending' guard plus InnoDB row locks guarantee no two
// workers claim the same row, so it is safe under N concurrent workers.
const claimSQL = `
UPDATE email_outbox
SET status = 'sending', locked_by = ?, locked_at = NOW()
WHERE status = 'pending' AND available_at <= NOW()
LIMIT ?`

func (s *SQLStore) Claim(ctx context.Context, token string, limit int) (int64, error) {
	res, err := s.db.ExecContext(ctx, claimSQL, token, limit)
	if err != nil {
		return 0, fmt.Errorf("outbox: claim batch: %w", err)
	}
	return res.RowsAffected()
}

const getClaimedSQL = `
SELECT id, to_addr, subject, body_html, COALESCE(body_text, ''), attempts
FROM email_outbox
WHERE locked_by = ? AND status = 'sending'
ORDER BY available_at, id`

func (s *SQLStore) GetClaimed(ctx context.Context, token string) ([]Email, error) {
	rows, err := s.db.QueryContext(ctx, getClaimedSQL, token)
	if err != nil {
		return nil, fmt.Errorf("outbox: get claimed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Email
	for rows.Next() {
		var e Email
		if err := rows.Scan(&e.ID, &e.ToAddr, &e.Subject, &e.BodyHTML, &e.BodyText, &e.Attempts); err != nil {
			return nil, fmt.Errorf("outbox: scan claimed row: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("outbox: iterate claimed rows: %w", err)
	}
	return out, nil
}

const markSentSQL = `
UPDATE email_outbox
SET status = 'sent', sent_at = NOW(), locked_by = NULL, locked_at = NULL, last_error = NULL
WHERE id = ?`

func (s *SQLStore) MarkSent(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, markSentSQL, id); err != nil {
		return fmt.Errorf("outbox: mark sent: %w", err)
	}
	return nil
}

const rescheduleSQL = `
UPDATE email_outbox
SET status = ?, attempts = attempts + 1, available_at = ?, last_error = ?, locked_by = NULL, locked_at = NULL
WHERE id = ?`

func (s *SQLStore) Reschedule(ctx context.Context, id, status string, availableAt time.Time, lastErr string) error {
	if _, err := s.db.ExecContext(ctx, rescheduleSQL, status, availableAt.UTC(), lastErr, id); err != nil {
		return fmt.Errorf("outbox: reschedule: %w", err)
	}
	return nil
}
