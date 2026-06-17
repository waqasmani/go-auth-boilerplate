// Package outbox drains the email_outbox table and delivers each message over
// SMTP. It is the durable, multi-instance replacement for the mailer's old
// in-memory send queue: producers INSERT a row in the request path (see
// auth_email.service.sendEmail) and this worker delivers it exactly once, even
// across a process crash and across many worker replicas.
//
// Data access is plain database/sql (see store.go), deliberately not sqlc — the
// generated layer is kept hand-curated in this repo, and the cleanup job sets
// the same raw-SQL precedent.
//
// # Claim protocol (safe under N concurrent workers)
//
//  1. ResetStale returns rows abandoned by a crashed worker (claimed longer ago
//     than staleAfter) to 'pending'.
//  2. Claim stamps up to batchSize due 'pending' rows with this worker's unique
//     token and flips them to 'sending' in one atomic UPDATE. The
//     status='pending' guard plus InnoDB row locks guarantee no two workers
//     claim the same row.
//  3. GetClaimed reads back this worker's rows by token; each is sent and then
//     marked 'sent', rescheduled with exponential back-off, or moved to 'failed'
//     once attempts are exhausted.
//
// The SMTP send happens outside any transaction, so a slow mail server never
// holds a database row lock.
package outbox

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
)

const (
	defaultBatchSize    = 50
	defaultMaxAttempts  = 5
	defaultPollInterval = 5 * time.Second
	defaultBaseBackoff  = 1 * time.Minute
	// staleAfter is how long a row may sit in 'sending' before it is assumed the
	// claiming worker died and the row is reclaimed. Must comfortably exceed the
	// worst-case single-send wall-clock (mailer dial+SMTP timeouts × retries).
	staleAfter = 10 * time.Minute

	maxLastErrorLen = 1000 // fits last_error VARCHAR(1024) with headroom
)

// Email is one claimed outbox row, carrying only what the worker needs.
type Email struct {
	ID       string
	ToAddr   string
	Subject  string
	BodyHTML string
	BodyText string // empty when the row has no plain-text alternative
	Attempts int    // attempts already made before this delivery
}

// Store is the persistence contract the worker drives. SQLStore (store.go) is
// the production implementation; tests supply an in-memory fake.
type Store interface {
	// ResetStale returns 'sending' rows claimed before cutoff to 'pending' and
	// reports how many were reclaimed.
	ResetStale(ctx context.Context, cutoff time.Time) (int64, error)
	// Claim stamps up to limit due 'pending' rows with token (→ 'sending') and
	// reports how many were claimed.
	Claim(ctx context.Context, token string, limit int) (int64, error)
	// GetClaimed returns the rows currently held under token.
	GetClaimed(ctx context.Context, token string) ([]Email, error)
	// MarkSent finalises a delivered row.
	MarkSent(ctx context.Context, id string) error
	// Reschedule records a failed attempt: it bumps attempts, stores lastErr, and
	// sets the row's next status ("pending" to retry, "failed" when exhausted)
	// and availableAt.
	Reschedule(ctx context.Context, id, status string, availableAt time.Time, lastErr string) error
}

// Sender is the subset of *mailer.Mailer the worker needs. Abstracted for tests.
type Sender interface {
	Send(ctx context.Context, msg mailer.Message) error
	Enabled() bool
}

// Config tunes the worker. Zero values fall back to package defaults.
type Config struct {
	BatchSize   int
	MaxAttempts int
	BaseBackoff time.Duration
}

// ConfigFromEnv reads OUTBOX_BATCH_SIZE / OUTBOX_MAX_ATTEMPTS, logging and
// falling back to defaults on absent or invalid values.
func ConfigFromEnv(log *zap.Logger) Config {
	return Config{
		BatchSize:   envInt("OUTBOX_BATCH_SIZE", defaultBatchSize, log),
		MaxAttempts: envInt("OUTBOX_MAX_ATTEMPTS", defaultMaxAttempts, log),
		BaseBackoff: defaultBaseBackoff,
	}
}

// Worker drains the outbox. Construct via NewWorker.
type Worker struct {
	store       Store
	mailer      Sender
	log         *zap.Logger
	batchSize   int
	maxAttempts int
	baseBackoff time.Duration
}

// Bounds keep operator-supplied (env) values sane. maxMaxAttempts is capped low
// because the back-off doubles each attempt (base × 2^(attempts-1)).
const (
	maxBatchSize   = 100_000
	maxMaxAttempts = 30
)

// NewWorker builds a Worker. store performs the persistence; mailer delivers.
func NewWorker(store Store, m Sender, log *zap.Logger, cfg Config) *Worker {
	if cfg.BatchSize <= 0 || cfg.BatchSize > maxBatchSize {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.MaxAttempts <= 0 || cfg.MaxAttempts > maxMaxAttempts {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	return &Worker{
		store:       store,
		mailer:      m,
		log:         log,
		batchSize:   cfg.BatchSize,
		maxAttempts: cfg.MaxAttempts,
		baseBackoff: cfg.BaseBackoff,
	}
}

// Run drains the outbox on every pollInterval tick until ctx is cancelled
// (SIGTERM). It returns ctx.Err() on shutdown.
func (w *Worker) Run(ctx context.Context, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	w.log.Info("outbox: worker started",
		zap.Duration("poll_interval", pollInterval),
		zap.Int("batch_size", w.batchSize),
		zap.Int("max_attempts", w.maxAttempts),
	)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		// Drain fully on each wake-up so a burst is not metered out one batch per
		// tick.
		if err := w.DrainOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.log.Error("outbox: drain pass failed", zap.Error(err))
		}

		select {
		case <-ctx.Done():
			w.log.Info("outbox: worker stopping", zap.Error(ctx.Err()))
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// DrainOnce reclaims stale rows then claims and processes batches until no due
// rows remain. Returns nil when the queue is drained, or the first fatal error.
func (w *Worker) DrainOnce(ctx context.Context) error {
	if _, err := w.store.ResetStale(ctx, time.Now().UTC().Add(-staleAfter)); err != nil {
		// Non-fatal: stale recovery will be retried next tick. Continue to the
		// claim loop so healthy rows still flow.
		w.log.Warn("outbox: reset stale rows failed", zap.Error(err))
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		token := uuid.NewString()
		claimed, err := w.store.Claim(ctx, token, w.batchSize)
		if err != nil {
			return err
		}
		if claimed == 0 {
			return nil // queue drained
		}

		rows, err := w.store.GetClaimed(ctx, token)
		if err != nil {
			return err
		}
		for _, row := range rows {
			w.process(ctx, row)
		}
	}
}

// process delivers one claimed row and records the outcome.
func (w *Worker) process(ctx context.Context, row Email) {
	msg := mailer.Message{To: row.ToAddr, Subject: row.Subject, HTML: row.BodyHTML, Text: row.BodyText}

	if err := w.mailer.Send(ctx, msg); err != nil {
		w.reschedule(ctx, row, err)
		return
	}

	if err := w.store.MarkSent(ctx, row.ID); err != nil {
		// The mail was sent but we failed to record it. The row stays 'sending'
		// and will be reclaimed after staleAfter — at-least-once delivery means
		// the worst case is a duplicate email, never a lost one. Log loudly.
		w.log.Error("outbox: mail sent but marking row 'sent' failed — may resend on stale recovery",
			zap.String("id", row.ID),
			zap.Error(err),
		)
	}
}

// reschedule records a failed send: retry with exponential back-off, or move to
// 'failed' once attempts are exhausted.
func (w *Worker) reschedule(ctx context.Context, row Email, sendErr error) {
	attempts := row.Attempts + 1 // value after this failure
	status := statusPending
	// Back-off grows with the attempt count: base × 2^(attempts-1).
	next := time.Now().UTC().Add(w.baseBackoff * time.Duration(1<<(attempts-1)))

	if attempts >= w.maxAttempts {
		status = statusFailed
		w.log.Error("outbox: message failed permanently after max attempts",
			zap.String("id", row.ID),
			zap.Int("attempts", attempts),
			zap.Error(sendErr),
		)
	} else {
		w.log.Warn("outbox: send failed — scheduling retry",
			zap.String("id", row.ID),
			zap.Int("attempt", attempts),
			zap.Time("next_attempt", next),
			zap.Error(sendErr),
		)
	}

	if err := w.store.Reschedule(ctx, row.ID, status, next, truncate(sendErr.Error(), maxLastErrorLen)); err != nil {
		// Row remains 'sending'; stale recovery will reclaim it. At-least-once.
		w.log.Error("outbox: failed to reschedule row — will be reclaimed after stale timeout",
			zap.String("id", row.ID),
			zap.Error(err),
		)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func envInt(key string, def int, log *zap.Logger) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		log.Warn("outbox: invalid env value — using default",
			zap.String("key", key),
			zap.String("raw", raw),
			zap.Int("default", def),
		)
		return def
	}
	return n
}
