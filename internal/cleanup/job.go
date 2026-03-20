// Package cleanup implements a one-shot database maintenance job that purges
// expired rows from token tables. It is designed to run as a Kubernetes
// CronJob or Unix cron entry — not as a long-lived background goroutine inside
// an HTTP pod.
//
// # Tables purged
//
//   - refresh_tokens      — rows whose expires_at is in the past.
//   - oauth_linking_states — rows whose expires_at is in the past.
//   - oauth_one_time_codes — rows whose expires_at is in the past AND whose
//     used_at is NOT NULL (unused-but-expired codes are also purged since they
//     can never be redeemed once the TTL has elapsed).
//
// # Batching
//
// Each pass deletes at most batchSize rows per SQL statement, then loops until
// fewer than batchSize rows are affected. This keeps individual statements
// short, reduces InnoDB lock contention, and avoids replication lag spikes on
// busy primaries. The default batch size of 10 000 rows can be overridden via
// CLEANUP_BATCH_SIZE.
//
// # Error handling
//
// A context cancellation or deadline in one pass aborts that pass and the
// entire job (a cancelled context means the CronJob's deadline has expired —
// continuing is pointless). All other errors are collected; the job continues
// with remaining passes and returns a combined error at the end so that a
// transient failure on one table does not prevent cleanup of the others. The
// caller (cmd/cleanup/main.go) converts a non-nil error into exit code 1.
package cleanup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"

	"go.uber.org/zap"
)

const defaultBatchSize = 10_000

// Job purges expired rows from token tables. Construct via NewJob.
type Job struct {
	db        *sql.DB
	log       *zap.Logger
	batchSize int64
}

// NewJob constructs a Job. The batch size defaults to 10 000 rows and may be
// overridden by the CLEANUP_BATCH_SIZE environment variable.
func NewJob(db *sql.DB, log *zap.Logger) *Job {
	bs := int64(defaultBatchSize)
	if raw := os.Getenv("CLEANUP_BATCH_SIZE"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			bs = n
		} else {
			log.Warn("cleanup: invalid CLEANUP_BATCH_SIZE — using default",
				zap.String("raw", raw),
				zap.Int64("default", defaultBatchSize),
			)
		}
	}
	return &Job{db: db, log: log, batchSize: bs}
}

// pass groups a table name with its delete function so Run can iterate
// uniformly. A context error aborts the whole job; any other error is
// accumulated so remaining passes still execute.
type pass struct {
	name string
	fn   func(context.Context) (int64, error)
}

// Run executes all cleanup passes in order. Context cancellation stops the
// entire job immediately; other pass errors are accumulated. Returns a non-nil
// error when any pass fails.
func (j *Job) Run(ctx context.Context) error {
	passes := []pass{
		{"refresh_tokens", j.purgeRefreshTokens},
		{"oauth_linking_states", j.purgeLinkingStates},
		{"oauth_one_time_codes", j.purgeOneTimeCodes},
	}

	var errs []error
	for _, p := range passes {
		n, err := p.fn(ctx)
		if err != nil {
			// Context errors mean the overall deadline has expired — abort now
			// rather than attempting further passes that will also fail.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				j.log.Error("cleanup: context expired — aborting remaining passes",
					zap.String("table", p.name),
					zap.Error(err),
				)
				errs = append(errs, fmt.Errorf("%s: %w", p.name, err))
				break
			}
			j.log.Error("cleanup: pass failed — continuing with remaining passes",
				zap.String("table", p.name),
				zap.Error(err),
			)
			errs = append(errs, fmt.Errorf("%s: %w", p.name, err))
			continue
		}
		j.log.Info("cleanup: pass complete",
			zap.String("table", p.name),
			zap.Int64("deleted", n),
		)
	}
	return errors.Join(errs...)
}

// ── Per-table passes ──────────────────────────────────────────────────────────

// purgeRefreshTokens removes refresh_tokens rows whose expires_at is before
// the current UTC time, regardless of used_at or revoked_at. Expired tokens
// cannot be redeemed by any code path, so their state flags are irrelevant.
func (j *Job) purgeRefreshTokens(ctx context.Context) (int64, error) {
	return j.deleteBatched(ctx,
		`DELETE FROM refresh_tokens
		  WHERE expires_at < UTC_TIMESTAMP()
		  LIMIT ?`,
		"refresh_tokens",
	)
}

// purgeLinkingStates removes oauth_linking_states rows whose expires_at is in
// the past. These rows are normally consumed (and individually deleted) by
// ConsumeLinkingState; this pass catches rows from flows that the user
// abandoned before completion.
func (j *Job) purgeLinkingStates(ctx context.Context) (int64, error) {
	return j.deleteBatched(ctx,
		`DELETE FROM oauth_linking_states
		  WHERE expires_at < UTC_TIMESTAMP()
		  LIMIT ?`,
		"oauth_linking_states",
	)
}

// purgeOneTimeCodes removes oauth_one_time_codes rows that are both expired
// and consumed (used_at IS NOT NULL). Unused-but-expired codes are also
// purged: they can never be redeemed (the repository checks expires_at before
// accepting a code), so they are dead weight regardless of used_at.
func (j *Job) purgeOneTimeCodes(ctx context.Context) (int64, error) {
	return j.deleteBatched(ctx,
		`DELETE FROM oauth_one_time_codes
		  WHERE expires_at < UTC_TIMESTAMP()
		  LIMIT ?`,
		"oauth_one_time_codes",
	)
}

// ── Batched delete helper ─────────────────────────────────────────────────────

// deleteBatched executes query in a loop, passing j.batchSize as the LIMIT
// argument, until fewer rows than batchSize are deleted in a single batch
// (which means the table is clean). Returns the total number of deleted rows.
//
// Context is checked before each batch: a cancelled or timed-out context
// causes an immediate return so the caller can abort cleanly.
func (j *Job) deleteBatched(ctx context.Context, query, table string) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("context: %w", err)
		}

		result, err := j.db.ExecContext(ctx, query, j.batchSize)
		if err != nil {
			return total, fmt.Errorf("exec batch delete: %w", err)
		}

		n, err := result.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("rows affected: %w", err)
		}
		total += n

		j.log.Debug("cleanup: batch deleted",
			zap.String("table", table),
			zap.Int64("batch", n),
			zap.Int64("total_so_far", total),
		)

		// Fewer rows than the batch ceiling → table is clean.
		if n < j.batchSize {
			break
		}
	}
	return total, nil
}
