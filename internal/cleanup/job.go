// Package cleanup implements a one-shot database maintenance job that purges
// expired rows from token tables. It is designed to run as a Kubernetes
// CronJob or Unix cron entry — not as a long-lived background goroutine inside
// an HTTP pod.
//
// # Tables purged
//
//   - refresh_tokens       — rows whose expires_at is in the past.
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
// continuing is pointless). All other errors are collected as structured
// PassError values; the job continues with remaining passes and returns a
// *RunError at the end so that a transient failure on one table does not
// prevent cleanup of the others.
//
// Each PassError carries the table name and the number of rows deleted before
// the failure occurred, so log aggregators (Datadog, Loki, CloudWatch Insights)
// can index them as discrete structured events rather than parsing a flat
// joined string. The caller (cmd/cleanup/main.go) converts a non-nil error
// into exit code 1.
package cleanup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

const defaultBatchSize = 10_000

// ── Structured error types ────────────────────────────────────────────────────

// PassError records the outcome of a single cleanup pass that encountered an
// error. It carries the table name and the row count deleted before failure so
// callers can log discrete structured events without parsing a joined string.
type PassError struct {
	// Table is the database table the pass was targeting.
	Table string
	// Deleted is the number of rows successfully removed before the error
	// occurred. Zero when the very first batch failed before deleting anything.
	// Non-zero on a partial run — useful for diagnosing whether a table is
	// growing faster than cleanup can keep up.
	Deleted int64
	// Err is the underlying cause, preserved for errors.Is / errors.As.
	Err error
}

func (e *PassError) Error() string {
	return fmt.Sprintf("cleanup: %s (deleted %d before error): %v", e.Table, e.Deleted, e.Err)
}

// Unwrap lets errors.Is and errors.As traverse into the underlying cause.
func (e *PassError) Unwrap() error { return e.Err }

// RunError is returned by Job.Run when one or more passes fail. It holds the
// full slice of PassError values so callers can log each failure as a separate
// structured event and aggregators can index them individually.
//
// It implements the multi-error Unwrap protocol introduced in Go 1.20 so
// errors.Is / errors.As can traverse all underlying causes.
type RunError struct {
	// Failures contains one PassError per failed pass, in execution order.
	// Passes that completed successfully are not included.
	Failures []*PassError
}

func (e *RunError) Error() string {
	msgs := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		msgs[i] = f.Error()
	}
	return strings.Join(msgs, "; ")
}

// Unwrap returns the slice of underlying errors, satisfying the multi-error
// interface so errors.Is / errors.As traverse every PassError in Failures.
func (e *RunError) Unwrap() []error {
	errs := make([]error, len(e.Failures))
	for i, f := range e.Failures {
		errs[i] = f
	}
	return errs
}

// ── Job ───────────────────────────────────────────────────────────────────────

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
// uniformly.
type pass struct {
	name string
	fn   func(context.Context) (int64, error)
}

// Run executes all cleanup passes in order.
//
// Each pass failure is logged immediately as a structured event with
// zap.String("table") and zap.Int64("deleted_before_error") so log
// aggregators can index and alert on individual tables without parsing a
// joined error string.
//
// Context cancellation aborts the job immediately; all other errors are
// collected and the remaining passes still execute. Returns *RunError when any
// pass failed, nil when all passes completed successfully.
func (j *Job) Run(ctx context.Context) error {
	passes := []pass{
		{"refresh_tokens", j.purgeRefreshTokens},
		{"oauth_linking_states", j.purgeLinkingStates},
		{"oauth_one_time_codes", j.purgeOneTimeCodes},
	}

	var failures []*PassError

	for _, p := range passes {
		n, err := p.fn(ctx)
		if err != nil {
			pe := &PassError{Table: p.name, Deleted: n, Err: err}

			// Context errors mean the overall deadline has expired — abort now
			// rather than attempting further passes that will also fail.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				j.log.Error("cleanup: context expired — aborting remaining passes",
					zap.String("table", p.name),
					zap.Int64("deleted_before_abort", n),
					zap.Error(err),
				)
				failures = append(failures, pe)
				break
			}

			// Non-context error: log a discrete structured event per table so
			// Datadog / Loki can index table and deleted_before_error as
			// individual fields rather than parsing a flat joined string.
			j.log.Error("cleanup: pass failed — continuing with remaining passes",
				zap.String("table", p.name),
				zap.Int64("deleted_before_error", n),
				zap.Error(err),
			)
			failures = append(failures, pe)
			continue
		}

		j.log.Info("cleanup: pass complete",
			zap.String("table", p.name),
			zap.Int64("deleted", n),
		)
	}

	if len(failures) == 0 {
		return nil
	}
	return &RunError{Failures: failures}
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
// (which means the table is clean). Returns the total number of deleted rows
// and the first error encountered; the total is accurate up to the point of
// failure so PassError can report partial progress.
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
