package outbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
)

// ── In-memory fake store ────────────────────────────────────────────────────

type fakeRow struct {
	email       Email
	status      string
	lockedBy    string
	lockedAt    time.Time
	availableAt time.Time
}

type fakeStore struct {
	mu   sync.Mutex
	rows map[string]*fakeRow
	now  time.Time
}

func newFakeStore(now time.Time) *fakeStore {
	return &fakeStore{rows: map[string]*fakeRow{}, now: now}
}

func (s *fakeStore) add(id string) {
	s.rows[id] = &fakeRow{
		email:       Email{ID: id, ToAddr: id + "@x.test", Subject: "s", BodyHTML: "<b>h</b>"},
		status:      statusPending,
		availableAt: s.now.Add(-time.Minute),
	}
}

func (s *fakeStore) ResetStale(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, r := range s.rows {
		if r.status == statusSending && r.lockedAt.Before(cutoff) {
			r.status = statusPending
			r.lockedBy = ""
			n++
		}
	}
	return n, nil
}

func (s *fakeStore) Claim(_ context.Context, token string, limit int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, r := range s.rows {
		if n >= int64(limit) {
			break
		}
		if r.status == statusPending && !r.availableAt.After(s.now) {
			r.status = statusSending
			r.lockedBy = token
			r.lockedAt = s.now
			n++
		}
	}
	return n, nil
}

func (s *fakeStore) GetClaimed(_ context.Context, token string) ([]Email, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Email
	for _, r := range s.rows {
		if r.status == statusSending && r.lockedBy == token {
			out = append(out, r.email)
		}
	}
	return out, nil
}

func (s *fakeStore) MarkSent(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.rows[id]; r != nil {
		r.status = statusSent
		r.lockedBy = ""
	}
	return nil
}

func (s *fakeStore) Reschedule(_ context.Context, id, status string, availableAt time.Time, lastErr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.rows[id]; r != nil {
		r.status = status
		r.email.Attempts++
		r.availableAt = availableAt
		r.lockedBy = ""
		_ = lastErr
	}
	return nil
}

// fakeSender records sends and optionally fails a fixed number of times.
type fakeSender struct {
	mu        sync.Mutex
	sent      []string
	failUntil int // fail this many sends, then succeed
	calls     int
}

func (f *fakeSender) Enabled() bool { return true }
func (f *fakeSender) Send(_ context.Context, msg mailer.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failUntil {
		return errors.New("smtp boom")
	}
	f.sent = append(f.sent, msg.To)
	return nil
}

func newTestWorker(store Store, snd Sender) *Worker {
	return NewWorker(store, snd, zap.NewNop(), Config{BatchSize: 10, MaxAttempts: 3, BaseBackoff: time.Minute})
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestWorker_DrainSendsAndMarksSent(t *testing.T) {
	now := time.Now().UTC()
	store := newFakeStore(now)
	store.add("a")
	store.add("b")
	snd := &fakeSender{}

	if err := newTestWorker(store, snd).DrainOnce(context.Background()); err != nil {
		t.Fatalf("DrainOnce: %v", err)
	}

	if len(snd.sent) != 2 {
		t.Fatalf("expected 2 messages sent, got %d", len(snd.sent))
	}
	for id, r := range store.rows {
		if r.status != statusSent {
			t.Fatalf("row %s: expected status 'sent', got %q", id, r.status)
		}
	}
}

func TestWorker_TransientFailureReschedulesWithBackoff(t *testing.T) {
	now := time.Now().UTC()
	store := newFakeStore(now)
	store.add("a")
	snd := &fakeSender{failUntil: 1} // first send fails

	if err := newTestWorker(store, snd).DrainOnce(context.Background()); err != nil {
		t.Fatalf("DrainOnce: %v", err)
	}

	r := store.rows["a"]
	if r.status != statusPending {
		t.Fatalf("expected status 'pending' after transient failure, got %q", r.status)
	}
	if r.email.Attempts != 1 {
		t.Fatalf("expected attempts=1, got %d", r.email.Attempts)
	}
	if !r.availableAt.After(now) {
		t.Fatalf("expected available_at pushed into the future (back-off), got %v", r.availableAt)
	}
}

func TestWorker_FailsPermanentlyAfterMaxAttempts(t *testing.T) {
	now := time.Now().UTC()
	store := newFakeStore(now)
	store.add("a")
	// Pre-set attempts to one below max so a single failure tips it over.
	store.rows["a"].email.Attempts = 2 // MaxAttempts is 3
	snd := &fakeSender{failUntil: 100}

	if err := newTestWorker(store, snd).DrainOnce(context.Background()); err != nil {
		t.Fatalf("DrainOnce: %v", err)
	}

	if got := store.rows["a"].status; got != statusFailed {
		t.Fatalf("expected status 'failed' after exhausting attempts, got %q", got)
	}
}
