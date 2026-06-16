package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// lockingRepo wraps the existing in-memory fakeRepo and replaces its no-op
// WithTx with one that serialises whole transactions behind a sync.Mutex,
// faithfully modelling the InnoDB SELECT ... FOR UPDATE row lock that the
// production Refresh flow depends on.
//
// The embedded *fakeRepo already implements the full Repository interface and,
// crucially, its ConsumeRefreshToken already honours "used_at IS NULL"
// (it returns consumed=false when t.UsedAt.Valid is true), exactly like the
// production UPDATE ... WHERE used_at IS NULL. We only override WithTx so the
// closures run one-at-a-time against the shared token map, which is precisely
// the serialisation guarantee the real row lock provides.
type lockingRepo struct {
	*fakeRepo
	txMu sync.Mutex
}

func newLockingRepo(user *UserWithRoles) *lockingRepo {
	return &lockingRepo{fakeRepo: newFakeRepo(user)}
}

// WithTx serialises the entire closure under txMu so that two concurrent
// /refresh requests presenting the same token cannot interleave their
// FOR-UPDATE-read → state-check → consume sequence. The inner repository handed
// to fn is the embedded fakeRepo, so all mutations (ConsumeRefreshToken,
// CreateRefreshToken) hit the same shared map and are visible to the next
// serialised transaction — exactly as a committed DB transaction would be.
func (l *lockingRepo) WithTx(ctx context.Context, fn func(tx Repository) error) error {
	l.txMu.Lock()
	defer l.txMu.Unlock()
	return fn(l.fakeRepo)
}

// TestRefresh_ConcurrentRace is the headline race test. N goroutines present the
// SAME refresh token simultaneously. The FOR-UPDATE-equivalent serialisation in
// lockingRepo.WithTx plus the "used_at IS NULL" consume guard must guarantee:
//
//   - exactly ONE goroutine wins and receives a brand-new token pair;
//   - every other goroutine loses with a benign ErrTokenInvalid (the
//     concurrent-use grace path), NOT ErrTokenReuse;
//   - the token family is NOT revoked — the legitimate winner's new session
//     must survive.
//
// Run under -race, this also asserts there are no data races on the shared
// token map across the serialised transactions and the post-tx revocation path.
func TestRefresh_ConcurrentRace(t *testing.T) {
	t.Parallel()

	const goroutines = 20

	repo := newLockingRepo(&UserWithRoles{
		ID: "u1", Email: "u@x.com", Roles: []string{"user"}, EmailVerified: true,
	})
	// Build the service against the locking repo so both the transactional path
	// (WithTx) and the post-tx RevokeRefreshTokenFamily call go through it.
	s := newTestService(t, repo)
	// Seed via the embedded fakeRepo so the resulting raw token is keyed in the
	// shared map that the locking repo also reads.
	raw := seedToken(t, s, repo.fakeRepo, time.Time{})

	family := repo.byHash(platformauth.HashRefreshToken(raw)).TokenFamily

	type outcome struct {
		resp *TokenResponse
		err  error
	}
	results := make([]outcome, goroutines)

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // release all goroutines as simultaneously as possible
			resp, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: raw})
			results[idx] = outcome{resp: resp, err: err}
		}(i)
	}
	close(start)
	wg.Wait()

	// ── Assert exactly one winner ──────────────────────────────────────────────
	winners := 0
	var winningRefresh string
	for i, o := range results {
		if o.err == nil {
			winners++
			if o.resp == nil || o.resp.RefreshToken == "" || o.resp.AccessToken == "" {
				t.Fatalf("goroutine %d succeeded but returned an empty token pair: %+v", i, o.resp)
			}
			if o.resp.RefreshToken == raw {
				t.Fatalf("goroutine %d 'won' but returned the SAME (un-rotated) refresh token", i)
			}
			winningRefresh = o.resp.RefreshToken
			continue
		}
		// Every loser must be the benign concurrent-duplicate rejection
		// (ErrTokenInvalid via the grace window), never ErrTokenReuse and never
		// a family-revocation 500.
		if !isCode(o.err, apperrors.ErrTokenInvalid.Code) {
			t.Fatalf("loser goroutine %d got %v, want ErrTokenInvalid (grace-window benign duplicate)", i, o.err)
		}
	}

	if winners != 1 {
		t.Fatalf("expected exactly 1 winning goroutine, got %d", winners)
	}

	// ── Assert the family was NOT spuriously revoked ───────────────────────────
	// A correct implementation treats concurrent duplicates as benign and leaves
	// the family live so the winner's new session keeps working.
	repo.mu.Lock()
	for _, tk := range repo.tokens {
		if tk.TokenFamily == family && tk.RevokedAt.Valid {
			repo.mu.Unlock()
			t.Fatalf("token %s in family %s was spuriously revoked by legitimate concurrent use", tk.ID, family)
		}
	}
	repo.mu.Unlock()

	// ── Assert the winner's new token is itself usable (family still live) ─────
	// This proves the concurrent losers did not poison the family: the brand-new
	// token issued to the winner can be exchanged again.
	resp, err := s.Refresh(context.Background(), RefreshRequest{RefreshToken: winningRefresh})
	if err != nil {
		t.Fatalf("winner's freshly-issued token should still refresh, got error: %v", err)
	}
	if resp.RefreshToken == "" || resp.RefreshToken == winningRefresh {
		t.Fatal("expected the winner's token to rotate again into a new token")
	}
}
