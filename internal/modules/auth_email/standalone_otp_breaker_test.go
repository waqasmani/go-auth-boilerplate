package authemail

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

const standaloneTestOTPSecret = "standalone-otp-hmac-secret-32-bytes-minimum-xxx"

// breakerFakeRepo is a dedicated fake for the standalone-OTP breaker tests. It
// is intentionally separate from fakeOTPRepo (otp_bruteforce_test.go) so we can
// (a) count GetEmailTokenByHash invocations to prove the breaker short-circuits
// the DB lookup, and (b) optionally serve a live challenge token for the MFA
// path. All other Repository methods are inert stubs satisfying the interface.
type breakerFakeRepo struct {
	// getCalls counts GetEmailTokenByHash invocations (atomic for -race safety).
	getCalls atomic.Int64

	// Optional MFA challenge wiring: when challengeRaw is non-empty a matching
	// hash returns the challenge token so the MFA path can be exercised.
	challengeRaw string
	challenge    *db.EmailToken
}

func (f *breakerFakeRepo) GetEmailTokenByHash(_ context.Context, hash string) (*db.EmailToken, error) {
	f.getCalls.Add(1)
	if f.challengeRaw != "" && hash == platformauth.HashRefreshToken(f.challengeRaw) {
		c := *f.challenge
		return &c, nil
	}
	// Any other hash — including every wrong standalone OTP guess (HMAC-keyed) —
	// resolves to no live token.
	return nil, apperrors.ErrTokenInvalid
}

func (f *breakerFakeRepo) RecordChallengeAttempt(_ context.Context, _ string) (int, error) {
	return 1, nil
}

func (f *breakerFakeRepo) ConsumeEmailToken(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func (f *breakerFakeRepo) GetUserMFAMethod(_ context.Context, _ string) (string, error) {
	return "email", nil
}

func (f *breakerFakeRepo) WithTx(ctx context.Context, fn func(tx Repository) error) error {
	return fn(f)
}

func (f *breakerFakeRepo) GetUserByEmail(_ context.Context, _ string) (*db.User, error) {
	return nil, apperrors.ErrNotFound
}

func (f *breakerFakeRepo) GetUserByID(_ context.Context, _ string) (*db.User, error) {
	return nil, apperrors.ErrNotFound
}

func (f *breakerFakeRepo) CreateEmailToken(_ context.Context, _ db.CreateEmailTokenParams) error {
	return nil
}

func (f *breakerFakeRepo) InvalidateUserTokensByType(_ context.Context, _ db.InvalidateUserTokensByTypeParams) error {
	return nil
}

func (f *breakerFakeRepo) UpdateUserPasswordHash(_ context.Context, _ db.UpdateUserPasswordHashParams) error {
	return nil
}

func (f *breakerFakeRepo) MarkEmailVerified(_ context.Context, _ string) error       { return nil }
func (f *breakerFakeRepo) ClearEmailVerified(_ context.Context, _ string) error      { return nil }
func (f *breakerFakeRepo) RevokeUserRefreshTokens(_ context.Context, _ string) error { return nil }

func (f *breakerFakeRepo) CreateRefreshToken(_ context.Context, _ db.CreateRefreshTokenParams) error {
	return nil
}

func (f *breakerFakeRepo) GetUserTOTPSecretEncrypted(_ context.Context, _ string) ([]byte, error) {
	return nil, ErrTOTPNotSetup
}

func (f *breakerFakeRepo) SetUserTOTPSecret(_ context.Context, _ string, _ []byte) error { return nil }
func (f *breakerFakeRepo) EnableUserTOTP(_ context.Context, _ string) error              { return nil }
func (f *breakerFakeRepo) DisableUserTOTP(_ context.Context, _ string) error             { return nil }

// breakerIssuer fails loudly if invoked: no standalone-breaker test path issues
// tokens, so a call here signals a logic error in the test or production code.
type breakerIssuer struct{}

func (breakerIssuer) PrepareTokensForUser(_ context.Context, _ string) (*platformauth.TokenPair, error) {
	return nil, errors.New("PrepareTokensForUser must not be called in the standalone-breaker tests")
}

// newBreakerService wires a service backed by the given miniredis-backed client.
func newBreakerService(t *testing.T, repo Repository, rdb *goredis.Client) Service {
	t.Helper()
	replay, err := platformauth.NewTOTPReplayCacheWithTTL(rdb, zap.NewNop(), 90*time.Second)
	if err != nil {
		t.Fatalf("replay cache: %v", err)
	}
	keySet, err := platformauth.NewTOTPKeySet([]platformauth.TOTPEncKey{
		{ID: "v1", Key: "totp-enc-key-needs-32-bytes-minimum-aaaaa", Active: true},
	})
	if err != nil {
		t.Fatalf("totp key set: %v", err)
	}
	svc, err := NewService(
		repo, nil, zap.NewNop(), "http://localhost:3000",
		breakerIssuer{}, standaloneTestOTPSecret, 3,
		audit.New(zap.NewNop()), keySet, "test", 30, 6, replay, rdb,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// readBreakerCounter returns the current value of the global standalone fail key,
// or 0 when the key does not yet exist.
func readBreakerCounter(t *testing.T, mr *miniredis.Miniredis) int {
	t.Helper()
	if !mr.Exists(standaloneOTPFailKey) {
		return 0
	}
	raw, err := mr.Get(standaloneOTPFailKey)
	if err != nil {
		t.Fatalf("miniredis Get(%q): %v", standaloneOTPFailKey, err)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("counter %q is not an integer: %v", raw, err)
	}
	return n
}

// Scenario 1: each failed standalone verification increments the global counter
// under "otp:standalone:fails".
func TestStandaloneOTPBreaker_CountsFailures(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

	repo := &breakerFakeRepo{}
	svc := newBreakerService(t, repo, rdb)
	ctx := context.Background()

	const attempts = 5
	for i := 1; i <= attempts; i++ {
		_, err := svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "000000"}) // empty MFAToken → standalone
		if !errors.Is(err, apperrors.ErrTokenInvalid) {
			t.Fatalf("attempt %d: expected ErrTokenInvalid, got %v", i, err)
		}
		if got := readBreakerCounter(t, mr); got != i {
			t.Fatalf("after %d failed attempts, counter = %d, want %d", i, got, i)
		}
	}

	// Sanity: the counter is under the canonical key the production breaker reads.
	if got := readBreakerCounter(t, mr); got != attempts {
		t.Fatalf("final counter under %q = %d, want %d", standaloneOTPFailKey, got, attempts)
	}
	// The DB lookup must have run on every (un-tripped) attempt.
	if got := repo.getCalls.Load(); got != attempts {
		t.Fatalf("GetEmailTokenByHash called %d times, want %d", got, attempts)
	}
}

// Scenario 2: once the counter reaches standaloneOTPFailMax, a subsequent verify
// is rejected up-front with ErrRateLimitExceeded and the DB lookup is skipped.
func TestStandaloneOTPBreaker_TripsAndShortCircuitsDB(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

	repo := &breakerFakeRepo{}
	svc := newBreakerService(t, repo, rdb)
	ctx := context.Background()

	// Pre-load the counter to exactly the cap so the breaker is tripped without
	// having to drive standaloneOTPFailMax real requests.
	if err := mr.Set(standaloneOTPFailKey, strconv.Itoa(standaloneOTPFailMax)); err != nil {
		t.Fatalf("seed counter: %v", err)
	}

	_, err = svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "123456"})
	if !errors.Is(err, apperrors.ErrRateLimitExceeded) {
		t.Fatalf("breaker tripped: expected ErrRateLimitExceeded, got %v", err)
	}
	if got := repo.getCalls.Load(); got != 0 {
		t.Fatalf("breaker tripped: GetEmailTokenByHash called %d times, want 0 (DB must be short-circuited)", got)
	}

	// One above the cap is still tripped.
	if err := mr.Set(standaloneOTPFailKey, strconv.Itoa(standaloneOTPFailMax+1)); err != nil {
		t.Fatalf("seed counter: %v", err)
	}
	_, err = svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "654321"})
	if !errors.Is(err, apperrors.ErrRateLimitExceeded) {
		t.Fatalf("over cap: expected ErrRateLimitExceeded, got %v", err)
	}
	if got := repo.getCalls.Load(); got != 0 {
		t.Fatalf("over cap: GetEmailTokenByHash called %d times, want 0", got)
	}
}

// Boundary: at exactly one below the cap the breaker is NOT tripped, so the
// request falls through to the DB lookup and returns ErrTokenInvalid.
func TestStandaloneOTPBreaker_BelowCapDoesNotTrip(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

	repo := &breakerFakeRepo{}
	svc := newBreakerService(t, repo, rdb)
	ctx := context.Background()

	if err := mr.Set(standaloneOTPFailKey, strconv.Itoa(standaloneOTPFailMax-1)); err != nil {
		t.Fatalf("seed counter: %v", err)
	}

	_, err = svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "000000"})
	if !errors.Is(err, apperrors.ErrTokenInvalid) {
		t.Fatalf("below cap: expected ErrTokenInvalid (breaker open), got %v", err)
	}
	if got := repo.getCalls.Load(); got != 1 {
		t.Fatalf("below cap: GetEmailTokenByHash called %d times, want 1", got)
	}
	// And that very failure pushed the counter up to the cap.
	if got := readBreakerCounter(t, mr); got != standaloneOTPFailMax {
		t.Fatalf("counter after the boundary failure = %d, want %d", got, standaloneOTPFailMax)
	}
}

// Scenario 3: fail-open. When Redis is unreachable the breaker must NOT block,
// even if the counter was previously above the cap. The standaloneOTPBreakerTripped
// helper returns false and a wrong code yields ErrTokenInvalid, never the
// rate-limit error.
func TestStandaloneOTPBreaker_FailsOpenWhenRedisDown(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

	// Drive the counter over the cap while Redis is still up.
	if err := mr.Set(standaloneOTPFailKey, strconv.Itoa(standaloneOTPFailMax+10)); err != nil {
		t.Fatalf("seed counter: %v", err)
	}

	repo := &breakerFakeRepo{}
	svc := newBreakerService(t, repo, rdb)
	ctx := context.Background()

	// Take Redis down: every breaker Get now errors → must fail open.
	mr.Close()

	_, err = svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "000000"})
	if errors.Is(err, apperrors.ErrRateLimitExceeded) {
		t.Fatal("Redis down: breaker must fail OPEN, but got ErrRateLimitExceeded")
	}
	if !errors.Is(err, apperrors.ErrTokenInvalid) {
		t.Fatalf("Redis down: expected ErrTokenInvalid (fall-through), got %v", err)
	}
	// The DB lookup still ran because the breaker did not short-circuit it.
	if got := repo.getCalls.Load(); got != 1 {
		t.Fatalf("Redis down: GetEmailTokenByHash called %d times, want 1", got)
	}
}

// Scenario 4: the MFA path (non-empty MFAToken → completeMFALoginDispatch) is
// independent of the standalone breaker — it must proceed to the challenge
// lookup even when the standalone counter is well over the cap.
func TestStandaloneOTPBreaker_DoesNotAffectMFAPath(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

	// Standalone counter way over the cap — would trip the standalone breaker.
	if err := mr.Set(standaloneOTPFailKey, strconv.Itoa(standaloneOTPFailMax*2)); err != nil {
		t.Fatalf("seed counter: %v", err)
	}

	repo := &breakerFakeRepo{
		challengeRaw: "raw-challenge-token",
		challenge: &db.EmailToken{
			ID:        "chal-1",
			UserID:    "u1",
			TokenType: "challenge",
			ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
			UsedAt:    sql.NullTime{},
		},
	}
	svc := newBreakerService(t, repo, rdb)
	ctx := context.Background()

	// Wrong OTP against a valid challenge: the MFA path must reach the lookup and
	// reject with ErrTokenInvalid — NOT the standalone rate-limit error.
	_, err = svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "000000", MFAToken: "raw-challenge-token"})
	if errors.Is(err, apperrors.ErrRateLimitExceeded) {
		t.Fatal("MFA path must be unaffected by the standalone breaker, but got ErrRateLimitExceeded")
	}
	if !errors.Is(err, apperrors.ErrTokenInvalid) {
		t.Fatalf("MFA path: expected ErrTokenInvalid, got %v", err)
	}
	// The MFA path performed its DB lookups (challenge + OTP), proving it was not
	// short-circuited by the standalone breaker.
	if got := repo.getCalls.Load(); got == 0 {
		t.Fatal("MFA path: GetEmailTokenByHash was never called — request was wrongly short-circuited")
	}
	// The standalone counter must be untouched by the MFA path.
	if got := readBreakerCounter(t, mr); got != standaloneOTPFailMax*2 {
		t.Fatalf("MFA path mutated the standalone counter: got %d, want %d", got, standaloneOTPFailMax*2)
	}
}
