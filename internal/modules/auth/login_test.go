package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// ── Login-specific fakes ────────────────────────────────────────────────────

// loginRepo extends the existing fakeRepo so the per-email user lookup that
// Login performs can be controlled per test (return a specific user, or an
// ErrNotFound). All other Repository methods are inherited from fakeRepo.
type loginRepo struct {
	*fakeRepo
	emailUser *UserWithRoles
	emailErr  error
}

func (r *loginRepo) GetUserByEmailWithRoles(ctx context.Context, email string) (*UserWithRoles, error) {
	if r.emailErr != nil {
		return nil, r.emailErr
	}
	return r.emailUser, nil
}

// stubMFAChallenger records whether InitiateChallenge was invoked and returns a
// deterministic challenge token so the MFA-gate test can assert a challenge was
// actually issued rather than a token pair.
type stubMFAChallenger struct {
	called    bool
	gotUserID string
	token     string
	expiresAt time.Time
	err       error
}

func (m *stubMFAChallenger) InitiateChallenge(ctx context.Context, userID, email, name string) (string, time.Time, error) {
	m.called = true
	m.gotUserID = userID
	if m.err != nil {
		return "", time.Time{}, m.err
	}
	return m.token, m.expiresAt, nil
}

// newRealLocker builds a genuine *platformauth.AccountLocker backed by an
// in-process miniredis so the production lockout gate runs unmodified. The
// service.locker field is a concrete type (not an interface), so a real locker
// is the only faithful way to exercise the lockout gate ordering.
func newRealLocker(t *testing.T, maxAttempts int) (*platformauth.AccountLocker, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	locker, err := platformauth.NewAccountLocker(rdb, zap.NewNop(), maxAttempts, 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewAccountLocker: %v", err)
	}
	return locker, mr
}

// makeUser builds a verified user whose stored password hash matches `password`,
// so VerifyPassword succeeds on the happy path. Set verified=false / twoFA=true
// to exercise the corresponding gates.
func makeUser(t *testing.T, password string, verified, twoFA bool) *UserWithRoles {
	t.Helper()
	hash, err := platformauth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return &UserWithRoles{
		ID:            "u1",
		Email:         "u@x.com",
		Name:          "User",
		Roles:         []string{"user"},
		PasswordHash:  hash,
		EmailVerified: verified,
		TwoFAEnabled:  twoFA,
	}
}

const goodPassword = "correct-horse-battery-staple"

// ── Test 2: Login gate ordering ─────────────────────────────────────────────

// TestLogin_LockedAccountRejectedBeforePasswordCheck proves the lockout gate
// short-circuits BEFORE credential verification. The user's stored hash matches
// the supplied password, so if the password gate were reached first the call
// would succeed (or at worst return INVALID_CREDENTIALS). Instead it must return
// ACCOUNT_LOCKED and never issue a token — demonstrating gate 0 precedes gate 1.
func TestLogin_LockedAccountRejectedBeforePasswordCheck(t *testing.T) {
	t.Parallel()

	user := makeUser(t, goodPassword, true, false)
	repo := &loginRepo{fakeRepo: newFakeRepo(user), emailUser: user}
	s := newTestService(t, repo)

	// maxAttempts=1 → a single recorded failure locks the account immediately.
	locker, _ := newRealLocker(t, 1)
	s.locker = locker

	// Drive the account into the locked state via a real failed login (wrong
	// password). This records a failure which, at threshold 1, locks the account.
	_, err := s.Login(context.Background(), LoginRequest{Email: user.Email, Password: "wrong-password"})
	if !isCode(err, apperrors.ErrInvalidCredentials.Code) {
		t.Fatalf("priming failed login: got %v, want ErrInvalidCredentials", err)
	}

	// Now log in with the CORRECT password. A locked account must still be
	// rejected with ACCOUNT_LOCKED — proving the lockout gate runs before, and
	// short-circuits, the (otherwise-succeeding) password check.
	result, err := s.Login(context.Background(), LoginRequest{Email: user.Email, Password: goodPassword})
	if result != nil {
		t.Fatalf("locked account must not return a result, got %+v", result)
	}
	if !isCode(err, apperrors.ErrAccountLocked.Code) {
		t.Fatalf("locked + correct password: got %v, want ACCOUNT_LOCKED", err)
	}
	// And it must carry a positive Retry-After (sourced from the real Redis TTL).
	var lockErr *apperrors.LockoutError
	if appErr, ok := apperrors.As(err); !ok || appErr.Code != apperrors.ErrAccountLocked.Code {
		t.Fatalf("expected an AppError with ACCOUNT_LOCKED code, got %v", err)
	}
	if le, ok := err.(*apperrors.LockoutError); ok {
		lockErr = le
	}
	if lockErr == nil || lockErr.RetryAfter <= 0 {
		t.Fatalf("expected a positive Retry-After on the lockout error, got %v", lockErr)
	}
}

// TestLogin_WrongPasswordRecordsFailure asserts that a wrong password returns
// INVALID_CREDENTIALS and, with maxAttempts=2, that two consecutive failures
// transition the account into the locked state (proving RecordFailure ran on the
// credential-failure path).
func TestLogin_WrongPasswordRecordsFailure(t *testing.T) {
	t.Parallel()

	user := makeUser(t, goodPassword, true, false)
	repo := &loginRepo{fakeRepo: newFakeRepo(user), emailUser: user}
	s := newTestService(t, repo)

	locker, _ := newRealLocker(t, 2)
	s.locker = locker

	// First wrong attempt: INVALID_CREDENTIALS, account not yet locked.
	_, err := s.Login(context.Background(), LoginRequest{Email: user.Email, Password: "nope-1"})
	if !isCode(err, apperrors.ErrInvalidCredentials.Code) {
		t.Fatalf("1st wrong password: got %v, want ErrInvalidCredentials", err)
	}

	// Second wrong attempt reaches the threshold. It still reports the failure as
	// INVALID_CREDENTIALS (lockout gate is evaluated at the START of the call, so
	// the lock takes effect on the NEXT attempt).
	_, err = s.Login(context.Background(), LoginRequest{Email: user.Email, Password: "nope-2"})
	if !isCode(err, apperrors.ErrInvalidCredentials.Code) {
		t.Fatalf("2nd wrong password: got %v, want ErrInvalidCredentials", err)
	}

	// Third attempt (even with the CORRECT password) must now be blocked by the
	// lockout gate, confirming the prior failures were recorded.
	_, err = s.Login(context.Background(), LoginRequest{Email: user.Email, Password: goodPassword})
	if !isCode(err, apperrors.ErrAccountLocked.Code) {
		t.Fatalf("post-threshold attempt: got %v, want ACCOUNT_LOCKED (failures were recorded)", err)
	}
}

// TestLogin_TableDriven covers the remaining gate outcomes.
func TestLogin_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// build returns the user the email lookup yields and the lookup error.
		emailUser func(t *testing.T) *UserWithRoles
		emailErr  error
		password  string
		withMFA   bool // wire a stub MFA challenger
		// assertion
		wantErrCode   string // "" → expect success
		wantChallenge bool
		wantTokenPair bool
	}{
		{
			name:        "unknown email → INVALID_CREDENTIALS",
			emailUser:   func(t *testing.T) *UserWithRoles { return nil },
			emailErr:    apperrors.ErrNotFound,
			password:    goodPassword,
			wantErrCode: apperrors.ErrInvalidCredentials.Code,
		},
		{
			name:        "wrong password → INVALID_CREDENTIALS",
			emailUser:   func(t *testing.T) *UserWithRoles { return makeUser(t, goodPassword, true, false) },
			password:    "definitely-wrong",
			wantErrCode: apperrors.ErrInvalidCredentials.Code,
		},
		{
			name:        "unverified email blocked → EMAIL_NOT_VERIFIED",
			emailUser:   func(t *testing.T) *UserWithRoles { return makeUser(t, goodPassword, false, false) },
			password:    goodPassword,
			wantErrCode: apperrors.ErrEmailNotVerified.Code,
		},
		{
			name:          "2FA enabled → MFA challenge, not a token pair",
			emailUser:     func(t *testing.T) *UserWithRoles { return makeUser(t, goodPassword, true, true) },
			password:      goodPassword,
			withMFA:       true,
			wantChallenge: true,
		},
		{
			name:          "happy path → token pair",
			emailUser:     func(t *testing.T) *UserWithRoles { return makeUser(t, goodPassword, true, false) },
			password:      goodPassword,
			wantTokenPair: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			user := tc.emailUser(t)
			repo := &loginRepo{fakeRepo: newFakeRepo(user), emailUser: user, emailErr: tc.emailErr}
			s := newTestService(t, repo)

			// A real (unlocked) locker so the lockout gate is exercised but never
			// trips, isolating the behaviour under test to the later gates.
			locker, _ := newRealLocker(t, 5)
			s.locker = locker

			var mfa *stubMFAChallenger
			if tc.withMFA {
				mfa = &stubMFAChallenger{token: "challenge-token-abc", expiresAt: time.Now().Add(5 * time.Minute)}
				s.SetMFAChallenger(mfa)
			}

			result, err := s.Login(context.Background(), LoginRequest{Email: "u@x.com", Password: tc.password})

			if tc.wantErrCode != "" {
				if !isCode(err, tc.wantErrCode) {
					t.Fatalf("got err %v, want code %s", err, tc.wantErrCode)
				}
				if result != nil {
					t.Fatalf("expected nil result on error, got %+v", result)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			switch {
			case tc.wantChallenge:
				if result.Challenge == nil {
					t.Fatal("expected an MFA challenge, got nil challenge")
				}
				if result.Token != nil {
					t.Fatal("MFA path must NOT return a token pair")
				}
				if !result.Challenge.RequiresMFA || result.Challenge.MFAToken != "challenge-token-abc" {
					t.Fatalf("challenge not populated from the challenger: %+v", result.Challenge)
				}
				if mfa == nil || !mfa.called {
					t.Fatal("MFA challenger was not invoked")
				}
				if mfa.gotUserID != "u1" {
					t.Fatalf("challenger called with userID %q, want u1", mfa.gotUserID)
				}
			case tc.wantTokenPair:
				if result.Token == nil {
					t.Fatal("expected a token pair, got nil token")
				}
				if result.Challenge != nil {
					t.Fatal("happy path must NOT return an MFA challenge")
				}
				if result.Token.AccessToken == "" || result.Token.RefreshToken == "" {
					t.Fatalf("token pair incomplete: %+v", result.Token)
				}
				if result.Token.TokenType != "Bearer" {
					t.Fatalf("token type = %q, want Bearer", result.Token.TokenType)
				}
			}
		})
	}
}

// TestLogin_TwoFAEnabledButChallengerMisconfigured asserts the defensive branch:
// a 2FA user with no wired MFAChallenger yields INTERNAL_SERVER_ERROR rather than
// silently issuing a full token pair (which would bypass the second factor).
func TestLogin_TwoFAEnabledButChallengerMisconfigured(t *testing.T) {
	t.Parallel()

	user := makeUser(t, goodPassword, true, true)
	repo := &loginRepo{fakeRepo: newFakeRepo(user), emailUser: user}
	s := newTestService(t, repo)
	locker, _ := newRealLocker(t, 5)
	s.locker = locker
	// Deliberately do NOT call SetMFAChallenger.

	result, err := s.Login(context.Background(), LoginRequest{Email: user.Email, Password: goodPassword})
	if result != nil {
		t.Fatalf("misconfigured 2FA must not return a result, got %+v", result)
	}
	if !isCode(err, apperrors.ErrInternalServer.Code) {
		t.Fatalf("got %v, want INTERNAL_SERVER_ERROR", err)
	}
}
