package authemail

import (
	"context"
	"database/sql"
	"errors"
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

const bruteForceOTPSecret = "otp-hmac-secret-at-least-32-bytes-long-xxxxx"

// fakeOTPRepo implements the subset of Repository behaviour exercised by the
// email-OTP MFA path. The wrong-guess path only touches GetEmailTokenByHash
// (challenge lookup + failed OTP lookup), GetUserMFAMethod, RecordChallengeAttempt,
// and ConsumeEmailToken; the rest satisfy the interface.
type fakeOTPRepo struct {
	challengeRaw string
	challenge    *db.EmailToken
	attempts     int
	burned       bool
}

func (f *fakeOTPRepo) GetEmailTokenByHash(ctx context.Context, hash string) (*db.EmailToken, error) {
	if hash == platformauth.HashRefreshToken(f.challengeRaw) {
		c := *f.challenge
		if f.burned {
			c.UsedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		}
		return &c, nil
	}
	// Any other hash (a wrong OTP guess, HMAC-keyed) does not match a live token.
	return nil, apperrors.ErrTokenInvalid
}

func (f *fakeOTPRepo) RecordChallengeAttempt(ctx context.Context, challengeID string) (int, error) {
	f.attempts++
	return f.attempts, nil
}

func (f *fakeOTPRepo) ConsumeEmailToken(ctx context.Context, id string) (bool, error) {
	if f.burned {
		return false, nil
	}
	f.burned = true
	return true, nil
}

func (f *fakeOTPRepo) GetUserMFAMethod(ctx context.Context, userID string) (string, error) {
	return "email", nil
}

// Remaining interface methods — unused by the wrong-guess path.
func (f *fakeOTPRepo) WithTx(ctx context.Context, fn func(tx Repository) error) error { return fn(f) }
func (f *fakeOTPRepo) GetUserByEmail(ctx context.Context, e string) (*db.User, error) {
	return nil, apperrors.ErrNotFound
}
func (f *fakeOTPRepo) GetUserByID(ctx context.Context, id string) (*db.User, error) {
	return nil, apperrors.ErrNotFound
}
func (f *fakeOTPRepo) CreateEmailToken(ctx context.Context, p db.CreateEmailTokenParams) error {
	return nil
}
func (f *fakeOTPRepo) InvalidateUserTokensByType(ctx context.Context, p db.InvalidateUserTokensByTypeParams) error {
	return nil
}
func (f *fakeOTPRepo) UpdateUserPasswordHash(ctx context.Context, p db.UpdateUserPasswordHashParams) error {
	return nil
}
func (f *fakeOTPRepo) MarkEmailVerified(ctx context.Context, id string) error      { return nil }
func (f *fakeOTPRepo) ClearEmailVerified(ctx context.Context, id string) error     { return nil }
func (f *fakeOTPRepo) RevokeUserRefreshTokens(ctx context.Context, u string) error { return nil }
func (f *fakeOTPRepo) EnqueueOutboxEmail(ctx context.Context, to, subject, html string) error {
	return nil
}
func (f *fakeOTPRepo) CreateRefreshToken(ctx context.Context, p db.CreateRefreshTokenParams) error {
	return nil
}
func (f *fakeOTPRepo) GetUserTOTPSecretEncrypted(ctx context.Context, u string) ([]byte, error) {
	return nil, ErrTOTPNotSetup
}
func (f *fakeOTPRepo) SetUserTOTPSecret(ctx context.Context, u string, s []byte) error { return nil }
func (f *fakeOTPRepo) EnableUserTOTP(ctx context.Context, u string) error              { return nil }
func (f *fakeOTPRepo) DisableUserTOTP(ctx context.Context, u string) error             { return nil }

type stubIssuer struct{}

func (stubIssuer) PrepareTokensForUser(ctx context.Context, userID string) (*platformauth.TokenPair, error) {
	return nil, errors.New("PrepareTokensForUser must not be called on the wrong-code path")
}

// TestVerifyOTP_EmailBruteForceBurnsChallenge proves the C3 fix: repeated wrong
// codes against one MFA challenge are counted, and the challenge is burned once
// OTP_MAX_ATTEMPTS is reached — capping brute force of the 6-digit code.
func TestVerifyOTP_EmailBruteForceBurnsChallenge(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer func() { _ = rdb.Close() }()

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

	repo := &fakeOTPRepo{
		challengeRaw: "raw-challenge-token",
		challenge: &db.EmailToken{
			ID:        "chal-1",
			UserID:    "u1",
			TokenType: "challenge",
			ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
		},
	}

	const maxAttempts = 3
	svc, err := NewService(
		repo, nil, zap.NewNop(), "http://localhost:3000",
		stubIssuer{}, bruteForceOTPSecret, maxAttempts,
		audit.New(zap.NewNop()), keySet, "test", 30, 6, replay, rdb, nil,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx := context.Background()
	for i := 1; i <= maxAttempts; i++ {
		_, err := svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "000000", MFAToken: "raw-challenge-token"})
		if err == nil {
			t.Fatalf("attempt %d: wrong code unexpectedly succeeded", i)
		}
	}

	if !repo.burned {
		t.Fatal("challenge was NOT burned after reaching OTP_MAX_ATTEMPTS — brute-force window is open")
	}
	if repo.attempts < maxAttempts {
		t.Fatalf("expected >= %d recorded attempts, got %d", maxAttempts, repo.attempts)
	}

	// A subsequent attempt now sees a burned challenge and is rejected up-front.
	if _, err := svc.VerifyOTP(ctx, VerifyOTPRequest{Code: "111111", MFAToken: "raw-challenge-token"}); err == nil {
		t.Fatal("burned challenge should reject further attempts")
	}
}
