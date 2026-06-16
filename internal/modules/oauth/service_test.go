package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/audit"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test constants and shared fixtures
// ─────────────────────────────────────────────────────────────────────────────

const testStateSecret = "oauth-state-secret-at-least-32-bytes-long-xxxxx"

// newTestKeySet returns a SymmetricKeySet usable for encrypting OAuth tokens.
func newTestKeySet(t *testing.T) *platformauth.SymmetricKeySet {
	t.Helper()
	ks, err := platformauth.NewSymmetricKeySet([]platformauth.SymmetricKeyConfig{
		{ID: "k1", Key: "0123456789abcdef0123456789abcdef", Active: true},
	})
	if err != nil {
		t.Fatalf("NewSymmetricKeySet: %v", err)
	}
	return ks
}

// newTestRedis returns a go-redis client backed by an in-process miniredis,
// plus the miniredis handle so tests can simulate outages via mr.Close().
func newTestRedis(t *testing.T) (*goredis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake token endpoint
//
// HandleCallback calls p.Config().Exchange(ctx, code, ...), which performs a
// real HTTP POST to Endpoint.TokenURL. Rather than hit the network, the fake
// provider points TokenURL at this in-process httptest server, which returns a
// deterministic OAuth2 token JSON. This keeps the full callback flow testable
// without code changes.
// ─────────────────────────────────────────────────────────────────────────────

func newTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"prov-access","refresh_token":"prov-refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake Provider
// ─────────────────────────────────────────────────────────────────────────────

type fakeProvider struct {
	name          string
	cfg           *oauth2.Config
	verifiesEmail bool
	user          *ProviderUserInfo
	fetchErr      error
}

func newFakeProvider(name, tokenURL string, verifiesEmail bool, user *ProviderUserInfo) *fakeProvider {
	return &fakeProvider{
		name:          name,
		verifiesEmail: verifiesEmail,
		user:          user,
		cfg: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://api.example.com/oauth/" + name + "/callback",
			Scopes:       []string{"email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.example.com/authorize",
				TokenURL: tokenURL,
			},
		},
	}
}

func (f *fakeProvider) Name() string           { return f.name }
func (f *fakeProvider) Config() *oauth2.Config { return f.cfg }
func (f *fakeProvider) VerifiesEmail() bool    { return f.verifiesEmail }
func (f *fakeProvider) FetchUser(_ context.Context, _ *oauth2.Token) (*ProviderUserInfo, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.user, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake TokenIssuer
// ─────────────────────────────────────────────────────────────────────────────

type fakeTokenIssuer struct {
	mu          sync.Mutex
	lastUserID  string
	issueCalled int
	err         error
}

func (f *fakeTokenIssuer) IssueTokensForUser(_ context.Context, userID string) (*platformauth.SessionTokens, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issueCalled++
	f.lastUserID = userID
	if f.err != nil {
		return nil, f.err
	}
	now := time.Now().UTC()
	return &platformauth.SessionTokens{
		AccessToken:           "access-for-" + userID,
		RefreshToken:          "refresh-for-" + userID,
		TokenType:             "Bearer",
		AccessTokenExpiresAt:  now.Add(15 * time.Minute),
		RefreshTokenExpiresAt: now.Add(24 * time.Hour),
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake Repository
//
// Implements the full Repository interface. Behaviour is controllable via
// function hooks so each test can simulate the exact DB outcome it needs.
// Defaults: no existing account, no email collision, all writes succeed.
// ─────────────────────────────────────────────────────────────────────────────

type fakeRepo struct {
	mu sync.Mutex

	getByProviderIDFn func(ctx context.Context, provider, providerID string) (*OAuthAccount, error)
	getUserByEmailFn  func(ctx context.Context, email string) (string, bool, error)
	createUserFn      func(ctx context.Context, id, email, name string, verified bool) error
	createAccountFn   func(ctx context.Context, p CreateOAuthAccountParams) error
	linkFn            func(ctx context.Context, p CreateOAuthAccountParams) error
	storeOTCFn        func(ctx context.Context, p dbpkg.StoreOneTimeCodeParams) error
	consumeOTCFn      func(ctx context.Context, codeHash string) (string, error)
	getNameEmailFn    func(ctx context.Context, userID string) (string, string, error)

	createdUsers    int
	createdAccounts int
	storedOTC       int
	linkCalls       int
}

func (r *fakeRepo) CreateOAuthAccount(ctx context.Context, p CreateOAuthAccountParams) error {
	r.mu.Lock()
	r.createdAccounts++
	r.mu.Unlock()
	if r.createAccountFn != nil {
		return r.createAccountFn(ctx, p)
	}
	return nil
}

func (r *fakeRepo) GetOAuthAccountByProviderID(ctx context.Context, provider, providerID string) (*OAuthAccount, error) {
	if r.getByProviderIDFn != nil {
		return r.getByProviderIDFn(ctx, provider, providerID)
	}
	return nil, apperrors.ErrNotFound
}

func (r *fakeRepo) GetOAuthAccountByUserIDAndProvider(_ context.Context, _, _ string) (*OAuthAccount, error) {
	return nil, apperrors.ErrNotFound
}

func (r *fakeRepo) UpdateOAuthTokens(_ context.Context, _ UpdateOAuthTokensParams) error {
	return nil
}

func (r *fakeRepo) LinkOAuthAccountToUser(ctx context.Context, p CreateOAuthAccountParams) error {
	r.mu.Lock()
	r.linkCalls++
	r.mu.Unlock()
	if r.linkFn != nil {
		return r.linkFn(ctx, p)
	}
	return nil
}

// WithTx runs fn against the same fakeRepo (no real transaction needed).
func (r *fakeRepo) WithTx(ctx context.Context, fn func(tx Repository) error) error {
	return fn(r)
}

func (r *fakeRepo) CreateOAuthOnlyUser(ctx context.Context, id, email, name string, emailVerified bool) error {
	r.mu.Lock()
	r.createdUsers++
	r.mu.Unlock()
	if r.createUserFn != nil {
		return r.createUserFn(ctx, id, email, name, emailVerified)
	}
	return nil
}

func (r *fakeRepo) GetUserNameAndEmail(ctx context.Context, userID string) (string, string, error) {
	if r.getNameEmailFn != nil {
		return r.getNameEmailFn(ctx, userID)
	}
	return "Test User", "user@example.com", nil
}

func (r *fakeRepo) GetUserByEmail(ctx context.Context, email string) (string, bool, error) {
	if r.getUserByEmailFn != nil {
		return r.getUserByEmailFn(ctx, email)
	}
	return "", false, nil
}

func (r *fakeRepo) StoreLinkingState(_ context.Context, _ string, _ []byte, _ time.Time) error {
	return nil
}

func (r *fakeRepo) ConsumeLinkingState(_ context.Context, _ string) ([]byte, error) {
	return nil, ErrInvalidLinkingToken
}

func (r *fakeRepo) StoreOneTimeCode(ctx context.Context, p dbpkg.StoreOneTimeCodeParams) error {
	r.mu.Lock()
	r.storedOTC++
	r.mu.Unlock()
	if r.storeOTCFn != nil {
		return r.storeOTCFn(ctx, p)
	}
	return nil
}

func (r *fakeRepo) ConsumeOneTimeCode(ctx context.Context, codeHash string) (string, error) {
	if r.consumeOTCFn != nil {
		return r.consumeOTCFn(ctx, codeHash)
	}
	return "", ErrInvalidOneTimeCode
}

// ─────────────────────────────────────────────────────────────────────────────
// Service construction helper
// ─────────────────────────────────────────────────────────────────────────────

type svcHarness struct {
	svc    *service
	repo   *fakeRepo
	issuer *fakeTokenIssuer
	rdb    *goredis.Client
	mr     *miniredis.Miniredis
}

// newHarness wires a *service with the given provider and (optionally) a Redis
// backend. Pass withRedis=false to test the rdb==nil branch.
func newHarness(t *testing.T, prov *fakeProvider, withRedis bool) *svcHarness {
	t.Helper()
	repo := &fakeRepo{}
	issuer := &fakeTokenIssuer{}
	var rdb *goredis.Client
	var mr *miniredis.Miniredis
	if withRedis {
		rdb, mr = newTestRedis(t)
	}
	providers := map[string]Provider{prov.Name(): prov}
	s := NewService(
		nil, // *sql.DB unused by the fake repo
		repo,
		providers,
		issuer,
		newTestKeySet(t),
		testStateSecret,
		zap.NewNop(),
		audit.New(zap.NewNop()),
		rdb,
	).(*service)
	return &svcHarness{svc: s, repo: repo, issuer: issuer, rdb: rdb, mr: mr}
}

// buildState produces a valid signed state for provider and records the nonce
// in Redis exactly as BuildAuthURL would, so HandleCallback's single-use check
// has a nonce to consume.
func (h *svcHarness) buildState(t *testing.T, provider, redirectURL string) string {
	t.Helper()
	_, signed, err := h.svc.BuildAuthURL(context.Background(), provider, redirectURL)
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	return signed
}

func mustAppErr(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", wantCode)
	}
	ae, ok := apperrors.As(err)
	if !ok {
		t.Fatalf("expected an apperror with code %q, got %T: %v", wantCode, err, err)
	}
	if ae.Code != wantCode {
		t.Fatalf("expected error code %q, got %q (%v)", wantCode, ae.Code, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildAuthURL
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildAuthURL_RecordsNonceAndSignsState(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, nil)
	h := newHarness(t, prov, true)

	authURL, signed, err := h.svc.BuildAuthURL(context.Background(), "google", "https://app.example.com/cb")
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(authURL, "code_challenge") || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("auth URL missing PKCE params: %s", authURL)
	}

	st, err := platformauth.ParseAndVerifyOAuthState(signed, testStateSecret)
	if err != nil {
		t.Fatalf("returned state does not verify: %v", err)
	}
	// The nonce must have been recorded in Redis for single-use enforcement.
	if got := h.mr.Exists(oauthStateRedisKey(st.Nonce)); !got {
		t.Fatalf("expected nonce %q to be recorded in Redis", st.Nonce)
	}
}

func TestBuildAuthURL_UnknownProvider(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, nil)
	h := newHarness(t, prov, true)

	_, _, err := h.svc.BuildAuthURL(context.Background(), "facebook", "")
	mustAppErr(t, err, ErrProviderNotEnabled.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. State nonce single-use
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCallback_StateNonceSingleUse(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-123", Email: "alice@example.com", Name: "Alice", Verified: true,
	})
	h := newHarness(t, prov, true)
	// Returning-user fast path so the flow completes without DB writes.
	h.repo.getByProviderIDFn = func(_ context.Context, _, _ string) (*OAuthAccount, error) {
		return &OAuthAccount{UserID: "user-1", Provider: "google", ProviderID: "sub-123"}, nil
	}

	signed := h.buildState(t, "google", "")

	// First callback: succeeds and consumes the nonce.
	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("first callback should succeed: %v", err)
	}
	if resp.UserID != "user-1" || resp.Tokens == nil {
		t.Fatalf("unexpected first response: %+v", resp)
	}

	// Replay with the SAME state: nonce already consumed → rejected.
	_, err = h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	mustAppErr(t, err, ErrInvalidState.Code)
}

func TestHandleCallback_FailsOpenOnRedisOutage(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-out", Email: "out@example.com", Name: "Out", Verified: true,
	})
	h := newHarness(t, prov, true)
	h.repo.getByProviderIDFn = func(_ context.Context, _, _ string) (*OAuthAccount, error) {
		return &OAuthAccount{UserID: "user-out", Provider: "google", ProviderID: "sub-out"}, nil
	}

	signed := h.buildState(t, "google", "")
	// Simulate a Redis outage: consumeStateNonce must FAIL OPEN (not reject),
	// relying on the single-use IdP code + PKCE as primary protection.
	h.mr.Close()

	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("callback must fail OPEN on Redis outage, got error: %v", err)
	}
	if resp.UserID != "user-out" {
		t.Fatalf("unexpected response on fail-open: %+v", resp)
	}
}

func TestHandleCallback_NilRedisSkipsNonceCheck(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-nil", Email: "nil@example.com", Name: "Nil", Verified: true,
	})
	h := newHarness(t, prov, false) // rdb == nil
	h.repo.getByProviderIDFn = func(_ context.Context, _, _ string) (*OAuthAccount, error) {
		return &OAuthAccount{UserID: "user-nil", Provider: "google", ProviderID: "sub-nil"}, nil
	}

	// Sign a state directly; with rdb==nil there is nothing to record.
	signed, _, err := platformauth.SignOAuthState(platformauth.OAuthState{
		Provider: "google", RedirectURL: "", PKCEVerifier: "v",
	}, testStateSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("callback with nil Redis should succeed: %v", err)
	}
	if resp.UserID != "user-nil" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHandleCallback_TamperedStateRejected(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, nil)
	h := newHarness(t, prov, true)

	_, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", "garbage.notavalidstate")
	mustAppErr(t, err, ErrInvalidState.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Provider mismatch
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCallback_ProviderMismatchRejected(t *testing.T) {
	ts := newTokenServer(t)
	// Two providers registered so getProvider would succeed for either; the
	// mismatch must be caught by the state↔URL provider comparison, not by a
	// missing-provider error.
	google := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{ProviderID: "g", Verified: true})
	h := newHarness(t, google, true)
	h.svc.providers["facebook"] = newFakeProvider("facebook", ts.URL, false, &ProviderUserInfo{ProviderID: "f"})

	// State issued for google, but presented on the facebook callback.
	signed := h.buildState(t, "google", "")

	_, err := h.svc.HandleCallback(context.Background(), "facebook", "auth-code", signed)
	mustAppErr(t, err, ErrInvalidState.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// Email verification gate
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCallback_UnverifiedEmailRejected(t *testing.T) {
	ts := newTokenServer(t)
	// Provider verifies email, but the returned profile is unverified.
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-unv", Email: "unv@example.com", Name: "Unv", Verified: false,
	})
	h := newHarness(t, prov, true)

	signed := h.buildState(t, "google", "")
	_, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	mustAppErr(t, err, ErrUnverifiedEmail.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// New-user creation path
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCallback_NewUserCreatesAccountAndIssuesTokens(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-new", Email: "new@example.com", Name: "New", Verified: true,
	})
	h := newHarness(t, prov, true)
	// No existing account (default) and no email collision (default).

	signed := h.buildState(t, "google", "")
	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("new-user callback: %v", err)
	}
	if resp.Tokens == nil || resp.UserID == "" {
		t.Fatalf("expected tokens + user id for new web user, got %+v", resp)
	}
	if h.repo.createdUsers != 1 || h.repo.createdAccounts != 1 {
		t.Fatalf("expected 1 user + 1 account created, got users=%d accounts=%d",
			h.repo.createdUsers, h.repo.createdAccounts)
	}
	if h.issuer.lastUserID != resp.UserID {
		t.Fatalf("issuer called for %q, response user %q", h.issuer.lastUserID, resp.UserID)
	}
}

func TestHandleCallback_NewMobileUserReturnsOneTimeCode(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-mob", Email: "mob@example.com", Name: "Mob", Verified: true,
	})
	h := newHarness(t, prov, true)

	signed := h.buildState(t, "google", "com.myapp://oauth/callback")
	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("mobile new-user callback: %v", err)
	}
	if resp.OneTimeCode == "" {
		t.Fatal("expected a one-time code for the mobile path")
	}
	if resp.Tokens != nil {
		t.Fatal("mobile path must not return session tokens directly")
	}
	if h.repo.storedOTC != 1 {
		t.Fatalf("expected one-time code stored once, got %d", h.repo.storedOTC)
	}
	if h.issuer.issueCalled != 0 {
		t.Fatal("mobile path must not issue session tokens at callback time")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Account-linking collision path
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCallback_EmailCollisionRequiresLinking(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-col", Email: "collide@example.com", Name: "Col", Verified: true,
	})
	h := newHarness(t, prov, true)
	// No OAuth account for this provider-id, but the email already belongs to a
	// local account → explicit linking required.
	h.repo.getUserByEmailFn = func(_ context.Context, email string) (string, bool, error) {
		if email == "collide@example.com" {
			return "existing-user", true, nil
		}
		return "", false, nil
	}

	signed := h.buildState(t, "google", "")
	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("collision callback: %v", err)
	}
	if !resp.RequiresLinking {
		t.Fatalf("expected RequiresLinking=true, got %+v", resp)
	}
	if resp.LinkingToken == "" {
		t.Fatal("expected a non-empty linking token on collision")
	}
	if resp.Tokens != nil {
		t.Fatal("collision path must not issue tokens")
	}
	if h.repo.createdUsers != 0 {
		t.Fatalf("collision path must not create a user, created %d", h.repo.createdUsers)
	}
}

func TestHandleCallback_EmailCollisionSkippedForUnverifiedProvider(t *testing.T) {
	ts := newTokenServer(t)
	// Facebook-style provider: VerifiesEmail()==false. Even though the email
	// collides, no collision check runs — a brand-new user is created keyed on
	// the stable provider id only.
	prov := newFakeProvider("facebook", ts.URL, false, &ProviderUserInfo{
		ProviderID: "fb-1", Email: "collide@example.com", Name: "FB", Verified: false,
	})
	h := newHarness(t, prov, true)

	collisionChecked := false
	h.repo.getUserByEmailFn = func(_ context.Context, _ string) (string, bool, error) {
		collisionChecked = true
		return "existing-user", true, nil
	}

	signed := h.buildState(t, "facebook", "")
	resp, err := h.svc.HandleCallback(context.Background(), "facebook", "auth-code", signed)
	if err != nil {
		t.Fatalf("facebook callback: %v", err)
	}
	if collisionChecked {
		t.Fatal("collision check must be skipped for providers that do not verify email")
	}
	if resp.RequiresLinking {
		t.Fatal("unverified-email provider must not trigger linking")
	}
	if h.repo.createdUsers != 1 {
		t.Fatalf("expected new user created, got %d", h.repo.createdUsers)
	}
}

func TestHandleCallback_EmailConflictRaceFallsBackToLinking(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-race", Email: "race@example.com", Name: "Race", Verified: true,
	})
	h := newHarness(t, prov, true)
	// Collision check passes (no email found), but the transactional user insert
	// loses a race and returns the email-conflict error → issue a linking token.
	h.repo.createUserFn = func(_ context.Context, _, _, _ string, _ bool) error {
		return apperrors.ErrEmailAlreadyExists
	}

	signed := h.buildState(t, "google", "")
	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("email-conflict race callback: %v", err)
	}
	if !resp.RequiresLinking || resp.LinkingToken == "" {
		t.Fatalf("expected linking fallback on email-conflict race, got %+v", resp)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Returning-user mobile fast path
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCallback_ReturningMobileUserStoresCode(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-rm", Email: "rm@example.com", Name: "RM", Verified: true,
	})
	h := newHarness(t, prov, true)
	h.repo.getByProviderIDFn = func(_ context.Context, _, _ string) (*OAuthAccount, error) {
		return &OAuthAccount{UserID: "ret-user", Provider: "google", ProviderID: "sub-rm"}, nil
	}

	signed := h.buildState(t, "google", "com.myapp://cb")
	resp, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("returning mobile callback: %v", err)
	}
	if resp.UserID != "ret-user" || resp.OneTimeCode == "" {
		t.Fatalf("expected ret-user + one-time code, got %+v", resp)
	}
	if h.repo.storedOTC != 1 {
		t.Fatalf("expected one stored code, got %d", h.repo.storedOTC)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Token exchange + fetch-user failure handling
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCallback_CodeExchangeFailure(t *testing.T) {
	// Token server that returns 400 so oauth2.Exchange fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(srv.Close)
	prov := newFakeProvider("google", srv.URL, true, &ProviderUserInfo{ProviderID: "x", Verified: true})
	h := newHarness(t, prov, true)

	signed := h.buildState(t, "google", "")
	_, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	mustAppErr(t, err, "OAUTH_CODE_EXCHANGE_FAILED")
}

func TestHandleCallback_FetchUserFailure(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, nil)
	prov.fetchErr = errors.New("graph api down")
	h := newHarness(t, prov, true)

	signed := h.buildState(t, "google", "")
	_, err := h.svc.HandleCallback(context.Background(), "google", "auth-code", signed)
	// FetchUser failure is wrapped as ErrInternalServer.
	mustAppErr(t, err, apperrors.ErrInternalServer.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// IssueOneTimeCode / ExchangeOneTimeCode
// ─────────────────────────────────────────────────────────────────────────────

func TestIssueAndExchangeOneTimeCode(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, nil)
	h := newHarness(t, prov, true)

	var storedHash string
	h.repo.storeOTCFn = func(_ context.Context, p dbpkg.StoreOneTimeCodeParams) error {
		storedHash = p.CodeHash
		return nil
	}

	plain, err := h.svc.IssueOneTimeCode(context.Background(), "u-otc")
	if err != nil {
		t.Fatalf("IssueOneTimeCode: %v", err)
	}
	if plain == "" || storedHash == "" {
		t.Fatal("expected non-empty plaintext and stored hash")
	}

	// Exchange: repo returns the user id for the matching hash.
	h.repo.consumeOTCFn = func(_ context.Context, codeHash string) (string, error) {
		if codeHash != storedHash {
			return "", ErrInvalidOneTimeCode
		}
		return "u-otc", nil
	}

	resp, err := h.svc.ExchangeOneTimeCode(context.Background(), plain)
	if err != nil {
		t.Fatalf("ExchangeOneTimeCode: %v", err)
	}
	if resp.Tokens == nil {
		t.Fatal("expected session tokens from exchange")
	}
	if h.issuer.lastUserID != "u-otc" {
		t.Fatalf("issuer called for %q, want u-otc", h.issuer.lastUserID)
	}
}

func TestExchangeOneTimeCode_EmptyCode(t *testing.T) {
	ts := newTokenServer(t)
	h := newHarness(t, newFakeProvider("google", ts.URL, true, nil), true)
	_, err := h.svc.ExchangeOneTimeCode(context.Background(), "   ")
	mustAppErr(t, err, ErrInvalidOneTimeCode.Code)
}

func TestExchangeOneTimeCode_UnknownCode(t *testing.T) {
	ts := newTokenServer(t)
	h := newHarness(t, newFakeProvider("google", ts.URL, true, nil), true)
	// Default consumeOTCFn returns ErrInvalidOneTimeCode.
	_, err := h.svc.ExchangeOneTimeCode(context.Background(), "deadbeef")
	mustAppErr(t, err, ErrInvalidOneTimeCode.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// LinkAccount — full round-trip via a real StoreLinkingState/ConsumeLinkingState
// backed by the fake repo, exercising issueLinkingToken + verifyAndConsume.
// ─────────────────────────────────────────────────────────────────────────────

// linkingRepo augments fakeRepo with an in-memory linking-state store so a
// linking token issued during a collision can later be consumed by LinkAccount.
type linkingRepo struct {
	*fakeRepo
	mu       sync.Mutex
	payloads map[string][]byte
	expires  map[string]time.Time
}

func newLinkingRepo() *linkingRepo {
	return &linkingRepo{
		fakeRepo: &fakeRepo{},
		payloads: map[string][]byte{},
		expires:  map[string]time.Time{},
	}
}

func (r *linkingRepo) StoreLinkingState(_ context.Context, nonce string, payload []byte, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.payloads[nonce] = payload
	r.expires[nonce] = expiresAt
	return nil
}

func (r *linkingRepo) ConsumeLinkingState(_ context.Context, nonce string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.payloads[nonce]
	if !ok {
		return nil, ErrInvalidLinkingToken
	}
	if time.Now().UTC().After(r.expires[nonce]) {
		return nil, ErrInvalidLinkingToken
	}
	delete(r.payloads, nonce) // single-use
	return p, nil
}

func newLinkingHarness(t *testing.T, prov *fakeProvider) (*service, *linkingRepo, *miniredis.Miniredis) {
	t.Helper()
	repo := newLinkingRepo()
	rdb, mr := newTestRedis(t)
	s := NewService(
		nil, repo, map[string]Provider{prov.Name(): prov},
		&fakeTokenIssuer{}, newTestKeySet(t), testStateSecret,
		zap.NewNop(), audit.New(zap.NewNop()), rdb,
	).(*service)
	return s, repo, mr
}

func TestLinkAccount_RoundTrip(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-link", Email: "link@example.com", Name: "Link", Verified: true,
	})
	s, repo, _ := newLinkingHarness(t, prov)
	repo.getUserByEmailFn = func(_ context.Context, _ string) (string, bool, error) {
		return "existing-user", true, nil
	}

	// Drive a collision to obtain a real linking token.
	_, signed, err := s.BuildAuthURL(context.Background(), "google", "")
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	resp, err := s.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("collision callback: %v", err)
	}
	if !resp.RequiresLinking || resp.LinkingToken == "" {
		t.Fatalf("expected a linking token, got %+v", resp)
	}

	// Now link to the authenticated user.
	linkResp, err := s.LinkAccount(context.Background(), "auth-user-id", resp.LinkingToken)
	if err != nil {
		t.Fatalf("LinkAccount: %v", err)
	}
	if linkResp.Tokens == nil {
		t.Fatal("expected session tokens after linking")
	}
	if repo.linkCalls != 1 {
		t.Fatalf("expected LinkOAuthAccountToUser called once, got %d", repo.linkCalls)
	}

	// The linking token is single-use: replay must fail.
	_, err = s.LinkAccount(context.Background(), "auth-user-id", resp.LinkingToken)
	mustAppErr(t, err, ErrInvalidLinkingToken.Code)
}

func TestLinkAccount_ProviderAlreadyLinkedConflict(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, &ProviderUserInfo{
		ProviderID: "sub-dup", Email: "dup@example.com", Name: "Dup", Verified: true,
	})
	s, repo, _ := newLinkingHarness(t, prov)
	repo.getUserByEmailFn = func(_ context.Context, _ string) (string, bool, error) {
		return "existing-user", true, nil
	}
	// The link write hits a uniqueness conflict (provider already linked).
	repo.linkFn = func(_ context.Context, _ CreateOAuthAccountParams) error {
		return ErrOAuthAccountExists
	}

	_, signed, _ := s.BuildAuthURL(context.Background(), "google", "")
	resp, err := s.HandleCallback(context.Background(), "google", "auth-code", signed)
	if err != nil {
		t.Fatalf("collision callback: %v", err)
	}

	_, err = s.LinkAccount(context.Background(), "auth-user-id", resp.LinkingToken)
	mustAppErr(t, err, ErrOAuthAccountExists.Code)
}

func TestLinkAccount_InvalidToken(t *testing.T) {
	ts := newTokenServer(t)
	prov := newFakeProvider("google", ts.URL, true, nil)
	s, _, _ := newLinkingHarness(t, prov)

	_, err := s.LinkAccount(context.Background(), "auth-user-id", "not-a-valid-token")
	mustAppErr(t, err, ErrInvalidLinkingToken.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// Redirect allowlist (handler.validateRedirectURL) + redirect classification
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateRedirectURL_Allowlist(t *testing.T) {
	cfg := &config.Config{
		OAuthProviders: map[string]config.OAuthProviderConfig{
			"google": {
				Enabled:          true,
				AllowedRedirects: []string{"https://app.example.com/cb", "com.myapp://oauth/callback"},
			},
		},
	}
	h := NewHandler(nil, cfg)

	cases := []struct {
		name     string
		provider string
		url      string
		wantErr  string // "" == allowed
	}{
		{"empty allowed (defaults)", "google", "", ""},
		{"exact https match", "google", "https://app.example.com/cb", ""},
		{"trailing slash normalised", "google", "https://app.example.com/cb/", ""},
		{"custom scheme match", "google", "com.myapp://oauth/callback", ""},
		{"non-allowlisted https", "google", "https://evil.example.com/cb", ErrRedirectNotAllowed.Code},
		{"plain http rejected", "google", "http://app.example.com/cb", ErrRedirectNotAllowed.Code},
		{"unknown provider", "facebook", "https://app.example.com/cb", ErrProviderNotEnabled.Code},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := h.validateRedirectURL(tc.provider, tc.url)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected allowed, got %v", err)
				}
				return
			}
			mustAppErr(t, err, tc.wantErr)
		})
	}
}

func TestClassifyRedirect(t *testing.T) {
	cases := []struct {
		url  string
		want redirectKind
	}{
		{"", redirectKindNone},
		{"https://app.example.com/cb", redirectKindWeb},
		{"http://app.example.com/cb", redirectKindNone},
		{"com.myapp://oauth/callback", redirectKindMobile},
		{"myapp://cb", redirectKindMobile},
	}
	for _, tc := range cases {
		if got := classifyRedirect(tc.url); got != tc.want {
			t.Fatalf("classifyRedirect(%q) = %d, want %d", tc.url, got, tc.want)
		}
	}
}

func TestAppendQueryParam(t *testing.T) {
	got := appendQueryParam("com.myapp://cb", "code", "abc123")
	if !strings.Contains(got, "code=abc123") {
		t.Fatalf("expected code param appended, got %q", got)
	}
	got2 := appendQueryParam("https://app.example.com/cb?foo=bar", "code", "x")
	if !strings.Contains(got2, "foo=bar") || !strings.Contains(got2, "code=x") {
		t.Fatalf("expected both params preserved, got %q", got2)
	}
}
