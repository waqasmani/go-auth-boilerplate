package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	dbpkg "github.com/waqasmani/go-auth-boilerplate/internal/db"
	authmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth"
	emailmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/auth_email"
	usersmodule "github.com/waqasmani/go-auth-boilerplate/internal/modules/users"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/platform/database"
	"github.com/waqasmani/go-auth-boilerplate/internal/router"
	"github.com/waqasmani/go-auth-boilerplate/sql/migrations"
)

// ── Test harness ──────────────────────────────────────────────────────────────

// testServer holds a live httptest.Server wired against a real MariaDB instance.
type testServer struct {
	srv *httptest.Server
}

func (ts *testServer) url(path string) string {
	return ts.srv.URL + path
}

// setupTestServer wires all modules against the real DB configured via env and
// returns a running httptest.Server. All cleanup (DB close, server shutdown) is
// registered via t.Cleanup so callers never need to call Close themselves.
func setupTestServer(t *testing.T) *testServer {
	t.Helper()

	dsn := requireEnv(t, "DB_DSN")
	jwtSecret := requireEnv(t, "JWT_SECRET")

	log := zap.NewNop()

	// ── Database ───────────────────────────────────────────────────────────────
	sqlDB, err := database.New(database.DefaultConfig(dsn))
	if err != nil {
		t.Fatalf("setup: connect database: %v", err)
	}
	t.Cleanup(func() {
		if cerr := sqlDB.Close(); cerr != nil {
			t.Logf("setup: close database: %v", cerr)
		}
	})

	// ── Migrations ─────────────────────────────────────────────────────────────
	if err := database.RunMigrations(sqlDB, migrations.FS, log); err != nil {
		t.Fatalf("setup: run migrations: %v", err)
	}

	// ── Prepared statements ────────────────────────────────────────────────────
	prepCtx, prepCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer prepCancel()
	queries, err := dbpkg.Prepare(prepCtx, sqlDB)
	if err != nil {
		t.Fatalf("setup: prepare statements: %v", err)
	}
	t.Cleanup(func() {
		if cerr := queries.Close(); cerr != nil {
			t.Logf("setup: close prepared statements: %v", cerr)
		}
	})

	// ── JWT ────────────────────────────────────────────────────────────────────
	// JWTConfig uses a Keys slice (multi-key rotation support).
	// The legacy JWT_SECRET env var maps to a single entry with id="ci".
	accessTTL := parseDurationOrDefault(t, "JWT_ACCESS_TTL", 15*time.Minute)
	refreshTTL := parseDurationOrDefault(t, "JWT_REFRESH_TTL", 720*time.Hour)

	jwtHelper := platformauth.NewJWT(platformauth.JWTConfig{
		Keys: []platformauth.JWTKey{
			{ID: "ci", Secret: jwtSecret, Active: true},
		},
		Issuer:     envOrDefault("JWT_ISSUER", "go-auth-boilerplate"),
		Audience:   envOrDefault("JWT_AUDIENCE", "go-auth-boilerplate-users"),
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	})

	// ── Minimal config for handlers ────────────────────────────────────────────
	// We construct *config.Config directly rather than calling config.Load() so
	// the integration test does not depend on every optional env var being set
	// (e.g. FRONT_END_DOMAIN, CORS_*, SEC_*, …).
	cfg := &config.Config{
		AppEnv:         "test",
		AppPort:        "8080",
		FrontEndDomain: "http://localhost:3000",
		RefreshTTL:     refreshTTL,
		AccessTTL:      accessTTL,
		JWTKeys: []config.JWTKeyConfig{
			{ID: "ci", Secret: jwtSecret, Active: true},
		},
		JWTIssuer:   envOrDefault("JWT_ISSUER", "go-auth-boilerplate"),
		JWTAudience: envOrDefault("JWT_AUDIENCE", "go-auth-boilerplate-users"),
	}

	// ── Modules ────────────────────────────────────────────────────────────────
	authMod := authmodule.NewModule(authmodule.ModuleConfig{
		SqlDB:   sqlDB,
		Queries: queries,
		Jwt:     jwtHelper,
		Log:     log,
		Cfg:     cfg,
	})

	// Mailer is nil — email sending is disabled in CI.
	emailMod := emailmodule.NewModule(emailmodule.ModuleConfig{
		Queries:        queries,
		Mailer:         nil,
		Log:            log,
		FrontEndDomain: "http://localhost:3000",
		TokenIssuer:    authMod.Service,
		Cfg:            cfg,
	})

	// Complete bidirectional wiring (auth ↔ email-auth).
	authMod.Service.SetMFAChallenger(emailMod.Service)

	// users module — takes (*db.Queries, *zap.Logger), not *sql.DB.
	usersMod := usersmodule.NewModule(queries, log)

	// ── Router ─────────────────────────────────────────────────────────────────
	routerOpts := router.Options{
		RateLimit:     router.RateLimitConfigFromValues(100, 200, time.Minute, 10_000),
		CORS:          router.CORSConfigFromValues([]string{"http://localhost:3000"}, nil, true, 600),
		SecureHeaders: router.SecureHeadersConfigFromValues(false, 0),
		CookieCSRF:    router.CookieCSRFConfigFromValues("http://localhost:3000"),
	}
	engine := router.New("test", log, jwtHelper, authMod, usersMod, routerOpts, emailMod)

	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return &testServer{srv: srv}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// requireEnv returns the value of key, or skips the test if it is unset.
// This replaces the //go:build integration constraint: tests are always
// compiled (so go list / IDEs are happy) but skipped when the DB is absent.
func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("integration test skipped: env var %q is not set", key)
	}
	return v
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDurationOrDefault(t *testing.T, key string, fallback time.Duration) time.Duration {
	t.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		t.Fatalf("invalid duration for %s=%q: %v", key, raw, err)
	}
	return d
}

// postJSON fires a POST request with a JSON body and returns the decoded
// response body together with the HTTP status code. The response body is
// always drained and closed before returning, satisfying bodyclose.
func postJSON(t *testing.T, url string, payload any, extraHeaders ...string) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(extraHeaders); i += 2 {
		req.Header.Set(extraHeaders[i], extraHeaders[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	defer func() {
		_ = resp.Body.Close()
	}()
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return drainAndDecode(t, resp)
}

// postJSONDiscardBody fires a POST request and discards the response body.
// Use this for setup calls whose response content is not needed by the test.
func postJSONDiscardBody(t *testing.T, url string, payload any) {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if cerr := resp.Body.Close(); cerr != nil {
		t.Logf("postJSONDiscardBody: close body: %v", cerr)
	}
}

// getJSON fires a GET request with an optional Authorization header and
// returns the decoded response body and HTTP status code.
func getJSON(t *testing.T, url, bearer string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	defer func() {
		_ = resp.Body.Close()
	}()
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return drainAndDecode(t, resp)
}

// drainAndDecode reads, closes, and JSON-decodes an HTTP response body.
// Centralising this eliminates the bodyclose and errcheck findings at every
// call site.
func drainAndDecode(t *testing.T, resp *http.Response) (int, map[string]any) {
	t.Helper()
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			t.Logf("drainAndDecode: close body: %v", cerr)
		}
	}()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil && err != io.EOF {
		t.Fatalf("decode response body: %v", err)
	}
	return resp.StatusCode, m
}

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s+%d@integration.test", prefix, time.Now().UnixNano())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestIntegration_Register_Success verifies that POST /api/v1/auth/register
// returns 201 with access and refresh tokens for a new unique email.
func TestIntegration_Register_Success(t *testing.T) {
	ts := setupTestServer(t)

	status, body := postJSON(t, ts.url("/api/v1/auth/register"), map[string]string{
		"name":     "Integration User",
		"email":    uniqueEmail("register"),
		"password": "strongpassword1234",
	})

	if status != http.StatusCreated {
		t.Errorf("expected 201, got %d; body: %v", status, body)
	}
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected data object in response")
	}
	if data["access_token"] == "" || data["access_token"] == nil {
		t.Error("expected non-empty access_token")
	}
	if data["refresh_token"] == "" || data["refresh_token"] == nil {
		t.Error("expected non-empty refresh_token")
	}
}

// TestIntegration_Register_DuplicateEmail verifies that registering the same
// email twice returns 409 CONFLICT on the second attempt.
func TestIntegration_Register_DuplicateEmail(t *testing.T) {
	ts := setupTestServer(t)
	email := uniqueEmail("dup")

	// First registration — result not needed.
	postJSONDiscardBody(t, ts.url("/api/v1/auth/register"), map[string]string{
		"name":     "First User",
		"email":    email,
		"password": "strongpassword1234",
	})

	status, body := postJSON(t, ts.url("/api/v1/auth/register"), map[string]string{
		"name":     "Second User",
		"email":    email,
		"password": "strongpassword1234",
	})

	if status != http.StatusConflict {
		t.Errorf("expected 409, got %d; body: %v", status, body)
	}
}

// TestIntegration_Register_ValidationError verifies that a short password
// (< 12 chars) is rejected with 422.
func TestIntegration_Register_ValidationError(t *testing.T) {
	ts := setupTestServer(t)

	status, body := postJSON(t, ts.url("/api/v1/auth/register"), map[string]string{
		"name":     "User",
		"email":    uniqueEmail("val"),
		"password": "short",
	})

	if status != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d; body: %v", status, body)
	}
}

// TestIntegration_Login_InvalidCredentials verifies that a wrong password
// returns 401.
func TestIntegration_Login_InvalidCredentials(t *testing.T) {
	ts := setupTestServer(t)
	email := uniqueEmail("login-wrong")

	// Register — response not needed.
	postJSONDiscardBody(t, ts.url("/api/v1/auth/register"), map[string]string{
		"name":     "Login Test",
		"email":    email,
		"password": "correctpassword1234",
	})

	status, body := postJSON(t, ts.url("/api/v1/auth/login"), map[string]string{
		"email":    email,
		"password": "wrongpassword1234",
	})

	if status != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %v", status, body)
	}
}

// TestIntegration_Login_EmailNotVerified verifies that an account whose email
// has not been verified cannot log in (403 EMAIL_NOT_VERIFIED).
//
// Registration does NOT auto-verify email — email_verified_at stays NULL until
// the user clicks the verification link. This is the expected gate.
func TestIntegration_Login_EmailNotVerified(t *testing.T) {
	ts := setupTestServer(t)
	email := uniqueEmail("unverified")

	// Register — creates account with email_verified_at = NULL.
	postJSONDiscardBody(t, ts.url("/api/v1/auth/register"), map[string]string{
		"name":     "Unverified",
		"email":    email,
		"password": "correctpassword1234",
	})

	// Attempt login before email is verified.
	status, body := postJSON(t, ts.url("/api/v1/auth/login"), map[string]string{
		"email":    email,
		"password": "correctpassword1234",
	})

	if status != http.StatusForbidden {
		t.Errorf("expected 403, got %d; body: %v", status, body)
	}
	if errObj, ok := body["error"].(map[string]any); ok {
		if code, _ := errObj["code"].(string); code != "EMAIL_NOT_VERIFIED" {
			t.Errorf("expected EMAIL_NOT_VERIFIED error code, got %q", code)
		}
	}
}

// TestIntegration_Refresh_InvalidToken verifies that an invalid refresh token
// returns 401.
func TestIntegration_Refresh_InvalidToken(t *testing.T) {
	ts := setupTestServer(t)

	status, body := postJSON(t, ts.url("/api/v1/auth/refresh"), map[string]string{
		"refresh_token": "not-a-real-token",
	})

	if status != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %v", status, body)
	}
}

// TestIntegration_Logout_InvalidToken verifies that an unknown refresh token
// returns 204 (idempotent logout).
func TestIntegration_Logout_InvalidToken(t *testing.T) {
	ts := setupTestServer(t)

	status, body := postJSON(t, ts.url("/api/v1/auth/logout"), map[string]string{
		"refresh_token": "token-that-never-existed",
	})

	if status != http.StatusNoContent {
		t.Errorf("expected 204, got %d; body: %v", status, body)
	}
}

// TestIntegration_GetMe_Unauthorized verifies that /users/me rejects requests
// without a bearer token with 401.
func TestIntegration_GetMe_Unauthorized(t *testing.T) {
	ts := setupTestServer(t)

	status, body := getJSON(t, ts.url("/api/v1/users/me"), "")

	if status != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d; body: %v", status, body)
	}
}
