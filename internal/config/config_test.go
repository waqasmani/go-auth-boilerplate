package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
)

// setenv sets one or more key=value pairs for the duration of a test and
// restores the original environment on cleanup. Keys with an empty value
// are unset (os.Unsetenv) rather than set to "".
func setenv(t *testing.T, pairs ...string) {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatal("setenv: pairs must be key, value, key, value, ...")
	}
	for i := 0; i < len(pairs); i += 2 {
		key, val := pairs[i], pairs[i+1]
		t.Setenv(key, val) // t.Setenv restores the original value on cleanup
		_ = val            // already handled by t.Setenv
	}
}

// minimalEnv sets the two required variables to valid values.
// Tests that want to exercise optional-variable behaviour call this first, then
// override the specific vars they care about.
func minimalEnv(t *testing.T) {
	t.Helper()
	setenv(t,
		"DB_DSN", "user:pass@tcp(localhost:3306)/testdb",
		"JWT_SECRET", "test-secret-at-least-32-chars-long!!",
	)
}

// ─── Required variable tests ──────────────────────────────────────────────────

func TestLoad_AllRequiredPresent(t *testing.T) {
	minimalEnv(t)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	if cfg.DBDSN == "" {
		t.Error("Config.DBDSN must not be empty")
	}
}

func TestLoad_BothRequiredMissing(t *testing.T) {
	// loadJWTKeys() runs first and returns early, so only the JWT error is
	// collected — DB_DSN is never reached in the current Load() flow.
	cfg, err := config.Load()
	if err == nil {
		t.Fatal("Load() expected error when required vars are absent, got nil")
	}
	if cfg != nil {
		t.Error("Load() must return nil config on error")
	}

	var missingErr *config.MissingEnvError
	if !errors.As(err, &missingErr) {
		t.Fatalf("error is %T, want *config.MissingEnvError", err)
	}
	// loadJWTKeys returns first; DB_DSN check never runs when JWT is missing.
	if len(missingErr.Keys) != 1 {
		t.Errorf("MissingEnvError.Keys = %v (len %d), want exactly 1 key",
			missingErr.Keys, len(missingErr.Keys))
	}
	if len(missingErr.Keys) > 0 && missingErr.Keys[0] != "JWT_KEYS (or legacy JWT_SECRET)" {
		t.Errorf("MissingEnvError.Keys[0] = %q, want %q",
			missingErr.Keys[0], "JWT_KEYS (or legacy JWT_SECRET)")
	}
}

func TestLoad_OnlyDBDSNMissing(t *testing.T) {
	setenv(t, "JWT_SECRET", "test-secret-at-least-32-chars-long!!")
	// DB_DSN intentionally absent.

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() expected error when DB_DSN is absent")
	}

	var missingErr *config.MissingEnvError
	if !errors.As(err, &missingErr) {
		t.Fatalf("error is %T, want *config.MissingEnvError", err)
	}
	if len(missingErr.Keys) != 1 || missingErr.Keys[0] != "DB_DSN" {
		t.Errorf("MissingEnvError.Keys = %v, want [DB_DSN]", missingErr.Keys)
	}
}

func TestLoad_OnlyJWTSecretMissing(t *testing.T) {
	setenv(t, "DB_DSN", "user:pass@tcp(localhost:3306)/testdb")
	// JWT_SECRET intentionally absent.

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() expected error when JWT_SECRET is absent")
	}

	var missingErr *config.MissingEnvError
	if !errors.As(err, &missingErr) {
		t.Fatalf("error is %T, want *config.MissingEnvError", err)
	}
	// The key name changed when JWT_KEYS support was added.
	wantKey := "JWT_KEYS (or legacy JWT_SECRET)"
	if len(missingErr.Keys) != 1 || missingErr.Keys[0] != wantKey {
		t.Errorf("MissingEnvError.Keys = %v, want [%s]", missingErr.Keys, wantKey)
	}
}

// TestLoad_NeverPanics ensures Load returns an error instead of panicking.
// It runs in a subprocess via t.Run so a panic would be caught as a test
// failure rather than crashing the whole test binary.
func TestLoad_NeverPanics(t *testing.T) {
	// No required variables set — would have panicked in the old code.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Load() panicked: %v", r)
		}
	}()
	_, _ = config.Load()
}

// ─── MissingEnvError ──────────────────────────────────────────────────────────

func TestMissingEnvError_ErrorMessage(t *testing.T) {
	err := &config.MissingEnvError{Keys: []string{"DB_DSN", "JWT_SECRET"}}
	msg := err.Error()

	if !strings.Contains(msg, "DB_DSN") {
		t.Errorf("error message %q must contain DB_DSN", msg)
	}
	if !strings.Contains(msg, "JWT_SECRET") {
		t.Errorf("error message %q must contain JWT_SECRET", msg)
	}
}

func TestIsMissingEnvError_True(t *testing.T) {
	err := &config.MissingEnvError{Keys: []string{"DB_DSN"}}
	if !config.IsMissingEnvError(err) {
		t.Error("IsMissingEnvError should return true for *MissingEnvError")
	}
}

func TestIsMissingEnvError_FalseForOtherErrors(t *testing.T) {
	if config.IsMissingEnvError(errors.New("some other error")) {
		t.Error("IsMissingEnvError should return false for a plain error")
	}
	if config.IsMissingEnvError(nil) {
		t.Error("IsMissingEnvError should return false for nil")
	}
}

func TestIsMissingEnvError_TrueForWrappedError(t *testing.T) {
	wrapped := errors.Join(
		errors.New("outer"),
		&config.MissingEnvError{Keys: []string{"DB_DSN"}},
	)
	if !config.IsMissingEnvError(wrapped) {
		t.Error("IsMissingEnvError should return true for a wrapped *MissingEnvError")
	}
}

// ─── Optional variables and defaults ─────────────────────────────────────────

func TestLoad_DefaultValues(t *testing.T) {
	minimalEnv(t)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.AppEnv != "development" {
		t.Errorf("AppEnv = %q, want %q", cfg.AppEnv, "development")
	}
	if cfg.AppPort != "8080" {
		t.Errorf("AppPort = %q, want %q", cfg.AppPort, "8080")
	}
	if cfg.JWTIssuer != "go-auth-boilerplate" {
		t.Errorf("JWTIssuer = %q, want %q", cfg.JWTIssuer, "go-auth-boilerplate")
	}
	if cfg.RateLimitRate != 5.0 {
		t.Errorf("RateLimitRate = %v, want 5.0", cfg.RateLimitRate)
	}
	if cfg.RateLimitBurst != 10 {
		t.Errorf("RateLimitBurst = %d, want 10", cfg.RateLimitBurst)
	}
	if cfg.CORSMaxAge != 43200 {
		t.Errorf("CORSMaxAge = %d, want 43200", cfg.CORSMaxAge)
	}
	if cfg.AccessTTL.String() != "15m0s" {
		t.Errorf("AccessTTL = %v, want 15m0s", cfg.AccessTTL)
	}
	if cfg.RefreshTTL.String() != "720h0m0s" {
		t.Errorf("RefreshTTL = %v, want 720h0m0s", cfg.RefreshTTL)
	}
}

func TestLoad_OverridesDefaults(t *testing.T) {
	minimalEnv(t)
	setenv(t,
		"APP_ENV", "production",
		"APP_PORT", "9090",
		"JWT_ACCESS_TTL", "30m",
		"RATE_LIMIT_RATE", "20",
		"RATE_LIMIT_BURST", "50",
	)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.AppEnv != "production" {
		t.Errorf("AppEnv = %q, want production", cfg.AppEnv)
	}
	if cfg.AppPort != "9090" {
		t.Errorf("AppPort = %q, want 9090", cfg.AppPort)
	}
	if cfg.AccessTTL.String() != "30m0s" {
		t.Errorf("AccessTTL = %v, want 30m0s", cfg.AccessTTL)
	}
	if cfg.RateLimitRate != 20.0 {
		t.Errorf("RateLimitRate = %v, want 20.0", cfg.RateLimitRate)
	}
	if cfg.RateLimitBurst != 50 {
		t.Errorf("RateLimitBurst = %d, want 50", cfg.RateLimitBurst)
	}
}

// ─── Invalid duration values ──────────────────────────────────────────────────

func TestLoad_InvalidAccessTTL(t *testing.T) {
	minimalEnv(t)
	setenv(t, "JWT_ACCESS_TTL", "not-a-duration")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() expected error for invalid JWT_ACCESS_TTL")
	}
	if config.IsMissingEnvError(err) {
		t.Error("error should not be a MissingEnvError for an invalid duration")
	}
	if !strings.Contains(err.Error(), "JWT_ACCESS_TTL") {
		t.Errorf("error message %q should mention JWT_ACCESS_TTL", err.Error())
	}
}

func TestLoad_InvalidRefreshTTL(t *testing.T) {
	minimalEnv(t)
	setenv(t, "JWT_REFRESH_TTL", "bad")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() expected error for invalid JWT_REFRESH_TTL")
	}
	if !strings.Contains(err.Error(), "JWT_REFRESH_TTL") {
		t.Errorf("error message %q should mention JWT_REFRESH_TTL", err.Error())
	}
}

func TestLoad_InvalidRateLimitTTL(t *testing.T) {
	minimalEnv(t)
	setenv(t, "RATE_LIMIT_TTL", "???")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load() expected error for invalid RATE_LIMIT_TTL")
	}
	if !strings.Contains(err.Error(), "RATE_LIMIT_TTL") {
		t.Errorf("error message %q should mention RATE_LIMIT_TTL", err.Error())
	}
}

// ─── CORS configuration ───────────────────────────────────────────────────────

func TestLoad_CORSAllowedOriginsFromEnv(t *testing.T) {
	minimalEnv(t)
	setenv(t, "CORS_ALLOWED_ORIGINS", "https://app.example.com,https://admin.example.com")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if len(cfg.CORSAllowedOrigins) != 2 {
		t.Fatalf("CORSAllowedOrigins = %v (len %d), want 2 entries",
			cfg.CORSAllowedOrigins, len(cfg.CORSAllowedOrigins))
	}
	if cfg.CORSAllowedOrigins[0] != "https://app.example.com" {
		t.Errorf("CORSAllowedOrigins[0] = %q, want https://app.example.com",
			cfg.CORSAllowedOrigins[0])
	}
}

func TestLoad_CORSDefaultOriginIsLocalhost(t *testing.T) {
	minimalEnv(t)
	// CORS_ALLOWED_ORIGINS intentionally not set.

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if len(cfg.CORSAllowedOrigins) == 0 {
		t.Fatal("CORSAllowedOrigins must not be empty when using defaults")
	}
	if cfg.CORSAllowedOrigins[0] != "http://localhost:3000" {
		t.Errorf("default CORSAllowedOrigins[0] = %q, want http://localhost:3000",
			cfg.CORSAllowedOrigins[0])
	}
}

func TestLoad_CORSAllowCredentialsFromEnv(t *testing.T) {
	minimalEnv(t)
	setenv(t, "CORS_ALLOW_CREDENTIALS", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.CORSAllowCredentials {
		t.Error("CORSAllowCredentials should be false when CORS_ALLOW_CREDENTIALS=false")
	}
}
