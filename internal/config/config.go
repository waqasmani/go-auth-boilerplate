package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all application configuration.
type Config struct {
	AppEnv      string
	AppPort     string
	DBDSN       string
	JWTSecret   string
	JWTIssuer   string
	JWTAudience string
	AccessTTL   time.Duration
	RefreshTTL  time.Duration

	// ─── Rate Limiting ────────────────────────────────────────────────────────
	RateLimitRate    float64
	RateLimitBurst   int
	RateLimitTTL     time.Duration
	RateLimitMaxKeys int

	// ─── CORS ────────────────────────────────────────────────────────────────
	CORSAllowedOrigins   []string
	CORSAllowedHeaders   []string
	CORSAllowCredentials bool
	CORSMaxAge           int

	// ─── Secure Headers ───────────────────────────────────────────────────────
	// SecHSTSEnabled controls whether the Strict-Transport-Security header is
	// written on every response.  Must only be true when the service is
	// reachable exclusively over HTTPS — HSTS sent over plain HTTP can lock
	// users out of the site for the entire SecHSTSMaxAge window.
	// Default: false (dev).  Set to true in production.
	SecHSTSEnabled bool

	// SecHSTSMaxAge is the HSTS max-age directive in seconds.  Two years
	// (63 072 000 s) is the threshold required for HSTS preloading and is a
	// practical production default.  Only used when SecHSTSEnabled is true.
	SecHSTSMaxAge int
}

// MissingEnvError is returned by Load when one or more required environment
// variables are absent. It lists every missing key in a single error so the
// operator can fix all gaps in one deployment cycle rather than discovering
// them one at a time.
type MissingEnvError struct {
	Keys []string
}

func (e *MissingEnvError) Error() string {
	return fmt.Sprintf(
		"config: missing required environment variable(s): %s",
		strings.Join(e.Keys, ", "),
	)
}

// IsMissingEnvError reports whether err (or any error in its chain) is a
// *MissingEnvError. Mirrors the errors.As pattern so callers can inspect the
// missing key list without a type assertion at every call site.
func IsMissingEnvError(err error) bool {
	var target *MissingEnvError
	return errors.As(err, &target)
}

// Load reads configuration from the environment (and optional .env file).
// It returns a *MissingEnvError when any required variable is absent, and a
// plain error when a value is present but cannot be parsed. Load never panics.
func Load() (*Config, error) {
	// Load .env if present — silently ignored when missing (production injects
	// real environment variables directly).
	_ = godotenv.Load()

	// ── Required variables ───────────────────────────────────────────────────
	// Collect every missing key before returning so the operator sees the
	// complete list of gaps in one error, not just the first one encountered.
	r := &requiredReader{}
	dbDSN := r.get("DB_DSN")
	jwtSecret := r.get("JWT_SECRET")
	if err := r.err(); err != nil {
		return nil, err
	}

	// ── Optional variables with defaults ─────────────────────────────────────
	cfg := &Config{
		AppEnv:      getEnv("APP_ENV", "development"),
		AppPort:     getEnv("APP_PORT", "8080"),
		DBDSN:       dbDSN,
		JWTSecret:   jwtSecret,
		JWTIssuer:   getEnv("JWT_ISSUER", "go-auth-boilerplate"),
		JWTAudience: getEnv("JWT_AUDIENCE", "go-auth-boilerplate-users"),

		RateLimitRate:    parseFloat("RATE_LIMIT_RATE", 5.0),
		RateLimitBurst:   parseInt("RATE_LIMIT_BURST", 10),
		RateLimitMaxKeys: parseInt("RATE_LIMIT_MAX_KEYS", 10_000),

		CORSAllowedOrigins:   parseStringSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
		CORSAllowedHeaders:   parseStringSlice("CORS_ALLOWED_HEADERS", []string{"Authorization", "Content-Type", "X-Request-ID"}),
		CORSAllowCredentials: parseBool("CORS_ALLOW_CREDENTIALS", true),
		CORSMaxAge:           parseInt("CORS_MAX_AGE", 43200), // 12 hours

		// HSTS is opt-in: default false so development over plain HTTP is safe.
		// Operators must explicitly set SEC_HSTS_ENABLED=true in production.
		SecHSTSEnabled: parseBool("SEC_HSTS_ENABLED", false),
		SecHSTSMaxAge:  parseInt("SEC_HSTS_MAX_AGE", 63_072_000), // 2 years
	}

	// ── Duration fields ───────────────────────────────────────────────────────
	var err error
	cfg.AccessTTL, err = parseDuration("JWT_ACCESS_TTL", "15m")
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	cfg.RefreshTTL, err = parseDuration("JWT_REFRESH_TTL", "720h")
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	cfg.RateLimitTTL, err = parseDuration("RATE_LIMIT_TTL", "10m")
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return cfg, nil
}

// ─── requiredReader ───────────────────────────────────────────────────────────

// requiredReader accumulates missing required variable names so Load can report
// all of them in a single error instead of failing on the first missing key.
type requiredReader struct {
	missing []string
}

// get returns the value of key, or "" if absent. The key is recorded in the
// missing list when the variable is not set.
func (r *requiredReader) get(key string) string {
	v := os.Getenv(key)
	if v == "" {
		r.missing = append(r.missing, key)
	}
	return v
}

// err returns a *MissingEnvError listing every absent key, or nil when all
// required variables were present.
func (r *requiredReader) err() error {
	if len(r.missing) == 0 {
		return nil
	}
	return &MissingEnvError{Keys: r.missing}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(key, fallback string) (time.Duration, error) {
	raw := getEnv(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s=%q: %w", key, raw, err)
	}
	return d, nil
}

func parseFloat(key string, fallback float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return v
}

func parseInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func parseBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

// parseStringSlice splits a comma-separated env var into a trimmed string
// slice, returning fallback when the variable is absent or empty.
func parseStringSlice(key string, fallback []string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}
