// Package config holds all application configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all application configuration.
type Config struct {
	AppEnv  string
	AppPort string
	DBDSN   string

	// JWTKeys is the full signing key set.  Exactly one entry must have
	// Active: true (used to sign new tokens).  All entries are used during
	// validation so tokens issued before a key rotation continue to work
	// until they expire naturally.
	//
	// Set via JWT_KEYS (JSON array, see JWTKeyConfig).
	// Legacy fallback: JWT_SECRET + optional JWT_KEY_ID.
	JWTKeys     []JWTKeyConfig
	JWTIssuer   string
	JWTAudience string
	AccessTTL   time.Duration
	RefreshTTL  time.Duration

	// ─── Rate Limiting ────────────────────────────────────────────────────────
	RateLimitRate    float64
	RateLimitBurst   int
	RateLimitTTL     time.Duration
	RateLimitMaxKeys int

	CORSAllowedOrigins   []string
	CORSAllowedHeaders   []string
	CORSAllowCredentials bool
	CORSMaxAge           int

	// ─── Front End Domain ───────────────────────────────────────────────────────
	FrontEndDomain string

	// ─── Secure Headers ───────────────────────────────────────────────────────
	SecHSTSEnabled bool
	SecHSTSMaxAge  int

	// TrustedProxyCIDRs is the list of CIDR blocks that are allowed to set
	// X-Forwarded-For / X-Real-IP headers.  Should be the CIDR of your LB
	// or ingress controller.  Empty means no proxy is trusted (direct mode).
	TrustedProxyCIDRs []string
}

// JWTKeyConfig is a single signing key entry as stored in config / env vars.
// It maps directly to platformauth.JWTKey; kept in the config package to
// avoid an import cycle (platform/auth → config would create a cycle).
//
// JSON encoding matches the JWT_KEYS environment variable format:
//
//	JWT_KEYS=[{"id":"v1","secret":"…","active":true},{"id":"v2","secret":"…","active":false}]
//
// Rules enforced by Load:
//   - every entry must have a non-empty id and non-empty secret
//   - no two entries may share the same id
//   - exactly one entry must have "active": true
type JWTKeyConfig struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Active bool   `json:"active"`
}

// MissingEnvError is returned by Load when one or more required environment
// variables are absent.
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
// *MissingEnvError.
func IsMissingEnvError(err error) bool {
	var target *MissingEnvError
	return errors.As(err, &target)
}

// Load reads configuration from the environment (and optional .env file).
// It returns a *MissingEnvError when any required variable is absent, and a
// plain error when a value is present but cannot be parsed.
func Load() (*Config, error) {
	_ = godotenv.Load()

	// ── JWT key set ───────────────────────────────────────────────────────────
	// JWT_KEYS (JSON array) takes precedence; JWT_SECRET is the legacy fallback.
	jwtKeys, err := loadJWTKeys()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	// ── Required variables ────────────────────────────────────────────────────
	r := &requiredReader{}
	dbDSN := r.get("DB_DSN")
	if err := r.err(); err != nil {
		return nil, err
	}

	// ── Optional variables with defaults ──────────────────────────────────────
	cfg := &Config{
		AppEnv:      getEnv("APP_ENV", "development"),
		AppPort:     getEnv("APP_PORT", "8080"),
		DBDSN:       dbDSN,
		JWTKeys:     jwtKeys,
		JWTIssuer:   getEnv("JWT_ISSUER", "go-auth-boilerplate"),
		JWTAudience: getEnv("JWT_AUDIENCE", "go-auth-boilerplate-users"),

		RateLimitRate:    parseFloat("RATE_LIMIT_RATE", 5.0),
		RateLimitBurst:   parseInt("RATE_LIMIT_BURST", 10),
		RateLimitMaxKeys: parseInt("RATE_LIMIT_MAX_KEYS", 10_000),

		CORSAllowedOrigins:   parseStringSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
		CORSAllowedHeaders:   parseStringSlice("CORS_ALLOWED_HEADERS", []string{"Authorization", "Content-Type", "X-Request-ID"}),
		CORSAllowCredentials: parseBool("CORS_ALLOW_CREDENTIALS", true),
		CORSMaxAge:           parseInt("CORS_MAX_AGE", 43200),

		FrontEndDomain:    getEnv("FRONT_END_DOMAIN", "http://localhost:3000"),
		SecHSTSEnabled:    parseBool("SEC_HSTS_ENABLED", false),
		SecHSTSMaxAge:     parseInt("SEC_HSTS_MAX_AGE", 63_072_000),
		TrustedProxyCIDRs: parseStringSlice("TRUSTED_PROXY_CIDRS", []string{"10.0.0.0/8"}),
	}

	if cfg.FrontEndDomain == "" {
		return nil, fmt.Errorf("config: FRONT_END_DOMAIN is required")
	}
	u, err := url.Parse(cfg.FrontEndDomain)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("config: FRONT_END_DOMAIN=%q is not a valid URL with a hostname", cfg.FrontEndDomain)
	}
	// ── Duration fields ───────────────────────────────────────────────────────
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

// ─── JWT key loading ──────────────────────────────────────────────────────────

// loadJWTKeys resolves the signing key set from the environment.
//
// Resolution order:
//  1. JWT_KEYS — JSON array of JWTKeyConfig objects.  Preferred for new
//     deployments and required once key rotation is needed.
//  2. JWT_SECRET — legacy single-secret fallback.  Wrapped into a
//     JWTKeyConfig with id = JWT_KEY_ID (default "default").
//
// Returns an error when neither variable is set or when the resulting key
// set fails validation.
func loadJWTKeys() ([]JWTKeyConfig, error) {
	if raw := os.Getenv("JWT_KEYS"); raw != "" {
		var keys []JWTKeyConfig
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			return nil, fmt.Errorf("JWT_KEYS: invalid JSON: %w", err)
		}
		if err := validateJWTKeys(keys); err != nil {
			return nil, fmt.Errorf("JWT_KEYS: %w", err)
		}
		return keys, nil
	}

	// Legacy path: a single JWT_SECRET.
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, &MissingEnvError{Keys: []string{"JWT_KEYS (or legacy JWT_SECRET)"}}
	}

	// JWT_KEY_ID lets operators pre-assign a stable kid to the legacy secret so
	// that when they later migrate to JWT_KEYS they can keep the same id and
	// avoid invalidating live tokens during the migration window.
	id := getEnv("JWT_KEY_ID", "default")

	return []JWTKeyConfig{{ID: id, Secret: secret, Active: true}}, nil
}

// validateJWTKeys enforces the invariants required by platformauth.NewJWT.
// Duplicating the checks here (rather than relying solely on the panic in
// NewJWT) produces actionable config errors at startup before any JWT helper
// is constructed.
func validateJWTKeys(keys []JWTKeyConfig) error {
	if len(keys) == 0 {
		return fmt.Errorf("array is empty — provide at least one key")
	}

	seen := make(map[string]struct{}, len(keys))
	activeCount := 0

	for i, k := range keys {
		if k.ID == "" {
			return fmt.Errorf("key[%d] has an empty id", i)
		}
		if k.Secret == "" {
			return fmt.Errorf("key %q has an empty secret", k.ID)
		}
		// ── NEW ──────────────────────────────────────────────────────────────
		// RFC 7518 §3.2 requires the HMAC key to be at least as long as the
		// hash output. For HS256 that is 32 bytes. Shorter keys are structurally
		// accepted by the JWT library but are cryptographically weak.
		if len(k.Secret) < 32 {
			return fmt.Errorf(
				"key %q secret is %d bytes — minimum 32 bytes required for HS256 (RFC 7518 §3.2)",
				k.ID, len(k.Secret),
			)
		}
		// ─────────────────────────────────────────────────────────────────────
		if _, dup := seen[k.ID]; dup {
			return fmt.Errorf("duplicate key id %q", k.ID)
		}
		seen[k.ID] = struct{}{}
		if k.Active {
			activeCount++
		}
	}

	switch activeCount {
	case 0:
		return fmt.Errorf("no key has \"active\": true — exactly one key must be active")
	case 1:
		return nil
	default:
		return fmt.Errorf("%d keys have \"active\": true — exactly one key must be active", activeCount)
	}
}

// ─── requiredReader ───────────────────────────────────────────────────────────

type requiredReader struct {
	missing []string
}

func (r *requiredReader) get(key string) string {
	v := os.Getenv(key)
	if v == "" {
		r.missing = append(r.missing, key)
	}
	return v
}

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

// sanitizeNumericEnv strips underscore thousand-separators that are valid in
// Go numeric literals (e.g. "10_000") but are rejected by strconv functions.
// It also trims leading/trailing whitespace for good measure.
func sanitizeNumericEnv(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "_", "")
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
	v, err := strconv.ParseFloat(sanitizeNumericEnv(raw), 64)
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
	v, err := strconv.Atoi(sanitizeNumericEnv(raw))
	if err != nil {
		// Panic or return a sentinel; at minimum, log loudly.
		panic(fmt.Sprintf("config: %s=%q is not a valid integer", key, raw))
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
