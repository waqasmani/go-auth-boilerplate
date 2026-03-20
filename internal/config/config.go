// Package config holds all application configuration.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all application configuration.
type Config struct {
	AppEnv         string
	AppPort        string
	DBDSN          string
	SkipMigrations bool

	// JWT
	JWTKeys     []JWTKeyConfig
	JWTIssuer   string
	JWTAudience string
	AccessTTL   time.Duration
	RefreshTTL  time.Duration

	// Security Secrets
	OTPSecret        string
	OAuthStateSecret string

	// Redis (always required)
	RedisDSN      string
	RedisPoolSize int

	// Rate Limiting
	RateLimitRate    float64
	RateLimitBurst   int
	RateLimitTTL     time.Duration
	RateLimitMaxKeys int

	// Per-endpoint Rate Limits
	RateLimitLoginEmail     float64
	RateLimitForgotPassword float64
	RateLimitResendVerify   float64
	RateLimitResetPassword  float64
	RateLimitVerifyEmail    float64
	RateLimitOTPVerify      float64
	RateLimitAuthRefresh    float64

	// OAuth Rate Limits
	RateLimitOAuthLogin    float64
	RateLimitOAuthCallback float64
	RateLimitOAuthLink     float64
	RateLimitOAuthExchange float64

	// CORS
	CORSAllowedOrigins   []string
	CORSAllowedHeaders   []string
	CORSAllowCredentials bool
	CORSMaxAge           int

	// Front End & Cookies
	FrontEndDomain string
	CookieDomain   string
	CookieSameSite string
	CookieSecure   bool

	// CookieCSRF
	CookieCSRF         string   // primary origin (FrontEndDomain)
	CSRFTrustedOrigins []string // CSRF_TRUSTED_ORIGINS — overrides FrontEndDomain when set

	// Secure Headers
	SecHSTSEnabled    bool
	SecHSTSMaxAge     int
	TrustedProxyCIDRs []string

	// Email (always required)
	EmailSMTPHost   string
	EmailSMTPPort   int
	EmailSMTPUser   string
	EmailSMTPPass   string
	EmailSMTPUseTLS bool
	EmailFrom       string

	// TOTP
	TOTPKeys   []TOTPKeyConfig
	TOTPIssuer string
	TOTPPeriod int
	TOTPDigits int

	// OAuth
	OAuthProviders map[string]OAuthProviderConfig
	OAuthTokenKeys []OAuthTokenKeyConfig

	// Account Lockout
	LockoutMaxAttempts int
	LockoutWindowTTL   time.Duration
	LockoutDuration    time.Duration
}

// JWTKeyConfig is a single signing key entry.
type JWTKeyConfig struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Active bool   `json:"active"`
}

// TOTPKeyConfig is a single TOTP encryption key entry.
type TOTPKeyConfig struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
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

// IsMissingEnvError reports whether err (or any error in its chain) is a *MissingEnvError.
func IsMissingEnvError(err error) bool {
	var target *MissingEnvError
	return errors.As(err, &target)
}

// Load reads configuration from the environment (and optional .env file).
func Load() (*Config, error) {
	_ = godotenv.Load()

	// ── JWT key set ───────────────────────────────────────────────────────────
	jwtKeys, err := loadJWTKeys()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	// ── Required variables ────────────────────────────────────────────────────
	r := &requiredReader{}
	dbDSN := r.get("DB_DSN")
	otpSecret := r.get("OTP_HMAC_SECRET")
	smtpHost := r.get("EMAIL_SMTP_HOST")
	if err := r.err(); err != nil {
		return nil, err
	}

	totpKeys, err := loadTOTPKeys()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if len(otpSecret) < 32 {
		return nil, fmt.Errorf(
			"config: OTP_HMAC_SECRET is %d bytes — minimum 32 bytes required "+
				"(generate with: openssl rand -base64 32)",
			len(otpSecret),
		)
	}

	// ── OAuth token keys ──────────────────────────────────────────────────────
	oauthTokenKeys, err := loadOAuthTokenKeys()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	// ── Optional variables with defaults ──────────────────────────────────────
	appEnv := getEnv("APP_ENV", "development")
	cfg := &Config{
		AppEnv:               appEnv,
		AppPort:              getEnv("APP_PORT", "8080"),
		DBDSN:                dbDSN,
		OTPSecret:            otpSecret,
		JWTKeys:              jwtKeys,
		JWTIssuer:            getEnv("JWT_ISSUER", "go-auth-boilerplate"),
		JWTAudience:          getEnv("JWT_AUDIENCE", "go-auth-boilerplate-users"),
		RateLimitRate:        parseFloat("RATE_LIMIT_RATE", 5.0),
		CORSAllowedOrigins:   parseStringSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
		CORSAllowedHeaders:   parseStringSlice("CORS_ALLOWED_HEADERS", []string{"Authorization", "Content-Type", "X-Request-ID"}),
		CORSAllowCredentials: parseBool("CORS_ALLOW_CREDENTIALS", true),
		FrontEndDomain:       getEnv("FRONT_END_DOMAIN", "http://localhost:3000"),
		SecHSTSEnabled:       parseBool("SEC_HSTS_ENABLED", false),
		TrustedProxyCIDRs:    parseStringSlice("TRUSTED_PROXY_CIDRS", []string{""}),
		EmailSMTPHost:        smtpHost,
		EmailSMTPUser:        getEnv("EMAIL_SMTP_USERNAME", ""),
		EmailSMTPPass:        getEnv("EMAIL_SMTP_PASSWORD", ""),
		EmailSMTPUseTLS:      parseBool("EMAIL_SMTP_USE_TLS", false),
		EmailFrom:            getEnv("EMAIL_FROM", "App <noreply@example.com>"),
		// Per-endpoint rate limits
		RateLimitLoginEmail:     parseFloat("RATE_LIMIT_LOGIN_EMAIL", 0.1),
		RateLimitForgotPassword: parseFloat("RATE_LIMIT_FORGOT_PASSWORD", 3.0/60.0),
		RateLimitResendVerify:   parseFloat("RATE_LIMIT_RESEND_VERIFY", 3.0/60.0),
		RateLimitResetPassword:  parseFloat("RATE_LIMIT_RESET_PASSWORD", 5.0/60.0),
		RateLimitVerifyEmail:    parseFloat("RATE_LIMIT_VERIFY_EMAIL", 10.0/60.0),
		RateLimitOTPVerify:      parseFloat("RATE_LIMIT_OTP_VERIFY", 5.0/60.0),
		RateLimitAuthRefresh:    parseFloat("RATE_LIMIT_AUTH_REFRESH", 1.0),
		// OAuth rate limits
		RateLimitOAuthLogin:    parseFloat("RATE_LIMIT_OAUTH_LOGIN", 0.5),
		RateLimitOAuthCallback: parseFloat("RATE_LIMIT_OAUTH_CALLBACK", 0.5),
		RateLimitOAuthLink:     parseFloat("RATE_LIMIT_OAUTH_LINK", 0.2),
		RateLimitOAuthExchange: parseFloat("RATE_LIMIT_OAUTH_EXCHANGE", 0.1),
		TOTPKeys:               totpKeys,
		TOTPIssuer:             getEnv("TOTP_ISSUER", "go-auth-boilerplate"),
		OAuthTokenKeys:         oauthTokenKeys,
		SkipMigrations:         parseBool("SKIP_MIGRATIONS", false),
	}

	// ── CSRF trusted origins ───────────────────────────────────────────────────
	// CSRF_TRUSTED_ORIGINS is an explicit override for multi-subdomain deployments.
	// When absent, the single FrontEndDomain is used as the only trusted origin.
	// When present it completely replaces the default — include FrontEndDomain
	// explicitly in the list if it must also be trusted.
	csrfOrigins := parseStringSlice("CSRF_TRUSTED_ORIGINS", nil)
	if len(csrfOrigins) == 0 {
		csrfOrigins = []string{cfg.FrontEndDomain}
	}
	cfg.CSRFTrustedOrigins = csrfOrigins

	cfg.EmailSMTPPort, err = parseInt("EMAIL_SMTP_PORT", 587)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.RateLimitBurst, err = parseInt("RATE_LIMIT_BURST", 10)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.RateLimitMaxKeys, err = parseInt("RATE_LIMIT_MAX_KEYS", 10_000)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.CORSMaxAge, err = parseInt("CORS_MAX_AGE", 43200)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.SecHSTSMaxAge, err = parseInt("SEC_HSTS_MAX_AGE", 63_072_000)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.TOTPPeriod, err = parseInt("TOTP_PERIOD", 30)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.TOTPDigits, err = parseInt("TOTP_DIGITS", 6)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if cfg.FrontEndDomain == "" {
		return nil, fmt.Errorf("config: FRONT_END_DOMAIN is required")
	}
	u, err := url.Parse(cfg.FrontEndDomain)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("config: FRONT_END_DOMAIN=%q is not a valid URL with a hostname", cfg.FrontEndDomain)
	}

	// ── Cookie domain ──────────────────────────────────────────────────────────
	cookieDomain := getEnv("COOKIE_DOMAIN", "")
	if cookieDomain != "" {
		if err := validateCookieDomain(cookieDomain, u.Hostname()); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	cfg.CookieDomain = cookieDomain

	// ── Duration fields ───────────────────────────────────────────────────────
	cfg.AccessTTL, err = parseDuration("JWT_ACCESS_TTL", "5m")
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

	// ── Cookie policy ──────────────────────────────────────────────────────────
	cfg.CookieSameSite = getEnv("COOKIE_SAMESITE", "lax")
	cfg.CookieSecure = parseBool("COOKIE_SECURE", appEnv == "production")
	if strings.EqualFold(cfg.CookieSameSite, "none") && !cfg.CookieSecure {
		return nil, fmt.Errorf(
			"config: COOKIE_SAMESITE=none requires COOKIE_SECURE=true — " +
				"browsers will refuse the refresh_token cookie otherwise",
		)
	}

	// ── OAuth providers ────────────────────────────────────────────────────────
	oauthProviders, err := loadOAuthProviders()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.OAuthProviders = oauthProviders

	// ── OAuth state secret ─────────────────────────────────────────────────────
	oauthStateSecret := os.Getenv("OAUTH_STATE_SECRET")
	for _, pc := range cfg.OAuthProviders {
		if !pc.Enabled {
			continue
		}
		if len(oauthStateSecret) < 32 {
			return nil, fmt.Errorf(
				"config: OAUTH_STATE_SECRET must be ≥32 bytes when any OAuth provider is enabled "+
					"(current: %d bytes) — generate with: openssl rand -base64 32",
				len(oauthStateSecret),
			)
		}
		break
	}
	cfg.OAuthStateSecret = oauthStateSecret

	// ── OAuth token key enforcement ────────────────────────────────────────────
	for _, pc := range cfg.OAuthProviders {
		if !pc.Enabled {
			continue
		}
		if len(oauthTokenKeys) == 0 {
			return nil, fmt.Errorf(
				"config: OAUTH_TOKEN_KEYS (or legacy OAUTH_TOKEN_SECRET) is required " +
					"when any OAuth provider is enabled — " +
					"generate with: openssl rand -base64 32 and set OAUTH_TOKEN_SECRET, " +
					"or provide a full key set via OAUTH_TOKEN_KEYS",
			)
		}
		break
	}

	// ── Redis (always required) ────────────────────────────────────────────────
	if err := loadRedisConfig(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	// ── Account lockout ────────────────────────────────────────────────────────
	cfg.LockoutMaxAttempts, err = parseInt("LOCKOUT_MAX_ATTEMPTS", 10)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.LockoutMaxAttempts < 1 {
		return nil, fmt.Errorf(
			"config: LOCKOUT_MAX_ATTEMPTS must be ≥1, got %d",
			cfg.LockoutMaxAttempts,
		)
	}
	cfg.LockoutWindowTTL, err = parseDuration("LOCKOUT_WINDOW_TTL", "15m")
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.LockoutWindowTTL < time.Minute {
		return nil, fmt.Errorf(
			"config: LOCKOUT_WINDOW_TTL must be ≥1m to prevent accidental lockouts, got %s",
			cfg.LockoutWindowTTL,
		)
	}
	cfg.LockoutDuration, err = parseDuration("LOCKOUT_DURATION", "15m")
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.LockoutDuration < time.Minute {
		return nil, fmt.Errorf(
			"config: LOCKOUT_DURATION must be ≥1m, got %s",
			cfg.LockoutDuration,
		)
	}

	// ── Validation ────────────────────────────────────────────────────────────
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
