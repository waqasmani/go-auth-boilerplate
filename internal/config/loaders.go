// Package config holds all application configuration.
// This file contains loading helpers for complex config values.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ── JWT key loading ──────────────────────────────────────────────────────────
func loadJWTKeys() ([]JWTKeyConfig, error) {
	if raw := os.Getenv("JWT_KEYS"); raw != "" {
		var keys []JWTKeyConfig
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			return nil, fmt.Errorf("JWT_KEYS: invalid JSON: %w", err)
		}
		if err := validateJWTKeysInternal(keys); err != nil {
			return nil, fmt.Errorf("JWT_KEYS: %w", err)
		}
		return keys, nil
	}
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, &MissingEnvError{Keys: []string{"JWT_KEYS (or legacy JWT_SECRET)"}}
	}
	id := getEnv("JWT_KEY_ID", "default")
	return []JWTKeyConfig{{ID: id, Secret: secret, Active: true}}, nil
}

func validateJWTKeysInternal(keys []JWTKeyConfig) error {
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
		if len(k.Secret) < 32 {
			return fmt.Errorf(
				"key %q secret is %d bytes — minimum 32 bytes required for HS256 (RFC 7518 §3.2)",
				k.ID, len(k.Secret),
			)
		}
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

// ── TOTP key loading ─────────────────────────────────────────────────────────
func loadTOTPKeys() ([]TOTPKeyConfig, error) {
	if raw := os.Getenv("TOTP_KEYS"); raw != "" {
		var keys []TOTPKeyConfig
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			return nil, fmt.Errorf("TOTP_KEYS: invalid JSON: %w", err)
		}
		if err := validateTOTPKeysInternal(keys); err != nil {
			return nil, fmt.Errorf("TOTP_KEYS: %w", err)
		}
		return keys, nil
	}
	secret := os.Getenv("TOTP_SECRET")
	if secret == "" {
		return nil, &MissingEnvError{Keys: []string{"TOTP_KEYS (or legacy TOTP_SECRET)"}}
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf(
			"TOTP_SECRET is %d bytes — minimum 32 bytes required "+
				"(generate with: openssl rand -base64 32)",
			len(secret),
		)
	}
	return []TOTPKeyConfig{{ID: "v1", Key: secret, Active: true}}, nil
}

func validateTOTPKeysInternal(keys []TOTPKeyConfig) error {
	if len(keys) == 0 {
		return fmt.Errorf("array is empty — provide at least one key")
	}
	seen := make(map[string]struct{}, len(keys))
	activeCount := 0
	for i, k := range keys {
		if k.ID == "" {
			return fmt.Errorf("key[%d] has an empty id", i)
		}
		if len(k.ID) > 255 {
			return fmt.Errorf("key %q id exceeds 255 bytes", k.ID)
		}
		if len(k.Key) < 32 {
			return fmt.Errorf(
				"key %q is %d bytes — minimum 32 bytes required for AES-256",
				k.ID, len(k.Key),
			)
		}
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

// ── OAuth provider loading ───────────────────────────────────────────────────
func loadOAuthProviders() (map[string]OAuthProviderConfig, error) {
	providers := map[string]OAuthProviderConfig{}
	for _, name := range []string{"google", "facebook"} {
		upper := strings.ToUpper(name)
		prefix := "OAUTH_" + upper + "_"
		enabled := parseBool(prefix+"ENABLED", false)
		if !enabled {
			providers[name] = OAuthProviderConfig{Enabled: false}
			continue
		}
		r := &requiredReader{}
		clientID := r.get(prefix + "CLIENT_ID")
		clientSecret := r.get(prefix + "CLIENT_SECRET")
		redirectURL := r.get(prefix + "REDIRECT_URL")
		allowedRaw := r.get(prefix + "ALLOWED_REDIRECTS")
		if err := r.err(); err != nil {
			return nil, fmt.Errorf("oauth %s: %w", name, err)
		}
		if _, err := url.Parse(redirectURL); err != nil || redirectURL == "" {
			return nil, fmt.Errorf("oauth %s: OAUTH_%s_REDIRECT_URL=%q is not a valid URL", name, upper, redirectURL)
		}
		var allowedRedirects []string
		for _, raw := range strings.Split(allowedRaw, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("oauth %s: OAUTH_%s_ALLOWED_REDIRECTS entry %q: %w",
					name, upper, raw, err)
			}
			scheme := strings.ToLower(u.Scheme)
			isValidWeb := scheme == "https" && u.Hostname() != ""
			isValidCustom := scheme != "" && scheme != "http" && scheme != "https"
			if !isValidWeb && !isValidCustom {
				return nil, fmt.Errorf(
					"oauth %s: OAUTH_%s_ALLOWED_REDIRECTS entry %q must be an https:// URL "+
						"(web) or a custom-scheme URI (mobile, e.g. com.myapp://…). "+
						"http:// and scheme-less URLs are not permitted.",
					name, upper, raw,
				)
			}
			allowedRedirects = append(allowedRedirects, raw)
		}
		providers[name] = OAuthProviderConfig{
			Enabled:          true,
			ClientID:         clientID,
			ClientSecret:     clientSecret,
			RedirectURL:      redirectURL,
			AllowedRedirects: allowedRedirects,
			Scopes:           parseStringSlice(prefix+"SCOPES", nil),
		}
	}
	return providers, nil
}

// ── OAuth token key loading ──────────────────────────────────────────────────
func loadOAuthTokenKeys() ([]OAuthTokenKeyConfig, error) {
	if raw := os.Getenv("OAUTH_TOKEN_KEYS"); raw != "" {
		var keys []OAuthTokenKeyConfig
		if err := json.Unmarshal([]byte(raw), &keys); err != nil {
			return nil, fmt.Errorf("OAUTH_TOKEN_KEYS: invalid JSON: %w", err)
		}
		if err := validateOAuthTokenKeysInternal(keys); err != nil {
			return nil, fmt.Errorf("OAUTH_TOKEN_KEYS: %w", err)
		}
		return keys, nil
	}
	secret := os.Getenv("OAUTH_TOKEN_SECRET")
	if secret == "" {
		return nil, nil
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf(
			"OAUTH_TOKEN_SECRET is %d bytes — minimum 32 bytes required "+
				"(generate with: openssl rand -base64 32)",
			len(secret),
		)
	}
	return []OAuthTokenKeyConfig{{ID: "v1", Key: secret, Active: true}}, nil
}

func validateOAuthTokenKeysInternal(keys []OAuthTokenKeyConfig) error {
	if len(keys) == 0 {
		return fmt.Errorf("array is empty — provide at least one key")
	}
	seen := make(map[string]struct{}, len(keys))
	activeCount := 0
	for i, k := range keys {
		if k.ID == "" {
			return fmt.Errorf("key[%d] has an empty id", i)
		}
		if len(k.ID) > 255 {
			return fmt.Errorf("key %q id exceeds 255 bytes", k.ID)
		}
		if len(k.Key) < 32 {
			return fmt.Errorf(
				"key %q is %d bytes — minimum 32 bytes required for AES-256",
				k.ID, len(k.Key),
			)
		}
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

// ── Redis config loading (always required) ───────────────────────────────────
//
// Redis is a hard dependency. There is no in-memory fallback. The application
// will not start unless REDIS_DSN resolves to a reachable Redis instance.
// REDIS_ENABLED is no longer a valid configuration key — remove it from your
// environment if it was previously set.
func loadRedisConfig(cfg *Config) error {
	redisDSN := os.Getenv("REDIS_DSN")
	if redisDSN == "" {
		return fmt.Errorf(
			"REDIS_DSN is required — Redis is a mandatory dependency with no in-memory fallback. " +
				"Set REDIS_DSN to a reachable Redis instance (e.g. redis://localhost:6379/0).",
		)
	}

	if err := validateRedisDSNInternal(redisDSN); err != nil {
		return err
	}

	poolSize, err := parseInt("REDIS_POOL_SIZE", 10)
	if err != nil {
		return fmt.Errorf("REDIS_POOL_SIZE: %w", err)
	}
	if poolSize < 1 {
		return fmt.Errorf("REDIS_POOL_SIZE must be ≥1, got %d", poolSize)
	}

	cfg.RedisDSN = redisDSN
	cfg.RedisPoolSize = poolSize
	return nil
}

func validateRedisDSNInternal(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("REDIS_DSN is not a valid URL: %w", err)
	}
	switch u.Scheme {
	case "redis", "rediss", "unix":
		// valid
	case "":
		return fmt.Errorf(
			"REDIS_DSN is missing a scheme — use redis://, rediss://, or unix://",
		)
	default:
		return fmt.Errorf(
			"REDIS_DSN has unrecognised scheme %q — use redis://, rediss://, or unix://",
			u.Scheme,
		)
	}
	if u.Scheme != "unix" && u.Hostname() == "" {
		return fmt.Errorf("REDIS_DSN is missing a hostname")
	}
	return nil
}

// ── Cookie domain validation ─────────────────────────────────────────────────
func validateCookieDomain(cookieDomain, frontendHostname string) error {
	d := strings.ToLower(strings.TrimPrefix(cookieDomain, "."))
	h := strings.ToLower(frontendHostname)
	if h == d || strings.HasSuffix(h, "."+d) {
		return nil
	}
	return fmt.Errorf(
		"COOKIE_DOMAIN=%q is not a suffix of FRONT_END_DOMAIN hostname %q — "+
			"set COOKIE_DOMAIN to the shared registrable domain (e.g. \".example.com\") "+
			"or leave it empty to restrict the cookie to the exact frontend hostname",
		cookieDomain, frontendHostname,
	)
}
