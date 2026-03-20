// Package config holds all application configuration.
// This file contains validation logic extracted from config.go for better maintainability.
package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Validator is a function that validates a Config struct.
type Validator func(*Config) error

// Validators is a list of all config validators.
var Validators = []Validator{
	validateJWTKeys,
	validateRedisDSN,
	validateCORSOrigins,
	validateTOTPKeys,
	validateOAuthProviders,
	validateSMTP,
}

// Validate runs all validators against the config.
func (c *Config) Validate() error {
	for _, v := range Validators {
		if err := v(c); err != nil {
			return err
		}
	}
	return nil
}

func validateJWTKeys(c *Config) error {
	if len(c.JWTKeys) == 0 {
		return fmt.Errorf("config: JWT_KEYS must contain at least one key")
	}
	activeCount := 0
	for _, k := range c.JWTKeys {
		if k.Active {
			activeCount++
		}
		if len(k.Secret) < 32 {
			return fmt.Errorf("config: JWT key %q secret must be at least 32 bytes", k.ID)
		}
	}
	if activeCount != 1 {
		return fmt.Errorf("config: exactly one JWT key must be active")
	}
	return nil
}

// validateRedisDSN validates that a reachable Redis DSN is configured.
// Redis is always required — there is no in-memory fallback.
func validateRedisDSN(c *Config) error {
	if c.RedisDSN == "" {
		return fmt.Errorf("config: REDIS_DSN is required — Redis is a mandatory dependency")
	}
	u, err := url.Parse(c.RedisDSN)
	if err != nil {
		return fmt.Errorf("config: REDIS_DSN is not a valid URL: %w", err)
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" && u.Scheme != "unix" {
		return fmt.Errorf("config: REDIS_DSN scheme must be redis, rediss, or unix")
	}
	return nil
}

func validateCORSOrigins(c *Config) error {
	if c.AppEnv == "production" {
		forbiddenPrefixes := []string{
			"http://localhost",
			"https://localhost",
			"http://127.0.0.1",
		}
		for _, origin := range c.CORSAllowedOrigins {
			for _, prefix := range forbiddenPrefixes {
				if strings.HasPrefix(strings.ToLower(origin), prefix) {
					return fmt.Errorf("config: CORS_ALLOWED_ORIGINS contains localhost in production")
				}
			}
		}
	}
	return nil
}

func validateTOTPKeys(c *Config) error {
	if len(c.TOTPKeys) == 0 {
		return nil
	}
	activeCount := 0
	for _, k := range c.TOTPKeys {
		if k.Active {
			activeCount++
		}
		if len(k.Key) < 32 {
			return fmt.Errorf("config: TOTP key %q must be at least 32 bytes", k.ID)
		}
	}
	if activeCount != 1 {
		return fmt.Errorf("config: exactly one TOTP key must be active")
	}
	return nil
}

func validateOAuthProviders(c *Config) error {
	for name, p := range c.OAuthProviders {
		if !p.Enabled {
			continue
		}
		if p.ClientID == "" || p.ClientSecret == "" {
			return fmt.Errorf("config: OAuth provider %q missing credentials", name)
		}
		if _, err := url.Parse(p.RedirectURL); err != nil {
			return fmt.Errorf("config: OAuth provider %q has invalid redirect URL", name)
		}
	}
	return nil
}

// validateSMTP ensures the SMTP host is configured. Email delivery is a hard
// dependency — the application will not start without a reachable SMTP server.
func validateSMTP(c *Config) error {
	if c.EmailSMTPHost == "" {
		return fmt.Errorf(
			"config: EMAIL_SMTP_HOST is required — SMTP is a mandatory dependency with no stub mode. " +
				"Set EMAIL_SMTP_HOST to a reachable SMTP server (e.g. localhost for MailHog in development).",
		)
	}
	if c.EmailSMTPPort < 1 || c.EmailSMTPPort > 65535 {
		return fmt.Errorf(
			"config: EMAIL_SMTP_PORT=%d is invalid — must be between 1 and 65535",
			c.EmailSMTPPort,
		)
	}
	return nil
}
