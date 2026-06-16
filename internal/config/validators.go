// Package config holds all application configuration.
// This file contains validation logic extracted from config.go for better maintainability.
package config

import (
	"fmt"
	"math"
	"net"
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
	validateCSRFTrustedOrigins,
	validateCookieDomainPolicy,
	validateTrustedProxies,
	validateSecretStrength,
	validateDBSecurity,
}

// localhostLikePrefixes is the single canonical list of origin prefixes that
// are forbidden in production CORS and CSRF configuration. Centralised here
// so loaders.go and validators.go cannot diverge.
//
// Covered cases:
//   - IPv4 loopback  : 127.0.0.1
//   - IPv6 loopback  : [::1]   (URL form per RFC 2732)
//   - wildcard bind  : 0.0.0.0 (not a valid browser origin, but caught for safety)
//   - "localhost"    : the hostname alias for all of the above
//
// Both http:// and https:// variants are included because a mis-configured
// local HTTPS proxy (e.g. mkcert) could otherwise slip through an http-only
// check.
var localhostLikePrefixes = []string{
	"http://localhost",
	"https://localhost",
	"http://127.0.0.1",
	"https://127.0.0.1",
	"http://[::1]",
	"https://[::1]",
	"http://0.0.0.0",
	"https://0.0.0.0",
}

// isLocalhostLikeOrigin reports whether origin starts with any of the
// localhost-like prefixes defined in localhostLikePrefixes.
func isLocalhostLikeOrigin(origin string) bool {
	lower := strings.ToLower(origin)
	for _, prefix := range localhostLikePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
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

// validateCORSOrigins rejects localhost-like origins in production.
// Uses the canonical localhostLikePrefixes list so the check stays in sync
// with the CSRF validator and any future callers.
func validateCORSOrigins(c *Config) error {
	// A wildcard origin combined with credentials is always unsafe (any site
	// could read credentialed responses). gin-contrib/cors does not reflect
	// arbitrary origins, but an operator could still list a "*"-bearing pattern.
	// Reject it in every environment when credentials are enabled.
	if c.CORSAllowCredentials {
		for _, origin := range c.CORSAllowedOrigins {
			if strings.Contains(origin, "*") {
				return fmt.Errorf(
					"config: CORS_ALLOWED_ORIGINS entry %q contains a wildcard while "+
						"CORS_ALLOW_CREDENTIALS=true — credentialed CORS must use an exact "+
						"origin allowlist. Remove the wildcard or set CORS_ALLOW_CREDENTIALS=false",
					origin,
				)
			}
		}
	}
	if c.AppEnv != "production" {
		return nil
	}
	for _, origin := range c.CORSAllowedOrigins {
		if isLocalhostLikeOrigin(origin) {
			return fmt.Errorf(
				"config: CORS_ALLOWED_ORIGINS contains a localhost/loopback origin (%q) in production — "+
					"set CORS_ALLOWED_ORIGINS to your real frontend domain(s) "+
					"(e.g. https://app.example.com)",
				origin,
			)
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
				"Set EMAIL_SMTP_HOST to a reachable SMTP server (e.g. localhost for MailHog in development)",
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

// validateCSRFTrustedOrigins ensures every entry is a parseable URL with both
// scheme and host, rejects localhost-like origins in production (using the
// same canonical list as validateCORSOrigins), and rejects plain-http origins
// in production.
func validateCSRFTrustedOrigins(c *Config) error {
	if len(c.CSRFTrustedOrigins) == 0 {
		return fmt.Errorf(
			"config: CSRFTrustedOrigins is empty — set CSRF_TRUSTED_ORIGINS or ensure FRONT_END_DOMAIN is valid",
		)
	}
	for _, raw := range c.CSRFTrustedOrigins {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf(
				"config: CSRF_TRUSTED_ORIGINS entry %q is not a valid URL with scheme and host",
				raw,
			)
		}
	}
	if c.AppEnv == "production" {
		for _, raw := range c.CSRFTrustedOrigins {
			if isLocalhostLikeOrigin(raw) {
				return fmt.Errorf(
					"config: CSRF_TRUSTED_ORIGINS entry %q is a localhost/loopback origin — "+
						"all trusted origins must be real domains in production",
					raw,
				)
			}
			if strings.HasPrefix(strings.ToLower(raw), "http://") {
				return fmt.Errorf(
					"config: CSRF_TRUSTED_ORIGINS entry %q uses plain http — "+
						"all trusted origins must use https in production",
					raw,
				)
			}
		}
	}
	return nil
}

// validateCookieDomainPolicy enforces a security-policy requirement on
// wildcard cookie domains.
//
// # Background
//
// When COOKIE_DOMAIN is left unset, ResolveCookieDomain falls back to the
// exact hostname of FRONT_END_DOMAIN (e.g. "app.example.com"). The browser
// treats this as a host-only scope and only sends the cookie to that exact
// origin — no other subdomain receives it.
//
// When COOKIE_DOMAIN is set with a leading dot (e.g. ".example.com"), the
// browser sends the cookie to every subdomain of example.com. This is
// necessary for multi-subdomain deployments (e.g. app.example.com and
// admin.example.com sharing one API), but it also means that a compromised
// or misconfigured sibling subdomain (e.g. marketing.example.com) will
// receive the refresh_token cookie on every request it handles.
//
// # Required safeguards for a wildcard (leading-dot) COOKIE_DOMAIN
//
//  1. COOKIE_SECURE=true — without this, any HTTP request to any subdomain
//     (e.g. an HTTP redirect or a non-TLS asset host) sends the cookie in
//     plaintext over the network, where it can be intercepted.
//
//  2. COOKIE_SAMESITE=strict — SameSite=Lax still sends the cookie on
//     top-level cross-site GET navigations. A link from an external site to
//     https://marketing.example.com would carry the refresh_token to the
//     marketing subdomain under Lax. Strict blocks all cross-site sends,
//     including top-level navigations, limiting delivery to same-site
//     requests only.
//
// Exact-host COOKIE_DOMAIN values (no leading dot) are always safe and require
// no additional policy enforcement — the browser's host-only scope already
// prevents the cookie reaching any other subdomain.
//
// # Operator guidance
//
// Only set COOKIE_DOMAIN when all subdomains of the target domain are:
//   - Served exclusively over HTTPS (satisfies COOKIE_SECURE=true)
//   - Under the same trust boundary as the API (no third-party or marketing
//     subdomains that could be independently compromised)
//
// If you cannot guarantee both, leave COOKIE_DOMAIN unset and accept that
// the SPA and API must share the same exact hostname.
func validateCookieDomainPolicy(c *Config) error {
	// Exact-host domain (no leading dot) — host-only scope, always safe.
	if c.CookieDomain == "" || !strings.HasPrefix(c.CookieDomain, ".") {
		return nil
	}

	// Wildcard domain (leading dot) — requires both Secure and SameSite=strict.
	var errs []string

	if !c.CookieSecure {
		errs = append(errs, "COOKIE_SECURE=true")
	}
	if !strings.EqualFold(strings.TrimSpace(c.CookieSameSite), "strict") {
		errs = append(errs, "COOKIE_SAMESITE=strict")
	}

	if len(errs) == 0 {
		return nil
	}

	// Build a single, actionable error message that names every missing
	// setting so operators do not hit the validator repeatedly.
	missing := strings.Join(errs, " and ")
	return fmt.Errorf(
		"config: COOKIE_DOMAIN=%q uses a wildcard (leading-dot) scope that sends the "+
			"refresh_token cookie to every subdomain of %q — this requires %s to prevent "+
			"token leakage via HTTP downgrade or cross-subdomain navigation. "+
			"Set %s, or remove the leading dot to restrict the cookie to the exact "+
			"FRONT_END_DOMAIN hostname",
		c.CookieDomain,
		strings.TrimPrefix(c.CookieDomain, "."),
		missing,
		missing,
	)
}

// validateTrustedProxies enforces a safe X-Forwarded-For trust boundary in
// production. An empty list makes forwarded headers unusable; a trust-all CIDR
// lets any client spoof its IP to bypass per-IP rate limits and poison audit
// logs. Both are rejected; entries must be valid IPs or CIDRs.
func validateTrustedProxies(c *Config) error {
	if c.AppEnv != "production" {
		return nil
	}
	if len(c.TrustedProxyCIDRs) == 0 {
		return fmt.Errorf(
			"config: TRUSTED_PROXY_CIDRS is required in production — set it to the exact " +
				"CIDR(s) of your load balancer / ingress (e.g. 10.0.0.0/8 for a private LB). " +
				"An empty value makes X-Forwarded-For unusable; a value of 0.0.0.0/0 would " +
				"let any client spoof its IP",
		)
	}
	for _, raw := range c.TrustedProxyCIDRs {
		entry := strings.TrimSpace(raw)
		if entry == "0.0.0.0/0" || entry == "::/0" {
			return fmt.Errorf(
				"config: TRUSTED_PROXY_CIDRS entry %q trusts every address — this lets any "+
					"client spoof X-Forwarded-For to bypass rate limits and forge audit-log IPs. "+
					"Restrict it to your proxy/LB CIDR",
				entry,
			)
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			if net.ParseIP(entry) == nil {
				return fmt.Errorf(
					"config: TRUSTED_PROXY_CIDRS entry %q is not a valid IP or CIDR", entry,
				)
			}
		}
	}
	return nil
}

// weakSecretMarkers are case-insensitive substrings that strongly indicate a
// placeholder or human-chosen (low-entropy) secret rather than a generated one.
var weakSecretMarkers = []string{
	"change", "replace", "example", "placeholder", "your-", "your_",
	"secret-here", "todo", "dummy", "insecure", "sample", "password",
	"changeme", "xxxx", "default-", "test-secret", "longrandom", "long-random",
}

// validateSecretStrength rejects placeholder / low-entropy secrets in
// production. The length-only checks elsewhere are insufficient: a 48-byte
// string like "change-me-in-production-use-a-long-random-secret" passes a
// length gate but is publicly known.
func validateSecretStrength(c *Config) error {
	if c.AppEnv != "production" {
		return nil
	}
	type namedSecret struct {
		name   string
		secret string
	}
	var secrets []namedSecret
	for _, k := range c.JWTKeys {
		secrets = append(secrets, namedSecret{fmt.Sprintf("JWT key %q secret", k.ID), k.Secret})
	}
	secrets = append(secrets, namedSecret{"OTP_HMAC_SECRET", c.OTPSecret})
	for _, k := range c.TOTPKeys {
		secrets = append(secrets, namedSecret{fmt.Sprintf("TOTP key %q", k.ID), k.Key})
	}
	if c.OAuthStateSecret != "" {
		secrets = append(secrets, namedSecret{"OAUTH_STATE_SECRET", c.OAuthStateSecret})
	}
	for _, k := range c.OAuthTokenKeys {
		secrets = append(secrets, namedSecret{fmt.Sprintf("OAuth token key %q", k.ID), k.Key})
	}
	for _, s := range secrets {
		if err := checkSecretStrength(s.name, s.secret); err != nil {
			return err
		}
	}
	return nil
}

func checkSecretStrength(name, secret string) error {
	lower := strings.ToLower(secret)
	for _, marker := range weakSecretMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf(
				"config: %s looks like a placeholder/low-entropy value (contains %q) — "+
					"production secrets must be randomly generated (e.g. openssl rand -base64 48)",
				name, marker,
			)
		}
	}
	distinct := map[rune]struct{}{}
	for _, r := range secret {
		distinct[r] = struct{}{}
	}
	if len(distinct) < 12 {
		return fmt.Errorf(
			"config: %s has only %d distinct characters — too low-entropy for production. "+
				"Generate a random secret (openssl rand -base64 48)",
			name, len(distinct),
		)
	}
	if shannonBitsPerByte(secret) < 3.0 {
		return fmt.Errorf(
			"config: %s has insufficient entropy for production — "+
				"generate a random secret (openssl rand -base64 48)",
			name,
		)
	}
	return nil
}

func shannonBitsPerByte(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	runes := []rune(s)
	for _, r := range runes {
		counts[r]++
	}
	n := float64(len(runes))
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// validateDBSecurity requires a TLS-enabled DB_DSN in production unless the
// operator explicitly acknowledges an already-encrypted transport via
// DB_ALLOW_INSECURE=true.
func validateDBSecurity(c *Config) error {
	if c.AppEnv != "production" || c.DBAllowInsecure {
		return nil
	}
	dsn := strings.ToLower(c.DBDSN)
	hasTLS := strings.Contains(dsn, "tls=") &&
		!strings.Contains(dsn, "tls=false") &&
		!strings.Contains(dsn, "tls=0")
	if !hasTLS {
		return fmt.Errorf(
			"config: DB_DSN does not enable TLS in production (expected a tls= parameter, " +
				"e.g. ...?tls=true). Database credentials and data would travel in plaintext. " +
				"Add tls=true (or tls=skip-verify behind a trusted network) to DB_DSN, " +
				"or set DB_ALLOW_INSECURE=true to acknowledge an already-encrypted transport",
		)
	}
	return nil
}
