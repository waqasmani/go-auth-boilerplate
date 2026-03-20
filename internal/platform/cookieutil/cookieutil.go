// Package cookieutil provides helpers for writing consistent HTTP cookies
// across the auth, auth_email, and oauth handlers.
//
// Previously each handler contained identical private copies of
// resolveCookieDomain and parseSameSite. A single authoritative copy here
// ensures that a future change (e.g. a new SameSite mode or a different
// domain-resolution strategy) is applied uniformly and is exercised by one
// set of tests rather than three.
package cookieutil

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
)

// ResolveCookieDomain returns the Domain attribute value to set on a cookie.
//
// Resolution priority:
//  1. cfg.CookieDomain (COOKIE_DOMAIN env var) — explicit operator override.
//     Use a leading-dot value (e.g. ".example.com") when the SPA and API live
//     on different subdomains and must share the same refresh-token cookie.
//  2. Hostname of cfg.FrontEndDomain — derived automatically when COOKIE_DOMAIN
//     is not set. Restricts the cookie to the exact SPA host.
func ResolveCookieDomain(cfg *config.Config) string {
	if cfg.CookieDomain != "" {
		return cfg.CookieDomain
	}
	u, err := url.Parse(cfg.FrontEndDomain)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ParseSameSite maps the COOKIE_SAMESITE string to the corresponding
// http.SameSite constant. Unrecognised or empty values fall back to
// http.SameSiteLaxMode, which is the safest cross-origin default.
//
// Accepted values (case-insensitive, leading/trailing space trimmed):
//
//	"strict" → http.SameSiteStrictMode
//	"none"   → http.SameSiteNoneMode   (requires Secure=true in production)
//	anything else → http.SameSiteLaxMode
func ParseSameSite(s string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
