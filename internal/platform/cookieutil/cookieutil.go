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
// # Resolution priority
//
//  1. cfg.CookieDomain (COOKIE_DOMAIN env var) — explicit operator override.
//  2. Hostname of cfg.FrontEndDomain — derived automatically when COOKIE_DOMAIN
//     is not set. Restricts the cookie to the exact SPA host.
//
// # Security note on wildcard (leading-dot) values
//
// A COOKIE_DOMAIN that begins with "." (e.g. ".example.com") instructs the
// browser to send the cookie to every subdomain of that domain. This is the
// correct setting for multi-subdomain deployments where the SPA and the API
// live on different subdomains (e.g. app.example.com and api.example.com),
// but it means that ANY subdomain — including ones you do not control or that
// serve third-party content — will receive the refresh_token cookie.
//
// The startup validator (config.validateCookieDomainPolicy) enforces that a
// leading-dot COOKIE_DOMAIN is only accepted when both COOKIE_SECURE=true and
// COOKIE_SAMESITE=strict are set. Without those safeguards the token is
// reachable over plain HTTP (Secure=false) or via cross-site top-level
// navigations (SameSite=Lax), which widens the blast radius of any compromised
// sibling subdomain.
//
// If you cannot guarantee that all subdomains of your domain are HTTPS-only and
// under the same trust boundary, leave COOKIE_DOMAIN unset and accept that the
// SPA and API must share the same exact hostname.
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
