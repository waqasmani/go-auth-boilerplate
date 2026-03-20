// Package middleware provides Gin middleware components for the application.
// This file implements a targeted CSRF check for the two routes that accept
// the refresh token via an HttpOnly cookie rather than a JSON request body.
//
// # Threat model
//
// POST /auth/refresh and POST /auth/logout are the only endpoints that consume
// the cookie path. SameSite=Lax already blocks top-level navigation CSRF
// (e.g. a form POST from a foreign page), but it does NOT block:
//
//   - fetch() / XMLHttpRequest from a malicious same-site subdomain
//   - browsers that do not implement SameSite (very old, but still deployed)
//   - edge-case browser bugs in the SameSite implementation
//
// Checking the Origin header (with Referer as a fallback) closes these gaps
// without any client-side changes and without a token round-trip.
//
// Why not a double-submit CSRF token?
//
// A double-submit token requires the server to issue a second cookie or a
// meta-tag value and the client to echo it in a header on every request.  For
// an API that is already session-free (JWT + opaque refresh token) this adds
// stateful machinery for no additional security benefit over Origin checking.
// Origin checking is simpler, has no client surface area, and is the approach
// recommended by the OWASP CSRF Prevention Cheat Sheet for API endpoints.
package middleware

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// CookieCSRFConfig holds the configuration for the cookie-scoped CSRF check.
type CookieCSRFConfig struct {
	// TrustedOrigins is the list of frontend origins permitted to send
	// cookie-bearing POST requests (e.g. ["https://app.example.com",
	// "https://admin.example.com"]).  Scheme and host are extracted at
	// construction time; any path component is ignored.
	//
	// A single-element slice is the common case (one frontend domain).
	// Multi-origin deployments — e.g. separate app and admin subdomains
	// sharing one API — add entries here without code changes.
	//
	// Derived from cfg.FrontEndDomain via CookieCSRFConfigFromValues; set
	// directly when multiple origins are required.
	TrustedOrigins []string
}

// CookieCSRF returns a Gin middleware that enforces Origin / Referer validation
// on any request that carries the refresh_token cookie.
//
// Enforcement is intentionally scoped to cookie-bearing requests only:
//
//  1. No refresh_token cookie → middleware is a no-op. API clients that pass
//     the token in the JSON body (mobile apps, curl, etc.) are unaffected.
//
//  2. Cookie present, Origin header set → compare "scheme://host" against
//     each entry in TrustedOrigins. Browsers set Origin on all cross-origin
//     POST requests made via fetch() or XMLHttpRequest, making this the
//     primary signal.
//
//  3. Cookie present, no Origin, Referer set → extract origin from Referer
//     and compare against TrustedOrigins. Referer is suppressed by some
//     privacy settings and the Referrer-Policy we set
//     ("strict-origin-when-cross-origin"), but it is a useful fallback for
//     same-origin page navigations.
//
//  4. Cookie present, neither Origin nor Referer → reject (fail-closed).
//     A genuine browser POST always carries at least one of these headers.
//     Absence is a strong signal of a tampered or synthetic request.
//
// Apply this middleware per-route on /auth/refresh and /auth/logout only.
// There is no reason to run it globally: the other endpoints do not consume
// the cookie and adding latency-free checks to every route is unnecessary
// noise.
//
// Panics at startup when TrustedOrigins is empty or contains an entry that
// cannot be normalised — configuration errors must be caught in CI rather
// than silently accepting all origins in production.
func CookieCSRF(cfg CookieCSRFConfig) gin.HandlerFunc {
	if len(cfg.TrustedOrigins) == 0 {
		panic("middleware: CookieCSRF: TrustedOrigins is empty — provide at least one trusted origin")
	}

	// Pre-normalise all trusted origins once at construction time so the hot
	// path (every request) does no allocation or URL parsing.
	trusted := make([]string, 0, len(cfg.TrustedOrigins))
	for _, raw := range cfg.TrustedOrigins {
		norm, err := normaliseOrigin(raw)
		if err != nil {
			panic(fmt.Sprintf(
				"middleware: CookieCSRF: invalid TrustedOrigin %q: %v",
				raw, err,
			))
		}
		trusted = append(trusted, norm)
	}

	isTrusted := func(raw string) bool {
		norm, err := normaliseOrigin(raw)
		if err != nil {
			return false
		}
		for _, t := range trusted {
			if strings.EqualFold(norm, t) {
				return true
			}
		}
		return false
	}

	return func(c *gin.Context) {
		// Gate: only enforce on requests that carry the refresh-token cookie.
		// API clients sending the token in the JSON body skip this check.
		if _, err := c.Cookie("refresh_token"); err != nil {
			c.Next()
			return
		}

		// ── 1. Origin header (primary signal) ─────────────────────────────────
		if origin := c.GetHeader("Origin"); origin != "" {
			if !isTrusted(origin) {
				denyCSRF(c)
				return
			}
			c.Next()
			return
		}

		// ── 2. Referer header (fallback) ──────────────────────────────────────
		// Parsed as a full URL; only scheme+host is compared so that path
		// differences (e.g. /login vs /dashboard) do not cause false negatives.
		if referer := c.GetHeader("Referer"); referer != "" {
			if !isTrusted(referer) {
				denyCSRF(c)
				return
			}
			c.Next()
			return
		}

		// ── 3. Neither header present → fail-closed ────────────────────────────
		denyCSRF(c)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// normaliseOrigin extracts a lowercased "scheme://host[:port]" string from any
// URL-shaped input.  It accepts both a bare origin ("https://app.example.com")
// and a full URL with path ("https://app.example.com/auth/login"); the path is
// discarded so Referer values compare correctly against an Origin value.
//
// Returns an error when the input is not a parseable URL with both a scheme
// and a host — for example a relative URL, an opaque URI, or an empty string.
func normaliseOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("url.Parse: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("missing scheme or host in %q", raw)
	}
	// Lower-case both components so EqualFold comparisons in the middleware
	// are always matching against a consistent canonical form.
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

func denyCSRF(c *gin.Context) {
	response.Error(c, apperrors.ErrCSRFRejected)
	c.Abort()
}
