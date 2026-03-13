// Package middleware provides Gin middleware components for the application.
// This file implements a secure-headers middleware that writes the defensive
// HTTP response headers every browser-facing API should carry.
//
// Headers written on every response:
//
//	X-Content-Type-Options: nosniff
//	  Prevents browsers from MIME-sniffing a response away from its declared
//	  Content-Type.  Without this, a browser may execute a JSON response as a
//	  script if it is loaded from a <script> tag on an attacker-controlled page.
//
//	X-Frame-Options: DENY
//	  Prohibits any page from embedding this origin in an <iframe>, <frame>, or
//	  <object>.  Eliminates the entire class of clickjacking attacks where an
//	  invisible iframe overlays a legitimate UI to steal clicks or keystrokes.
//	  DENY is used instead of SAMEORIGIN because this is a pure JSON API — it
//	  has no UI of its own and should never be framed by anyone.
//
//	X-XSS-Protection: 0
//	  Explicitly disables the legacy IE/Chrome XSS auditor.  Modern browsers
//	  have removed it entirely; on old IE it can be weaponised to *introduce*
//	  XSS by suppressing legitimate content.  Setting it to 0 is the current
//	  OWASP recommendation.
//
//	Referrer-Policy: strict-origin-when-cross-origin
//	  Sends the full URL as Referer on same-origin requests and only the origin
//	  on cross-origin requests, omitting it entirely when downgrading from HTTPS
//	  to HTTP.  Prevents leaking path or query-string tokens to third-party
//	  services (analytics, CDNs, error trackers) included in the frontend.
//
//	Content-Security-Policy: default-src 'none'
//	  For a pure JSON API that returns no HTML, scripts, or stylesheets,
//	  default-src 'none' is the tightest possible policy.  It tells the browser
//	  that if this response is ever mistakenly rendered as a page, no resources
//	  of any kind may be loaded.
//
// Conditional header (production only):
//
//	Strict-Transport-Security: max-age=<n>; includeSubDomains
//	  Instructs browsers to contact this origin over HTTPS only for the next
//	  <n> seconds, even if the user types a plain http:// URL.  Eliminated
//	  SSL-stripping / protocol-downgrade attacks.
//
//	  THIS HEADER MUST NOT BE SENT OVER PLAIN HTTP.  A browser that receives
//	  HSTS over HTTP and then encounters a TLS error will refuse to connect for
//	  the entire max-age period with no user-visible escape hatch.  For this
//	  reason HSTSEnabled defaults to false and must be opted into explicitly in
//	  production where TLS termination is guaranteed at the load-balancer or
//	  ingress layer.
package middleware

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecureHeadersConfig holds every tuneable parameter for the secure-headers
// middleware.  The zero value is safe: all headers except HSTS are written
// with their recommended values, and HSTS is off until explicitly enabled.
type SecureHeadersConfig struct {
	// HSTSEnabled controls whether the Strict-Transport-Security header is
	// written.  Must only be true when the service is reachable exclusively
	// over HTTPS — sending HSTS over plain HTTP can lock users out of the site
	// for the entire HSTSMaxAge window.  Default: false.
	HSTSEnabled bool

	// HSTSMaxAge is the max-age directive value in seconds.  Two years
	// (63 072 000 s) is the threshold required for HSTS preloading; it is also
	// a practical production default.  Only used when HSTSEnabled is true.
	// Default: 63_072_000.
	HSTSMaxAge int

	// HSTSIncludeSubDomains appends the includeSubDomains directive, which
	// extends the HSTS policy to every subdomain of this origin.  Enable only
	// when all subdomains are guaranteed to serve valid TLS.  Default: true.
	HSTSIncludeSubDomains bool
}

// DefaultSecureHeadersConfig returns the recommended configuration for local
// development: all headers enabled at their safe values, HSTS off (no TLS in
// dev).
func DefaultSecureHeadersConfig() SecureHeadersConfig {
	return SecureHeadersConfig{
		HSTSEnabled:           false, // must be opted into in production
		HSTSMaxAge:            63_072_000,
		HSTSIncludeSubDomains: true,
	}
}

// ProductionSecureHeadersConfig returns the recommended configuration for
// production: identical to DefaultSecureHeadersConfig but with HSTS enabled.
// Only use this when TLS termination is guaranteed before traffic reaches the
// Go process (load balancer, ingress, etc.).
func ProductionSecureHeadersConfig() SecureHeadersConfig {
	cfg := DefaultSecureHeadersConfig()
	cfg.HSTSEnabled = true
	return cfg
}

// SecureHeaders returns a Gin middleware that writes defensive security headers
// on every response.  It is side-effect-free: it never reads the request body,
// never touches the response body, and always calls c.Next() so the handler
// chain continues normally.
//
// Place it immediately after CORS in the global middleware stack so security
// headers are present even on preflight (OPTIONS) responses:
//
//	r.Use(middleware.CORS(opts.CORS))
//	r.Use(middleware.SecureHeaders(opts.SecureHeaders))
//	r.Use(middleware.RequestID())
//	...
func SecureHeaders(cfg SecureHeadersConfig) gin.HandlerFunc {
	// Pre-compute the HSTS header value once at construction time so the hot
	// path (every request) does no string formatting.
	hstsValue := buildHSTSValue(cfg)

	return func(c *gin.Context) {
		// ── Always-on headers ───────────────────────────────────────────────
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "0")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'none'")

		// ── Conditional headers ─────────────────────────────────────────────
		if cfg.HSTSEnabled {
			c.Header("Strict-Transport-Security", hstsValue)
		}

		c.Next()
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// buildHSTSValue constructs the Strict-Transport-Security header value from
// the supplied config.  Called once during middleware construction so the
// result can be reused on every request without allocation.
func buildHSTSValue(cfg SecureHeadersConfig) string {
	if !cfg.HSTSEnabled {
		return ""
	}
	maxAge := cfg.HSTSMaxAge
	if maxAge <= 0 {
		maxAge = 63_072_000
	}

	var b strings.Builder
	fmt.Fprintf(&b, "max-age=%d", maxAge)
	if cfg.HSTSIncludeSubDomains {
		b.WriteString("; includeSubDomains")
	}
	return b.String()
}
