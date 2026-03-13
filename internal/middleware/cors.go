// Package middleware provides Gin middleware components for the application.
// This file implements CORS (Cross-Origin Resource Sharing) using the official
// gin-contrib/cors package. All policy knobs are driven by CORSConfig so they
// can be controlled through environment variables without touching code.
package middleware

import (
	"fmt"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORSConfig holds every tuneable parameter for the CORS middleware.
// All fields map 1-to-1 to the environment variables documented in config.go
// so operators can adjust the policy without recompiling.
type CORSConfig struct {
	// AllowedOrigins is the strict allowlist of origins the browser may make
	// credentialed or simple cross-origin requests from. The value "*" is only
	// appropriate for fully public, unauthenticated APIs — it must never be
	// combined with AllowCredentials: true (browsers will reject such responses
	// and the middleware panics at startup to surface the misconfiguration early).
	//
	// Correct production value: ["https://app.example.com", "https://admin.example.com"]
	AllowedOrigins []string

	// AllowedHeaders lists the non-simple request headers clients may include.
	// "Origin", "Content-Length", and "Content-Type" are added automatically by
	// gin-contrib/cors; list only the extras your frontend sends.
	AllowedHeaders []string

	// AllowCredentials instructs the browser that it may expose the response to
	// JavaScript when the request carries credentials (cookies, HTTP auth,
	// client-side TLS certificates). Setting this to true with AllowedOrigins
	// containing "*" is a CORS specification violation and will cause a panic at
	// startup — intentionally, so a misconfigured service never reaches prod.
	AllowCredentials bool

	// MaxAge controls how long (in seconds) the browser caches a preflight
	// response. Longer values reduce OPTIONS round-trips; the effective ceiling
	// for Chrome is 7 200 s (2 h) and for Firefox 86 400 s (24 h). A value of
	// 43 200 s (12 h) is a safe, portable choice.
	MaxAge int
}

// DefaultCORSConfig returns a conservative local-development configuration.
// It allows only localhost:3000, includes the common auth/custom headers, and
// permits credentials. Override all fields via environment variables in prod.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           43200,
	}
}

// CORS returns a Gin middleware that applies the supplied CORS policy.
//
// It panics at startup when AllowCredentials is true and AllowedOrigins
// contains "*" because that combination violates the CORS specification —
// browsers will always block such responses, and surfacing the
// misconfiguration at boot time is safer than silently serving broken
// preflight responses in production.
//
// Allowed methods are fixed to the set required by this API:
//
//	GET, POST, PUT, PATCH, DELETE, OPTIONS
//
// OPTIONS is always handled so preflight requests receive a proper 204 and
// are never forwarded to business-logic handlers.
func CORS(cfg CORSConfig) gin.HandlerFunc {
	if err := validateCORSConfig(cfg); err != nil {
		// Panic at startup so a misconfigured service never silently reaches
		// production. This mirrors how gin itself panics on invalid route
		// registrations — fast failure beats a subtly broken runtime.
		panic(fmt.Sprintf("middleware: CORS: invalid configuration: %v", err))
	}

	corsCfg := cors.Config{
		AllowOrigins: cfg.AllowedOrigins,
		AllowMethods: []string{
			"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
		},
		AllowHeaders:     buildAllowedHeaders(cfg.AllowedHeaders),
		ExposeHeaders:    []string{"X-Request-ID"},
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           time.Duration(cfg.MaxAge) * time.Second,
	}

	return cors.New(corsCfg)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// validateCORSConfig returns an error when the configuration is illegal.
// The only hard rule enforced here is the wildcard-origin + credentials
// combination that the CORS spec explicitly forbids.
func validateCORSConfig(cfg CORSConfig) error {
	if !cfg.AllowCredentials {
		return nil
	}
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			return fmt.Errorf(
				"AllowCredentials cannot be true when AllowedOrigins contains \"*\": " +
					"browsers always block such responses — list origins explicitly instead",
			)
		}
	}
	return nil
}

// buildAllowedHeaders merges caller-supplied headers with the minimal set that
// must always be present for the API to function correctly. Duplicates are
// de-duplicated so the response header stays compact.
func buildAllowedHeaders(extra []string) []string {
	// Always required regardless of what the caller passes.
	required := []string{"Origin", "Content-Length", "Content-Type", "Authorization"}

	seen := make(map[string]struct{}, len(required)+len(extra))
	merged := make([]string, 0, len(required)+len(extra))

	for _, h := range append(required, extra...) {
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			merged = append(merged, h)
		}
	}
	return merged
}
