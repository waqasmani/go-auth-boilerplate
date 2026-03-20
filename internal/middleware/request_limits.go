// Package middleware — request-size guards for non-body input vectors.
//
// # Why a separate file?
//
// router.go already wraps every request body in http.MaxBytesReader (64 KiB).
// That wrapper is effective for POST/PUT/PATCH routes whose handlers call
// ShouldBindJSON, but it has no effect on:
//
//   - URL query strings   — read entirely from net/url.URL.RawQuery before
//     the handler chain begins; never passes through the body reader.
//   - URL path parameters — embedded in the URL itself.
//
// An attacker can therefore supply an arbitrarily-long `state=` or `code=`
// query parameter to the OAuth callback endpoint, bypassing the body limit
// completely. The parameter reaches ParseAndVerifyOAuthState (HMAC work),
// base64 decoding, and JSON unmarshalling before any size gate fires.
//
// # Limits chosen
//
// QuerySizeLimitBytes (4 KiB):
//
//	A full OAuth callback query string — code (~180 chars) plus a signed
//	state (~320 chars including base64url payload, separator, and hex HMAC)
//	plus provider error fields — totals roughly 600 bytes in the worst
//	legitimate case. 4 KiB is ~6.5× that ceiling, leaving ample room for
//	any future additions without permitting abuse.
//
// HTTP status 414 URI Too Long (RFC 9110 §15.5.15) is the correct response
// when the request-target URI exceeds what the server is willing to process.
// Using 414 instead of 400 or 413 lets reverse proxies and monitoring systems
// identify oversized-URL abuse without parsing the response body.
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

const (
	// DefaultQuerySizeLimit is the maximum byte length of the raw URL query
	// string (everything after the "?") that the server will process.
	// Requests whose query string exceeds this value are rejected with 414
	// before any handler or parameter decoder runs.
	DefaultQuerySizeLimit = 4 * 1024 // 4 KiB
)

// errQueryTooLong is the sentinel returned to the response helper when the
// query string exceeds the configured limit. Defined as a package-level var
// so it can be matched by errors.Is in tests without importing the apperrors
// package directly.
var errQueryTooLong = apperrors.New(
	"URI_TOO_LONG",
	"request URI exceeds the maximum allowed length",
	http.StatusRequestURITooLong, // 414
	nil,
)

// QuerySizeLimit returns a middleware that rejects requests whose raw URL
// query string is longer than maxBytes. Pass DefaultQuerySizeLimit for the
// standard production cap.
//
// The check runs before any gin parameter binding, so an oversized `state=`,
// `code=`, or `redirect_url=` value never reaches application logic.
//
// The middleware is deliberately narrow: it checks only the query string, not
// the path or fragment. Path length is constrained upstream by the HTTP server
// and any reverse proxy (nginx default: 8 KiB); query strings are the vector
// that gin exposes to application code without a built-in cap.
//
// Place this immediately after the body MaxBytesReader wrapper in the global
// middleware chain:
//
//	r.Use(func(c *gin.Context) { /* MaxBytesReader … */ })
//	r.Use(middleware.QuerySizeLimit(middleware.DefaultQuerySizeLimit))
func QuerySizeLimit(maxBytes int) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.URL.RawQuery) > maxBytes {
			response.Error(c, errQueryTooLong)
			c.Abort()
			return
		}
		c.Next()
	}
}
