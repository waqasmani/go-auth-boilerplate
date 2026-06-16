package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// RequestIDHeader is the HTTP header key used to propagate request IDs.
	RequestIDHeader = "X-Request-ID"
	// RequestIDKey is the context key used to store the request ID internally.
	RequestIDKey = "request_id"
)

// maxRequestIDLen bounds an accepted client-supplied correlation ID.
const maxRequestIDLen = 128

// RequestID injects or propagates a unique request ID. A client-supplied
// X-Request-ID is accepted only when it is a sane length and uses a safe
// character set; otherwise a fresh UUID is generated. This prevents log
// injection / pollution via a forged correlation ID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := sanitizeRequestID(c.GetHeader(RequestIDHeader))
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set(RequestIDKey, requestID)
		c.Header(RequestIDHeader, requestID)
		c.Next()
	}
}

// sanitizeRequestID returns id when it is a safe correlation identifier, or ""
// to signal that a fresh ID should be generated. Allowed characters are limited
// to [A-Za-z0-9._-] so the value cannot smuggle newlines or control characters
// into structured logs.
func sanitizeRequestID(id string) string {
	if len(id) == 0 || len(id) > maxRequestIDLen {
		return ""
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return ""
		}
	}
	return id
}
