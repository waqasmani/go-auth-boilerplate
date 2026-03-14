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

// RequestID injects or propagates a unique request ID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set(RequestIDKey, requestID)
		c.Header(RequestIDHeader, requestID)
		c.Next()
	}
}
