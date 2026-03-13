package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

// Logger injects a request-scoped zap logger into the request context and
// logs a structured summary line after the handler chain completes.
//
// Injection happens before c.Next() so every downstream handler — including
// service-layer code that calls logger.FromContext(ctx) — receives a real
// logger pre-seeded with the request_id field.  Without this injection,
// logger.FromContext silently returns zap.NewNop() and all service-layer log
// calls are silently discarded.
//
// The request_id is read from the gin context rather than the header directly
// so this middleware is order-independent with respect to RequestID: whether
// RequestID runs before or after Logger, the value in the gin context is what
// both middlewares agree on.
func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Seed the request-scoped logger with request_id before the handler
		// chain runs.  All service code that calls logger.FromContext(ctx) will
		// get this logger and every log line they emit will automatically carry
		// the request_id without any extra instrumentation at the call site.
		requestID, _ := c.Get(RequestIDKey)
		reqLog := log.With(zap.String("request_id", requestIDStr(requestID)))
		c.Request = c.Request.WithContext(logger.WithContext(c.Request.Context(), reqLog))

		c.Next()

		log.Info("request",
			zap.String("request_id", requestIDStr(requestID)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.FullPath()),
			zap.String("url", c.Request.URL.RequestURI()),
			zap.Int("status", c.Writer.Status()),
			zap.Int("bytes", c.Writer.Size()),
			zap.String("ip", c.ClientIP()),
			zap.Duration("latency", time.Since(start)),
			zap.String("user_agent", c.Request.UserAgent()),
		)
	}
}
