package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Logger logs each request with structured fields.
func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		requestID, _ := c.Get(RequestIDKey)
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
