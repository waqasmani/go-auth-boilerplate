package middleware

import (
	"github.com/gin-gonic/gin"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
	"go.uber.org/zap"
)

// Recovery handles panics, logs them with the request_id, and returns 500.
func Recovery(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				requestID, _ := c.Get(RequestIDKey)
				log.Error("panic recovered",
					zap.Any("panic", r),
					zap.String("request_id", requestIDStr(requestID)),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
				)
				response.Error(c, apperrors.ErrInternalServer)
			}
		}()
		c.Next()
	}
}

func requestIDStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
