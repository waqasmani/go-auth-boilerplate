package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

const (
	// ClaimsKey is the context key used to store authenticated user claims.
	ClaimsKey = "claims"
	// UserIDKey is the context key used to store authenticated user id.
	UserIDKey = "user_id"
)

// Auth validates the JWT Bearer token and populates gin context with claims.
func Auth(jwtHelper *platformauth.JWT, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			response.Error(c, apperrors.ErrUnauthorized)
			c.Abort()
			return
		}

		parts := strings.SplitN(authorization, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			response.Error(c, apperrors.ErrTokenInvalid)
			c.Abort()
			return
		}

		claims, err := jwtHelper.ValidateAccessToken(parts[1])
		if err != nil {
			log.Debug("token validation failed",
				zap.Error(err),
				zap.String("request_id", requestIDStr(c.MustGet(RequestIDKey))),
			)
			response.Error(c, err)
			c.Abort()
			return
		}

		c.Set(ClaimsKey, claims)
		c.Set(UserIDKey, claims.UserID)
		c.Next()
	}
}

// GetClaims extracts JWT claims from the gin context. The second return value
// reports whether claims were present and well-typed. Returns false when the
// Auth middleware was not applied before the calling handler, surfacing
// route mis-wiring as a 401 at test time rather than a panic in production.
//
//	claims, ok := middleware.GetClaims(c)
//	if !ok {
//	    response.Error(c, apperrors.ErrUnauthorized)
//	    c.Abort()
//	    return
//	}
func GetClaims(c *gin.Context) (*platformauth.Claims, bool) {
	val, exists := c.Get(ClaimsKey)
	if !exists {
		return nil, false
	}
	claims, ok := val.(*platformauth.Claims)
	if !ok || claims == nil {
		return nil, false
	}
	return claims, true
}
