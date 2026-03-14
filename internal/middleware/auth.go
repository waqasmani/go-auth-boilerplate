package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
	"go.uber.org/zap"
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

// MustGetClaims extracts JWT claims from the gin context.
// It panics when claims are absent, which means the Auth middleware was not
// applied before this handler. Use only on routes that are protected by Auth.
func MustGetClaims(c *gin.Context) *platformauth.Claims {
	val, exists := c.Get(ClaimsKey)
	if !exists {
		panic("middleware: MustGetClaims called on a route without Auth middleware — " +
			"add middleware.Auth to the route group")
	}
	claims, ok := val.(*platformauth.Claims)
	if !ok || claims == nil {
		panic("middleware: ClaimsKey is set but does not contain *platformauth.Claims — " +
			"this is a bug in the Auth middleware")
	}
	return claims
}
