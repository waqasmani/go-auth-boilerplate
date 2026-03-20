package oauth

import (
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// RateLimits carries per-endpoint token-bucket rates for the OAuth module.
type RateLimits struct {
	Login    float64
	Callback float64
	Link     float64
	Exchange float64
}

// RegisterRoutes attaches the OAuth endpoints to the provided router group.
//
// Route map:
//
//	GET  /oauth/:provider/login     — initiate authorisation (rate-limited)
//	GET  /oauth/:provider/callback  — provider callback (rate-limited)
//	POST /oauth/:provider/link      — explicit account linking (Auth + rate-limited)
//	POST /oauth/exchange            — mobile one-time code redemption (rate-limited)
func RegisterRoutes(
	rg *gin.RouterGroup,
	h *Handler,
	jwtHelper *platformauth.JWT,
	log *zap.Logger,
	limits RateLimits,
	rdb *goredis.Client,
) {
	loginRL := middleware.RateLimit(middleware.RateLimitConfig{
		Rate:    rateLimitFromFloat(limits.Login, 0.5),
		Burst:   5,
		TTL:     rateLimitTTL,
		MaxKeys: rateLimitMaxKeys,
	}, rdb, log)

	callbackRL := middleware.RateLimit(middleware.RateLimitConfig{
		Rate:    rateLimitFromFloat(limits.Callback, 0.5),
		Burst:   5,
		TTL:     rateLimitTTL,
		MaxKeys: rateLimitMaxKeys,
	}, rdb, log)

	linkRL := middleware.RateLimit(middleware.RateLimitConfig{
		Rate:    rateLimitFromFloat(limits.Link, 0.2),
		Burst:   3,
		TTL:     rateLimitTTL,
		MaxKeys: rateLimitMaxKeys,
	}, rdb, log)

	// exchangeRL is deliberately tight: burst=2 allows one legitimate retry in
	// case of a transient failure while making brute-force impractical.
	exchangeRL := middleware.RateLimit(middleware.RateLimitConfig{
		Rate:    rateLimitFromFloat(limits.Exchange, 0.1),
		Burst:   2,
		TTL:     rateLimitTTL,
		MaxKeys: rateLimitMaxKeys,
	}, rdb, log)

	rg.GET("/:provider/login", loginRL, h.Login)
	rg.GET("/:provider/callback", callbackRL, h.Callback)
	rg.POST("/:provider/link",
		middleware.Auth(jwtHelper, log),
		linkRL,
		h.Link,
	)
	rg.POST("/exchange", exchangeRL, h.Exchange)
}

// DefaultRateLimits returns conservative rate limits for all OAuth endpoints.
func DefaultRateLimits() RateLimits {
	return RateLimits{
		Login:    0.5,
		Callback: 0.5,
		Link:     0.2,
		Exchange: 0.1,
	}
}

func rateLimitFromFloat(r, fallback float64) rate.Limit {
	if r <= 0 {
		return rate.Limit(fallback)
	}
	return rate.Limit(r)
}
