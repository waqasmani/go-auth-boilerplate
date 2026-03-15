package authemail

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/waqasmani/go-auth-boilerplate/internal/config"
	"github.com/waqasmani/go-auth-boilerplate/internal/db"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
	mailer "github.com/waqasmani/go-auth-boilerplate/internal/platform/email"
)

// ── Module wiring ─────────────────────────────────────────────────────────────

type Module struct {
	Handler *Handler
	Service Service
}

// ModuleConfig carries every external dependency needed to build the module.
//
// TokenIssuer must be set to authMod.Service in app.go — it is used by
// VerifyOTP to issue a session token pair at the end of an MFA login.
// Mailer may be nil; see NewModule for details.
type ModuleConfig struct {
	Queries        *db.Queries
	Mailer         *mailer.Mailer // optional; may be nil
	Log            *zap.Logger
	FrontEndDomain string
	// TokenIssuer is auth.Service. Passed as the local TokenIssuer interface
	// (structural match) to avoid importing the auth module.
	TokenIssuer TokenIssuer
	// Cfg is needed by Handler.setCookie when VerifyOTP completes an MFA login.
	Cfg *config.Config
}

// NewModule constructs the email-auth module with its full dependency tree.
func NewModule(cfg ModuleConfig) *Module {
	repo := NewRepository(cfg.Queries)
	svc := NewService(repo, cfg.Mailer, cfg.Log, cfg.FrontEndDomain, cfg.TokenIssuer)
	h := NewHandler(svc, cfg.Cfg)
	return &Module{Handler: h, Service: svc}
}

// ── Route registration ────────────────────────────────────────────────────────

// RegisterRoutes attaches email-auth endpoints to a RouterGroup.
//
// Rate limiting strategy:
//   - /forgot-password       — 3 req/min; prevents email-spam-cannon abuse.
//   - /resend-verification   — 3 req/min; same risk profile as forgot-password.
//   - /reset-password        — 5 req/min; token is single-use but long-lived.
//   - /verify-email          — 10 req/min; generous for mobile deep-link retries.
//   - /otp/verify            — 5 req/min; tightest — brute-force protection for
//     6-digit codes (10^6 space, 10-minute window).
func RegisterRoutes(rg *gin.RouterGroup, h *Handler, jwt *platformauth.JWT, log *zap.Logger) {
	rg.POST("/forgot-password",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(3.0 / 60.0), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}),
		h.ForgotPassword,
	)

	// Unauthenticated resend — same rate profile as forgot-password.
	rg.POST("/resend-verification",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(3.0 / 60.0), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}),
		h.ResendVerification,
	)

	rg.POST("/reset-password",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(5.0 / 60.0), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}),
		h.ResetPassword,
	)

	rg.POST("/verify-email",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(10.0 / 60.0), Burst: 10, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}),
		h.VerifyEmail,
	)

	rg.POST("/otp/verify",
		middleware.RateLimit(middleware.RateLimitConfig{
			Rate: rate.Limit(5.0 / 60.0), Burst: 5, TTL: 5 * time.Minute, MaxKeys: 10_000,
		}),
		h.VerifyOTP,
	)

	// JWT-protected routes — for already-authenticated users only.
	//
	// /send-verification: re-sends the verification link to the authenticated
	//   user's current address. Useful when the user is still logged in from a
	//   session issued before the email gate was enforced, or after an email
	//   change that unverifies the new address.
	//
	// /otp/send: triggers a fresh OTP for step-up auth on a sensitive action.
	//   NOT used for MFA login — that path goes through InitiateChallenge which
	//   is called internally by auth.Service.Login, never by the client.
	protected := rg.Group("")
	protected.Use(middleware.Auth(jwt, log))
	{
		protected.POST("/send-verification", h.SendVerification)
		protected.POST("/otp/send", h.SendOTP)
	}
}
