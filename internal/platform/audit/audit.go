// Package audit provides a structured, append-only audit log for
// security-critical events. Events are emitted to a named child logger
// ("audit") so they can be routed, retained, and alerted on independently of
// the application request log in any structured-log aggregator (Datadog, Loki,
// CloudWatch Insights, etc.).
//
// # PII policy
//
// Audit logs may be shipped to external SIEM systems, log aggregators, and
// long-retention cold storage. Raw PII (email addresses, names, phone numbers)
// in these streams creates GDPR/CCPA retention and data-minimisation obligations
// that are difficult to enforce retroactively once data has been ingested.
//
// Rules:
//   - Always pass email addresses through MaskEmail before including them in a
//     zap.Field. MaskEmail preserves enough information for incident
//     investigation (first char + domain) while preventing the full address
//     from appearing in log pipelines.
//   - user_id (UUID) is not PII under most frameworks and may be logged in full
//     as it is required to cross-reference events across the audit stream.
//   - Never log passwords, tokens, secrets, or raw OTP codes in any field.
//
// Example:
//
//	auditLog.Log(ctx, audit.EventLoginFailed, userID,
//	    zap.String("email", audit.MaskEmail(req.Email)),
//	    zap.String("reason", "invalid_password"),
//	)
package audit

import (
	"context"
	"strings"

	"go.uber.org/zap"

	"github.com/waqasmani/go-auth-boilerplate/internal/platform/logger"
)

// EventType is a stable string identifier for an audit event.
// Values follow the "domain.action" naming convention so multiple services can
// share one log sink without naming collisions.
type EventType string

const (
	// ─── Authentication lifecycle ─────────────────────────────────────────────
	EventRegister           EventType = "auth.register"
	EventLoginSuccess       EventType = "auth.login_success"
	EventLoginFailed        EventType = "auth.login_failed"
	EventLogout             EventType = "auth.logout"
	EventTokenRefreshed     EventType = "auth.token_refreshed"
	EventTokenReuseDetected EventType = "auth.token_reuse_detected"
	EventSessionsRevoked    EventType = "auth.sessions_revoked"

	// ─── Multi-factor authentication ─────────────────────────────────────────
	EventMFAChallenged EventType = "auth.mfa_challenged"
	EventMFACompleted  EventType = "auth.mfa_completed"
	EventOTPFailed     EventType = "auth.otp_failed"

	// ─── Email / credential lifecycle ────────────────────────────────────────
	EventPasswordResetRequested EventType = "auth.password_reset_requested"
	EventPasswordReset          EventType = "auth.password_reset"
	EventEmailVerified          EventType = "auth.email_verified"
	EventVerificationSent       EventType = "auth.verification_sent"
	EventOTPSent                EventType = "auth.otp_sent"

	// ─── TOTP ─────────────────────────────────────────────────────────────────────
	EventTOTPSetup    EventType = "auth.totp_setup"
	EventTOTPEnabled  EventType = "auth.totp_enabled"
	EventTOTPDisabled EventType = "auth.totp_disabled"
	EventTOTPFailed   EventType = "auth.totp_failed"
)

// Logger writes append-only structured audit events. Embed it in any service
// struct that needs to record security-significant operations.
type Logger struct {
	log *zap.Logger
}

// New returns an audit Logger backed by a named child of base.
func New(base *zap.Logger) *Logger {
	return &Logger{log: base.Named("audit")}
}

// Log emits one audit event at Info level.
//
// When ctx carries a request-scoped logger (injected by middleware.Logger),
// the event is written through that logger so request_id is included
// automatically. When no context logger is present — background goroutines,
// tests without a full middleware stack — the module-level "audit" logger is
// used as a fallback, guaranteeing that events are never silently discarded.
func (l *Logger) Log(ctx context.Context, eventType EventType, userID string, fields ...zap.Field) {
	base := make([]zap.Field, 0, 2+len(fields))
	base = append(base,
		zap.String("event_type", string(eventType)),
		zap.String("user_id", userID),
	)
	base = append(base, fields...)
	logger.FromContextOrFallback(ctx, l.log).Info("audit_event", base...)
}

// ─── PII helpers ──────────────────────────────────────────────────────────────

// MaskEmail masks an email address for safe inclusion in audit log fields,
// reducing PII exposure without eliminating the information needed for
// incident investigation.
//
// Masking rules:
//   - The first character of the local part is preserved.
//   - The last character of the local part is preserved when the local part is
//     longer than two characters; for two-character local parts only the first
//     character is preserved.
//   - All intermediate characters of the local part are replaced with "*".
//   - The "@" separator and full domain are always preserved — the domain alone
//     is enough to identify the mail provider for an investigation without
//     revealing the full address to a log reader.
//
// Examples:
//
//	"alice@example.com"           → "a***e@example.com"
//	"ab@example.com"              → "a*@example.com"
//	"a@example.com"               → "a@example.com"
//	"alice.smith@company.co.uk"   → "a**********h@company.co.uk"
//	""                            → ""
//	"notanemail"                  → "n*********l"  (no "@" — masks all but first/last)
//
// Always pass email fields through MaskEmail before calling audit.Log:
//
//	zap.String("email", audit.MaskEmail(req.Email))
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}

	at := strings.LastIndex(email, "@")
	if at < 0 {
		// Not a recognisable email shape — mask all but the first and last chars.
		return maskString(email)
	}

	local := email[:at]
	domain := email[at:] // includes the "@" prefix
	return maskString(local) + domain
}

// maskString partially obfuscates s, preserving the first and last characters
// and replacing the interior with asterisks. For strings of length ≤ 1 the
// value is returned as-is; for length 2 only the first character is kept.
func maskString(s string) string {
	n := len(s)
	switch {
	case n <= 1:
		return s
	case n == 2:
		return string(s[0]) + "*"
	default:
		return string(s[0]) + strings.Repeat("*", n-2) + string(s[n-1])
	}
}
