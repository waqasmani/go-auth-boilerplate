// Package errors is the central error type for the application.
package errors

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// AppError is the central error type for the application.
type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
	Err        error  `json:"-"`
	Details    any    `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates a new AppError with an underlying cause.
func New(code, message string, httpStatus int, err error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
		Err:        err,
	}
}

// Wrap wraps a standard error into an AppError.
func Wrap(appErr *AppError, err error) *AppError {
	return &AppError{
		Code:       appErr.Code,
		Message:    appErr.Message,
		HTTPStatus: appErr.HTTPStatus,
		Err:        err,
	}
}

// As checks if the error is an *AppError.
func As(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// WrapDatabase wraps database errors with consistent context.
func WrapDatabase(err error, operation string) *AppError {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	// Add specific MySQL error handling here if needed (e.g. duplicate key)
	return Wrap(ErrInternalServer, fmt.Errorf("db.%s: %w", operation, err))
}

// ─── Common Application Error Instances ───────────────────────────────────────
var ErrInternalServer = &AppError{
	Code:       "INTERNAL_SERVER_ERROR",
	Message:    "an unexpected error occurred",
	HTTPStatus: http.StatusInternalServerError,
}

var ErrNotFound = &AppError{
	Code:       "NOT_FOUND",
	Message:    "resource not found",
	HTTPStatus: http.StatusNotFound,
}

var ErrUnauthorized = &AppError{
	Code:       "UNAUTHORIZED",
	Message:    "authentication required",
	HTTPStatus: http.StatusUnauthorized,
}

var ErrForbidden = &AppError{
	Code:       "FORBIDDEN",
	Message:    "you do not have permission to perform this action",
	HTTPStatus: http.StatusForbidden,
}

var ErrBadRequest = &AppError{
	Code:       "BAD_REQUEST",
	Message:    "invalid request",
	HTTPStatus: http.StatusBadRequest,
}

var ErrConflict = &AppError{
	Code:       "CONFLICT",
	Message:    "resource already exists",
	HTTPStatus: http.StatusConflict,
}

var ErrInvalidCredentials = &AppError{
	Code:       "INVALID_CREDENTIALS",
	Message:    "invalid email or password",
	HTTPStatus: http.StatusUnauthorized,
}

var ErrTokenExpired = &AppError{
	Code:       "TOKEN_EXPIRED",
	Message:    "token has expired",
	HTTPStatus: http.StatusUnauthorized,
}

var ErrTokenInvalid = &AppError{
	Code:       "TOKEN_INVALID",
	Message:    "token is invalid",
	HTTPStatus: http.StatusUnauthorized,
}

var ErrTokenRevoked = &AppError{
	Code:       "TOKEN_REVOKED",
	Message:    "token has been revoked",
	HTTPStatus: http.StatusUnauthorized,
}

var ErrTokenReuse = &AppError{
	Code:       "TOKEN_REUSE_DETECTED",
	Message:    "token reuse detected — all sessions have been revoked",
	HTTPStatus: http.StatusUnauthorized,
}

var ErrEmailAlreadyExists = &AppError{
	Code:       "EMAIL_ALREADY_EXISTS",
	Message:    "an account with this email already exists",
	HTTPStatus: http.StatusConflict,
}

var ErrValidation = &AppError{
	Code:       "VALIDATION_ERROR",
	Message:    "request validation failed",
	HTTPStatus: http.StatusUnprocessableEntity,
}

var ErrRateLimitExceeded = &AppError{
	Code:       "RATE_LIMIT_EXCEEDED",
	Message:    "too many requests — slow down and try again",
	HTTPStatus: http.StatusTooManyRequests,
}

var ErrCSRFRejected = &AppError{
	Code:       "CSRF_REJECTED",
	Message:    "request origin could not be verified",
	HTTPStatus: http.StatusForbidden,
}

var ErrEmailNotVerified = &AppError{
	Code:       "EMAIL_NOT_VERIFIED",
	Message:    "please verify your email address before signing in",
	HTTPStatus: http.StatusForbidden,
}

// ErrAccountLocked is the sentinel AppError embedded inside LockoutError.
// Use NewLockoutError to attach a Retry-After duration; do not return this
// sentinel directly from the service layer.
var ErrAccountLocked = &AppError{
	Code:       "ACCOUNT_LOCKED",
	Message:    "account temporarily locked due to too many failed login attempts — check the Retry-After header",
	HTTPStatus: http.StatusTooManyRequests,
}

// LockoutError wraps ErrAccountLocked and carries the remaining lock duration
// so the handler can emit an accurate Retry-After response header without
// needing access to application configuration.
//
// response.Error correctly uses the embedded *AppError's HTTP 429 status and
// ACCOUNT_LOCKED code because errors.As traverses Unwrap and finds *AppError.
//
// Handler pattern:
//
//	result, err := h.svc.Login(c.Request.Context(), req)
//	if err != nil {
//	    var lockErr *apperrors.LockoutError
//	    if errors.As(err, &lockErr) {
//	        seconds := max(int(lockErr.RetryAfter.Seconds())+1, 1)
//	        c.Header("Retry-After", strconv.Itoa(seconds))
//	    }
//	    response.Error(c, err)
//	    return
//	}
type LockoutError struct {
	*AppError
	// RetryAfter is the remaining lock duration as reported by Redis TTL.
	// Always positive when a LockoutError is returned from the service layer.
	RetryAfter time.Duration
}

func (e *LockoutError) Error() string { return e.AppError.Error() }
func (e *LockoutError) Unwrap() error { return e.AppError }

// NewLockoutError constructs a LockoutError with the given remaining lock duration.
// retryAfter is sourced from AccountLocker.IsLocked and reflects the real
// Redis TTL — it is never a hardcoded configuration value.
func NewLockoutError(retryAfter time.Duration) *LockoutError {
	return &LockoutError{
		AppError:   ErrAccountLocked,
		RetryAfter: retryAfter,
	}
}

// ErrRequestTooLarge is returned by BindAndValidate when the request body
// exceeds the 64 KiB limit enforced by the MaxBytesReader wrapper in router.go.
//
// HTTP 413 Content Too Large (RFC 9110 §15.5.14) is the correct status: the
// server is refusing to process the request because the body is larger than it
// is willing to handle. The issue description suggests 400, but 413 is the
// semantically accurate code and is what well-behaved clients use to detect
// this condition without ambiguity.
var ErrRequestTooLarge = &AppError{
	Code:       "REQUEST_TOO_LARGE",
	Message:    "request body exceeds the maximum allowed size",
	HTTPStatus: http.StatusRequestEntityTooLarge, // 413
}
