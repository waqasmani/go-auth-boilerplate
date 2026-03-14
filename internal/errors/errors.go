// Package errors is the central error type for the application
package errors

import (
	"errors"
	"fmt"
	"net/http"
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

// ─── Common Application Error Instances ───────────────────────────────────────

// ErrInternalServer is returned when an unexpected internal server error occurs.
var ErrInternalServer = &AppError{
	Code:       "INTERNAL_SERVER_ERROR",
	Message:    "an unexpected error occurred",
	HTTPStatus: http.StatusInternalServerError,
}

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = &AppError{
	Code:       "NOT_FOUND",
	Message:    "resource not found",
	HTTPStatus: http.StatusNotFound,
}

// ErrUnauthorized is returned when authentication is required but missing or invalid.
var ErrUnauthorized = &AppError{
	Code:       "UNAUTHORIZED",
	Message:    "authentication required",
	HTTPStatus: http.StatusUnauthorized,
}

// ErrForbidden is returned when the user lacks permission for the requested action.
var ErrForbidden = &AppError{
	Code:       "FORBIDDEN",
	Message:    "you do not have permission to perform this action",
	HTTPStatus: http.StatusForbidden,
}

// ErrBadRequest is returned when the request payload is malformed or invalid.
var ErrBadRequest = &AppError{
	Code:       "BAD_REQUEST",
	Message:    "invalid request",
	HTTPStatus: http.StatusBadRequest,
}

// ErrConflict is returned when a request conflicts with the current state of the server.
var ErrConflict = &AppError{
	Code:       "CONFLICT",
	Message:    "resource already exists",
	HTTPStatus: http.StatusConflict,
}

// Auth-specific errors

// ErrInvalidCredentials is returned when login credentials fail verification.
var ErrInvalidCredentials = &AppError{
	Code:       "INVALID_CREDENTIALS",
	Message:    "invalid email or password",
	HTTPStatus: http.StatusUnauthorized,
}

// ErrTokenExpired is returned when a presented token has passed its expiration time.
var ErrTokenExpired = &AppError{
	Code:       "TOKEN_EXPIRED",
	Message:    "token has expired",
	HTTPStatus: http.StatusUnauthorized,
}

// ErrTokenInvalid is returned when a token fails signature or format validation.
var ErrTokenInvalid = &AppError{
	Code:       "TOKEN_INVALID",
	Message:    "token is invalid",
	HTTPStatus: http.StatusUnauthorized,
}

// ErrTokenRevoked is returned when a token has been explicitly revoked before expiry.
var ErrTokenRevoked = &AppError{
	Code:       "TOKEN_REVOKED",
	Message:    "token has been revoked",
	HTTPStatus: http.StatusUnauthorized,
}

// ErrTokenReuse is returned when token reuse is detected, triggering cascade revocation.
var ErrTokenReuse = &AppError{
	Code:       "TOKEN_REUSE_DETECTED",
	Message:    "token reuse detected — all sessions have been revoked",
	HTTPStatus: http.StatusUnauthorized,
}

// ErrEmailAlreadyExists is returned when attempting to register with a duplicate email.
var ErrEmailAlreadyExists = &AppError{
	Code:       "EMAIL_ALREADY_EXISTS",
	Message:    "an account with this email already exists",
	HTTPStatus: http.StatusConflict,
}

// Validation errors

// ErrValidation is returned when request data fails schema or business rule validation.
var ErrValidation = &AppError{
	Code:       "VALIDATION_ERROR",
	Message:    "request validation failed",
	HTTPStatus: http.StatusUnprocessableEntity,
}

// ErrRateLimitExceeded returns the JSON body for a 429 response.
var ErrRateLimitExceeded = &AppError{
	Code:       "RATE_LIMIT_EXCEEDED",
	Message:    "too many requests — slow down and try again",
	HTTPStatus: http.StatusTooManyRequests,
}
