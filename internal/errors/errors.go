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

var (
	ErrInternalServer = &AppError{
		Code:       "INTERNAL_SERVER_ERROR",
		Message:    "an unexpected error occurred",
		HTTPStatus: http.StatusInternalServerError,
	}
	ErrNotFound = &AppError{
		Code:       "NOT_FOUND",
		Message:    "resource not found",
		HTTPStatus: http.StatusNotFound,
	}
	ErrUnauthorized = &AppError{
		Code:       "UNAUTHORIZED",
		Message:    "authentication required",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrForbidden = &AppError{
		Code:       "FORBIDDEN",
		Message:    "you do not have permission to perform this action",
		HTTPStatus: http.StatusForbidden,
	}
	ErrBadRequest = &AppError{
		Code:       "BAD_REQUEST",
		Message:    "invalid request",
		HTTPStatus: http.StatusBadRequest,
	}
	ErrConflict = &AppError{
		Code:       "CONFLICT",
		Message:    "resource already exists",
		HTTPStatus: http.StatusConflict,
	}

	// Auth-specific errors
	ErrInvalidCredentials = &AppError{
		Code:       "INVALID_CREDENTIALS",
		Message:    "invalid email or password",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrTokenExpired = &AppError{
		Code:       "TOKEN_EXPIRED",
		Message:    "token has expired",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrTokenInvalid = &AppError{
		Code:       "TOKEN_INVALID",
		Message:    "token is invalid",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrTokenRevoked = &AppError{
		Code:       "TOKEN_REVOKED",
		Message:    "token has been revoked",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrTokenReuse = &AppError{
		Code:       "TOKEN_REUSE_DETECTED",
		Message:    "token reuse detected — all sessions have been revoked",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrEmailAlreadyExists = &AppError{
		Code:       "EMAIL_ALREADY_EXISTS",
		Message:    "an account with this email already exists",
		HTTPStatus: http.StatusConflict,
	}

	// Validation error
	ErrValidation = &AppError{
		Code:       "VALIDATION_ERROR",
		Message:    "request validation failed",
		HTTPStatus: http.StatusUnprocessableEntity,
	}
)
