package errors_test

import (
	"errors"
	"net/http"
	"testing"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

func TestAppError_Error(t *testing.T) {
	err := &apperrors.AppError{
		Code:       "TEST_CODE",
		Message:    "test message",
		HTTPStatus: http.StatusBadRequest,
	}
	if err.Error() == "" {
		t.Error("Error() should return non-empty string")
	}
}

func TestAppError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := apperrors.New("TEST", "msg", http.StatusInternalServerError, cause)
	if !errors.Is(err, cause) {
		t.Error("errors.Is should traverse Unwrap chain")
	}
}

func TestAs_MatchesAppError(t *testing.T) {
	wrapped := apperrors.Wrap(apperrors.ErrNotFound, errors.New("db error"))

	appErr, ok := apperrors.As(wrapped)
	if !ok {
		t.Fatal("expected As to return true")
	}
	if appErr.Code != apperrors.ErrNotFound.Code {
		t.Errorf("expected code NOT_FOUND, got %s", appErr.Code)
	}
}

func TestAs_NonAppError(t *testing.T) {
	_, ok := apperrors.As(errors.New("plain error"))
	if ok {
		t.Error("expected As to return false for plain error")
	}
}

func TestPredefinedErrors_HaveHTTPStatus(t *testing.T) {
	errs := []*apperrors.AppError{
		apperrors.ErrInternalServer,
		apperrors.ErrNotFound,
		apperrors.ErrUnauthorized,
		apperrors.ErrForbidden,
		apperrors.ErrBadRequest,
		apperrors.ErrConflict,
		apperrors.ErrInvalidCredentials,
		apperrors.ErrTokenExpired,
		apperrors.ErrTokenInvalid,
		apperrors.ErrTokenRevoked,
		apperrors.ErrTokenReuse,
		apperrors.ErrEmailAlreadyExists,
	}
	for _, e := range errs {
		if e.HTTPStatus == 0 {
			t.Errorf("error %s has zero HTTPStatus", e.Code)
		}
		if e.Code == "" {
			t.Error("error has empty Code")
		}
	}
}
