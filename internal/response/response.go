package response

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
)

// Response is the standard API envelope.
type Response struct {
	Success bool       `json:"success"`
	Message string     `json:"message,omitempty"`
	Data    any        `json:"data,omitempty"`
	Error   *ErrorBody `json:"error,omitempty"`
}

// ErrorBody carries error code and human-readable detail.
type ErrorBody struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

// OK sends a 200 JSON response with data.
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    data,
	})
}

// Created sends a 201 JSON response with data.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, Response{
		Success: true,
		Data:    data,
	})
}

// NoContent sends a 204 response.
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error maps an AppError to a JSON error response.
func Error(c *gin.Context, err error) {
	if appErr, ok := apperrors.As(err); ok {
		c.JSON(appErr.HTTPStatus, Response{
			Success: false,
			Error: &ErrorBody{
				Code:    appErr.Code,
				Message: appErr.Message,
			},
		})
		return
	}
	// Fallback for non-app errors
	c.JSON(http.StatusInternalServerError, Response{
		Success: false,
		Error: &ErrorBody{
			Code:    "INTERNAL_SERVER_ERROR",
			Message: "an unexpected error occurred",
		},
	})
}

// ValidationError sends a 422 with field-level detail.
func ValidationError(c *gin.Context, details map[string]string) {
	c.JSON(http.StatusUnprocessableEntity, Response{
		Success: false,
		Error: &ErrorBody{
			Code:    "VALIDATION_ERROR",
			Message: "request validation failed",
			Details: details,
		},
	})
}

// BindAndValidate binds the request body as JSON and validates the resulting
// struct against business rules. It returns a typed AppError on failure.
func BindAndValidate(c *gin.Context, req any, v *validator.Validate) bool {
	// Reject requests whose Content-Type is not application/json before
	// attempting to decode the body.
	//
	// HasPrefix rather than exact equality tolerates legitimate variations
	// such as "application/json; charset=utf-8" that some clients send.
	//
	// This check runs before ShouldBindJSON for two reasons:
	//   1. ShouldBindJSON will happily decode any body regardless of the
	//      declared media type, so a text/plain body containing valid JSON
	//      would otherwise succeed silently.
	//   2. When Content-Type is correct but the body is absent, the error
	//      from ShouldBindJSON ("EOF") is unambiguous and the existing
	//      "malformed or invalid JSON body" message is accurate.
	if ct := c.GetHeader("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		c.JSON(http.StatusUnsupportedMediaType, Response{
			Success: false,
			Error: &ErrorBody{
				Code:    "UNSUPPORTED_MEDIA_TYPE",
				Message: `Content-Type must be "application/json"`,
			},
		})
		return false
	}

	if err := c.ShouldBindJSON(req); err != nil {
		ValidationError(c, map[string]string{"body": "malformed or invalid JSON body"})
		return false
	}

	if err := v.Struct(req); err != nil {
		var validationErrs validator.ValidationErrors
		if errors.As(err, &validationErrs) {
			fields := make(map[string]string, len(validationErrs))
			for _, fe := range validationErrs {
				fields[fieldName(fe)] = humanMessage(fe.Tag())
			}
			ValidationError(c, fields)
		} else {
			// Catch-all: still must write a response.
			ValidationError(c, map[string]string{"body": "invalid request format"})
		}
		return false
	}

	return true
}

// fieldName extracts the JSON tag name from the validator FieldError so the
// response key matches what the client sent, not the Go struct field name.
// "Password" (struct) → "password" (json tag) closes a secondary leak where
// internal naming conventions are visible to API consumers.
func fieldName(fe validator.FieldError) string {
	return fe.Field()
}

// humanMessage converts a validator tag into a generic, non-revealing message.
// It deliberately omits parameter values (fe.Param()) to avoid leaking schema
// constraints such as minimum password length or maximum field sizes.
func humanMessage(tag string) string {
	switch tag {
	case "required":
		return "this field is required"
	case "email":
		return "invalid email address"
	case "min":
		return "value does not meet minimum length or size requirements"
	case "max":
		return "value exceeds maximum length or size"
	case "url", "uri":
		return "invalid URL format"
	case "uuid", "uuid4":
		return "invalid identifier format"
	case "oneof":
		return "value is not one of the accepted options"
	case "alphanum":
		return "only alphanumeric characters are allowed"
	default:
		return "invalid field format"
	}
}
