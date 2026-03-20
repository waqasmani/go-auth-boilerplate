package response

import (
	"errors"
	"mime"
	"net/http"

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
//
// Content-Type validation uses mime.ParseMediaType for strict RFC 7231
// compliance — only "application/json" is accepted regardless of charset or
// other parameters. This prevents mis-typed media types such as
// "application/jsonp" from bypassing the check, which strings.HasPrefix
// would have allowed.
//
// Body-size handling: the router wraps every request body in a
// MaxBytesReader(64 KiB) before routing. When the client sends more than
// 64 KiB, the underlying Read call returns *http.MaxBytesError, which
// json.Decoder propagates unwrapped. We detect it here with errors.As —
// available since Go 1.19, which is the minimum version implied by the
// dependencies in this module — and return 413 Content Too Large rather than
// the generic 422 that the catch-all ShouldBindJSON branch would produce.
// The check must come before the generic branch because *http.MaxBytesError
// is not a JSON syntax error and should not be reported as one.
func BindAndValidate(c *gin.Context, req any, v *validator.Validate) bool {
	// Reject requests whose Content-Type is not application/json.
	ct := c.GetHeader("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/json" {
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
		// ── Body-size guard ──────────────────────────────────────────────────
		// *http.MaxBytesError is returned when the MaxBytesReader installed by
		// the router middleware fires. It must be checked before the generic
		// branch below so that oversized bodies produce 413 Content Too Large
		// (RFC 9110 §15.5.14) rather than 422 Unprocessable Entity.
		//
		// errors.As traverses the full error chain, which is necessary because
		// json.Decoder may wrap the read error in a *json.SyntaxError or
		// return it directly depending on where in the stream the limit fires.
		// Using errors.As handles both cases without brittle string matching.
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			Error(c, apperrors.ErrRequestTooLarge)
			return false
		}

		// ── Generic JSON decode failure ───────────────────────────────────────
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
			ValidationError(c, map[string]string{"body": "invalid request format"})
		}
		return false
	}

	return true
}

// fieldName extracts the JSON tag name from the validator FieldError so the
// response key matches what the client sent, not the Go struct field name.
func fieldName(fe validator.FieldError) string {
	return fe.Field()
}

// humanMessage converts a validator tag into a generic, non-revealing message.
// Parameter values (fe.Param()) are intentionally omitted to avoid leaking
// schema constraints such as minimum password length or maximum field sizes.
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
	case "len":
		return "value does not match the required length"
	case "numeric":
		return "only numeric characters are allowed"
	default:
		return "invalid field format"
	}
}
