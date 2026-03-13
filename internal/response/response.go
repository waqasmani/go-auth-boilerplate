package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
