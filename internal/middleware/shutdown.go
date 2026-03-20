package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	apperrors "github.com/waqasmani/go-auth-boilerplate/internal/errors"
	"github.com/waqasmani/go-auth-boilerplate/internal/response"
)

// Shutdown returns a middleware that responds 503 Service Unavailable with a
// Retry-After: 5 header to every new request once shutdownCh is closed.
//
// Place this immediately after CORS in the global middleware chain. Requests
// that arrived before the channel is closed continue to the handler normally;
// only new requests received during the drain window are rejected.
//
// Wiring in app.go:
//
//	shutdownCh := make(chan struct{})
//	// pass shutdownCh to router via Options.ShutdownCh
//	// close(shutdownCh) when SIGTERM/SIGINT is received, before draining
func Shutdown(shutdownCh <-chan struct{}) gin.HandlerFunc {
	unavailable := apperrors.New(
		"SERVICE_UNAVAILABLE",
		"server is shutting down — please retry in a few seconds",
		http.StatusServiceUnavailable,
		nil,
	)

	return func(c *gin.Context) {
		select {
		case <-shutdownCh:
			c.Header("Retry-After", "5")
			response.Error(c, unavailable)
			c.Abort()
		default:
			c.Next()
		}
	}
}
