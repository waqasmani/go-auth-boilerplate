package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
)

func TestQuerySizeLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const limit = 100

	newRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(middleware.QuerySizeLimit(limit))
		r.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		return r
	}

	tests := []struct {
		name       string
		rawQuery   string
		wantStatus int
	}{
		{
			name:       "empty query string",
			rawQuery:   "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "query string exactly at limit",
			rawQuery:   strings.Repeat("a", limit),
			wantStatus: http.StatusOK,
		},
		{
			name:       "query string one byte over limit",
			rawQuery:   strings.Repeat("a", limit+1),
			wantStatus: http.StatusRequestURITooLong, // 414
		},
		{
			// "code=" (5) + 50×"x" (50) + "&state=" (7) + 30×"y" (30) = 92 bytes < 100
			name:       "realistic OAuth callback within limit",
			rawQuery:   "code=" + strings.Repeat("x", 50) + "&state=" + strings.Repeat("y", 30),
			wantStatus: http.StatusOK,
		},
		{
			name:       "oversized state parameter",
			rawQuery:   "code=abc&state=" + strings.Repeat("z", limit),
			wantStatus: http.StatusRequestURITooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRouter()
			target := "/test"
			if tt.rawQuery != "" {
				target += "?" + tt.rawQuery
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (query len=%d, limit=%d)",
					w.Code, tt.wantStatus, len(tt.rawQuery), limit)
			}

			// 414 responses must include our structured error body, not a bare status.
			if tt.wantStatus == http.StatusRequestURITooLong {
				body := w.Body.String()
				if !strings.Contains(body, "URI_TOO_LONG") {
					t.Errorf("expected URI_TOO_LONG error code in body, got: %s", body)
				}
			}
		})
	}
}

// TestQuerySizeLimitAbortsProperly verifies that a rejected request does not
// reach any downstream handler — critical for the OAuth callback where
// reaching the handler with an oversized state parameter is the threat.
func TestQuerySizeLimitAbortsProperly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handlerReached := false
	r := gin.New()
	r.Use(middleware.QuerySizeLimit(10))
	r.GET("/test", func(c *gin.Context) {
		handlerReached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test?"+strings.Repeat("x", 11), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestURITooLong {
		t.Fatalf("expected 414, got %d", w.Code)
	}
	if handlerReached {
		t.Error("handler must not be called when query string exceeds the limit")
	}
}
