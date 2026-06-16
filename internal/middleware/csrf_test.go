package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
)

// csrfEngine builds a minimal Gin engine with CookieCSRF applied to a single
// POST /auth/refresh route. The downstream handler records whether it was
// reached and returns 200 OK so tests can distinguish "passed through" from
// "rejected".
func csrfEngine(t *testing.T, cfg middleware.CookieCSRFConfig) (*gin.Engine, *bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	reached := false
	r := gin.New()
	r.POST("/auth/refresh", middleware.CookieCSRF(cfg), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})
	return r, &reached
}

const trustedOrigin = "https://app.example.com"

func trustedCSRFConfig() middleware.CookieCSRFConfig {
	return middleware.CookieCSRFConfig{
		TrustedOrigins: []string{trustedOrigin, "https://admin.example.com"},
	}
}

// ─── Gate: enforcement only on cookie-bearing requests ─────────────────────────

// TestCookieCSRF_NoCookie_PassesThrough confirms the documented rule: the
// middleware is a no-op when the refresh_token cookie is absent, so JSON-body
// API clients are unaffected even with a hostile Origin header.
func TestCookieCSRF_NoCookie_PassesThrough(t *testing.T) {
	r, reached := csrfEngine(t, trustedCSRFConfig())

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	// A hostile Origin must NOT matter when there is no cookie.
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("no-cookie request: status = %d, want 200 (CSRF check must not apply)", w.Code)
	}
	if !*reached {
		t.Error("no-cookie request: downstream handler must be reached")
	}
}

// ─── Origin header (primary signal) ────────────────────────────────────────────

func TestCookieCSRF_CookiePresent_OriginCases(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		wantStatus int
		wantReach  bool
	}{
		{
			name:       "trusted origin allowed",
			origin:     trustedOrigin,
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "second trusted origin allowed",
			origin:     "https://admin.example.com",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "trusted origin case-insensitive host",
			origin:     "https://APP.EXAMPLE.COM",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "untrusted origin rejected",
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
			wantReach:  false,
		},
		{
			name:       "trusted host wrong scheme rejected",
			origin:     "http://app.example.com",
			wantStatus: http.StatusForbidden,
			wantReach:  false,
		},
		{
			name:       "malformed origin rejected",
			origin:     "://not a url",
			wantStatus: http.StatusForbidden,
			wantReach:  false,
		},
		{
			name:       "origin missing host rejected",
			origin:     "https://",
			wantStatus: http.StatusForbidden,
			wantReach:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, reached := csrfEngine(t, trustedCSRFConfig())

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "abc123"})
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("origin=%q: status = %d, want %d", tt.origin, w.Code, tt.wantStatus)
			}
			if *reached != tt.wantReach {
				t.Errorf("origin=%q: handler reached = %v, want %v", tt.origin, *reached, tt.wantReach)
			}
			if tt.wantStatus == http.StatusForbidden && !strings.Contains(w.Body.String(), "CSRF_REJECTED") {
				t.Errorf("origin=%q: expected CSRF_REJECTED in body, got: %s", tt.origin, w.Body.String())
			}
		})
	}
}

// ─── Referer fallback (when Origin absent) ─────────────────────────────────────

func TestCookieCSRF_CookiePresent_RefererFallback(t *testing.T) {
	tests := []struct {
		name       string
		referer    string
		wantStatus int
		wantReach  bool
	}{
		{
			name:       "trusted referer with path allowed",
			referer:    trustedOrigin + "/login",
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "trusted referer bare origin allowed",
			referer:    trustedOrigin,
			wantStatus: http.StatusOK,
			wantReach:  true,
		},
		{
			name:       "untrusted referer rejected",
			referer:    "https://evil.example.com/login",
			wantStatus: http.StatusForbidden,
			wantReach:  false,
		},
		{
			name:       "malformed referer rejected",
			referer:    "not-a-url",
			wantStatus: http.StatusForbidden,
			wantReach:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, reached := csrfEngine(t, trustedCSRFConfig())

			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "abc123"})
			// No Origin header — force the Referer fallback path.
			req.Header.Set("Referer", tt.referer)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("referer=%q: status = %d, want %d", tt.referer, w.Code, tt.wantStatus)
			}
			if *reached != tt.wantReach {
				t.Errorf("referer=%q: handler reached = %v, want %v", tt.referer, *reached, tt.wantReach)
			}
		})
	}
}

// TestCookieCSRF_OriginTakesPrecedenceOverReferer confirms that when both headers
// are present the Origin is the deciding signal: a trusted Origin wins even with
// a hostile Referer, and a hostile Origin loses even with a trusted Referer.
func TestCookieCSRF_OriginTakesPrecedenceOverReferer(t *testing.T) {
	t.Run("trusted origin wins over hostile referer", func(t *testing.T) {
		r, reached := csrfEngine(t, trustedCSRFConfig())
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "abc123"})
		req.Header.Set("Origin", trustedOrigin)
		req.Header.Set("Referer", "https://evil.example.com/x")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK || !*reached {
			t.Fatalf("trusted Origin must pass regardless of Referer: status=%d reached=%v", w.Code, *reached)
		}
	})

	t.Run("hostile origin loses despite trusted referer", func(t *testing.T) {
		r, reached := csrfEngine(t, trustedCSRFConfig())
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "abc123"})
		req.Header.Set("Origin", "https://evil.example.com")
		req.Header.Set("Referer", trustedOrigin+"/login")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || *reached {
			t.Fatalf("hostile Origin must be rejected even with trusted Referer: status=%d reached=%v", w.Code, *reached)
		}
	})
}

// ─── Fail-closed: cookie present, neither Origin nor Referer ───────────────────

// TestCookieCSRF_CookiePresent_NoHeaders_FailsClosed verifies the security
// invariant: a cookie-bearing request that carries neither an Origin nor a
// Referer header is rejected. A genuine browser POST always sets at least one.
func TestCookieCSRF_CookiePresent_NoHeaders_FailsClosed(t *testing.T) {
	r, reached := csrfEngine(t, trustedCSRFConfig())

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "abc123"})
	// Deliberately set neither Origin nor Referer.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("no Origin/Referer with cookie: status = %d, want 403 (fail-closed)", w.Code)
	}
	if *reached {
		t.Error("no Origin/Referer with cookie: handler must NOT be reached (fail-closed)")
	}
	if !strings.Contains(w.Body.String(), "CSRF_REJECTED") {
		t.Errorf("expected CSRF_REJECTED in body, got: %s", w.Body.String())
	}
}

// ─── Construction-time validation ──────────────────────────────────────────────

func TestCookieCSRF_PanicsOnEmptyTrustedOrigins(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("CookieCSRF must panic when TrustedOrigins is empty")
		}
	}()
	_ = middleware.CookieCSRF(middleware.CookieCSRFConfig{TrustedOrigins: nil})
}

func TestCookieCSRF_PanicsOnMalformedTrustedOrigin(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("CookieCSRF must panic when a TrustedOrigin cannot be normalised")
		}
	}()
	_ = middleware.CookieCSRF(middleware.CookieCSRFConfig{
		TrustedOrigins: []string{"relative/path-only"},
	})
}
