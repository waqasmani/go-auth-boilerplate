package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
)

// secureEngine builds a minimal Gin engine with SecureHeaders applied and a
// single GET /test handler that returns 200 OK.  It is separate from the CORS
// test helper so the two test files remain independent.
func secureEngine(cfg middleware.SecureHeadersConfig) *gin.Engine {
	r := gin.New()
	r.Use(middleware.SecureHeaders(cfg))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// get fires a plain GET /test request against the engine and returns the
// recorded response.
func get(r *gin.Engine) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── DefaultSecureHeadersConfig ───────────────────────────────────────────────

func TestDefaultSecureHeadersConfig_HSTSDisabled(t *testing.T) {
	cfg := middleware.DefaultSecureHeadersConfig()
	if cfg.HSTSEnabled {
		t.Error("DefaultSecureHeadersConfig: HSTSEnabled must be false — " +
			"HSTS over plain HTTP in dev locks users out of the site")
	}
}

func TestDefaultSecureHeadersConfig_ReasonableMaxAge(t *testing.T) {
	cfg := middleware.DefaultSecureHeadersConfig()
	// Two years is the HSTS preload threshold; less than one year is too short.
	const oneYear = 31_536_000
	if cfg.HSTSMaxAge < oneYear {
		t.Errorf("DefaultSecureHeadersConfig: HSTSMaxAge = %d, want >= %d (1 year)",
			cfg.HSTSMaxAge, oneYear)
	}
}

func TestProductionSecureHeadersConfig_HSTSEnabled(t *testing.T) {
	cfg := middleware.ProductionSecureHeadersConfig()
	if !cfg.HSTSEnabled {
		t.Error("ProductionSecureHeadersConfig: HSTSEnabled must be true")
	}
}

// ─── Always-on headers ────────────────────────────────────────────────────────

func TestSecureHeaders_XContentTypeOptions(t *testing.T) {
	w := get(secureEngine(middleware.DefaultSecureHeadersConfig()))

	got := w.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
}

func TestSecureHeaders_XFrameOptions(t *testing.T) {
	w := get(secureEngine(middleware.DefaultSecureHeadersConfig()))

	got := w.Header().Get("X-Frame-Options")
	if got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
	}
}

func TestSecureHeaders_XXSSProtection(t *testing.T) {
	w := get(secureEngine(middleware.DefaultSecureHeadersConfig()))

	got := w.Header().Get("X-XSS-Protection")
	if got != "0" {
		t.Errorf("X-XSS-Protection = %q, want %q", got, "0")
	}
}

func TestSecureHeaders_ReferrerPolicy(t *testing.T) {
	w := get(secureEngine(middleware.DefaultSecureHeadersConfig()))

	got := w.Header().Get("Referrer-Policy")
	if got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want %q", got, "strict-origin-when-cross-origin")
	}
}

func TestSecureHeaders_ContentSecurityPolicy(t *testing.T) {
	w := get(secureEngine(middleware.DefaultSecureHeadersConfig()))

	got := w.Header().Get("Content-Security-Policy")
	if got != "default-src 'none'" {
		t.Errorf("Content-Security-Policy = %q, want %q", got, "default-src 'none'")
	}
}

// ─── HSTS — disabled (default / dev) ─────────────────────────────────────────

func TestSecureHeaders_HSTS_AbsentWhenDisabled(t *testing.T) {
	w := get(secureEngine(middleware.DefaultSecureHeadersConfig()))

	got := w.Header().Get("Strict-Transport-Security")
	if got != "" {
		t.Errorf("Strict-Transport-Security must be absent when HSTSEnabled=false, got %q", got)
	}
}

// ─── HSTS — enabled (production) ─────────────────────────────────────────────

func TestSecureHeaders_HSTS_PresentWhenEnabled(t *testing.T) {
	w := get(secureEngine(middleware.ProductionSecureHeadersConfig()))

	got := w.Header().Get("Strict-Transport-Security")
	if got == "" {
		t.Error("Strict-Transport-Security must be set when HSTSEnabled=true")
	}
}

func TestSecureHeaders_HSTS_ContainsMaxAge(t *testing.T) {
	w := get(secureEngine(middleware.ProductionSecureHeadersConfig()))

	got := w.Header().Get("Strict-Transport-Security")
	if len(got) == 0 || got[:len("max-age=")] != "max-age=" {
		t.Errorf("Strict-Transport-Security = %q, must start with max-age=", got)
	}
}

func TestSecureHeaders_HSTS_CustomMaxAge(t *testing.T) {
	cfg := middleware.SecureHeadersConfig{
		HSTSEnabled:           true,
		HSTSMaxAge:            3600,
		HSTSIncludeSubDomains: false,
	}
	w := get(secureEngine(cfg))

	got := w.Header().Get("Strict-Transport-Security")
	if got != "max-age=3600" {
		t.Errorf("Strict-Transport-Security = %q, want %q", got, "max-age=3600")
	}
}

func TestSecureHeaders_HSTS_IncludeSubDomains(t *testing.T) {
	cfg := middleware.SecureHeadersConfig{
		HSTSEnabled:           true,
		HSTSMaxAge:            63_072_000,
		HSTSIncludeSubDomains: true,
	}
	w := get(secureEngine(cfg))

	got := w.Header().Get("Strict-Transport-Security")
	const want = "max-age=63072000; includeSubDomains"
	if got != want {
		t.Errorf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

func TestSecureHeaders_HSTS_WithoutIncludeSubDomains(t *testing.T) {
	cfg := middleware.SecureHeadersConfig{
		HSTSEnabled:           true,
		HSTSMaxAge:            63_072_000,
		HSTSIncludeSubDomains: false,
	}
	w := get(secureEngine(cfg))

	got := w.Header().Get("Strict-Transport-Security")
	const want = "max-age=63072000"
	if got != want {
		t.Errorf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

// TestSecureHeaders_HSTS_ZeroMaxAgeFallback verifies that a misconfigured
// HSTSMaxAge of 0 falls back to the safe default rather than writing
// "max-age=0", which would immediately remove HSTS protection.
func TestSecureHeaders_HSTS_ZeroMaxAgeFallback(t *testing.T) {
	cfg := middleware.SecureHeadersConfig{
		HSTSEnabled:           true,
		HSTSMaxAge:            0, // misconfigured — must not write max-age=0
		HSTSIncludeSubDomains: false,
	}
	w := get(secureEngine(cfg))

	got := w.Header().Get("Strict-Transport-Security")
	if got == "max-age=0" {
		t.Error("Strict-Transport-Security must not be max-age=0 — " +
			"that immediately revokes HSTS protection; use a safe default instead")
	}
	if got == "" {
		t.Error("Strict-Transport-Security must be set when HSTSEnabled=true")
	}
}

// ─── Handler chain continuity ─────────────────────────────────────────────────

// TestSecureHeaders_ChainContinues verifies that the middleware calls c.Next()
// and does not short-circuit the handler.  A real handler returning 201 should
// still return 201 when SecureHeaders is in the stack.
func TestSecureHeaders_ChainContinues(t *testing.T) {
	r := gin.New()
	r.Use(middleware.SecureHeaders(middleware.DefaultSecureHeadersConfig()))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusCreated) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 — SecureHeaders must not swallow the handler response", w.Code)
	}
}

// ─── All response statuses carry headers ─────────────────────────────────────

func TestSecureHeaders_PresentOn4xx(t *testing.T) {
	r := gin.New()
	r.Use(middleware.SecureHeaders(middleware.DefaultSecureHeadersConfig()))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusUnauthorized) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") == "" {
		t.Error("X-Content-Type-Options must be present on 401 responses")
	}
	if w.Header().Get("X-Frame-Options") == "" {
		t.Error("X-Frame-Options must be present on 401 responses")
	}
}

func TestSecureHeaders_PresentOn5xx(t *testing.T) {
	r := gin.New()
	r.Use(middleware.SecureHeaders(middleware.DefaultSecureHeadersConfig()))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") == "" {
		t.Error("X-Content-Type-Options must be present on 500 responses")
	}
}
