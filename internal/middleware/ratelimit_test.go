package middleware_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

// tightCfg returns a RateLimitConfig with Burst=1 and the given KeyFunc so
// a single request exhausts the bucket; the second is always rejected.
func tightCfg(kf middleware.KeyFunc) middleware.RateLimitConfig {
	return middleware.RateLimitConfig{
		KeyFunc: kf,
		Rate:    rate.Limit(1),
		Burst:   1,
		TTL:     time.Minute,
		MaxKeys: 100,
	}
}

// newRouter builds a minimal Gin engine: the rate-limit middleware is applied
// globally, a single POST /test handler returns 200.
func newRouter(cfg middleware.RateLimitConfig) *gin.Engine {
	r := gin.New()
	r.Use(middleware.RateLimit(cfg))
	r.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// newRouterWithAuth builds a router where the Auth middleware stub runs first
// and injects a user_id into the context before the rate-limiter sees it.
// authUserID may be "" to simulate an unauthenticated request.
func newRouterWithAuth(cfg middleware.RateLimitConfig, authUserID string) *gin.Engine {
	r := gin.New()
	// Simulate the JWT Auth middleware by pre-populating UserIDKey.
	r.Use(func(c *gin.Context) {
		if authUserID != "" {
			c.Set(middleware.UserIDKey, authUserID)
		}
		c.Next()
	})
	r.Use(middleware.RateLimit(cfg))
	r.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// hit fires a POST /test with the given X-Forwarded-For header.
func hit(r *gin.Engine, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-Forwarded-For", ip)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// hitWithHeader fires a POST /test with an arbitrary extra header.
func hitWithHeader(r *gin.Engine, ip, headerName, headerValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("X-Forwarded-For", ip)
	if headerName != "" {
		req.Header.Set(headerName, headerValue)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	return m
}

func assertStatus(t *testing.T, label string, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("%s: expected HTTP %d, got %d", label, want, w.Code)
	}
}

// ─── Section 1: KeyByIP (default) ────────────────────────────────────────────

func TestKeyByIP_UniquePerIP(t *testing.T) {
	r := newRouter(tightCfg(middleware.KeyByIP))

	// IP-A: first request OK, second rejected.
	assertStatus(t, "IP-A req 1", hit(r, "1.2.3.4"), http.StatusOK)
	assertStatus(t, "IP-A req 2", hit(r, "1.2.3.4"), http.StatusTooManyRequests)

	// IP-B: completely independent bucket — still full.
	assertStatus(t, "IP-B req 1", hit(r, "5.6.7.8"), http.StatusOK)
}

func TestKeyByIP_BurstAllowed(t *testing.T) {
	const burst = 4
	r := newRouter(middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByIP,
		Rate:    rate.Limit(1),
		Burst:   burst,
		TTL:     time.Minute,
		MaxKeys: 50,
	})
	for i := range burst {
		assertStatus(t, fmt.Sprintf("burst req %d", i+1), hit(r, "10.0.0.1"), http.StatusOK)
	}
	assertStatus(t, "burst+1", hit(r, "10.0.0.1"), http.StatusTooManyRequests)
}

func TestKeyByIP_DefaultConfigIsIP(t *testing.T) {
	// DefaultRateLimitConfig must produce IP-based throttling.
	cfg := middleware.DefaultRateLimitConfig()
	if cfg.KeyFunc == nil {
		t.Fatal("DefaultRateLimitConfig: KeyFunc must not be nil")
	}
	// Verify by checking two different IPs get independent limits.
	tightDefault := middleware.RateLimitConfig{
		KeyFunc: cfg.KeyFunc,
		Rate:    rate.Limit(1),
		Burst:   1,
		TTL:     time.Minute,
		MaxKeys: 100,
	}
	r := newRouter(tightDefault)
	hit(r, "9.9.9.9") // exhaust IP-A
	assertStatus(t, "same IP blocked", hit(r, "9.9.9.9"), http.StatusTooManyRequests)
	assertStatus(t, "other IP free", hit(r, "8.8.8.8"), http.StatusOK)
}

// ─── Section 2: KeyByUserID ───────────────────────────────────────────────────

func TestKeyByUserID_UniquePerUser(t *testing.T) {
	// Two users, same IP → independent buckets.
	cfgUser1 := tightCfg(middleware.KeyByUserID)
	r1 := newRouterWithAuth(cfgUser1, "user-alice")
	r2 := newRouterWithAuth(cfgUser1, "user-bob")

	// Alice's bucket is exhausted.
	assertStatus(t, "Alice req 1", hit(r1, "1.2.3.4"), http.StatusOK)
	assertStatus(t, "Alice req 2", hit(r1, "1.2.3.4"), http.StatusTooManyRequests)

	// Bob shares the same IP but has his own bucket — must not be affected.
	assertStatus(t, "Bob req 1", hit(r2, "1.2.3.4"), http.StatusOK)
}

func TestKeyByUserID_SameUserDifferentIPs_SameBucket(t *testing.T) {
	// One user hitting from two different IPs → same bucket (user-scoped).
	cfg := tightCfg(middleware.KeyByUserID)
	r := newRouterWithAuth(cfg, "user-carol")

	// First request (IP-A) consumes the only token.
	assertStatus(t, "IP-A req 1", hit(r, "10.0.0.1"), http.StatusOK)

	// Second request (IP-B, different IP, same user) must be rejected.
	assertStatus(t, "IP-B req 2 (same user)", hit(r, "10.0.0.2"), http.StatusTooManyRequests)
}

func TestKeyByUserID_FallsBackToIPWhenUnauthenticated(t *testing.T) {
	// KeyByUserID returns an error when no user_id is in context.
	// The middleware must silently fall back to IP — not hard-reject.
	cfg := tightCfg(middleware.KeyByUserID)
	// newRouterWithAuth with "" means no UserIDKey is set.
	r := newRouterWithAuth(cfg, "")

	// With IP fallback the first request from any IP must succeed.
	assertStatus(t, "anon req 1", hit(r, "3.3.3.3"), http.StatusOK)
	// Second request from same IP → throttled (IP bucket is now exhausted).
	assertStatus(t, "anon req 2", hit(r, "3.3.3.3"), http.StatusTooManyRequests)
}

// ─── Section 3: KeyByUserIDWithIPFallback ─────────────────────────────────────

func TestKeyByUserIDWithIPFallback_AuthedUsesUserID(t *testing.T) {
	cfg := tightCfg(middleware.KeyByUserIDWithIPFallback)

	// Authenticated user from IP-A exhausts their per-user bucket.
	r := newRouterWithAuth(cfg, "user-dave")
	assertStatus(t, "authed req 1", hit(r, "10.0.1.1"), http.StatusOK)
	assertStatus(t, "authed req 2", hit(r, "10.0.1.1"), http.StatusTooManyRequests)
}

func TestKeyByUserIDWithIPFallback_AnonUsesIP(t *testing.T) {
	cfg := tightCfg(middleware.KeyByUserIDWithIPFallback)

	// Unauthenticated (no UserIDKey) → keyed by IP.
	r := newRouterWithAuth(cfg, "")
	assertStatus(t, "anon req 1", hit(r, "10.0.2.1"), http.StatusOK)
	assertStatus(t, "anon req 2", hit(r, "10.0.2.1"), http.StatusTooManyRequests)
}

func TestKeyByUserIDWithIPFallback_AuthedAndAnonHaveIndependentBuckets(t *testing.T) {
	// Authed user and anonymous user behind the SAME IP must not share a bucket.
	cfg := tightCfg(middleware.KeyByUserIDWithIPFallback)

	rAuthed := newRouterWithAuth(cfg, "user-erin")
	rAnon := newRouterWithAuth(cfg, "")

	sharedIP := "172.16.100.1"

	// Authed user exhausts their user-scoped bucket.
	assertStatus(t, "authed req 1", hit(rAuthed, sharedIP), http.StatusOK)
	assertStatus(t, "authed req 2", hit(rAuthed, sharedIP), http.StatusTooManyRequests)

	// Anonymous user on the same IP has a separate IP-scoped bucket — still full.
	assertStatus(t, "anon req 1 (same IP)", hit(rAnon, sharedIP), http.StatusOK)
}

func TestKeyByUserIDWithIPFallback_MultipleAuthUsers_SameIP_Independent(t *testing.T) {
	// Three authenticated users, all behind a NAT at the same IP.
	// Each must have their own independent bucket.
	const burst = 2
	cfg := middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByUserIDWithIPFallback,
		Rate:    rate.Limit(1),
		Burst:   burst,
		TTL:     time.Minute,
		MaxKeys: 100,
	}
	sharedIP := "203.0.113.99"
	users := []string{"user-f", "user-g", "user-h"}

	for _, uid := range users {
		r := newRouterWithAuth(cfg, uid)
		for i := range burst {
			assertStatus(t,
				fmt.Sprintf("user=%s req=%d", uid, i+1),
				hit(r, sharedIP),
				http.StatusOK,
			)
		}
		assertStatus(t,
			fmt.Sprintf("user=%s over-burst", uid),
			hit(r, sharedIP),
			http.StatusTooManyRequests,
		)
	}
}

// ─── Section 4: KeyByHeader ───────────────────────────────────────────────────

func TestKeyByHeader_UniquePerHeaderValue(t *testing.T) {
	cfg := tightCfg(middleware.KeyByHeader("X-API-Key"))
	r := newRouter(cfg)

	// Key-A exhausted.
	assertStatus(t, "key-A req 1", hitWithHeader(r, "1.1.1.1", "X-API-Key", "key-aaa"), http.StatusOK)
	assertStatus(t, "key-A req 2", hitWithHeader(r, "1.1.1.1", "X-API-Key", "key-aaa"), http.StatusTooManyRequests)

	// Key-B is a different bucket — still full.
	assertStatus(t, "key-B req 1", hitWithHeader(r, "1.1.1.1", "X-API-Key", "key-bbb"), http.StatusOK)
}

func TestKeyByHeader_FallsBackToIPWhenHeaderAbsent(t *testing.T) {
	cfg := tightCfg(middleware.KeyByHeader("X-API-Key"))
	r := newRouter(cfg)

	// No X-API-Key header → middleware falls back to IP bucket.
	assertStatus(t, "no header req 1", hit(r, "2.2.2.2"), http.StatusOK)
	assertStatus(t, "no header req 2", hit(r, "2.2.2.2"), http.StatusTooManyRequests)
}

func TestKeyByHeader_SameKeyDifferentIPs_SameBucket(t *testing.T) {
	cfg := tightCfg(middleware.KeyByHeader("X-API-Key"))
	r := newRouter(cfg)

	// Same API key, different source IPs → same bucket.
	assertStatus(t, "IP-A key-X", hitWithHeader(r, "4.4.4.4", "X-API-Key", "shared-key"), http.StatusOK)
	assertStatus(t, "IP-B key-X (same key)", hitWithHeader(r, "5.5.5.5", "X-API-Key", "shared-key"), http.StatusTooManyRequests)
}

// ─── Section 5: Custom KeyFunc ────────────────────────────────────────────────

func TestCustomKeyFunc_UsedCorrectly(t *testing.T) {
	// Custom KeyFunc: rate-limit by a synthetic "tenant" claim stored in context.
	const tenantKey = "tenant_id"
	customKF := func(c *gin.Context) (string, error) {
		v, ok := c.Get(tenantKey)
		if !ok {
			return "", fmt.Errorf("tenant_id not set")
		}
		return "tenant:" + v.(string), nil
	}

	cfg := tightCfg(customKF)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Inject tenant from a header to simulate multi-tenant routing.
		if t := c.GetHeader("X-Tenant"); t != "" {
			c.Set(tenantKey, t)
		}
		c.Next()
	})
	r.Use(middleware.RateLimit(cfg))
	r.POST("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	fire := func(ip, tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("X-Tenant", tenant)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// Tenant-A's bucket is exhausted.
	assertStatus(t, "tenant-A req 1", fire("1.1.1.1", "acme"), http.StatusOK)
	assertStatus(t, "tenant-A req 2", fire("1.1.1.1", "acme"), http.StatusTooManyRequests)

	// Tenant-B has its own bucket — unaffected.
	assertStatus(t, "tenant-B req 1", fire("1.1.1.1", "globex"), http.StatusOK)
}

func TestCustomKeyFunc_ErrorFallsBackToIP(t *testing.T) {
	// A KeyFunc that always errors → must silently fall back to IP.
	alwaysErr := func(_ *gin.Context) (string, error) {
		return "", fmt.Errorf("intentional error")
	}
	cfg := tightCfg(alwaysErr)
	r := newRouter(cfg)

	// Should still work — falls back to IP bucket.
	assertStatus(t, "error kf req 1", hit(r, "7.7.7.7"), http.StatusOK)
	assertStatus(t, "error kf req 2", hit(r, "7.7.7.7"), http.StatusTooManyRequests)
	// Different IP → own bucket, should pass.
	assertStatus(t, "other IP req 1", hit(r, "8.8.8.8"), http.StatusOK)
}

// ─── Section 6: Response shape ────────────────────────────────────────────────

func TestResponse_429Body(t *testing.T) {
	r := newRouter(tightCfg(middleware.KeyByIP))
	ip := "20.20.20.20"
	hit(r, ip) // exhaust

	w := hit(r, ip)
	assertStatus(t, "429 status", w, http.StatusTooManyRequests)

	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type: want application/json; charset=utf-8, got %q", ct)
	}

	body := decodeBody(t, w)

	if success, _ := body["success"].(bool); success {
		t.Error("expected success=false")
	}

	errObj, ok := body["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected error object, got %T", body["error"])
	}
	if code, _ := errObj["code"].(string); code != "RATE_LIMIT_EXCEEDED" {
		t.Errorf("expected code=RATE_LIMIT_EXCEEDED, got %q", code)
	}
	if msg, _ := errObj["message"].(string); msg == "" {
		t.Error("expected non-empty message")
	}
}

func TestResponse_RetryAfterHeader(t *testing.T) {
	r := newRouter(tightCfg(middleware.KeyByIP))
	ip := "21.21.21.21"
	hit(r, ip)

	w := hit(r, ip)
	assertStatus(t, "429", w, http.StatusTooManyRequests)

	ra := w.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("Retry-After header missing on 429")
	}
	n := 0
	for _, ch := range ra {
		if ch < '0' || ch > '9' {
			t.Fatalf("Retry-After %q is not a plain positive integer", ra)
		}
		n = n*10 + int(ch-'0')
	}
	if n < 1 {
		t.Errorf("Retry-After must be >= 1, got %d", n)
	}
}

func TestResponse_NoRetryAfterOnSuccess(t *testing.T) {
	r := newRouter(middleware.DefaultRateLimitConfig())
	w := hit(r, "22.22.22.22")
	assertStatus(t, "200", w, http.StatusOK)
	if h := w.Header().Get("Retry-After"); h != "" {
		t.Errorf("Retry-After must be absent on 200, got %q", h)
	}
}

func TestResponse_AbortsPipeline(t *testing.T) {
	// A downstream middleware that would corrupt the body if the pipeline
	// were not aborted after a 429.
	cfg := tightCfg(middleware.KeyByIP)
	r := gin.New()
	r.Use(middleware.RateLimit(cfg))
	r.Use(func(c *gin.Context) {
		c.Next()
		if c.Writer.Status() == http.StatusTooManyRequests {
			t.Error("pipeline NOT aborted: post-middleware ran after 429")
		}
	})
	r.POST("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	ip := "30.30.30.30"
	hit(r, ip)
	assertStatus(t, "429 aborted", hit(r, ip), http.StatusTooManyRequests)
}

// ─── Section 7: Cache TTL expiration ─────────────────────────────────────────

func TestCacheTTL_ResetsLimiterAfterExpiry(t *testing.T) {
	const ttl = 80 * time.Millisecond
	cfg := middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByIP,
		Rate:    rate.Limit(1),
		Burst:   1,
		TTL:     ttl,
		MaxKeys: 50,
	}
	r := newRouter(cfg)
	ip := "40.40.40.40"

	assertStatus(t, "req 1 OK", hit(r, ip), http.StatusOK)
	assertStatus(t, "req 2 throttled", hit(r, ip), http.StatusTooManyRequests)

	time.Sleep(ttl + 40*time.Millisecond)

	// Entry was evicted → fresh bucket → allowed again.
	assertStatus(t, "post-TTL OK", hit(r, ip), http.StatusOK)
}

func TestCacheTTL_UserBucketResetsAfterExpiry(t *testing.T) {
	const ttl = 80 * time.Millisecond
	cfg := middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByUserID,
		Rate:    rate.Limit(1),
		Burst:   1,
		TTL:     ttl,
		MaxKeys: 50,
	}
	r := newRouterWithAuth(cfg, "user-ttl-test")

	assertStatus(t, "req 1 OK", hit(r, "50.50.50.50"), http.StatusOK)
	assertStatus(t, "req 2 throttled", hit(r, "50.50.50.50"), http.StatusTooManyRequests)

	time.Sleep(ttl + 40*time.Millisecond)

	assertStatus(t, "post-TTL OK", hit(r, "50.50.50.50"), http.StatusOK)
}

// ─── Section 8: LRU capacity eviction ────────────────────────────────────────

func TestLRUEviction_EvictedEntryGetsNewBucket(t *testing.T) {
	cfg := middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByIP,
		Rate:    rate.Limit(1),
		Burst:   1,
		TTL:     time.Hour,
		MaxKeys: 3, // tiny cache
	}
	r := newRouter(cfg)

	// Fill the cache and exhaust all three buckets.
	for _, ip := range []string{"60.0.0.1", "60.0.0.2", "60.0.0.3"} {
		assertStatus(t, ip+" req 1", hit(r, ip), http.StatusOK)
		assertStatus(t, ip+" req 2", hit(r, ip), http.StatusTooManyRequests)
	}

	// Access the 2nd and 3rd to make the 1st the LRU candidate.
	hit(r, "60.0.0.2")
	hit(r, "60.0.0.3")

	// A 4th IP fills the cache → evicts "60.0.0.1".
	hit(r, "60.0.0.4")

	// "60.0.0.1" was evicted → fresh bucket → allowed.
	assertStatus(t, "evicted IP fresh bucket", hit(r, "60.0.0.1"), http.StatusOK)
}

// ─── Section 9: Preset configs ───────────────────────────────────────────────

func TestDefaultRateLimitConfig_SaneValues(t *testing.T) {
	cfg := middleware.DefaultRateLimitConfig()
	if cfg.Rate <= 0 {
		t.Errorf("Rate must be > 0, got %v", cfg.Rate)
	}
	if cfg.Burst < 1 {
		t.Errorf("Burst must be >= 1, got %d", cfg.Burst)
	}
	if cfg.TTL <= 0 {
		t.Errorf("TTL must be > 0, got %v", cfg.TTL)
	}
	if cfg.MaxKeys < 1 {
		t.Errorf("MaxKeys must be >= 1, got %d", cfg.MaxKeys)
	}
	if cfg.KeyFunc == nil {
		t.Error("DefaultRateLimitConfig: KeyFunc must not be nil")
	}
}

func TestAuthenticatedRateLimitConfig_UsesUserIDFallback(t *testing.T) {
	cfg := middleware.AuthenticatedRateLimitConfig()
	if cfg.KeyFunc == nil {
		t.Fatal("AuthenticatedRateLimitConfig: KeyFunc must not be nil")
	}

	// Authenticated users → user-scoped.
	tightAuth := middleware.RateLimitConfig{
		KeyFunc: cfg.KeyFunc,
		Rate:    rate.Limit(1),
		Burst:   1,
		TTL:     time.Minute,
		MaxKeys: 50,
	}
	r := newRouterWithAuth(tightAuth, "user-preset")
	assertStatus(t, "authed req 1", hit(r, "70.0.0.1"), http.StatusOK)
	assertStatus(t, "authed req 2", hit(r, "70.0.0.1"), http.StatusTooManyRequests)

	// Anonymous → IP-scoped (different bucket from the user).
	rAnon := newRouterWithAuth(tightAuth, "")
	assertStatus(t, "anon req 1 same IP", hit(rAnon, "70.0.0.1"), http.StatusOK)
}

func TestRateLimitWithDefaults_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RateLimitWithDefaults panicked: %v", r)
		}
	}()
	h := middleware.RateLimitWithDefaults()
	if h == nil {
		t.Fatal("RateLimitWithDefaults returned nil HandlerFunc")
	}
}
