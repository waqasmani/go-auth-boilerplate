package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/waqasmani/go-auth-boilerplate/internal/middleware"
)

// newTestRedis returns a go-redis client backed by an in-process miniredis,
// mirroring the wiring used in internal/platform/auth/lockout_test.go.
func newTestRedis(t *testing.T) (*goredis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

// fireGET issues a GET /test against r from a fixed client IP so every request
// lands in the same KeyByIP bucket, then returns the recorded response.
func fireGET(t *testing.T, r *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ─── In-memory backend: burst then throttle ───────────────────────────────────

// TestRateLimitMemory_BurstThenThrottle drives the memory token-bucket limiter
// deterministically: with Rate≈0 the bucket never refills within the test, so
// exactly Burst requests are allowed (200) and every subsequent request is
// throttled (429). No time.Sleep is used.
func TestRateLimitMemory_BurstThenThrottle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const burst = 5
	cfg := middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByIP,
		// A tiny refill rate means no whole token is added during the test run,
		// so the allowed count equals Burst exactly.
		Rate:    rate.Limit(0.0001),
		Burst:   burst,
		TTL:     time.Minute,
		MaxKeys: 100,
	}

	r := gin.New()
	r.Use(middleware.RateLimitMemory(cfg))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	allowed, blocked := 0, 0
	for i := 0; i < burst+5; i++ {
		w := fireGET(t, r)
		switch w.Code {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			blocked++
			if w.Header().Get("Retry-After") == "" {
				t.Error("429 response must carry a Retry-After header")
			}
			if !strings.Contains(w.Body.String(), "RATE_LIMIT_EXCEEDED") {
				t.Errorf("429 body must contain RATE_LIMIT_EXCEEDED, got: %s", w.Body.String())
			}
		default:
			t.Fatalf("unexpected status %d", w.Code)
		}
	}

	if allowed != burst {
		t.Errorf("allowed = %d, want exactly Burst=%d", allowed, burst)
	}
	if blocked != 5 {
		t.Errorf("blocked = %d, want 5 (all requests past the burst)", blocked)
	}
}

// TestRateLimitMemory_DistinctKeysIndependentBuckets verifies KeyFunc behaviour:
// two different client IPs get independent buckets, so exhausting one does not
// throttle the other.
func TestRateLimitMemory_DistinctKeysIndependentBuckets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const burst = 2
	cfg := middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByIP,
		Rate:    rate.Limit(0.0001),
		Burst:   burst,
		TTL:     time.Minute,
		MaxKeys: 100,
	}
	r := gin.New()
	r.Use(middleware.RateLimitMemory(cfg))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	fire := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = ip + ":40000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// Exhaust the first IP's bucket.
	for i := 0; i < burst; i++ {
		if code := fire("198.51.100.1"); code != http.StatusOK {
			t.Fatalf("ip1 request %d: got %d, want 200", i, code)
		}
	}
	if code := fire("198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("ip1 over-limit: got %d, want 429", code)
	}

	// A different IP must still have a full bucket.
	if code := fire("198.51.100.2"); code != http.StatusOK {
		t.Errorf("ip2 first request: got %d, want 200 (independent bucket)", code)
	}
}

// ─── KeyFunc unit behaviour ────────────────────────────────────────────────────

func TestKeyByIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.RemoteAddr = "192.0.2.10:5000"

	key, err := middleware.KeyByIP(c)
	if err != nil {
		t.Fatalf("KeyByIP: unexpected error %v", err)
	}
	if !strings.HasPrefix(key, "ip:") {
		t.Errorf("KeyByIP returned %q, want an \"ip:\" prefix", key)
	}
}

func TestKeyByUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("present", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Set(middleware.UserIDKey, "user-42")
		key, err := middleware.KeyByUserID(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "user:user-42" {
			t.Errorf("key = %q, want %q", key, "user:user-42")
		}
	})

	t.Run("absent returns error", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		if _, err := middleware.KeyByUserID(c); err == nil {
			t.Error("KeyByUserID must error when UserIDKey is absent")
		}
	})
}

func TestKeyByUserIDWithIPFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("uses user id when authenticated", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.RemoteAddr = "192.0.2.50:5000"
		c.Set(middleware.UserIDKey, "user-99")
		key, err := middleware.KeyByUserIDWithIPFallback(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "user:user-99" {
			t.Errorf("key = %q, want %q", key, "user:user-99")
		}
	})

	t.Run("falls back to IP when unauthenticated", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.RemoteAddr = "192.0.2.51:5000"
		key, err := middleware.KeyByUserIDWithIPFallback(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(key, "ip:") {
			t.Errorf("key = %q, want an \"ip:\" prefix fallback", key)
		}
	})
}

func TestKeyByHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	kf := middleware.KeyByHeader("X-API-Key")

	t.Run("present", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("X-API-Key", "secret")
		key, err := kf(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "header:X-API-Key:secret" {
			t.Errorf("key = %q, want %q", key, "header:X-API-Key:secret")
		}
	})

	t.Run("absent returns error", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		if _, err := kf(c); err == nil {
			t.Error("KeyByHeader must error when the header is absent")
		}
	})
}

// ─── Redis backend: happy path ────────────────────────────────────────────────

// TestRateLimitRedis_BurstThenThrottle exercises the Lua token-bucket script via
// miniredis: exactly Burst requests are allowed, then 429.
func TestRateLimitRedis_BurstThenThrottle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rdb, _ := newTestRedis(t)

	const burst = 3
	cfg := middleware.RateLimitConfig{
		KeyFunc:     middleware.KeyByIP,
		Rate:        rate.Limit(0.0001),
		Burst:       burst,
		TTL:         time.Minute,
		MaxKeys:     100,
		ErrorPolicy: middleware.PolicyFailClosed,
	}

	r := gin.New()
	r.Use(middleware.RateLimit(cfg, rdb, zap.NewNop()))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	allowed, blocked := 0, 0
	for i := 0; i < burst+3; i++ {
		w := fireGET(t, r)
		switch w.Code {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			blocked++
		default:
			t.Fatalf("unexpected status %d", w.Code)
		}
	}
	if allowed != burst {
		t.Errorf("redis allowed = %d, want exactly Burst=%d", allowed, burst)
	}
	if blocked != 3 {
		t.Errorf("redis blocked = %d, want 3", blocked)
	}
}

// ─── Redis backend: outage policy ──────────────────────────────────────────────

// TestRateLimitRedis_FailClosedOnOutage verifies the secure default: when Redis
// is unreachable and ErrorPolicy is PolicyFailClosed (the zero value), the
// request is REJECTED with 429. This is the policy mandated for /auth/* routes.
func TestRateLimitRedis_FailClosedOnOutage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rdb, mr := newTestRedis(t)

	cfg := middleware.RateLimitConfig{
		KeyFunc:     middleware.KeyByIP,
		Rate:        rate.Limit(5),
		Burst:       10,
		TTL:         time.Minute,
		MaxKeys:     100,
		ErrorPolicy: middleware.PolicyFailClosed,
	}
	r := gin.New()
	r.Use(middleware.RateLimit(cfg, rdb, zap.NewNop()))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	mr.Close() // simulate a Redis outage

	w := fireGET(t, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("fail-closed: status = %d, want 429 during Redis outage", w.Code)
	}
	if !strings.Contains(w.Body.String(), "RATE_LIMIT_EXCEEDED") {
		t.Errorf("fail-closed 429 body must contain RATE_LIMIT_EXCEEDED, got: %s", w.Body.String())
	}
}

// TestRateLimitRedis_DefaultPolicyIsFailClosed confirms that omitting ErrorPolicy
// entirely (relying on the zero value) yields fail-closed behaviour — the
// security guarantee documented on RateLimitConfig.
func TestRateLimitRedis_DefaultPolicyIsFailClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rdb, mr := newTestRedis(t)

	cfg := middleware.RateLimitConfig{
		KeyFunc: middleware.KeyByIP,
		Rate:    rate.Limit(5),
		Burst:   10,
		TTL:     time.Minute,
		MaxKeys: 100,
		// ErrorPolicy deliberately left unset (zero value == PolicyFailClosed).
	}
	r := gin.New()
	r.Use(middleware.RateLimit(cfg, rdb, zap.NewNop()))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	mr.Close()

	if w := fireGET(t, r); w.Code != http.StatusTooManyRequests {
		t.Fatalf("default (unset) policy must fail closed: status = %d, want 429", w.Code)
	}
}

// TestRateLimitRedis_FailOpenOnOutage verifies the opt-in PolicyFailOpen: when
// Redis is unreachable the request is ALLOWED (200). Confirms the limiter does
// what the code says regardless of the README wording.
func TestRateLimitRedis_FailOpenOnOutage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rdb, mr := newTestRedis(t)

	cfg := middleware.RateLimitConfig{
		KeyFunc:     middleware.KeyByIP,
		Rate:        rate.Limit(5),
		Burst:       10,
		TTL:         time.Minute,
		MaxKeys:     100,
		ErrorPolicy: middleware.PolicyFailOpen,
	}
	r := gin.New()
	r.Use(middleware.RateLimit(cfg, rdb, zap.NewNop()))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	mr.Close() // simulate a Redis outage

	w := fireGET(t, r)
	if w.Code != http.StatusOK {
		t.Fatalf("fail-open: status = %d, want 200 during Redis outage", w.Code)
	}
}

// ─── Constructor guards ────────────────────────────────────────────────────────

func TestRateLimit_PanicsOnNilRedis(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("RateLimit must panic when the Redis client is nil")
		}
	}()
	_ = middleware.RateLimit(middleware.DefaultRateLimitConfig(), nil, zap.NewNop())
}

func TestNewLimiter_ErrorsOnNilRedis(t *testing.T) {
	if _, err := middleware.NewLimiter(middleware.DefaultRateLimitConfig(), nil, zap.NewNop()); err == nil {
		t.Error("NewLimiter must return an error when the Redis client is nil")
	}
}

// TestNewLimiterMemory_Allow exercises the imperative Limiter wrapper over the
// memory store: Burst calls allowed, then exhausted.
func TestNewLimiterMemory_Allow(t *testing.T) {
	const burst = 2
	lim := middleware.NewLimiterMemory(middleware.RateLimitConfig{
		Rate:    rate.Limit(0.0001),
		Burst:   burst,
		TTL:     time.Minute,
		MaxKeys: 100,
	})

	for i := 0; i < burst; i++ {
		if allowed, _ := lim.Allow("k"); !allowed {
			t.Fatalf("call %d: expected allowed within burst", i)
		}
	}
	allowed, retry := lim.Allow("k")
	if allowed {
		t.Error("call past burst must be denied")
	}
	if retry <= 0 {
		t.Errorf("denied call must report a positive retryAfter, got %v", retry)
	}
}
