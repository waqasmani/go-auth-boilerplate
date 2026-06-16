package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// HTTP metrics are registered once at package init via promauto against the
// default registry (the same one promhttp.Handler() serves). Package-level vars
// make repeated router.New calls (e.g. in tests) safe — no duplicate-registration
// panic.
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests by method, matched route, and status code.",
		},
		[]string{"method", "route", "status"},
	)
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds by method and matched route.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)
	// httpRequestsInFlight exposes current concurrency so saturation /
	// connection pile-up is directly observable instead of inferred from latency.
	httpRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "Number of HTTP requests currently being served.",
		},
	)
	// panicsTotal counts panics caught by the Recovery middleware, so crashes
	// that would otherwise be invisible to alerting (only logged) have a signal.
	panicsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "panics_total",
			Help: "Total panics recovered by the Recovery middleware.",
		},
	)
)

// Metrics records per-request Prometheus counters and a latency histogram.
//
// It labels on the matched route template (c.FullPath(), e.g.
// "/api/v1/auth/login") rather than the raw URL path, so label cardinality
// stays bounded regardless of path parameters or attacker-supplied URLs.
func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		httpRequestsInFlight.Inc()
		defer httpRequestsInFlight.Dec()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		httpRequestsTotal.
			WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).
			Inc()
		httpRequestDuration.
			WithLabelValues(c.Request.Method, route).
			Observe(time.Since(start).Seconds())
	}
}
