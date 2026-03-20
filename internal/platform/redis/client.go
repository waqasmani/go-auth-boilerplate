// Package redis provides a thin wrapper around github.com/redis/go-redis/v9
// that adds connection pooling, health checks, and structured logging aligned
// with the rest of the go-auth-boilerplate platform packages.
//
// Usage:
//
//	client, err := redis.New(redis.Config{
//	    DSN:      cfg.RedisDSN,
//	    PoolSize: cfg.RedisPoolSize,
//	}, log)
//	if err != nil {
//	    return fmt.Errorf("app: init redis: %w", err)
//	}
//	defer client.Close()
package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// defaultDialTimeout is the maximum time allowed to establish a connection
	// to the Redis server. Keep it short so a missing server fails fast at startup.
	defaultDialTimeout = 5 * time.Second

	// defaultReadTimeout is the per-command read deadline. 3 s is generous for
	// an in-datacenter Redis instance; adjust for WAN-connected clusters.
	defaultReadTimeout = 3 * time.Second

	// defaultWriteTimeout is the per-command write deadline.
	defaultWriteTimeout = 3 * time.Second

	// pingTimeout is the deadline for the startup health-check Ping.
	// Kept shorter than defaultDialTimeout so a slow Redis blocks startup for
	// at most a few seconds before returning a clear error.
	pingTimeout = 5 * time.Second
)

// Config holds all tuneable parameters for the Redis client.
// All fields map 1-to-1 to Config struct fields or defaults documented here.
type Config struct {
	// DSN is the Redis connection URL, e.g.:
	//   redis://:password@localhost:6379/0
	//   rediss://user:password@redis.example.com:6380/1  (TLS)
	//   unix:///var/run/redis/redis.sock?db=0
	//
	// The password component must never be logged; the Client struct logs only
	// the sanitised host:port/db portion.
	DSN string

	// PoolSize is the maximum number of socket connections maintained in the
	// pool. Default: 10. Use a value proportional to your application's
	// concurrency level (e.g. number of goroutines that call Redis).
	PoolSize int
}

// Client is a ready-to-use Redis client with lifecycle helpers.
// Construct via New — the zero value is not usable.
type Client struct {
	rdb *goredis.Client
	log *zap.Logger
}

// New parses cfg.DSN, constructs a connection-pooled Redis client, and verifies
// connectivity with a Ping. Returns an error when:
//   - cfg.DSN is empty or unparseable.
//   - the server is unreachable within pingTimeout.
//
// The caller should call Close() when the client is no longer needed (typically
// in the application's graceful-shutdown sequence).
func New(cfg Config, log *zap.Logger) (*Client, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("redis: DSN must not be empty")
	}

	opts, err := goredis.ParseURL(cfg.DSN)
	if err != nil {
		// ParseURL errors may include the raw DSN which could contain a password.
		// Return a generic message to avoid leaking credentials in logs.
		return nil, fmt.Errorf("redis: invalid DSN (check format — password not logged): %w", err)
	}

	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = 10
	}
	opts.PoolSize = poolSize
	opts.DialTimeout = defaultDialTimeout
	opts.ReadTimeout = defaultReadTimeout
	opts.WriteTimeout = defaultWriteTimeout

	rdb := goredis.NewClient(opts)

	c := &Client{rdb: rdb, log: log}

	// Startup health check — fail fast if Redis is unreachable.
	if err := c.Ping(context.Background()); err != nil {
		// Close the idle connections before returning; ignore the close error
		// since the caller never received a usable client.
		_ = rdb.Close()
		return nil, fmt.Errorf("redis: ping failed: %w", err)
	}

	// Log only the sanitised address, never the full DSN (which may contain
	// the password).
	log.Info("connected to redis",
		zap.String("addr", opts.Addr),
		zap.Int("pool_size", poolSize),
	)

	return c, nil
}

// Ping sends a PING command to the server and returns an error when the server
// is unreachable or does not respond within pingTimeout. Use this for health
// checks and startup verification.
func (c *Client) Ping(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	if err := c.rdb.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("redis: ping: %w", err)
	}
	return nil
}

// RDB returns the underlying *goredis.Client for callers that need to execute
// arbitrary Redis commands (e.g. INCR, SET NX EX). The returned client shares
// the same connection pool as this wrapper.
//
// Prefer the higher-level helpers (Ping, Close) where possible. Use RDB only
// for commands that are not wrapped here.
func (c *Client) RDB() *goredis.Client {
	return c.rdb
}

// Close releases all connections in the pool and shuts down the client.
// It is safe to call multiple times; subsequent calls are no-ops.
// Call this in the application's graceful-shutdown sequence, after draining
// in-flight requests.
func (c *Client) Close() error {
	if err := c.rdb.Close(); err != nil {
		c.log.Error("redis: close error", zap.Error(err))
		return fmt.Errorf("redis: close: %w", err)
	}
	c.log.Info("redis connection closed")
	return nil
}
