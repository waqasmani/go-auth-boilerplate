// Package logger provides a structured, level-based logging interface with environment-aware output.
package logger

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey string

const loggerKey contextKey = "logger"

// New builds a production-ready zap logger at the env's default level.
func New(env string) (*zap.Logger, error) {
	return NewWithLevel(env, "")
}

// NewWithLevel builds a logger whose encoding/output follows env (production vs
// development) but whose minimum level is overridden by level when non-empty.
// This lets operators dial verbosity at deploy time (LOG_LEVEL=debug) without
// flipping to development encoding. An unrecognised level is ignored (the env
// default is kept) so a typo can never silence logging entirely.
func NewWithLevel(env, level string) (*zap.Logger, error) {
	var cfg zap.Config

	if env == "production" {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "timestamp"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	if level != "" {
		if lvl, err := zapcore.ParseLevel(level); err == nil {
			cfg.Level = zap.NewAtomicLevelAt(lvl)
		}
	}

	return cfg.Build()
}

// WithContext attaches a logger to a context.
func WithContext(ctx context.Context, log *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, log)
}

// FromContext retrieves the logger from a context, falling back to a no-op logger.
func FromContext(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(loggerKey).(*zap.Logger); ok && l != nil {
		return l
	}
	return zap.NewNop()
}

// FromContextOrFallback returns the request-scoped logger stored in ctx when
// present, and fallback otherwise. Use this instead of FromContext when a
// non-discarding fallback is required — for example in background goroutines
// or paths that must guarantee event delivery regardless of whether an HTTP
// request context is in scope.
func FromContextOrFallback(ctx context.Context, fallback *zap.Logger) *zap.Logger {
	if l, ok := ctx.Value(loggerKey).(*zap.Logger); ok && l != nil {
		return l
	}
	return fallback
}
