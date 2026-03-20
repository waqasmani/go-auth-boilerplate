// Package config holds all application configuration.
// This file contains parsing helpers for environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// getEnv returns the value of an environment variable or a fallback.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// sanitizeNumericEnv removes underscores from numeric strings (e.g. "1_000" -> "1000").
func sanitizeNumericEnv(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "_", "")
}

// parseDuration parses an environment variable as time.Duration.
func parseDuration(key, fallback string) (time.Duration, error) {
	raw := getEnv(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s=%q: %w", key, raw, err)
	}
	return d, nil
}

// parseFloat parses an environment variable as float64.
func parseFloat(key string, fallback float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(sanitizeNumericEnv(raw), 64)
	if err != nil {
		return fallback
	}
	return v
}

// parseInt parses an environment variable as int.
func parseInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(sanitizeNumericEnv(raw))
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer", key, raw)
	}
	return v, nil
}

// parseBool parses an environment variable as bool.
func parseBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

// parseStringSlice parses a comma-separated environment variable as []string.
func parseStringSlice(key string, fallback []string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

// requiredReader helps collect missing required environment variables.
type requiredReader struct {
	missing []string
}

func (r *requiredReader) get(key string) string {
	v := os.Getenv(key)
	if v == "" {
		r.missing = append(r.missing, key)
	}
	return v
}

func (r *requiredReader) err() error {
	if len(r.missing) == 0 {
		return nil
	}
	return &MissingEnvError{Keys: r.missing}
}
