// Package config — Viper-backed configuration source.
//
// All configuration values are read through a single *viper.Viper instance.
// Layering and precedence (highest first):
//
//  1. Process environment variables (incl. values loaded from .env by godotenv)
//     — Viper's AutomaticEnv reads these directly, so a plain `DB_DSN=...` works.
//  2. An optional config file (YAML/JSON/TOML): set CONFIG_FILE to an explicit
//     path, or drop a `config.yaml` in the working directory (or ./config).
//     File keys are flat and match the env names, case-insensitively
//     (e.g. `DB_DSN:` or `db_dsn:`).
//
// In-code fallbacks in helpers.go / loaders.go provide the final default layer,
// so a deployment that sets nothing but the required variables still boots with
// sensible defaults. Complex JSON values (JWT_KEYS, TOTP_KEYS, OAUTH_TOKEN_KEYS)
// are read as opaque strings and should be provided via environment variables.
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// vp is the process-wide configuration source, initialised at the top of Load.
// It is read-only after Load returns. Until Load runs, env falls back to
// os.Getenv so helpers remain usable in isolation (e.g. unit tests).
var vp *viper.Viper

// env returns the configured value for key from Viper (environment first, then
// any config file). Before Load initialises Viper it falls back to os.Getenv so
// the helper functions behave identically when called outside Load.
func env(key string) string {
	if vp == nil {
		return os.Getenv(key)
	}
	return vp.GetString(key)
}

// initConfigViper builds the Viper instance: AutomaticEnv for environment
// variables plus an optional, lower-precedence config file. A missing
// auto-discovered file is not an error (env-only operation); an unreadable
// explicitly-requested CONFIG_FILE is.
func initConfigViper() (*viper.Viper, error) {
	v := viper.New()
	v.AutomaticEnv()

	if path := os.Getenv("CONFIG_FILE"); path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("config: reading CONFIG_FILE %q: %w", path, err)
		}
		return v, nil
	}

	v.SetConfigName("config")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("config: reading config file: %w", err)
		}
		// No config file present — environment-only operation. Not an error.
	}
	return v, nil
}
