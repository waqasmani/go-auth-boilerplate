package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnv_FallsBackToOSWhenViperNil(t *testing.T) {
	old := vp
	vp = nil
	t.Cleanup(func() { vp = old })

	t.Setenv("CFG_TEST_FALLBACK", "os-value")
	if got := env("CFG_TEST_FALLBACK"); got != "os-value" {
		t.Fatalf("env() fallback = %q, want os-value", got)
	}
}

func TestEnv_ReadsFromEnvViaViper(t *testing.T) {
	t.Setenv("CFG_TEST_VIPER", "viper-env-value")

	v, err := initConfigViper()
	if err != nil {
		t.Fatalf("initConfigViper: %v", err)
	}
	old := vp
	vp = v
	t.Cleanup(func() { vp = old })

	if got := env("CFG_TEST_VIPER"); got != "viper-env-value" {
		t.Fatalf("env() = %q, want viper-env-value", got)
	}
	// Lower-case key resolves to the same env var (Viper is case-insensitive).
	if got := env("cfg_test_viper"); got != "viper-env-value" {
		t.Fatalf("case-insensitive env() = %q, want viper-env-value", got)
	}
}

func TestInitConfigViper_ConfigFileWithEnvOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "myconfig.yaml")
	body := "FILE_ONLY_KEY: from-file\nOVERRIDDEN_KEY: file-value\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("CONFIG_FILE", cfgPath)
	t.Setenv("OVERRIDDEN_KEY", "env-value") // env must win over the file

	v, err := initConfigViper()
	if err != nil {
		t.Fatalf("initConfigViper: %v", err)
	}
	old := vp
	vp = v
	t.Cleanup(func() { vp = old })

	if got := env("FILE_ONLY_KEY"); got != "from-file" {
		t.Fatalf("file-only key = %q, want from-file", got)
	}
	if got := env("OVERRIDDEN_KEY"); got != "env-value" {
		t.Fatalf("env should override config file: got %q, want env-value", got)
	}
}

func TestInitConfigViper_MissingFileIsNotAnError(t *testing.T) {
	// No CONFIG_FILE set and no config.yaml in the package dir → env-only, no error.
	if _, err := initConfigViper(); err != nil {
		t.Fatalf("initConfigViper with no file should not error: %v", err)
	}
}

func TestInitConfigViper_ExplicitMissingFileErrors(t *testing.T) {
	t.Setenv("CONFIG_FILE", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if _, err := initConfigViper(); err == nil {
		t.Fatal("expected an error when an explicitly-requested CONFIG_FILE is missing")
	}
}
