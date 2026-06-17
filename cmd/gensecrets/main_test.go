package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	platformauth "github.com/waqasmani/go-auth-boilerplate/internal/platform/auth"
)

// keyEntry matches any of the generated single-key JSON key sets.
type keyEntry struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Secret string `json:"secret"`
	Active bool   `json:"active"`
}

func generatedValue(t *testing.T, key string) string {
	t.Helper()
	secrets, err := generateAll()
	if err != nil {
		t.Fatalf("generateAll: %v", err)
	}
	for _, s := range secrets {
		if s.key == key {
			return s.value
		}
	}
	t.Fatalf("generated secret %q not found", key)
	return ""
}

// Strongest verification: feed the generated AES key sets into the SAME
// constructors the application uses and prove they encrypt/decrypt.
func TestGeneratedAESKeySetsRoundTrip(t *testing.T) {
	t.Run("TOTP_KEYS", func(t *testing.T) {
		var entries []keyEntry
		if err := json.Unmarshal([]byte(generatedValue(t, "TOTP_KEYS")), &entries); err != nil {
			t.Fatalf("TOTP_KEYS invalid JSON: %v", err)
		}
		encKeys := make([]platformauth.TOTPEncKey, len(entries))
		for i, e := range entries {
			encKeys[i] = platformauth.TOTPEncKey{ID: e.ID, Key: e.Key, Active: e.Active}
		}
		ks, err := platformauth.NewTOTPKeySet(encKeys)
		if err != nil {
			t.Fatalf("NewTOTPKeySet rejected generated keys: %v", err)
		}
		blob, err := ks.Encrypt("super-secret-totp-seed")
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		plain, err := ks.Decrypt(blob)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if plain != "super-secret-totp-seed" {
			t.Fatalf("round-trip mismatch: %q", plain)
		}
	})

	t.Run("OAUTH_TOKEN_KEYS", func(t *testing.T) {
		var entries []keyEntry
		if err := json.Unmarshal([]byte(generatedValue(t, "OAUTH_TOKEN_KEYS")), &entries); err != nil {
			t.Fatalf("OAUTH_TOKEN_KEYS invalid JSON: %v", err)
		}
		symKeys := make([]platformauth.SymmetricKeyConfig, len(entries))
		for i, e := range entries {
			symKeys[i] = platformauth.SymmetricKeyConfig{ID: e.ID, Key: e.Key, Active: e.Active}
		}
		ks, err := platformauth.NewSymmetricKeySet(symKeys)
		if err != nil {
			t.Fatalf("NewSymmetricKeySet rejected generated keys: %v", err)
		}
		blob, err := ks.Encrypt([]byte("oauth-refresh-token"))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		plain, err := ks.Decrypt(blob)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if string(plain) != "oauth-refresh-token" {
			t.Fatalf("round-trip mismatch: %q", plain)
		}
	})
}

// JWT_KEYS must be exactly one active key whose secret is >= 32 bytes (the
// loader's HS256 minimum).
func TestGeneratedJWTKeysAreValid(t *testing.T) {
	var entries []keyEntry
	if err := json.Unmarshal([]byte(generatedValue(t, "JWT_KEYS")), &entries); err != nil {
		t.Fatalf("JWT_KEYS invalid JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 JWT key, got %d", len(entries))
	}
	e := entries[0]
	if e.ID == "" || !e.Active {
		t.Fatalf("JWT key must have id and active=true: %+v", e)
	}
	if len(e.Secret) < 32 {
		t.Fatalf("JWT secret is %d bytes, need >= 32", len(e.Secret))
	}
}

// Every generated scalar secret must clear the production strength rules and the
// length minimums.
func TestGeneratedScalarSecrets(t *testing.T) {
	for _, key := range []string{"OTP_HMAC_SECRET", "OAUTH_STATE_SECRET", "METRICS_TOKEN"} {
		v := generatedValue(t, key)
		if len(v) < 32 {
			t.Errorf("%s is %d bytes, need >= 32", key, len(v))
		}
		if !okStrength(v) {
			t.Errorf("%s failed strength check: %q", key, v)
		}
	}
}

// gensecrets must NOT generate infrastructure credentials — those are
// operator-defined and a random value would simply fail to connect.
func TestInfraCredentialsAreNotGenerated(t *testing.T) {
	secrets, err := generateAll()
	if err != nil {
		t.Fatalf("generateAll: %v", err)
	}
	for _, s := range secrets {
		switch s.key {
		case "DB_ROOT_PASSWORD", "DB_PASSWORD", "REDIS_PASSWORD":
			t.Errorf("gensecrets must not generate infra credential %q", s.key)
		}
	}
}

func TestMergeFillsPlaceholdersPreservesReal(t *testing.T) {
	in := strings.Join([]string{
		"# comment",
		"APP_ENV=production",
		`JWT_KEYS=[{"id":"v1","secret":"REPLACE_WITH_64_BYTE_BASE64_SECRET","active":true}]`,
		"OTP_HMAC_SECRET=",
		"OAUTH_STATE_SECRET=already-a-real-strong-value-AbC123XyZ789Qwerty",
		"DB_PASSWORD=change_me_app",
		"DB_DSN=app_user:change_me@tcp(127.0.0.1:3306)/go_auth?parseTime=true",
		"REDIS_DSN=redis://:change_me@127.0.0.1:6379/0",
		"SOME_OTHER_KEY=keep-me",
	}, "\n")

	secrets, err := generateAll()
	if err != nil {
		t.Fatalf("generateAll: %v", err)
	}
	out := mergeEnv(in, secrets)

	// Comment + unrelated key preserved.
	if !strings.Contains(out, "# comment") || !strings.Contains(out, "SOME_OTHER_KEY=keep-me") {
		t.Error("merge dropped unrelated lines")
	}
	// A value that was NOT a placeholder is preserved untouched.
	if !strings.Contains(out, "OAUTH_STATE_SECRET=already-a-real-strong-value-AbC123XyZ789Qwerty") {
		t.Error("merge clobbered a real (non-placeholder) value")
	}
	// The app's own secret placeholders were filled.
	if strings.Contains(out, "REPLACE_WITH") {
		t.Error("JWT_KEYS placeholder not filled")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "OTP_HMAC_SECRET=") && len(strings.TrimPrefix(line, "OTP_HMAC_SECRET=")) < 32 {
			t.Errorf("empty OTP_HMAC_SECRET not filled: %q", line)
		}
	}
	// Infrastructure credentials are operator-defined and must be left EXACTLY
	// as-is — never generated, never rewritten.
	if !strings.Contains(out, "DB_PASSWORD=change_me_app") {
		t.Error("DB_PASSWORD was modified — infra credentials must be left to the operator")
	}
	if !strings.Contains(out, "DB_DSN=app_user:change_me@tcp(127.0.0.1:3306)/go_auth?parseTime=true") {
		t.Error("DB_DSN was rewritten — infra DSNs must be left to the operator")
	}
	if !strings.Contains(out, "REDIS_DSN=redis://:change_me@127.0.0.1:6379/0") {
		t.Error("REDIS_DSN was rewritten — infra DSNs must be left to the operator")
	}
}

func TestMergeAppendsMissingKeys(t *testing.T) {
	secrets, err := generateAll()
	if err != nil {
		t.Fatalf("generateAll: %v", err)
	}
	out := mergeEnv("APP_ENV=development\n", secrets)
	for _, s := range secrets {
		if !strings.Contains(out, s.key+"=") {
			t.Errorf("missing managed key %q was not appended", s.key)
		}
	}
}

func TestRotateJWTKeysDemotesAndAppends(t *testing.T) {
	const old = `[{"id":"v1","secret":"original-secret-value-at-least-32-bytes-long-xyz","active":true}]`
	out, err := rotateKeyset("JWT_KEYS", old)
	if err != nil {
		t.Fatalf("rotateKeyset: %v", err)
	}
	var keys []keyEntry
	if err := json.Unmarshal([]byte(out), &keys); err != nil {
		t.Fatalf("rotated JWT_KEYS invalid JSON: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys after rotation, got %d", len(keys))
	}
	// Old key retained but demoted (still validates existing tokens).
	if keys[0].ID != "v1" || keys[0].Active {
		t.Errorf("old key v1 should be retained and inactive, got %+v", keys[0])
	}
	if keys[0].Secret != "original-secret-value-at-least-32-bytes-long-xyz" {
		t.Errorf("old key secret must be preserved verbatim for validation, got %q", keys[0].Secret)
	}
	// New key is active, has the next id, and a >=32-byte secret.
	if keys[1].ID != "v2" || !keys[1].Active {
		t.Errorf("new key should be v2 and active, got %+v", keys[1])
	}
	if len(keys[1].Secret) < 32 {
		t.Errorf("new JWT secret is %d bytes, need >= 32", len(keys[1].Secret))
	}
}

// The strongest proof of "validate sessions, then change": a secret encrypted
// under the pre-rotation key still decrypts with the rotated key set.
func TestRotateTOTPKeysPreservesOldKeyDecryption(t *testing.T) {
	// Start with one active key and encrypt a secret under it.
	oldVal := generatedValue(t, "TOTP_KEYS")
	var oldEntries []keyEntry
	if err := json.Unmarshal([]byte(oldVal), &oldEntries); err != nil {
		t.Fatalf("bad TOTP_KEYS: %v", err)
	}
	oldSet, err := platformauth.NewTOTPKeySet([]platformauth.TOTPEncKey{
		{ID: oldEntries[0].ID, Key: oldEntries[0].Key, Active: true},
	})
	if err != nil {
		t.Fatalf("NewTOTPKeySet(old): %v", err)
	}
	blob, err := oldSet.Encrypt("totp-seed-under-old-key")
	if err != nil {
		t.Fatalf("encrypt under old key: %v", err)
	}

	// Rotate, then build a key set from the rotated value (old + new).
	rotated, err := rotateKeyset("TOTP_KEYS", oldVal)
	if err != nil {
		t.Fatalf("rotateKeyset: %v", err)
	}
	var newEntries []keyEntry
	if err := json.Unmarshal([]byte(rotated), &newEntries); err != nil {
		t.Fatalf("rotated TOTP_KEYS invalid JSON: %v", err)
	}
	encKeys := make([]platformauth.TOTPEncKey, len(newEntries))
	for i, e := range newEntries {
		encKeys[i] = platformauth.TOTPEncKey{ID: e.ID, Key: e.Key, Active: e.Active}
	}
	rotatedSet, err := platformauth.NewTOTPKeySet(encKeys)
	if err != nil {
		t.Fatalf("NewTOTPKeySet(rotated): %v", err)
	}

	// The blob made by the OLD key must still decrypt after rotation.
	plain, err := rotatedSet.Decrypt(blob)
	if err != nil {
		t.Fatalf("rotated set failed to decrypt old-key blob (sessions would break!): %v", err)
	}
	if plain != "totp-seed-under-old-key" {
		t.Fatalf("decrypt mismatch after rotation: %q", plain)
	}
	// And the new active key is v2 (verified structurally from the rotated JSON).
	if newEntries[len(newEntries)-1].ID != "v2" || !newEntries[len(newEntries)-1].Active {
		t.Errorf("new active key after rotation should be v2/active, got %+v", newEntries[len(newEntries)-1])
	}
}

func TestRotateRejectsNonKeysetAndPlaceholders(t *testing.T) {
	if _, err := rotateKeyset("OTP_HMAC_SECRET", "anything"); err == nil {
		t.Error("rotating a scalar secret should error")
	}
	if _, err := rotateKeyset("JWT_KEYS", ""); err == nil {
		t.Error("rotating an empty key set should error")
	}
	if _, err := rotateKeyset("JWT_KEYS", `[{"id":"v1","secret":"REPLACE_WITH_SECRET","active":true}]`); err == nil {
		t.Error("rotating a placeholder key set should error")
	}
}

func TestRotateInFile(t *testing.T) {
	in := strings.Join([]string{
		"APP_ENV=production",
		`TOTP_KEYS=[{"id":"v1","key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","active":true}]`,
		"KEEP=me",
	}, "\n")
	out, err := rotateInFile(in, "TOTP_KEYS")
	if err != nil {
		t.Fatalf("rotateInFile: %v", err)
	}
	if !strings.Contains(out, "APP_ENV=production") || !strings.Contains(out, "KEEP=me") {
		t.Error("rotateInFile dropped unrelated lines")
	}
	if !strings.Contains(out, `"id":"v2"`) || !strings.Contains(out, `"id":"v1"`) {
		t.Errorf("rotated line should contain both v1 (retained) and v2 (new):\n%s", out)
	}
	if _, err := rotateInFile("APP_ENV=x\n", "TOTP_KEYS"); err == nil {
		t.Error("rotateInFile should error when the key is absent")
	}
}

func TestNextKeyID(t *testing.T) {
	cases := []struct {
		ids  []string
		want string
	}{
		{[]string{"v1"}, "v2"},
		{[]string{"v1", "v2", "v3"}, "v4"},
		{[]string{"v2", "v5"}, "v6"},
		{[]string{"legacy"}, "v1"},
		{[]string{"v1", "legacy"}, "v2"},
	}
	for _, c := range cases {
		if got := nextKeyID(c.ids); got != c.want {
			t.Errorf("nextKeyID(%v) = %q, want %q", c.ids, got, c.want)
		}
	}
}

func TestSplitEnvLine(t *testing.T) {
	cases := []struct {
		line          string
		wantOK        bool
		wantKey, wVal string
	}{
		{"# comment", false, "", ""},
		{"", false, "", ""},
		{"  ", false, "", ""},
		{"KEY=value", true, "KEY", "value"},
		{"KEY=a=b==", true, "KEY", "a=b=="}, // value may contain '='
		{"=novalue", false, "", ""},
	}
	for _, c := range cases {
		k, v, ok := splitEnvLine(c.line)
		if ok != c.wantOK || k != c.wantKey || v != c.wVal {
			t.Errorf("splitEnvLine(%q) = (%q,%q,%v), want (%q,%q,%v)", c.line, k, v, ok, c.wantKey, c.wVal, c.wantOK)
		}
	}
}

// Rotation must stamp the new key with a creation timestamp so -prune can later
// retire it by age; the demoted old key keeps whatever it had (none here).
func TestRotateStampsCreatedOnNewKey(t *testing.T) {
	const old = `[{"id":"v1","secret":"original-secret-value-at-least-32-bytes-long-xyz","active":true}]`
	out, err := rotateKeyset("JWT_KEYS", old)
	if err != nil {
		t.Fatalf("rotateKeyset: %v", err)
	}
	var keys []anyKey
	if err := json.Unmarshal([]byte(out), &keys); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	newKey := keys[len(keys)-1]
	if newKey.Created == "" {
		t.Fatal("new key should carry a created timestamp")
	}
	if _, err := time.Parse(time.RFC3339, newKey.Created); err != nil {
		t.Errorf("created timestamp %q is not RFC3339: %v", newKey.Created, err)
	}
}

func TestPruneKeysetRemovesOldInactiveKeepsActiveAndRecent(t *testing.T) {
	now := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	old := now.Add(-1000 * time.Hour).Format(time.RFC3339) // well past the window
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339) // inside the window
	in := `[` +
		`{"id":"v1","secret":"old-inactive-secret-at-least-32-bytes-long-aaa","active":false,"created":"` + old + `"},` +
		`{"id":"v2","secret":"recent-inactive-secret-32-bytes-long-bbbbbb","active":false,"created":"` + recent + `"},` +
		`{"id":"v3","secret":"current-active-secret-at-least-32-bytes-long-cc","active":true,"created":"` + recent + `"}` +
		`]`
	out, res, err := pruneKeyset("JWT_KEYS", in, 720*time.Hour, now)
	if err != nil {
		t.Fatalf("pruneKeyset: %v", err)
	}
	var keys []anyKey
	if err := json.Unmarshal([]byte(out), &keys); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	ids := map[string]bool{}
	for _, k := range keys {
		ids[k.ID] = true
	}
	if ids["v1"] {
		t.Error("v1 was older than the window and inactive — should have been pruned")
	}
	if !ids["v2"] || !ids["v3"] {
		t.Errorf("v2 (recent inactive) and v3 (active) must be retained, got %+v", ids)
	}
	if len(res.removed) != 1 || res.removed[0] != "v1" {
		t.Errorf("want removed=[v1], got %v", res.removed)
	}
}

// The active key must never be pruned even if its timestamp is ancient.
func TestPruneNeverRemovesActiveKey(t *testing.T) {
	now := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	old := now.Add(-100000 * time.Hour).Format(time.RFC3339)
	in := `[{"id":"v1","secret":"ancient-but-active-secret-at-least-32-bytes-xx","active":true,"created":"` + old + `"}]`
	out, res, err := pruneKeyset("JWT_KEYS", in, time.Hour, now)
	if err != nil {
		t.Fatalf("pruneKeyset: %v", err)
	}
	if !strings.Contains(out, `"id":"v1"`) {
		t.Errorf("active key must survive pruning, got %s", out)
	}
	if len(res.removed) != 0 {
		t.Errorf("no key should be removed, got %v", res.removed)
	}
}

// Inactive keys without a creation timestamp predate timestamped rotation;
// their age is unknown, so they must be kept (and reported), never deleted.
func TestPruneKeepsUnstampedInactiveKeys(t *testing.T) {
	now := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	in := `[` +
		`{"id":"v1","secret":"legacy-inactive-no-timestamp-32-bytes-long-aa","active":false},` +
		`{"id":"v2","secret":"current-active-secret-at-least-32-bytes-long-cc","active":true}` +
		`]`
	out, res, err := pruneKeyset("JWT_KEYS", in, time.Hour, now)
	if err != nil {
		t.Fatalf("pruneKeyset: %v", err)
	}
	if !strings.Contains(out, `"id":"v1"`) {
		t.Error("unstamped inactive key must be kept (unknown age)")
	}
	if len(res.keptNoStamp) != 1 || res.keptNoStamp[0] != "v1" {
		t.Errorf("want keptNoStamp=[v1], got %v", res.keptNoStamp)
	}
	if len(res.removed) != 0 {
		t.Errorf("nothing should be removed, got %v", res.removed)
	}
}

func TestPruneInFilePreservesOtherLines(t *testing.T) {
	now := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	old := now.Add(-1000 * time.Hour).Format(time.RFC3339)
	in := strings.Join([]string{
		"APP_ENV=production",
		`JWT_KEYS=[{"id":"v1","secret":"old-inactive-secret-at-least-32-bytes-long-aaa","active":false,"created":"` + old + `"},{"id":"v2","secret":"current-active-secret-at-least-32-bytes-long-cc","active":true,"created":"` + old + `"}]`,
		"KEEP=me",
	}, "\n")
	out, res, err := pruneInFile(in, "JWT_KEYS", 720*time.Hour, now)
	if err != nil {
		t.Fatalf("pruneInFile: %v", err)
	}
	if !strings.Contains(out, "APP_ENV=production") || !strings.Contains(out, "KEEP=me") {
		t.Error("pruneInFile dropped unrelated lines")
	}
	if strings.Contains(out, `"id":"v1"`) {
		t.Error("old inactive v1 should have been pruned from the file")
	}
	if !strings.Contains(out, `"id":"v2"`) {
		t.Error("active v2 must remain")
	}
	if len(res.removed) != 1 {
		t.Errorf("want 1 removed, got %v", res.removed)
	}
	if _, _, err := pruneInFile("APP_ENV=x\n", "JWT_KEYS", time.Hour, now); err == nil {
		t.Error("pruneInFile should error when the key is absent")
	}
}
