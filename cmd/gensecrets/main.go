// Command gensecrets generates strong, correctly-formatted values for every
// secret environment variable the service requires — not just the JWT keys that
// `make jwt-gen-keyset` covers. Each value is produced in the exact format the
// config loaders expect (internal/config/loaders.go) and is guaranteed to pass
// the production strength validator (internal/config/validators.go):
//
//   - JWT_KEYS / TOTP_KEYS / OAUTH_TOKEN_KEYS — single-key JSON key sets ready
//     for zero-downtime rotation (id "v1", active). The AES key sets use the
//     first 32 bytes of the value as the AES-256 key.
//   - OTP_HMAC_SECRET / OAUTH_STATE_SECRET — base64 of 32 random bytes.
//   - METRICS_TOKEN — hex bearer token.
//
// It deliberately does NOT generate infrastructure credentials —
// DB_ROOT_PASSWORD, DB_PASSWORD, REDIS_PASSWORD and the passwords embedded in
// DB_DSN / REDIS_DSN. Those must match the database / cache you provision (or an
// existing managed instance), so the operator defines them; a random value would
// simply fail to connect.
//
// Usage:
//
//	go run ./cmd/gensecrets                       # print a block of KEY=VALUE secret lines
//	go run ./cmd/gensecrets -merge .env.example   # fill placeholders, print the merged file
//	go run ./cmd/gensecrets -merge .env.example -o .env   # ...and write it (won't clobber)
//
// In -merge mode only empty / placeholder values for the app's own secret keys
// are replaced — real secrets and operator-defined infra credentials are left
// untouched.
package main

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// secret is one generated KEY=VALUE pair.
type secret struct {
	key   string
	value string
}

// managedKeys is the set of secret env vars this tool generates, in emission
// order. A key not in this set is never touched by -merge. Infrastructure
// credentials (DB_ROOT_PASSWORD, DB_PASSWORD, REDIS_PASSWORD, and the passwords
// in DB_DSN / REDIS_DSN) are intentionally excluded — they are operator-defined.
var managedKeys = map[string]struct{}{
	"JWT_KEYS":           {},
	"OTP_HMAC_SECRET":    {},
	"TOTP_KEYS":          {},
	"OAUTH_STATE_SECRET": {},
	"OAUTH_TOKEN_KEYS":   {},
	"METRICS_TOKEN":      {},
}

// weakMarkers mirrors internal/config/validators.go weakSecretMarkers. A
// generated value containing any of these (astronomically unlikely for random
// data) is regenerated; an existing value containing one is treated as a
// placeholder to be replaced.
var weakMarkers = []string{
	"change", "replace", "example", "placeholder", "your-", "your_",
	"secret-here", "todo", "dummy", "insecure", "sample", "password",
	"changeme", "xxxx", "default-", "test-secret", "longrandom", "long-random",
}

func main() {
	merge := flag.String("merge", "", "path to an existing env file to merge generated secrets into (fills only placeholder/empty values)")
	rotate := flag.String("rotate", "", "rotate this key set (JWT_KEYS|TOTP_KEYS|OAUTH_TOKEN_KEYS): append a new active key and demote existing keys to still-validating, so live sessions/secrets keep working")
	out := flag.String("o", "", "output path (default: stdout)")
	force := flag.Bool("force", false, "overwrite -o if it already exists")
	flag.Parse()

	if *rotate != "" {
		runRotate(*rotate, *merge, *out, *force)
		return
	}

	secrets, err := generateAll()
	if err != nil {
		fatalf("gensecrets: %v", err)
	}

	var content string
	if *merge != "" {
		raw, rErr := os.ReadFile(*merge)
		if rErr != nil {
			fatalf("gensecrets: read %s: %v", *merge, rErr)
		}
		content = mergeEnv(string(raw), secrets)
	} else {
		content = block(secrets)
	}
	writeOut(content, *out, *force, *merge)
}

// runRotate rotates a single key set. With -merge it edits that key's line in
// the file in place; without -merge it rotates the value found in the process
// environment and prints the new KEY=VALUE line.
func runRotate(name, merge, out string, force bool) {
	if keysetField(name) == "" {
		fatalf("gensecrets: %s is not a rotatable key set — rotatable: JWT_KEYS, TOTP_KEYS, OAUTH_TOKEN_KEYS "+
			"(scalar secrets like OTP_HMAC_SECRET have no multi-key validation window; regenerate them with gen-secrets instead)", name)
	}

	if merge == "" {
		current := os.Getenv(name)
		if current == "" {
			fatalf("gensecrets: %s is not set in the environment — pass -merge <env-file> to rotate the value stored in a file", name)
		}
		rotated, err := rotateKeyset(name, current)
		if err != nil {
			fatalf("gensecrets: %v", err)
		}
		fmt.Printf("%s=%s\n", name, rotated)
		rotateChecklist(name)
		return
	}

	raw, err := os.ReadFile(merge)
	if err != nil {
		fatalf("gensecrets: read %s: %v", merge, err)
	}
	content, err := rotateInFile(string(raw), name)
	if err != nil {
		fatalf("gensecrets: %v", err)
	}
	writeOut(content, out, force, merge)
	rotateChecklist(name)
}

// writeOut sends content to stdout (out == "") or to a file. It refuses to
// overwrite an existing file unless -force is set, EXCEPT for an in-place edit
// (out == the -merge source), which is the intended target you just read from.
func writeOut(content, out string, force bool, mergeSrc string) {
	if out == "" {
		fmt.Print(content)
		return
	}
	inPlace := mergeSrc != "" && out == mergeSrc
	if !force && !inPlace {
		if _, sErr := os.Stat(out); sErr == nil {
			fatalf("gensecrets: %s already exists — refusing to overwrite (pass -force to override)", out)
		}
	}
	// 0600: secrets must not be world-readable.
	wErr := os.WriteFile(out, []byte(content), 0o600) // #nosec G703 -- out is an operator-supplied path for a local dev/ops CLI (gensecrets), not untrusted input
	if wErr != nil {
		fatalf("gensecrets: write %s: %v", out, wErr)
	}
	fmt.Fprintf(os.Stderr, "gensecrets: wrote %s (mode 0600)\n", out)
}

func rotateChecklist(name string) {
	fmt.Fprintf(os.Stderr, `
%s rotated: the new key is active; the previous key(s) are retained (inactive) so existing tokens/secrets still VALIDATE.
  1. Deploy with the updated %s.
  2. New tokens are signed/encrypted with the new key; tokens issued under the old key keep validating until they expire.
  3. After the old key's max TTL has elapsed (e.g. JWT_REFRESH_TTL for JWT_KEYS), remove the inactive key(s) and redeploy.
`, name, name)
}

// generateAll produces the full ordered set of secrets.
func generateAll() ([]secret, error) {
	jwtKeys, err := jwtKeysetJSON()
	if err != nil {
		return nil, err
	}
	totpKeys, err := aesKeysetJSON()
	if err != nil {
		return nil, err
	}
	oauthTokenKeys, err := aesKeysetJSON()
	if err != nil {
		return nil, err
	}
	return []secret{
		{"JWT_KEYS", jwtKeys},
		{"OTP_HMAC_SECRET", strong(func() string { return b64(32) })},
		{"TOTP_KEYS", totpKeys},
		{"OAUTH_STATE_SECRET", strong(func() string { return b64(32) })},
		{"OAUTH_TOKEN_KEYS", oauthTokenKeys},
		{"METRICS_TOKEN", hexN(32)},
	}, nil
}

// Ordered structs so the emitted JSON reads id→secret/key→active, matching
// .env.example, rather than the alphabetised order a map would produce.
type jwtKeyOut struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Active bool   `json:"active"`
}

type aesKeyOut struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Active bool   `json:"active"`
}

// jwtKeysetJSON builds a single-active-key JWT key set; the HS256 secret is
// base64(64 random bytes) and is regenerated until it clears the strength rules.
func jwtKeysetJSON() (string, error) {
	value := strong(func() string { return b64(64) })
	b, err := json.Marshal([]jwtKeyOut{{ID: "v1", Secret: value, Active: true}})
	return string(b), err
}

// aesKeysetJSON builds a single-active-key AES-256 key set (used by TOTP_KEYS
// and OAUTH_TOKEN_KEYS). The first 32 bytes of the value are the AES key, so
// base64(32 random bytes) gives a full-strength key.
func aesKeysetJSON() (string, error) {
	value := strong(func() string { return b64(32) })
	b, err := json.Marshal([]aesKeyOut{{ID: "v1", Key: value, Active: true}})
	return string(b), err
}

// ── Rotation ──────────────────────────────────────────────────────────────────

// anyKey captures either key-set shape (JWT uses "secret", the AES sets use
// "key"); omitempty keeps the irrelevant field out of the re-marshalled JSON.
type anyKey struct {
	ID     string `json:"id"`
	Secret string `json:"secret,omitempty"`
	Key    string `json:"key,omitempty"`
	Active bool   `json:"active"`
}

// keysetField returns the value field name for a rotatable key set, or "" if
// the key is not a rotatable multi-key set.
func keysetField(name string) string {
	switch name {
	case "JWT_KEYS":
		return "secret"
	case "TOTP_KEYS", "OAUTH_TOKEN_KEYS":
		return "key"
	default:
		return ""
	}
}

// rotateKeyset appends a fresh active key to an existing key set and demotes
// every existing key to Active:false. The old keys are RETAINED so the service
// keeps validating tokens / decrypting secrets produced under them — only new
// material uses the new key. This is the "validate existing sessions, then
// change" workflow; the caller removes the old key later, after its TTL.
func rotateKeyset(name, currentJSON string) (string, error) {
	field := keysetField(name)
	if field == "" {
		return "", fmt.Errorf("%s is not a rotatable key set", name)
	}
	currentJSON = strings.TrimSpace(currentJSON)
	if currentJSON == "" || isPlaceholder(currentJSON) {
		return "", fmt.Errorf("%s has no existing keys to rotate (value is empty or a placeholder) — create the first key with `make env-init` / `make gen-secrets`", name)
	}
	var keys []anyKey
	if err := json.Unmarshal([]byte(currentJSON), &keys); err != nil {
		return "", fmt.Errorf("%s: current value is not a valid key-set JSON array: %w", name, err)
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("%s: current key set is empty", name)
	}

	ids := make([]string, 0, len(keys))
	for i := range keys {
		keys[i].Active = false
		ids = append(ids, keys[i].ID)
	}

	value := strong(func() string {
		if field == "secret" {
			return b64(64)
		}
		return b64(32)
	})
	newKey := anyKey{ID: nextKeyID(ids), Active: true}
	if field == "secret" {
		newKey.Secret = value
	} else {
		newKey.Key = value
	}
	keys = append(keys, newKey)

	b, err := json.Marshal(keys)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// nextKeyID returns the next "v<N>" id: max(N)+1 over ids matching v<number>,
// falling back to a non-colliding candidate when ids don't follow the pattern.
func nextKeyID(ids []string) string {
	max := 0
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
		if len(id) > 1 && id[0] == 'v' {
			if n, err := strconv.Atoi(id[1:]); err == nil && n > max {
				max = n
			}
		}
	}
	candidate := fmt.Sprintf("v%d", max+1)
	for seen[candidate] {
		max++
		candidate = fmt.Sprintf("v%d", max+1)
	}
	return candidate
}

// rotateInFile rewrites the single uncommented `name=...` line in raw with its
// rotated value, preserving every other line. Errors if the key is absent.
func rotateInFile(raw, name string) (string, error) {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		key, val, ok := splitEnvLine(line)
		if !ok || key != name {
			continue
		}
		rotated, err := rotateKeyset(name, val)
		if err != nil {
			return "", err
		}
		lines[i] = key + "=" + rotated
		return strings.Join(lines, "\n"), nil
	}
	return "", fmt.Errorf("%s not found (uncommented) in the env file", name)
}

// block renders the generated secrets as a copy-pasteable env section.
func block(secrets []secret) string {
	var sb strings.Builder
	sb.WriteString("# ─── Generated secrets (gensecrets) ───────────────────────────────────────\n")
	sb.WriteString("# Strong, randomly-generated values in the formats the config loaders expect.\n")
	sb.WriteString("# Treat these as real credentials: never commit them. Append to your .env or\n")
	sb.WriteString("# run `make env-init` to produce a complete .env from .env.example.\n")
	for _, s := range secrets {
		sb.WriteString(s.key)
		sb.WriteString("=")
		sb.WriteString(s.value)
		sb.WriteString("\n")
	}
	return sb.String()
}

// mergeEnv fills placeholder/empty managed-key values in raw with generated
// secrets, rewrites the DB_DSN / REDIS_DSN passwords to match, preserves every
// other line, and appends any managed key that was absent.
func mergeEnv(raw string, secrets []secret) string {
	gen := make(map[string]string, len(secrets))
	for _, s := range secrets {
		gen[s.key] = s.value
	}

	seen := make(map[string]bool, len(secrets))
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		key, val, ok := splitEnvLine(line)
		if !ok {
			continue
		}
		if isManaged(key) {
			seen[key] = true
			if isPlaceholder(val) {
				lines[i] = key + "=" + gen[key]
			}
		}
	}

	// Ensure trailing newline before appending missing keys.
	merged := strings.Join(lines, "\n")
	var missing []secret
	for _, s := range secrets {
		if !seen[s.key] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		if !strings.HasSuffix(merged, "\n") {
			merged += "\n"
		}
		merged += "\n" + block(missing)
	}
	return merged
}

// splitEnvLine parses "KEY=VALUE", ignoring comments and blanks. The value may
// itself contain '=' (e.g. base64 padding); only the first '=' splits.
func splitEnvLine(line string) (key, val string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	eq := strings.IndexByte(trimmed, '=')
	if eq <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(trimmed[:eq]), trimmed[eq+1:], true
}

func isManaged(key string) bool { _, ok := managedKeys[key]; return ok }

// isPlaceholder reports whether val is empty or looks like an unfilled template
// value (contains a weak marker such as "REPLACE" or "change_me").
func isPlaceholder(val string) bool {
	if strings.TrimSpace(val) == "" {
		return true
	}
	lower := strings.ToLower(val)
	for _, m := range weakMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// strong returns gen()'s output, regenerating until it passes the production
// strength rules (no weak markers, ≥12 distinct chars).
func strong(gen func() string) string {
	for {
		v := gen()
		if okStrength(v) {
			return v
		}
	}
}

func okStrength(v string) bool {
	lower := strings.ToLower(v)
	for _, m := range weakMarkers {
		if strings.Contains(lower, m) {
			return false
		}
	}
	distinct := map[rune]struct{}{}
	for _, r := range v {
		distinct[r] = struct{}{}
	}
	return len(distinct) >= 12
}

// b64 returns base64(n random bytes). The first 32 bytes of the result are used
// directly as an AES-256 key by the symmetric key sets.
func b64(n int) string {
	return base64.StdEncoding.EncodeToString(randomBytes(n))
}

// hexN returns the hex encoding of n random bytes.
func hexN(n int) string { return hex.EncodeToString(randomBytes(n)) }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		fatalf("gensecrets: crypto/rand: %v", err)
	}
	return b
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
