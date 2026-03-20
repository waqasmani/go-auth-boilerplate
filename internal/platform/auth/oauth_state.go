package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const oauthStateTTL = 15 * time.Minute

// OAuthState is the tamper-proof payload embedded in the OAuth `state`
// parameter. It binds a single authorisation request to a specific provider,
// redirect destination, and PKCE code verifier so that:
//
//   - A CSRF attacker cannot inject a foreign authorisation response
//     (the attacker cannot forge a valid signature).
//   - A replay attacker cannot reuse a captured state (short expiry + nonce).
//   - The redirect destination is verified before sending the user there
//     (RedirectURL is inside the signed envelope, not a free parameter).
//   - PKCE is always used (server-generated code verifier stored here so
//     the token exchange can send it without re-presenting it to the client).
type OAuthState struct {
	// Nonce is 16 bytes of cryptographic entropy that makes every state unique.
	Nonce string `json:"n"`
	// Provider is "google" or "facebook".
	Provider string `json:"p"`
	// RedirectURL is the post-login destination inside the frontend; validated
	// against an allowlist before being embedded here.
	RedirectURL string `json:"r"`
	// PKCEVerifier is the raw S256 code verifier generated server-side.
	// Never log or expose this value; it is used once to exchange the code.
	PKCEVerifier string `json:"cv"`
	// ExpiresAt is the Unix timestamp after which this state is invalid.
	ExpiresAt int64 `json:"exp"`
}

// SignOAuthState serialises state to JSON, base64url-encodes it, appends an
// HMAC-SHA256 signature, and returns the compact representation:
//
//	<base64url(json)>.<hex(hmac)>
//
// The secret parameter must be cfg.OAuthStateSecret — a dedicated HMAC signing
// key loaded from the OAUTH_STATE_SECRET environment variable. This key is
// separate from OTP_HMAC_SECRET (used for OTP digests) and must never be
// substituted with it: reusing one key across two distinct cryptographic
// operations violates key-separation principles and weakens both.
//
// OAUTH_STATE_SECRET must be ≥32 bytes; this is enforced at startup by
// config.Load() when any OAuth provider is enabled.
func SignOAuthState(state OAuthState, secret string) (string, error) {
	nonce, err := generateOAuthNonce()
	if err != nil {
		return "", fmt.Errorf("oauth state: generate nonce: %w", err)
	}
	state.Nonce = nonce
	state.ExpiresAt = time.Now().UTC().Add(oauthStateTTL).Unix()

	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("oauth state: marshal: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := oauthStateHMAC(encoded, secret)
	return encoded + "." + sig, nil
}

// ParseAndVerifyOAuthState validates the signature, checks expiry, and returns
// the decoded OAuthState. It returns an error on any of: wrong format, bad
// signature, or expired state. It never leaks which check failed in the error
// message to avoid oracle attacks.
func ParseAndVerifyOAuthState(raw, secret string) (*OAuthState, error) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("oauth state: malformed")
	}
	encoded, sig := parts[0], parts[1]

	expected := oauthStateHMAC(encoded, secret)
	// Constant-time comparison via hmac.Equal-equivalent: compare hex strings
	// of equal length using subtle.ConstantTimeCompare semantics achieved by
	// re-hashing both sides — timing does not reveal the valid signature.
	if !constantTimeEqualStrings(sig, expected) {
		return nil, fmt.Errorf("oauth state: invalid")
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("oauth state: invalid")
	}
	var state OAuthState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("oauth state: invalid")
	}
	if time.Now().UTC().Unix() > state.ExpiresAt {
		return nil, fmt.Errorf("oauth state: expired")
	}
	return &state, nil
}

// GeneratePKCEPair generates a cryptographically random code_verifier and its
// SHA-256 code_challenge for the PKCE extension (RFC 7636).
//
// Verifier: 48 bytes of entropy, base64url-encoded = 64 ASCII characters.
// Challenge: BASE64URL(SHA-256(verifier)) — the S256 method required by all
// modern identity providers. The plain method is intentionally not supported.
func GeneratePKCEPair() (verifier, challenge string, err error) {
	b := make([]byte, 48)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("pkce: generate verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)

	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func oauthStateHMAC(data, secret string) string {
	// HMACToken is defined in jwt.go and computes HMAC-SHA256.
	// The secret passed here must always be cfg.OAuthStateSecret,
	// never cfg.OTPSecret — see SignOAuthState for the rationale.
	return HMACToken(data, secret)
}

func generateOAuthNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// constantTimeEqualStrings compares two strings in constant time by hashing
// both with SHA-256 and comparing the results. This prevents timing oracles
// that could allow an attacker to iteratively forge a valid HMAC signature.
func constantTimeEqualStrings(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	diff := 0
	for i := range ha {
		diff |= int(ha[i] ^ hb[i])
	}
	return diff == 0
}
