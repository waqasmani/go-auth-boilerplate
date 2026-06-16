package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

const stateSecret = "oauth-state-secret-at-least-32-bytes-long-xxxxx"

func TestSignAndVerifyOAuthState_RoundTrip(t *testing.T) {
	in := OAuthState{Provider: "google", RedirectURL: "https://app.example.com/cb", PKCEVerifier: "verifier-123"}
	signed, nonce, err := SignOAuthState(in, stateSecret)
	if err != nil {
		t.Fatalf("SignOAuthState: %v", err)
	}
	if nonce == "" {
		t.Fatal("expected a non-empty nonce to be returned for single-use tracking")
	}

	out, err := ParseAndVerifyOAuthState(signed, stateSecret)
	if err != nil {
		t.Fatalf("ParseAndVerifyOAuthState: %v", err)
	}
	if out.Provider != "google" || out.RedirectURL != "https://app.example.com/cb" || out.PKCEVerifier != "verifier-123" {
		t.Fatalf("state mismatch: %+v", out)
	}
	if out.Nonce != nonce {
		t.Fatalf("nonce mismatch: parsed %q, signed %q", out.Nonce, nonce)
	}
}

func TestVerifyOAuthState_TamperRejected(t *testing.T) {
	signed, _, err := SignOAuthState(OAuthState{Provider: "google"}, stateSecret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Flip a byte in the payload portion (before the ".") — signature must fail.
	dot := strings.IndexByte(signed, '.')
	if dot < 1 {
		t.Fatalf("unexpected state format: %q", signed)
	}
	b := []byte(signed)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	if _, err := ParseAndVerifyOAuthState(string(b), stateSecret); err == nil {
		t.Fatal("tampered state was ACCEPTED")
	}
}

func TestVerifyOAuthState_WrongSecretRejected(t *testing.T) {
	signed, _, _ := SignOAuthState(OAuthState{Provider: "google"}, stateSecret)
	if _, err := ParseAndVerifyOAuthState(signed, "a-totally-different-secret-32-bytes-or-more"); err == nil {
		t.Fatal("state verified under the wrong secret")
	}
}

func TestVerifyOAuthState_Malformed(t *testing.T) {
	if _, err := ParseAndVerifyOAuthState("no-dot-here", stateSecret); err == nil {
		t.Fatal("malformed state accepted")
	}
}

func TestGeneratePKCEPair_S256(t *testing.T) {
	verifier, challenge, err := GeneratePKCEPair()
	if err != nil {
		t.Fatalf("GeneratePKCEPair: %v", err)
	}
	if verifier == "" || challenge == "" {
		t.Fatal("empty verifier or challenge")
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge is not S256(verifier): got %q want %q", challenge, want)
	}
}
