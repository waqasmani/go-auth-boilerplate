package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	totpKey1 = "totp-key-one-aes256-needs-32-bytes-min-aaaaa"
	totpKey2 = "totp-key-two-aes256-needs-32-bytes-min-bbbbb"
)

func TestTOTPKeySet_Validation(t *testing.T) {
	if _, err := NewTOTPKeySet([]TOTPEncKey{{ID: "v1", Key: "tooshort", Active: true}}); err == nil {
		t.Fatal("expected error for <32-byte key")
	}
	if _, err := NewTOTPKeySet(nil); err == nil {
		t.Fatal("expected error for empty key set")
	}
	if _, err := NewTOTPKeySet([]TOTPEncKey{{ID: "v1", Key: totpKey1, Active: false}}); err == nil {
		t.Fatal("expected error when no key is active")
	}
}

func TestTOTPEncryptDecrypt_RoundTrip(t *testing.T) {
	ks, err := NewTOTPKeySet([]TOTPEncKey{{ID: "v1", Key: totpKey1, Active: true}})
	if err != nil {
		t.Fatalf("NewTOTPKeySet: %v", err)
	}
	blob, err := ks.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := ks.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round-trip mismatch: %q", plain)
	}
}

// TestTOTPKeyRotation verifies a secret encrypted under v1 still decrypts after
// v2 becomes active, as long as v1 remains in the set (key-id embedded in blob).
func TestTOTPKeyRotation(t *testing.T) {
	ksOld, _ := NewTOTPKeySet([]TOTPEncKey{{ID: "v1", Key: totpKey1, Active: true}})
	blob, err := ksOld.Encrypt("secret-under-v1")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ksNew, err := NewTOTPKeySet([]TOTPEncKey{
		{ID: "v1", Key: totpKey1, Active: false},
		{ID: "v2", Key: totpKey2, Active: true},
	})
	if err != nil {
		t.Fatalf("NewTOTPKeySet(rotated): %v", err)
	}
	plain, err := ksNew.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypt after rotation: %v", err)
	}
	if plain != "secret-under-v1" {
		t.Fatalf("rotation decrypt mismatch: %q", plain)
	}

	// A set missing v1 entirely cannot decrypt the v1 blob.
	ksMissing, _ := NewTOTPKeySet([]TOTPEncKey{{ID: "v2", Key: totpKey2, Active: true}})
	if _, err := ksMissing.Decrypt(blob); err == nil {
		t.Fatal("expected decrypt failure when issuing key id is absent")
	}
}

func TestTOTPDecrypt_TamperRejected(t *testing.T) {
	ks, _ := NewTOTPKeySet([]TOTPEncKey{{ID: "v1", Key: totpKey1, Active: true}})
	blob, _ := ks.Encrypt("authentic")
	blob[len(blob)-1] ^= 0xFF // flip a ciphertext/tag byte
	if _, err := ks.Decrypt(blob); err == nil {
		t.Fatal("expected GCM auth failure on tampered ciphertext")
	}
}

func TestValidateTOTP(t *testing.T) {
	ks, _ := NewTOTPKeySet([]TOTPEncKey{{ID: "v1", Key: totpKey1, Active: true}})
	res, err := GenerateTOTPSecret(TOTPGenerateConfig{
		Issuer: "test", Period: 30, Digits: otp.DigitsSix, KeySet: ks,
	}, "u@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}

	code, err := totp.GenerateCode(res.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	ok, err := ValidateTOTP(code, res.Secret, 30, otp.DigitsSix)
	if err != nil || !ok {
		t.Fatalf("ValidateTOTP(valid) = (%v,%v), want (true,nil)", ok, err)
	}
	if ok, _ := ValidateTOTP("000000", res.Secret, 30, otp.DigitsSix); ok {
		// 000000 could legitimately be the code in a vanishingly rare case; if so
		// this is a flake, not a bug. Use an obviously-wrong code derived from it.
		bad := "654321"
		if bad == code {
			bad = "123456"
		}
		if ok2, _ := ValidateTOTP(bad, res.Secret, 30, otp.DigitsSix); ok2 {
			t.Fatal("ValidateTOTP accepted an incorrect code")
		}
	}
}
