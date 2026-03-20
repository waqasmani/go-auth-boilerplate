package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const defaultCost = 12

// prehash derives a bcrypt-safe input from plain by SHA-256-hashing it and
// base64-encoding the 32-byte result (yielding 44 ASCII characters).
//
// bcrypt silently truncates any input longer than 72 bytes, which means two
// passwords that share the same first 72 bytes would produce the same hash —
// a user who sets a 100-character password could authenticate with only the
// first 72 characters. Prehashing eliminates this entirely: the input to bcrypt
// is always 44 bytes regardless of the original password length.
//
// Both HashPassword and VerifyPassword apply prehash so the two operations
// remain in sync. Never call bcrypt.GenerateFromPassword or
// bcrypt.CompareHashAndPassword with a raw password in this package.
func prehash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// HashPassword hashes a plain-text password using bcrypt at cost 12.
// The input is SHA-256-prehashed before being passed to bcrypt so that
// passwords of arbitrary length hash consistently and correctly.
func HashPassword(plain string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(prehash(plain)), defaultCost)
	if err != nil {
		return "", fmt.Errorf("password: hash: %w", err)
	}
	return string(hashed), nil
}

// VerifyPassword compares a plain-text password against a bcrypt hash.
// Returns nil when the password matches, an error otherwise.
// The same SHA-256 prehash applied during HashPassword is applied here
// so the comparison is always performed on the prehashed value.
func VerifyPassword(plain, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(prehash(plain)))
}
