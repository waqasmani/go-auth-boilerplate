package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const defaultCost = 12

// HashPassword hashes a plain-text password using bcrypt.
func HashPassword(plain string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), defaultCost)
	if err != nil {
		return "", fmt.Errorf("password: hash: %w", err)
	}
	return string(hashed), nil
}

// VerifyPassword compares a plain-text password against its bcrypt hash.
// Returns nil on match, error otherwise.
func VerifyPassword(plain, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}
