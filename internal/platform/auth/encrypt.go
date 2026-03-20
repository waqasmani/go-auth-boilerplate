// Package auth — generic AES-256-GCM symmetric key set.
//
// This helper provides the same blob layout as the TOTP key set but is named
// for general use so OAuth token storage and any future credential encryption
// are not coupled to TOTP naming. The wire format is intentionally identical:
//
//	[1 byte: len(keyID)] [keyID bytes] [12-byte GCM nonce] [GCM ciphertext+tag]
//
// This means a SymmetricKeySet can decrypt blobs produced by TOTPKeySet if the
// same raw key material is registered under the same ID — useful during a future
// consolidation of the two helpers.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// SymmetricKeyConfig is a single AES-256 encryption key entry. Its fields are
// intentionally identical to TOTPKeyConfig so env-var loading helpers can be
// shared via a type conversion in config/config.go.
type SymmetricKeyConfig struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Active bool   `json:"active"`
}

// SymmetricKeySet is a validated, indexed AES-256-GCM key set that supports
// key rotation. Construct via NewSymmetricKeySet — the zero value is not usable.
type SymmetricKeySet struct {
	activeKey SymmetricKeyConfig
	keyByID   map[string]SymmetricKeyConfig
}

// NewSymmetricKeySet validates keys and returns a ready-to-use key set.
// Returns a descriptive error on any misconfiguration so that container.New
// can surface it as a structured startup message rather than a crash. Typical
// failure modes: empty slice, duplicate key IDs, key shorter than 32 bytes,
// zero or multiple active keys.
func NewSymmetricKeySet(keys []SymmetricKeyConfig) (*SymmetricKeySet, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("symmetric: keys slice is empty — provide at least one key")
	}
	keyByID := make(map[string]SymmetricKeyConfig, len(keys))
	var activeKey SymmetricKeyConfig
	activeCount := 0

	for _, k := range keys {
		if k.ID == "" {
			return nil, fmt.Errorf("symmetric: a key has an empty ID")
		}
		if len(k.ID) > 255 {
			return nil, fmt.Errorf("symmetric: key ID %q exceeds 255 bytes", k.ID)
		}
		if len(k.Key) < 32 {
			return nil, fmt.Errorf(
				"symmetric: key %q is %d bytes — minimum 32 required for AES-256",
				k.ID, len(k.Key),
			)
		}
		if _, dup := keyByID[k.ID]; dup {
			return nil, fmt.Errorf("symmetric: duplicate key ID %q", k.ID)
		}
		keyByID[k.ID] = k
		if k.Active {
			activeKey = k
			activeCount++
		}
	}
	switch activeCount {
	case 0:
		return nil, fmt.Errorf("symmetric: no key has Active: true — exactly one must be active")
	case 1:
		// correct
	default:
		return nil, fmt.Errorf("symmetric: %d keys have Active: true — exactly one must be active", activeCount)
	}
	return &SymmetricKeySet{activeKey: activeKey, keyByID: keyByID}, nil
}

// Encrypt encrypts plaintext with the active key, returning a self-describing
// blob that embeds the key ID so Decrypt can locate the correct key on read.
//
// Blob layout:
//
//	[1 byte: len(keyID)] [keyID bytes] [12 byte GCM nonce] [GCM ciphertext+tag]
func (ks *SymmetricKeySet) Encrypt(plaintext []byte) ([]byte, error) {
	k := ks.activeKey
	block, err := aes.NewCipher([]byte(k.Key)[:32])
	if err != nil {
		return nil, fmt.Errorf("symmetric: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("symmetric: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("symmetric: nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)

	idBytes := []byte(k.ID)
	blob := make([]byte, 0, 1+len(idBytes)+len(sealed))
	blob = append(blob, byte(len(idBytes)))
	blob = append(blob, idBytes...)
	blob = append(blob, sealed...)
	return blob, nil
}

// Decrypt extracts the key ID from the blob, looks up the matching key, and
// decrypts. Returns an error when the key ID is unknown (the issuing key has
// been removed before re-encryption was complete).
func (ks *SymmetricKeySet) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < 1 {
		return nil, fmt.Errorf("symmetric: decrypt: ciphertext too short")
	}
	idLen := int(blob[0])
	if len(blob) < 1+idLen {
		return nil, fmt.Errorf("symmetric: decrypt: ciphertext truncated reading key ID")
	}
	keyID := string(blob[1 : 1+idLen])
	payload := blob[1+idLen:]

	k, ok := ks.keyByID[keyID]
	if !ok {
		return nil, fmt.Errorf("symmetric: decrypt: unknown key ID %q — key may have been removed before re-encryption", keyID)
	}

	block, err := aes.NewCipher([]byte(k.Key)[:32])
	if err != nil {
		return nil, fmt.Errorf("symmetric: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("symmetric: gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(payload) < ns {
		return nil, fmt.Errorf("symmetric: decrypt: payload too short for nonce")
	}
	plain, err := gcm.Open(nil, payload[:ns], payload[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("symmetric: decrypt: %w", err)
	}
	return plain, nil
}

// ActiveKeyID returns the ID of the key currently used for encryption.
// Useful for logging which key was used without exposing the key material.
func (ks *SymmetricKeySet) ActiveKeyID() string {
	return ks.activeKey.ID
}
