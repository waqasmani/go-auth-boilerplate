// Package auth — TOTP helpers (RFC 6238) with key-rotation support.
//
// Encryption key rotation workflow (mirrors JWT key rotation):
//  1. Generate a new key and append it with Active: false in TOTP_KEYS.
//  2. Deploy — existing secrets (encrypted with old key) continue to decrypt
//     because the old key is still in the set.
//  3. Set new key to Active: true, old key to Active: false. Deploy — new
//     secrets are now encrypted with the new key; old secrets remain readable.
//  4. Re-encrypt stored secrets with the new key (optional background job),
//     then remove the old key entirely.
package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image/png"
	"io"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ── Key set ───────────────────────────────────────────────────────────────────

// TOTPEncKey is a single AES-256 encryption key entry.
// Key must be ≥32 bytes; only the first 32 are used for AES-256.
type TOTPEncKey struct {
	// ID is embedded in every ciphertext blob so Decrypt can look up the
	// correct key without ambiguity. Must be ≤255 bytes (1-byte length prefix).
	ID string

	// Key is the raw AES key material. Minimum 32 bytes.
	Key string

	// Active marks the single key used to encrypt new TOTP secrets.
	// Exactly one entry in the set must be true.
	Active bool
}

// TOTPKeySet is the validated, indexed TOTP encryption key set.
// Construct via NewTOTPKeySet — the zero value is not usable.
type TOTPKeySet struct {
	activeKey TOTPEncKey
	keyByID   map[string]TOTPEncKey
}

// NewTOTPKeySet validates keys and returns a ready-to-use key set.
// Returns a descriptive error on misconfiguration so that container.New and
// module constructors can surface it as a structured startup message rather
// than a raw panic stack trace. Common failure modes: empty slice, duplicate
// key IDs, key shorter than 32 bytes, zero or multiple active keys.
func NewTOTPKeySet(keys []TOTPEncKey) (*TOTPKeySet, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("totp: keys slice is empty — provide at least one key")
	}
	keyByID := make(map[string]TOTPEncKey, len(keys))
	var activeKey TOTPEncKey
	activeCount := 0

	for _, k := range keys {
		if k.ID == "" {
			return nil, fmt.Errorf("totp: a key has an empty ID")
		}
		if len(k.ID) > 255 {
			return nil, fmt.Errorf("totp: key ID %q exceeds 255 bytes", k.ID)
		}
		if len(k.Key) < 32 {
			return nil, fmt.Errorf(
				"totp: key %q is %d bytes — minimum 32 required for AES-256",
				k.ID, len(k.Key),
			)
		}
		if _, dup := keyByID[k.ID]; dup {
			return nil, fmt.Errorf("totp: duplicate key ID %q", k.ID)
		}
		keyByID[k.ID] = k
		if k.Active {
			activeKey = k
			activeCount++
		}
	}
	switch activeCount {
	case 0:
		return nil, fmt.Errorf("totp: no key has Active: true — exactly one must be active")
	case 1:
		// correct
	default:
		return nil, fmt.Errorf("totp: %d keys have Active: true — exactly one must be active", activeCount)
	}
	return &TOTPKeySet{activeKey: activeKey, keyByID: keyByID}, nil
}

// Encrypt encrypts plaintext with the active key.
//
// Blob layout (little-endian length prefix):
//
//	[1 byte: len(keyID)] [keyID bytes] [12 byte GCM nonce] [GCM ciphertext+tag]
//
// The embedded key ID makes Decrypt key-rotation-safe: any key in the set
// whose ID matches the blob prefix can decrypt it, regardless of which key is
// currently active.
func (ks *TOTPKeySet) Encrypt(plaintext string) ([]byte, error) {
	return encryptWithKey(ks.activeKey, plaintext)
}

// Decrypt extracts the key ID from the blob, looks up the matching key, and
// decrypts. Returns an error when the key ID is unknown (the issuing key has
// been removed before re-encryption was complete).
func (ks *TOTPKeySet) Decrypt(ciphertext []byte) (string, error) {
	if len(ciphertext) < 1 {
		return "", fmt.Errorf("totp: decrypt: ciphertext too short")
	}
	idLen := int(ciphertext[0])
	if len(ciphertext) < 1+idLen {
		return "", fmt.Errorf("totp: decrypt: ciphertext truncated reading key ID")
	}
	keyID := string(ciphertext[1 : 1+idLen])

	k, ok := ks.keyByID[keyID]
	if !ok {
		return "", fmt.Errorf("totp: decrypt: unknown key ID %q — key may have been removed before re-encryption", keyID)
	}
	return decryptWithKey(k, ciphertext[1+idLen:])
}

// ── Key generation & validation ───────────────────────────────────────────────

// TOTPGenerateConfig parameterises TOTP key generation.
type TOTPGenerateConfig struct {
	Issuer string
	Period uint
	Digits otp.Digits
	// KeySet is used to encrypt the generated secret for DB storage.
	// The active key in the set is used; the key ID is embedded in the blob.
	KeySet *TOTPKeySet
}

// TOTPSetupResult is returned by GenerateTOTPSecret.
type TOTPSetupResult struct {
	// Secret is the plaintext base32 secret — show to the user once, then discard.
	Secret string
	// URI is the otpauth:// provisioning URL for authenticator apps.
	URI string
	// QRCodePNG is the raw PNG of the QR code.
	QRCodePNG []byte
	// QRCodeBase64 is QRCodePNG base64-encoded; embed as data:image/png;base64,…
	QRCodeBase64 string
	// EncryptedSecret is the key-versioned AES-GCM blob ready for DB storage.
	EncryptedSecret []byte
}

// GenerateTOTPSecret creates a new TOTP key, renders a 256×256 QR code PNG,
// and encrypts the base32 secret using the key set's active key.
func GenerateTOTPSecret(cfg TOTPGenerateConfig, accountName string) (*TOTPSetupResult, error) {
	if cfg.KeySet == nil {
		return nil, fmt.Errorf("totp: GenerateTOTPSecret: KeySet must not be nil")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.Issuer,
		AccountName: accountName,
		Period:      cfg.Period,
		Digits:      cfg.Digits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("totp: generate key: %w", err)
	}

	img, err := key.Image(256, 256)
	if err != nil {
		return nil, fmt.Errorf("totp: generate qr image: %w", err)
	}
	var buf bytes.Buffer
	if err = png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("totp: encode qr png: %w", err)
	}
	qrBytes := buf.Bytes()

	encrypted, err := cfg.KeySet.Encrypt(key.Secret())
	if err != nil {
		return nil, fmt.Errorf("totp: encrypt secret: %w", err)
	}

	return &TOTPSetupResult{
		Secret:          key.Secret(),
		URI:             key.URL(),
		QRCodePNG:       qrBytes,
		QRCodeBase64:    base64.StdEncoding.EncodeToString(qrBytes),
		EncryptedSecret: encrypted,
	}, nil
}

// ValidateTOTP checks a TOTP code against the plaintext base32 secret.
// Allows ±1 step (±period seconds) of clock skew.
func ValidateTOTP(code, secret string, period uint, digits otp.Digits) (bool, error) {
	return totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    period,
		Skew:      1,
		Digits:    digits,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// encryptWithKey encrypts plaintext and prepends the key ID length + key ID.
// Returned layout: [1-byte idLen][idBytes][12-byte nonce][GCM ciphertext+tag]
func encryptWithKey(k TOTPEncKey, plaintext string) ([]byte, error) {
	block, gcm, err := newGCM(k.Key)
	if err != nil {
		return nil, err
	}
	_ = block
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("totp: nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	idBytes := []byte(k.ID)
	blob := make([]byte, 0, 1+len(idBytes)+len(sealed))
	blob = append(blob, byte(len(idBytes)))
	blob = append(blob, idBytes...)
	blob = append(blob, sealed...)
	return blob, nil
}

// decryptWithKey decrypts the nonce-prefixed GCM payload (without the key ID prefix).
func decryptWithKey(k TOTPEncKey, payload []byte) (string, error) {
	_, gcm, err := newGCM(k.Key)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(payload) < ns {
		return "", fmt.Errorf("totp: decrypt: payload too short for nonce")
	}
	plain, err := gcm.Open(nil, payload[:ns], payload[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("totp: decrypt: %w", err)
	}
	return string(plain), nil
}

func newGCM(rawKey string) (cipher.Block, cipher.AEAD, error) {
	key := []byte(rawKey)[:32]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("totp: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("totp: gcm: %w", err)
	}
	return block, gcm, nil
}
