package cryptenv

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// DataKeyBytes is the per-account data-key length (256 bits).
const DataKeyBytes = chacha20poly1305.KeySize

// DataKey is a 32-byte per-account symmetric key. It is generated
// fresh per account and is itself sealed (envelope-encrypted) under
// the master key before persistence.
type DataKey [DataKeyBytes]byte

// GenerateDataKey returns a fresh, cryptographically random data key.
func GenerateDataKey() (DataKey, error) {
	var k DataKey
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return DataKey{}, fmt.Errorf("cryptenv: read random: %w", err)
	}
	return k, nil
}

// Seal encrypts plaintext under `key` using XChaCha20-Poly1305 with a
// fresh random 24-byte nonce. The returned ciphertext is
// `nonce || encrypted` so the layout is self-describing for Open.
//
// `aad` is optional additional authenticated data — pass nil if none.
// Reduit currently does not use aad, but the parameter is exposed so
// future per-field domain separation (e.g., binding the column name
// into the auth tag) is a non-breaking change.
func Seal(key []byte, plaintext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("cryptenv: key length %d, want %d", len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("cryptenv: new aead: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cryptenv: read nonce: %w", err)
	}
	out := make([]byte, 0, aead.NonceSize()+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// Open reverses Seal. The input MUST be `nonce || ciphertext` as
// produced by Seal. Returns the plaintext or an error if
// authentication fails (wrong key, tampered ciphertext, malformed
// input).
func Open(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("cryptenv: key length %d, want %d", len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("cryptenv: new aead: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize+aead.Overhead() {
		return nil, errors.New("cryptenv: ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	body := ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, fmt.Errorf("cryptenv: open: %w", err)
	}
	return plaintext, nil
}

// SealEnvelope seals a data key under the master key. The returned
// blob is the persisted `key_envelope` column value.
func SealEnvelope(master MasterKey, dk DataKey) ([]byte, error) {
	return Seal(master[:], dk[:], nil)
}

// OpenEnvelope unseals a data key from its persisted envelope.
func OpenEnvelope(master MasterKey, envelope []byte) (DataKey, error) {
	plaintext, err := Open(master[:], envelope, nil)
	if err != nil {
		return DataKey{}, err
	}
	if len(plaintext) != DataKeyBytes {
		return DataKey{}, fmt.Errorf("cryptenv: envelope plaintext length %d, want %d", len(plaintext), DataKeyBytes)
	}
	var dk DataKey
	copy(dk[:], plaintext)
	return dk, nil
}
