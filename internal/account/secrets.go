// Per-account secret helpers. Each call unseals the envelope, performs
// the operation, and zeroes the data key. Every Seal call uses a fresh
// nonce (delegated to cryptenv.Seal), satisfying SPEC-0001 REQ
// "Encrypted Secret Storage".
//
// IMAP password rotation generates a 20-byte random secret encoded as
// base32 (32 chars without padding). The secret is sealed under the
// data key for one-time admin-UI display, AND hashed with bcrypt
// (cost 12) for SASL lookups. Bcrypt was picked over Argon2id for v0.2
// because (a) the SASL hot-path is rare-and-expensive (one verify per
// IMAP login, not per request), so bcrypt's slower-than-Argon2id
// per-call cost is fine, and (b) bcrypt has no tuning knobs to get
// wrong on a low-spec self-hosted box. Cost 12 is the current OWASP
// floor; bumping it later is a no-op for already-hashed values.
//
// Governing: ADR-0003 (envelope encryption), SPEC-0001 REQ "Encrypted
// Secret Storage".
package account

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"

	"github.com/joestump/reduit/internal/cryptenv"
)

// bcryptCost is the work factor for IMAP password hashes. Bumping it
// does not invalidate existing hashes — bcrypt encodes the cost in the
// hash itself, so verification keeps working.
const bcryptCost = 12

// imapPasswordRandomBytes is the entropy budget for a generated relay
// password: 20 raw bytes = 160 bits. Encoded as RFC 4648 base32
// (no padding) that produces 32 displayable ASCII characters.
const imapPasswordRandomBytes = 20

// ErrSecretNotPresent is returned by Open* helpers when the requested
// secret column is NULL/empty (i.e. the secret has not been sealed yet).
var ErrSecretNotPresent = errors.New("account: secret not present")

// loadDataKey decrypts the per-account data key for use within a single
// secret operation. Callers MUST defer-zero the returned key.
func (s *service) loadDataKey(ctx context.Context, accountID string) (cryptenv.DataKey, *accountRow, error) {
	row, err := s.repo.getByID(ctx, accountID)
	if err != nil {
		return cryptenv.DataKey{}, nil, err
	}
	dk, err := cryptenv.OpenEnvelope(s.master, row.KeyEnvelope)
	if err != nil {
		return cryptenv.DataKey{}, nil, fmt.Errorf("account: open envelope: %w", err)
	}
	return dk, row, nil
}

// SealRefreshToken seals plaintext under the account's data key and
// persists ciphertext.
func (s *service) SealRefreshToken(ctx context.Context, accountID string, plaintext []byte) error {
	dk, _, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return err
	}
	defer zeroDataKey(&dk)

	sealed, err := cryptenv.Seal(dk[:], plaintext, nil)
	if err != nil {
		return fmt.Errorf("account: seal refresh token: %w", err)
	}
	return s.repo.updateRefreshToken(ctx, accountID, sealed, s.now().UTC())
}

// UpdateRefreshToken is an explicit alias used by external callers
// (e.g. the proton client wrapper) so the package boundary stays
// readable from their side.
func (s *service) UpdateRefreshToken(ctx context.Context, accountID string, plaintext []byte) error {
	return s.SealRefreshToken(ctx, accountID, plaintext)
}

// OpenRefreshToken returns the plaintext refresh token.
func (s *service) OpenRefreshToken(ctx context.Context, accountID string) ([]byte, error) {
	dk, row, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return nil, err
	}
	defer zeroDataKey(&dk)

	if len(row.RefreshTokenCiphertext) == 0 {
		return nil, ErrSecretNotPresent
	}
	pt, err := cryptenv.Open(dk[:], row.RefreshTokenCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("account: open refresh token: %w", err)
	}
	return pt, nil
}

func (s *service) SealMailboxPassphrase(ctx context.Context, accountID string, plaintext []byte) error {
	dk, _, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return err
	}
	defer zeroDataKey(&dk)

	sealed, err := cryptenv.Seal(dk[:], plaintext, nil)
	if err != nil {
		return fmt.Errorf("account: seal mailbox passphrase: %w", err)
	}
	return s.repo.updateMailboxPassphrase(ctx, accountID, sealed, s.now().UTC())
}

func (s *service) OpenMailboxPassphrase(ctx context.Context, accountID string) ([]byte, error) {
	dk, row, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return nil, err
	}
	defer zeroDataKey(&dk)

	if len(row.MailboxPassphraseCiphertext) == 0 {
		return nil, ErrSecretNotPresent
	}
	pt, err := cryptenv.Open(dk[:], row.MailboxPassphraseCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("account: open mailbox passphrase: %w", err)
	}
	return pt, nil
}

// SealIMAPPassword seals plaintext AND writes a bcrypt hash. Callers
// that need to *generate* a new password should use RotateIMAPPassword
// instead; SealIMAPPassword exists so externally-supplied passwords
// (e.g. admin override) can still take the same persistence path.
func (s *service) SealIMAPPassword(ctx context.Context, accountID string, plaintext []byte) error {
	dk, _, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return err
	}
	defer zeroDataKey(&dk)

	sealed, err := cryptenv.Seal(dk[:], plaintext, nil)
	if err != nil {
		return fmt.Errorf("account: seal imap password: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword(plaintext, bcryptCost)
	if err != nil {
		return fmt.Errorf("account: bcrypt imap password: %w", err)
	}
	return s.repo.updateIMAPPassword(ctx, accountID, sealed, string(hash), s.now().UTC())
}

func (s *service) OpenIMAPPassword(ctx context.Context, accountID string) ([]byte, error) {
	dk, row, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return nil, err
	}
	defer zeroDataKey(&dk)

	if len(row.IMAPPasswordCiphertext) == 0 {
		return nil, ErrSecretNotPresent
	}
	pt, err := cryptenv.Open(dk[:], row.IMAPPasswordCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("account: open imap password: %w", err)
	}
	return pt, nil
}

// RotateIMAPPassword generates a fresh password, persists ciphertext +
// bcrypt hash, and returns the plaintext for one-time admin-UI display.
//
// Governing: SPEC-0001 REQ "Encrypted Secret Storage" (the encrypted
// form is for display in the admin UI on rotation only; SASL uses the
// hash).
func (s *service) RotateIMAPPassword(ctx context.Context, accountID string) (string, error) {
	raw := make([]byte, imapPasswordRandomBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("account: rotate imap password: read random: %w", err)
	}
	plaintext := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	if err := s.SealIMAPPassword(ctx, accountID, []byte(plaintext)); err != nil {
		// Wipe the buffer before returning.
		for i := range raw {
			raw[i] = 0
		}
		return "", err
	}
	for i := range raw {
		raw[i] = 0
	}
	return plaintext, nil
}

// VerifyIMAPPassword compares candidate against the stored bcrypt hash.
// Returns nil on match; bcrypt.ErrMismatchedHashAndPassword on miss.
func (s *service) VerifyIMAPPassword(ctx context.Context, accountID string, candidate []byte) error {
	row, err := s.repo.getByID(ctx, accountID)
	if err != nil {
		return err
	}
	if !row.IMAPPasswordHash.Valid || row.IMAPPasswordHash.String == "" {
		return ErrSecretNotPresent
	}
	if err := bcrypt.CompareHashAndPassword([]byte(row.IMAPPasswordHash.String), candidate); err != nil {
		return fmt.Errorf("account: verify imap password: %w", err)
	}
	return nil
}
