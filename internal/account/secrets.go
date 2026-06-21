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

// bcryptMaxPasswordBytes is bcrypt's hard input ceiling. bcrypt
// silently truncates inputs longer than 72 bytes, which would let two
// distinct passwords (sharing the first 72 bytes) hash to the same
// digest — a verification footgun for externally-supplied secrets.
const bcryptMaxPasswordBytes = 72

// Column-name AAD constants. Every Seal/Open call passes the matching
// canonical column name as additional authenticated data so an
// attacker (or buggy code) with DB write cannot copy a ciphertext from
// one column into another column that shares the same per-account
// data key — the AEAD tag will fail to verify with the wrong AAD.
//
// Governing: ADR-0003. Column-name AAD prevents ciphertext substitution
// across columns sealed with the same per-account key.
const (
	aadRefreshToken      = "refresh_token_ciphertext"
	aadMailboxPassphrase = "mailbox_passphrase_ciphertext"
	aadSessionUID        = "session_uid_ciphertext"
	aadIMAPPassword      = "imap_password_ciphertext"
)

// ErrIMAPPasswordTooLong is returned when an externally-supplied IMAP
// password exceeds bcrypt's 72-byte input ceiling. Internal callers
// (RotateIMAPPassword) generate a fixed 32-char secret and never trip
// this; the guard exists for SealIMAPPassword's "admin override" path.
var ErrIMAPPasswordTooLong = fmt.Errorf("account: imap password exceeds %d bytes (bcrypt input ceiling)", bcryptMaxPasswordBytes)

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

	sealed, err := cryptenv.Seal(dk[:], plaintext, []byte(aadRefreshToken))
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
	pt, err := cryptenv.Open(dk[:], row.RefreshTokenCiphertext, []byte(aadRefreshToken))
	if err != nil {
		return nil, fmt.Errorf("account: open refresh token: %w", err)
	}
	return pt, nil
}

// SealSessionUID seals the Proton *session* UID under the account's
// data key and persists the ciphertext. The session UID is ephemeral
// (minted per login) but credential-adjacent: it is one of the three
// inputs /auth/v4/refresh needs to re-establish a session on restart
// (alongside the sealed refresh token + mailbox passphrase). It is
// sealed — never stored in plaintext, never logged — and carries its
// own column-name AAD so a ciphertext cannot be moved between columns
// sealed under the same data key.
//
// Governing: ADR-0003 (envelope encryption), ADR-0001 (the UID is
// required by go-proton-api's refresh path), SPEC-0001 REQ "Encrypted
// Secret Storage"; #28 (closes its boot-re-unlock blocker), #34.
func (s *service) SealSessionUID(ctx context.Context, accountID string, plaintext []byte) error {
	dk, _, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return err
	}
	defer zeroDataKey(&dk)

	sealed, err := cryptenv.Seal(dk[:], plaintext, []byte(aadSessionUID))
	if err != nil {
		return fmt.Errorf("account: seal session uid: %w", err)
	}
	return s.repo.updateSessionUID(ctx, accountID, sealed, s.now().UTC())
}

// OpenSessionUID returns the plaintext Proton session UID as a string,
// or ErrSecretNotPresent when no UID has been sealed (a NULL/empty
// column — every account created or last set up before #34's migration).
// The string return shape mirrors what protonlive.UIDSource consumes
// (ReUnlock takes the UID as a string), and an empty/not-present UID is
// the signal Lifecycle.sessionUID treats as the missing-UID gap: it
// SKIPS boot re-unlock for that account with a WARN rather than failing
// it, preserving backward compatibility for pre-migration accounts.
//
// Unlike the refresh token (a long-lived []byte we can defer-zero), the
// UID must cross the package boundary as a string for the
// /auth/v4/refresh entry point; we still zero the unsealed []byte source
// before returning so the longer-lived buffer we control does not linger.
//
// Governing: ADR-0003, SPEC-0001 REQ "Encrypted Secret Storage",
// SPEC-0002 REQ "One Worker Per Active Account"; #34.
func (s *service) OpenSessionUID(ctx context.Context, accountID string) (string, error) {
	dk, row, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return "", err
	}
	defer zeroDataKey(&dk)

	if len(row.SessionUIDCiphertext) == 0 {
		return "", ErrSecretNotPresent
	}
	pt, err := cryptenv.Open(dk[:], row.SessionUIDCiphertext, []byte(aadSessionUID))
	if err != nil {
		return "", fmt.Errorf("account: open session uid: %w", err)
	}
	uid := string(pt)
	for i := range pt {
		pt[i] = 0
	}
	return uid, nil
}

func (s *service) SealMailboxPassphrase(ctx context.Context, accountID string, plaintext []byte) error {
	dk, _, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return err
	}
	defer zeroDataKey(&dk)

	sealed, err := cryptenv.Seal(dk[:], plaintext, []byte(aadMailboxPassphrase))
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
	pt, err := cryptenv.Open(dk[:], row.MailboxPassphraseCiphertext, []byte(aadMailboxPassphrase))
	if err != nil {
		return nil, fmt.Errorf("account: open mailbox passphrase: %w", err)
	}
	return pt, nil
}

// SealIMAPPassword seals plaintext AND writes a bcrypt hash. Callers
// that need to *generate* a new password should use RotateIMAPPassword
// instead; SealIMAPPassword exists so externally-supplied passwords
// (e.g. admin override) can still take the same persistence path.
//
// Returns ErrIMAPPasswordTooLong if plaintext exceeds 72 bytes; bcrypt
// silently truncates beyond that, which would let two distinct
// passwords sharing a 72-byte prefix verify against the same hash.
func (s *service) SealIMAPPassword(ctx context.Context, accountID string, plaintext []byte) error {
	if len(plaintext) > bcryptMaxPasswordBytes {
		return ErrIMAPPasswordTooLong
	}
	dk, _, err := s.loadDataKey(ctx, accountID)
	if err != nil {
		return err
	}
	defer zeroDataKey(&dk)

	sealed, err := cryptenv.Seal(dk[:], plaintext, []byte(aadIMAPPassword))
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
	pt, err := cryptenv.Open(dk[:], row.IMAPPasswordCiphertext, []byte(aadIMAPPassword))
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
