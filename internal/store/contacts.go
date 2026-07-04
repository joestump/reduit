// Package store — contact materialization for sync (SPEC-0002).
//
// Every distinct sender/recipient address sync sees is upserted into
// contact_identifiers; an address with no existing contact mints a fresh
// contacts row (UUIDv7). This materializes the contact layer SPEC-0011 (contact
// facts) and the TUI read from. Manual merge of contacts is SPEC-0011's
// `reduit contacts merge`, out of scope here.
//
// Governing: SPEC-0002 REQ "Contact Materialization", ADR-0006.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ContactInput is a correspondent the sync engine saw on a message — an email
// address and, when the header carried one, a display name.
type ContactInput struct {
	Address     string
	DisplayName string
}

// normalizeAddress canonicalizes an email address for identity comparison so
// "Joe@Example.com" and "joe@example.com " do not mint two contacts. Email is
// case-insensitive in practice for Proton addresses, and surrounding whitespace
// is never significant.
func normalizeAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

// upsertContactIdentifier ensures a contact_identifiers row for address exists
// and returns the contact id it is linked to. It is idempotent and never
// creates a second contact for a known address (SPEC-0002 "Known address reuses
// its contact"):
//
//   - If the address already exists, its existing contact is reused; the
//     contact's display_name is backfilled only if it was empty and a name is
//     now available (never overwritten).
//   - If the address is new, a fresh contacts row (UUIDv7) is created and the
//     identifier linked to it (SPEC-0002 "New address creates a contact").
//
// An empty address is a no-op (returns "", nil) — some headers carry a display
// name with no parseable address, and that should not fail the message.
func upsertContactIdentifier(ctx context.Context, e execer, address, displayName string) (string, error) {
	addr := normalizeAddress(address)
	if addr == "" {
		return "", nil
	}
	name := strings.TrimSpace(displayName)

	var contactID string
	err := e.GetContext(ctx, &contactID,
		`SELECT contact_id FROM contact_identifiers WHERE address = ?`, addr)
	switch {
	case err == nil:
		// Known address: reuse its contact. Backfill the name only if empty.
		if name != "" {
			if _, err := e.ExecContext(ctx,
				`UPDATE contacts SET display_name = ? WHERE id = ? AND display_name = ''`,
				name, contactID); err != nil {
				return "", fmt.Errorf("store: backfill contact name: %w", err)
			}
		}
		return contactID, nil
	case errors.Is(err, sql.ErrNoRows):
		// New address: mint a contact and link the identifier.
		id, genErr := newID()
		if genErr != nil {
			return "", genErr
		}
		if _, err := e.ExecContext(ctx,
			`INSERT INTO contacts (id, display_name) VALUES (?, ?)`, id, name); err != nil {
			return "", fmt.Errorf("store: insert contact: %w", err)
		}
		if _, err := e.ExecContext(ctx,
			`INSERT INTO contact_identifiers (contact_id, address) VALUES (?, ?)`, id, addr); err != nil {
			return "", fmt.Errorf("store: insert contact identifier: %w", err)
		}
		return id, nil
	default:
		return "", fmt.Errorf("store: lookup contact identifier: %w", err)
	}
}

// UpsertContactIdentifier materializes a contact for address on the writer pool
// and returns the linked contact id. See upsertContactIdentifier.
func (s *Store) UpsertContactIdentifier(ctx context.Context, address, displayName string) (string, error) {
	if s == nil || s.WriterDB() == nil {
		return "", errNotOpen
	}
	return upsertContactIdentifier(ctx, s.WriterDB(), address, displayName)
}

// UpsertContactIdentifier materializes a contact for address within the
// transaction and returns the linked contact id.
func (t *Tx) UpsertContactIdentifier(ctx context.Context, address, displayName string) (string, error) {
	return upsertContactIdentifier(ctx, t.tx, address, displayName)
}
