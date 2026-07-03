// Package store — message cache writes for sync (SPEC-0002).
//
// This file owns the `messages` table writes and the stable-hash identity that
// makes sync idempotent, plus ApplyMessage, the atomic per-message unit the
// engine commits (message + its contacts + links + attachments).
//
// Governing: SPEC-0002 (Sync & Local Cache), ADR-0014 (stable-hash keying),
//
//	ADR-0006 (SQLite cache — FTS maintained by triggers).
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// errNotOpen is returned by write paths when the Store has no writer handle.
var errNotOpen = errors.New("store: not open")

// MessageRow is the store-layer input for one cached message. The sync engine
// maps a proton.DecryptedMessage into this; proton types never cross into the
// store. Every field except MailboxID/ProtonID is MUTABLE — re-sync updates
// them in place on the row identified by the stable hash.
type MessageRow struct {
	// MailboxID is the owning mailbox (mailboxes.id). It, with ProtonID,
	// determines the stable hash and is never changed by an update.
	MailboxID string
	// ProtonID is Proton's message id. Immutable identity input.
	ProtonID string
	// Timestamp is the message date (messages.ts). Mutable.
	Timestamp time.Time
	// Sender is the From address, formatted by the engine. Mutable.
	Sender string
	// Subject is the decrypted subject. Mutable.
	Subject string
	// Body is the decrypted plaintext body. Mutable.
	Body string
	// Folder is the engine-derived folder/label label. Mutable.
	Folder string
}

// MessageHash computes a message's stable content identity — the value stored
// in messages.hash and the key every derived table (embeddings, contact_facts,
// attachments.extracted_text, links) hangs off.
//
// DECISION: the hash is a PURE PER-MAILBOX MESSAGE IDENTITY —
//
//	hash = sha256hex(mailbox_id + "\x00" + proton_id)
//
// It deliberately folds in NOTHING mutable (not subject, body, folder, sender,
// or timestamp). Two consequences, both required by SPEC-0002:
//
//   - Convergence (REQ "Idempotent Stable-Hash Keying"): re-import and
//     overlapping backfill/tail windows produce the SAME hash for a message, so
//     the upsert updates one row instead of inserting a duplicate. The message
//     count does not grow for a re-synced message.
//   - Derived data survives re-sync (same REQ, scenario "Derived data survives
//     re-sync"): because a body/folder/label edit does NOT change the hash, the
//     message row is UPDATED in place and its embeddings, contact facts, and
//     extracted attachment text — all keyed by this hash — stay attached. Had we
//     folded content into the hash, any body change would mint a new hash and
//     orphan all of that derived data, violating the spec. So content lives in
//     mutable columns, never in the identity.
//
// The NUL separator keeps the two inputs unambiguous (no mailbox_id/proton_id
// pair can collide with another by concatenation).
func MessageHash(mailboxID, protonID string) string {
	sum := sha256.Sum256([]byte(mailboxID + "\x00" + protonID))
	return hex.EncodeToString(sum[:])
}

// upsertMessage inserts or converges one message row and returns its stable
// hash. On an existing hash it updates ONLY the mutable columns (ts, sender,
// subject, body, folder) — mailbox_id, proton_id, the internal id, and
// created_at are preserved, and no derived table is touched. The messages_ai/
// _au triggers keep messages_fts in sync automatically (ADR-0006), so callers
// must never write messages_fts directly.
func upsertMessage(ctx context.Context, e execer, row MessageRow) (string, error) {
	if row.MailboxID == "" || row.ProtonID == "" {
		return "", fmt.Errorf("store: upsert message: mailbox_id and proton_id are required")
	}
	hash := MessageHash(row.MailboxID, row.ProtonID)
	id, err := newID()
	if err != nil {
		return "", err
	}
	// The generated id is used only on INSERT; ON CONFLICT does not set it, so
	// a converging update keeps the existing row's id (no churn on re-sync).
	const q = `
        INSERT INTO messages (id, hash, mailbox_id, proton_id, ts, sender, subject, body, folder)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hash) DO UPDATE SET
            ts      = excluded.ts,
            sender  = excluded.sender,
            subject = excluded.subject,
            body    = excluded.body,
            folder  = excluded.folder`
	if _, err := e.ExecContext(ctx, q, id, hash, row.MailboxID, row.ProtonID,
		row.Timestamp, row.Sender, row.Subject, row.Body, row.Folder); err != nil {
		return "", fmt.Errorf("store: upsert message: %w", err)
	}
	return hash, nil
}

// MessageWrite is the full atomic unit for one message the sync engine applies:
// the message plus every distinct correspondent, extracted link, and attachment
// it carries. ApplyMessage writes them all under one message identity.
type MessageWrite struct {
	Message     MessageRow
	Contacts    []ContactInput
	Links       []LinkInput
	Attachments []AttachmentInput
}

// applyMessage writes a message and all its derived rows against e. When e is a
// transaction (via Tx.ApplyMessage / Store.WithTx), the whole unit — and the
// engine's UpsertSyncState cursor advance in the same tx — commits atomically,
// so a partial message is never observable (SPEC-0002 "Partial application
// never corrupts the cache"). Contacts are materialized first so the contact
// layer exists regardless of link/attachment content; links and attachments key
// off the message's stable hash.
func applyMessage(ctx context.Context, e execer, w MessageWrite) error {
	hash, err := upsertMessage(ctx, e, w.Message)
	if err != nil {
		return err
	}
	for _, c := range w.Contacts {
		if _, err := upsertContactIdentifier(ctx, e, c.Address, c.DisplayName); err != nil {
			return err
		}
	}
	for _, l := range w.Links {
		if err := upsertLink(ctx, e, hash, l.URL, l.AnchorText); err != nil {
			return err
		}
	}
	for _, a := range w.Attachments {
		if err := upsertAttachment(ctx, e, hash, a); err != nil {
			return err
		}
	}
	return nil
}

// deleteMessageByProtonID removes a message and its links and attachments,
// keyed by the stable hash derived from (mailboxID, protonID). Contacts are
// left intact — they are shared across messages and not owned by any one
// message (SPEC-0002 "Contact Materialization" — re-sync never cascade-wipes
// the contact layer). The messages_ad trigger removes the FTS entry. Deleting a
// message that is not present is a no-op, so replayed deletes are idempotent.
func deleteMessageByProtonID(ctx context.Context, e execer, mailboxID, protonID string) error {
	hash := MessageHash(mailboxID, protonID)
	if _, err := e.ExecContext(ctx, `DELETE FROM links WHERE message_hash = ?`, hash); err != nil {
		return fmt.Errorf("store: delete message links: %w", err)
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM attachments WHERE message_hash = ?`, hash); err != nil {
		return fmt.Errorf("store: delete message attachments: %w", err)
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM messages WHERE hash = ?`, hash); err != nil {
		return fmt.Errorf("store: delete message: %w", err)
	}
	return nil
}

// UpsertMessage inserts or converges a single message on the writer pool and
// returns its stable hash. See upsertMessage for the convergence semantics.
func (s *Store) UpsertMessage(ctx context.Context, row MessageRow) (string, error) {
	if s == nil || s.WriterDB() == nil {
		return "", errNotOpen
	}
	return upsertMessage(ctx, s.WriterDB(), row)
}

// ApplyMessage writes a message and its contacts, links, and attachments in one
// transaction on the writer pool. To commit it together with a sync-cursor
// advance, use Store.WithTx and call Tx.ApplyMessage + Tx.UpsertSyncState inside.
func (s *Store) ApplyMessage(ctx context.Context, w MessageWrite) error {
	return s.WithTx(ctx, func(ctx context.Context, tx *Tx) error {
		return applyMessage(ctx, tx.tx, w)
	})
}

// DeleteMessageByProtonID removes a message and its links/attachments on the
// writer pool, leaving contacts. It is idempotent.
func (s *Store) DeleteMessageByProtonID(ctx context.Context, mailboxID, protonID string) error {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	return deleteMessageByProtonID(ctx, s.WriterDB(), mailboxID, protonID)
}

// UpsertMessage inserts or converges a single message within the transaction.
func (t *Tx) UpsertMessage(ctx context.Context, row MessageRow) (string, error) {
	return upsertMessage(ctx, t.tx, row)
}

// ApplyMessage writes a message and its derived rows within the transaction, so
// the caller can commit it together with a cursor advance (Tx.UpsertSyncState).
func (t *Tx) ApplyMessage(ctx context.Context, w MessageWrite) error {
	return applyMessage(ctx, t.tx, w)
}

// DeleteMessageByProtonID removes a message and its links/attachments within the
// transaction, leaving contacts. It is idempotent.
func (t *Tx) DeleteMessageByProtonID(ctx context.Context, mailboxID, protonID string) error {
	return deleteMessageByProtonID(ctx, t.tx, mailboxID, protonID)
}
