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

// UpsertResult reports the outcome of one message upsert: the stable hash the
// row is keyed by, and whether this call INSERTED a new row (true) or CONVERGED
// onto an existing one (false). The sync engine sums Inserted to report
// added-vs-updated counts per run (SPEC-0002 REQ "Bookkeeping And
// Observability") without changing the idempotent convergence semantics.
type UpsertResult struct {
	// Hash is the message's stable content identity (messages.hash).
	Hash string
	// Inserted is true when the row did not exist and was created, false when an
	// existing row was updated in place. Derived from RETURNING (see
	// upsertMessage), so it is exact under the single writer, not a heuristic.
	Inserted bool
}

// upsertMessage inserts or converges one message row and reports its stable hash
// plus whether the row was inserted or updated. On an existing hash it updates
// ONLY the mutable columns (ts, sender, subject, body, folder) — mailbox_id,
// proton_id, the internal id, and created_at are preserved, and no derived table
// is touched. The messages_ai/_au triggers keep messages_fts in sync
// automatically (ADR-0006), so callers must never write messages_fts directly.
//
// Insert-vs-update detection is exact and race-free: the freshly generated id is
// bound into VALUES, and ON CONFLICT DO UPDATE deliberately does NOT touch id, so
// a converging update keeps the row's EXISTING id. RETURNING id then equals the
// generated id iff this statement inserted; on an update it returns the older id.
// It is a single statement on the single-writer pool (WriterDB, MaxOpenConns(1)),
// so no concurrent writer can interleave between a check and the write — there is
// no check, only the atomic upsert's own RETURNING.
func upsertMessage(ctx context.Context, e execer, row MessageRow) (UpsertResult, error) {
	if row.MailboxID == "" || row.ProtonID == "" {
		return UpsertResult{}, fmt.Errorf("store: upsert message: mailbox_id and proton_id are required")
	}
	hash := MessageHash(row.MailboxID, row.ProtonID)
	id, err := newID()
	if err != nil {
		return UpsertResult{}, err
	}
	// The generated id is used only on INSERT; ON CONFLICT does not set it, so
	// a converging update keeps the existing row's id (no churn on re-sync). The
	// RETURNING id lets us tell the two apart: it echoes the generated id on an
	// insert and the pre-existing id on an update.
	const q = `
        INSERT INTO messages (id, hash, mailbox_id, proton_id, ts, sender, subject, body, folder)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hash) DO UPDATE SET
            ts      = excluded.ts,
            sender  = excluded.sender,
            subject = excluded.subject,
            body    = excluded.body,
            folder  = excluded.folder
        RETURNING id`
	var returnedID string
	if err := e.GetContext(ctx, &returnedID, q, id, hash, row.MailboxID, row.ProtonID,
		row.Timestamp, row.Sender, row.Subject, row.Body, row.Folder); err != nil {
		return UpsertResult{}, fmt.Errorf("store: upsert message: %w", err)
	}
	return UpsertResult{Hash: hash, Inserted: returnedID == id}, nil
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
func applyMessage(ctx context.Context, e execer, w MessageWrite) (UpsertResult, error) {
	res, err := upsertMessage(ctx, e, w.Message)
	if err != nil {
		return UpsertResult{}, err
	}
	for _, c := range w.Contacts {
		if _, err := upsertContactIdentifier(ctx, e, c.Address, c.DisplayName); err != nil {
			return UpsertResult{}, err
		}
	}
	for _, l := range w.Links {
		if err := upsertLink(ctx, e, res.Hash, l.URL, l.AnchorText); err != nil {
			return UpsertResult{}, err
		}
	}
	for _, a := range w.Attachments {
		if err := upsertAttachment(ctx, e, res.Hash, a); err != nil {
			return UpsertResult{}, err
		}
	}
	return res, nil
}

// deleteMessageByProtonID removes a message and the derived rows OWNED by it,
// keyed by the stable hash derived from (mailboxID, protonID), and reports
// whether a message row was actually removed. It returns deleted=false (nil
// error) when no such message exists, so replayed/duplicate deletes are
// idempotent and the engine counts only real deletes (SPEC-0002 REQ
// "Bookkeeping And Observability").
//
// Delete-hygiene decision (reviewer-flagged orphan-on-delete):
//
//   - links and attachments are 1:1-owned by the message via message_hash and
//     are purged with it.
//   - embeddings ARE purged too. An embedding is the vector OF this exact
//     message/chunk, keyed 1:1 by its hash; once the message is gone a surviving
//     embedding is a dangling vector — a semantic-search hit that resolves to no
//     message, a real read-layer hazard (SPEC-0002 reads: browse / keyword /
//     semantic). This is distinct from re-sync, which UPDATES a message in place
//     (hash unchanged) and MUST keep embeddings (SPEC-0002 "Derived data
//     survives re-sync"); a genuine delete has no message to preserve them for.
//   - contact_facts are deliberately RETAINED. A fact is keyed by
//     fact_hash = hash(contact_id, fact) with UNIQUE(fact_hash), so the same
//     fact asserted by several messages collapses to one row whose
//     source_message_hash records only the FIRST citing message. Deleting that
//     one message does not mean the fact is unsupported — other messages may
//     still assert it — so a blind cascade would drop still-valid facts. Facts
//     are downstream state owned by the facts layer (SPEC-0011), which reconciles
//     citations; sync does not cascade-wipe them, matching how the contact layer
//     itself is left intact here.
//   - contacts / contact_identifiers are left intact — shared across messages,
//     owned by the contact layer, never cascade-wiped by sync (SPEC-0002
//     "Contact Materialization").
//
// The messages_ad trigger removes the FTS entry.
func deleteMessageByProtonID(ctx context.Context, e execer, mailboxID, protonID string) (bool, error) {
	hash := MessageHash(mailboxID, protonID)
	if _, err := e.ExecContext(ctx, `DELETE FROM links WHERE message_hash = ?`, hash); err != nil {
		return false, fmt.Errorf("store: delete message links: %w", err)
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM attachments WHERE message_hash = ?`, hash); err != nil {
		return false, fmt.Errorf("store: delete message attachments: %w", err)
	}
	if _, err := e.ExecContext(ctx, `DELETE FROM embeddings WHERE hash = ?`, hash); err != nil {
		return false, fmt.Errorf("store: delete message embeddings: %w", err)
	}
	res, err := e.ExecContext(ctx, `DELETE FROM messages WHERE hash = ?`, hash)
	if err != nil {
		return false, fmt.Errorf("store: delete message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: delete message rows affected: %w", err)
	}
	return n > 0, nil
}

// UpsertMessage inserts or converges a single message on the writer pool and
// reports its stable hash plus whether the row was inserted or updated. See
// upsertMessage for the convergence semantics.
func (s *Store) UpsertMessage(ctx context.Context, row MessageRow) (UpsertResult, error) {
	if s == nil || s.WriterDB() == nil {
		return UpsertResult{}, errNotOpen
	}
	return upsertMessage(ctx, s.WriterDB(), row)
}

// ApplyMessage writes a message and its contacts, links, and attachments in one
// transaction on the writer pool and reports the message's upsert result. To
// commit it together with a sync-cursor advance, use Store.WithTx and call
// Tx.ApplyMessage + Tx.UpsertSyncState inside.
func (s *Store) ApplyMessage(ctx context.Context, w MessageWrite) (UpsertResult, error) {
	var res UpsertResult
	err := s.WithTx(ctx, func(ctx context.Context, tx *Tx) error {
		var e error
		res, e = applyMessage(ctx, tx.tx, w)
		return e
	})
	if err != nil {
		return UpsertResult{}, err
	}
	return res, nil
}

// DeleteMessageByProtonID removes a message and its owned derived rows
// (links, attachments, embeddings) on the writer pool, leaving contacts and
// contact_facts. It reports whether a message row was actually removed and is
// idempotent.
func (s *Store) DeleteMessageByProtonID(ctx context.Context, mailboxID, protonID string) (bool, error) {
	if s == nil || s.WriterDB() == nil {
		return false, errNotOpen
	}
	return deleteMessageByProtonID(ctx, s.WriterDB(), mailboxID, protonID)
}

// UpsertMessage inserts or converges a single message within the transaction,
// reporting its stable hash and whether the row was inserted or updated.
func (t *Tx) UpsertMessage(ctx context.Context, row MessageRow) (UpsertResult, error) {
	return upsertMessage(ctx, t.tx, row)
}

// ApplyMessage writes a message and its derived rows within the transaction and
// reports the message's upsert result, so the caller can commit it together with
// a cursor advance (Tx.UpsertSyncState) and count added-vs-updated.
func (t *Tx) ApplyMessage(ctx context.Context, w MessageWrite) (UpsertResult, error) {
	return applyMessage(ctx, t.tx, w)
}

// DeleteMessageByProtonID removes a message and its owned derived rows within
// the transaction, leaving contacts and contact_facts. It reports whether a
// message row was actually removed and is idempotent.
func (t *Tx) DeleteMessageByProtonID(ctx context.Context, mailboxID, protonID string) (bool, error) {
	return deleteMessageByProtonID(ctx, t.tx, mailboxID, protonID)
}
