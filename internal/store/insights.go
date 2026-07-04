// Package store — read-only aggregates for the TUI's insights views (SPEC-0005).
//
// These methods back the attachments and contact-facts destinations of the
// local TUI (ADR-0025). They are strictly read-only and, like the other store
// reads, are the SAME methods any other surface (MCP, future callers) would use
// so behavior cannot drift (ADR-0017). Each joins derived rows to just enough
// owning-message/contact context for a glanceable index and a citation.
//
// Governing: ADR-0025 (Bubble Tea TUI insights views), ADR-0017 (shared store,
// one query path), ADR-0016 (attachment extraction), ADR-0019 (contact facts),
// SPEC-0005 REQ "Insights Views".
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AttachmentRow is one row of the attachments index: the attachment's metadata
// plus the subject of its owning message (resolved by stable hash) and whether
// extraction has produced text for it. Raw attachment bytes are NOT cached
// (the schema stores metadata + extracted text only), so this is what the TUI
// can show.
type AttachmentRow struct {
	ID            string `db:"id"`
	MessageHash   string `db:"message_hash"`
	Filename      string `db:"filename"`
	MIME          string `db:"mime"`
	SizeBytes     int64  `db:"size_bytes"`
	MessageSubj   string `db:"message_subject"`
	MessageSender string `db:"message_sender"`
	HasText       bool   `db:"has_text"`
}

// ListAttachments returns the attachment index ordered by owning-message
// timestamp (newest first), capped at limit. A limit <= 0 applies a sane
// default so the TUI never issues an unbounded scan (design.md pagination).
// The owning message is resolved by stable hash with a LEFT JOIN so an
// attachment whose message is not (yet) cached still lists, with empty
// subject/sender rather than being dropped. Read-only.
func (s *Store) ListAttachments(ctx context.Context, limit int) ([]AttachmentRow, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("store: not open")
	}
	if limit <= 0 {
		limit = 500
	}
	const q = `SELECT
		a.id                                   AS id,
		a.message_hash                         AS message_hash,
		a.filename                             AS filename,
		a.mime                                 AS mime,
		a.size_bytes                           AS size_bytes,
		COALESCE(m.subject, '')                AS message_subject,
		COALESCE(m.sender, '')                 AS message_sender,
		(a.extracted_text IS NOT NULL
		   AND a.extracted_text <> '')         AS has_text
		FROM attachments a
		LEFT JOIN messages m ON m.hash = a.message_hash
		ORDER BY m.ts DESC, a.filename ASC
		LIMIT ?`
	var rows []AttachmentRow
	if err := s.DB.SelectContext(ctx, &rows, q, limit); err != nil {
		return nil, fmt.Errorf("store: list attachments: %w", err)
	}
	return rows, nil
}

// AttachmentText returns the extracted text for one attachment by id, and
// whether a row was found. Empty text with found==true means the attachment
// exists but has not been through an extraction pass. Read-only.
func (s *Store) AttachmentText(ctx context.Context, id string) (string, bool, error) {
	if s == nil || s.DB == nil {
		return "", false, errors.New("store: not open")
	}
	var text *string
	const q = `SELECT extracted_text FROM attachments WHERE id = ?`
	if err := s.DB.GetContext(ctx, &text, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("store: attachment text: %w", err)
	}
	if text == nil {
		return "", true, nil
	}
	return *text, true, nil
}

// ContactRow is one row of the contacts index: the contact's display name, a
// primary address, and how many facts have been extracted for them.
type ContactRow struct {
	ID          string `db:"id"`
	DisplayName string `db:"display_name"`
	Address     string `db:"address"`
	FactCount   int64  `db:"fact_count"`
}

// ListContacts returns contacts that have at least one identifier, ordered by
// fact count (most-known first) then display name, capped at limit. Contacts
// with no facts still list (fact_count 0) so the view shows the full roster.
// Read-only.
func (s *Store) ListContacts(ctx context.Context, limit int) ([]ContactRow, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("store: not open")
	}
	if limit <= 0 {
		limit = 500
	}
	const q = `SELECT
		c.id           AS id,
		c.display_name AS display_name,
		COALESCE((SELECT ci.address FROM contact_identifiers ci
		            WHERE ci.contact_id = c.id ORDER BY ci.address LIMIT 1), '') AS address,
		(SELECT COUNT(*) FROM contact_facts f WHERE f.contact_id = c.id)         AS fact_count
		FROM contacts c
		ORDER BY fact_count DESC, c.display_name ASC
		LIMIT ?`
	var rows []ContactRow
	if err := s.DB.SelectContext(ctx, &rows, q, limit); err != nil {
		return nil, fmt.Errorf("store: list contacts: %w", err)
	}
	return rows, nil
}

// ContactFactRow is one extracted fact with its citation (the stable hash of
// the message it was drawn from) so the TUI can show provenance.
type ContactFactRow struct {
	Fact              string `db:"fact"`
	Category          string `db:"category"`
	SourceMessageHash string `db:"source_message_hash"`
}

// ContactFacts returns the facts extracted for one contact, newest first.
// Read-only; the TUI never mutates facts (mutations stay CLI/MCP per SPEC-0011).
func (s *Store) ContactFacts(ctx context.Context, contactID string) ([]ContactFactRow, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("store: not open")
	}
	const q = `SELECT fact, category, source_message_hash
		FROM contact_facts
		WHERE contact_id = ?
		ORDER BY created_at DESC`
	var rows []ContactFactRow
	if err := s.DB.SelectContext(ctx, &rows, q, contactID); err != nil {
		return nil, fmt.Errorf("store: contact facts: %w", err)
	}
	return rows, nil
}
