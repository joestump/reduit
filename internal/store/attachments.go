// Package store — attachment metadata writes for sync (SPEC-0002).
//
// Sync writes attachment METADATA (filename, mime, size) keyed by
// (message_hash, proton_att_id). The `extracted_text` column is owned by the
// downstream extract/embed pass (ADR-0016) and is NEVER touched here, so
// re-sync of a message does not wipe text an earlier extract pass produced
// (SPEC-0002 "Derived data survives re-sync").
//
// Governing: SPEC-0002 REQ "Idempotent Stable-Hash Keying", ADR-0016.
package store

import (
	"context"
	"fmt"
	"strings"
)

// AttachmentInput is one attachment's metadata as the sync engine saw it. It
// carries no payload and no extracted text — those are the extract pass's
// concern (ADR-0016).
type AttachmentInput struct {
	ProtonAttID string
	Filename    string
	MIME        string
	SizeBytes   int64
}

// upsertAttachment writes one attachment's metadata for a message, keyed by
// (message_hash, proton_att_id). On a repeat it converges on the existing row,
// updating only the metadata columns (filename, mime, size_bytes). It
// deliberately never writes extracted_text: the INSERT omits it (defaults NULL)
// and the ON CONFLICT update does not set it, so an extract pass's text on an
// existing row is preserved across re-sync. An empty proton_att_id is a no-op.
func upsertAttachment(ctx context.Context, e execer, messageHash string, a AttachmentInput) error {
	if strings.TrimSpace(a.ProtonAttID) == "" {
		return nil
	}
	id, err := newID()
	if err != nil {
		return err
	}
	const q = `
        INSERT INTO attachments (id, message_hash, proton_att_id, filename, mime, size_bytes)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(message_hash, proton_att_id) DO UPDATE SET
            filename   = excluded.filename,
            mime       = excluded.mime,
            size_bytes = excluded.size_bytes`
	if _, err := e.ExecContext(ctx, q, id, messageHash, a.ProtonAttID, a.Filename, a.MIME, a.SizeBytes); err != nil {
		return fmt.Errorf("store: upsert attachment: %w", err)
	}
	return nil
}

// UpsertAttachment writes one attachment's metadata for messageHash on the
// writer pool. It never touches extracted_text. See upsertAttachment.
func (s *Store) UpsertAttachment(ctx context.Context, messageHash, protonAttID, filename, mime string, sizeBytes int64) error {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	return upsertAttachment(ctx, s.WriterDB(), messageHash, AttachmentInput{
		ProtonAttID: protonAttID, Filename: filename, MIME: mime, SizeBytes: sizeBytes,
	})
}

// UpsertAttachment writes one attachment's metadata for messageHash within the
// transaction. It never touches extracted_text.
func (t *Tx) UpsertAttachment(ctx context.Context, messageHash, protonAttID, filename, mime string, sizeBytes int64) error {
	return upsertAttachment(ctx, t.tx, messageHash, AttachmentInput{
		ProtonAttID: protonAttID, Filename: filename, MIME: mime, SizeBytes: sizeBytes,
	})
}
