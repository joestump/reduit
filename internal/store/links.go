// Package store — link extraction writes for sync (SPEC-0002).
//
// URLs the engine parses out of a decrypted body are written to the `links`
// table, keyed to their message by the message's stable hash. SPEC-0006's
// `list_links` tool and `has_link` filter read this table; sync only writes it.
//
// Governing: SPEC-0002 REQ "Link Extraction", ADR-0006.
package store

import (
	"context"
	"fmt"
	"strings"
)

// LinkInput is one URL the engine extracted from a message body, with the
// anchor text it appeared under when the body carried one.
type LinkInput struct {
	URL        string
	AnchorText string
}

// upsertLink writes one link for a message, keyed by (message_hash, url). On a
// repeat of the same URL it converges on the existing row (updating the anchor
// text, which is re-derived from the body each sync) rather than inserting a
// duplicate, so a message's link set survives re-sync without growing
// (SPEC-0002 "Re-sync converges links without duplicating"). An empty URL is a
// no-op, so a body with nothing to extract writes no rows and never fails the
// message (SPEC-0002 "A message with no URLs yields no links").
func upsertLink(ctx context.Context, e execer, messageHash, url, anchorText string) error {
	u := strings.TrimSpace(url)
	if u == "" {
		return nil
	}
	id, err := newID()
	if err != nil {
		return err
	}
	const q = `
        INSERT INTO links (id, message_hash, url, anchor_text)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(message_hash, url) DO UPDATE SET anchor_text = excluded.anchor_text`
	if _, err := e.ExecContext(ctx, q, id, messageHash, u, anchorText); err != nil {
		return fmt.Errorf("store: upsert link: %w", err)
	}
	return nil
}

// UpsertLink writes one link for messageHash on the writer pool. See upsertLink.
func (s *Store) UpsertLink(ctx context.Context, messageHash, url, anchorText string) error {
	if s == nil || s.WriterDB() == nil {
		return errNotOpen
	}
	return upsertLink(ctx, s.WriterDB(), messageHash, url, anchorText)
}

// UpsertLink writes one link for messageHash within the transaction.
func (t *Tx) UpsertLink(ctx context.Context, messageHash, url, anchorText string) error {
	return upsertLink(ctx, t.tx, messageHash, url, anchorText)
}
