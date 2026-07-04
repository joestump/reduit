// Package store — keyword/FTS search over cached messages (SPEC-0008 keyword
// floor; the store method behind #90 and the TUI search view #169).
//
// Search runs against messages_fts, the FTS5 external-content index kept in
// sync with messages by triggers (ADR-0006). It is bm25-ranked and always
// available with no LLM and no network — the keyword floor the richer semantic
// search (SPEC-0008) later layers on. Read-only.
//
// Governing: ADR-0006 (SQLite + FTS5), ADR-0017 (shared store, one query path),
// SPEC-0008 REQ "Keyword Search Is Always Available", "Safe Snippet
// Highlighting".
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// SearchHit is one keyword-search result: message metadata plus a bm25-ranked
// snippet of the body with the matched terms bracketed. Ordered best-first.
type SearchHit struct {
	Hash    string    `db:"hash"`
	Ts      time.Time `db:"ts"`
	Sender  string    `db:"sender"`
	Subject string    `db:"subject"`
	Folder  string    `db:"folder"`
	Snippet string    `db:"snippet"`
}

// SearchMessages runs a bm25-ranked FTS5 keyword search over cached messages
// and returns the best hits (capped at limit; a limit <= 0 applies a default).
// The raw user query is converted to a safe FTS5 expression by ftsQuery so
// arbitrary punctuation can never raise an FTS syntax error — an unparseable
// or empty query yields zero hits, not an error (SPEC-0008 "always available",
// and the TUI's "no matches" scenario). Read-only.
func (s *Store) SearchMessages(ctx context.Context, query string, limit int) ([]SearchHit, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("store: not open")
	}
	if limit <= 0 {
		limit = 200
	}
	match := ftsQuery(query)
	if match == "" {
		return nil, nil // empty/blank query: no hits, no error
	}
	// snippet(fts, 2, ...) highlights column 2 (body). bm25() is ascending
	// (lower = better), so ORDER BY rank returns best-first.
	const q = `SELECT
		m.hash    AS hash,
		m.ts      AS ts,
		m.sender  AS sender,
		m.subject AS subject,
		m.folder  AS folder,
		snippet(messages_fts, 2, '[', ']', '…', 12) AS snippet
		FROM messages_fts
		JOIN messages m ON m.rowid = messages_fts.rowid
		WHERE messages_fts MATCH ?
		ORDER BY bm25(messages_fts)
		LIMIT ?`
	var hits []SearchHit
	if err := s.DB.SelectContext(ctx, &hits, q, match, limit); err != nil {
		// A malformed FTS expression that slipped past ftsQuery must degrade to
		// "no matches", not error the whole search (SPEC-0008).
		if isFTSSyntaxError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: search messages: %w", err)
	}
	return hits, nil
}

// MessageDetail is a single cached message with its full body, for the pager
// opened from a search hit.
type MessageDetail struct {
	Hash    string    `db:"hash"`
	Ts      time.Time `db:"ts"`
	Sender  string    `db:"sender"`
	Subject string    `db:"subject"`
	Folder  string    `db:"folder"`
	Body    string    `db:"body"`
}

// GetMessage returns one cached message by stable hash, and whether it was
// found. Read-only.
func (s *Store) GetMessage(ctx context.Context, hash string) (MessageDetail, bool, error) {
	if s == nil || s.DB == nil {
		return MessageDetail{}, false, errors.New("store: not open")
	}
	const q = `SELECT hash, ts, sender, subject, folder, body FROM messages WHERE hash = ?`
	var d MessageDetail
	if err := s.DB.GetContext(ctx, &d, q, hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MessageDetail{}, false, nil
		}
		return MessageDetail{}, false, fmt.Errorf("store: get message: %w", err)
	}
	return d, true, nil
}

// ftsQuery converts a raw user string into a safe FTS5 MATCH expression. Each
// whitespace-separated token becomes a double-quoted prefix term
// (`"token"*`), with any internal double quote doubled per FTS5 string rules;
// tokens are ANDed by juxtaposition. Quoting neutralizes every FTS5 operator
// character (`( ) " * : - ^ NEAR`), so punctuation in a subject search can
// never raise a syntax error, while the trailing `*` keeps prefix matching so
// "recei" finds "receipt". A blank input returns "".
func ftsQuery(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(fields))
	for _, f := range fields {
		// Strip control runes (incl. NUL) before quoting. A NUL is especially
		// dangerous: it truncates the bound MATCH string at SQLite's C-string
		// layer, leaving an unterminated quote and a hard "unterminated string"
		// error — which would defeat the "never errors" contract. Removing
		// controls keeps the expression well-formed for any input.
		f = strings.Map(func(r rune) rune {
			if r == 0 || unicode.IsControl(r) {
				return -1
			}
			return r
		}, f)
		if f == "" {
			continue
		}
		quoted = append(quoted, `"`+strings.ReplaceAll(f, `"`, `""`)+`"*`)
	}
	if len(quoted) == 0 {
		return ""
	}
	return strings.Join(quoted, " ")
}

// isFTSSyntaxError reports whether err is an FTS5 query-syntax error, which the
// modernc.org/sqlite driver surfaces as a plain message. Matched so a bad query
// degrades to "no matches" rather than erroring.
func isFTSSyntaxError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "fts5") ||
		strings.Contains(msg, "malformed match") ||
		strings.Contains(msg, "syntax error") ||
		strings.Contains(msg, "unterminated") ||
		strings.Contains(msg, "no such column")
}
