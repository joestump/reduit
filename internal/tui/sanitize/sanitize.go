// Package sanitize strips terminal control and escape sequences from
// attacker-influenced strings before they reach lipgloss/bubbletea rendering.
//
// Mail-derived text (subjects, sender names, filenames, fact text, message
// bodies) is fully attacker-controlled: a crafted message can embed ANSI
// escape sequences, cursor moves, OSC title-setters, DCS payloads, or raw
// C0/C1 control bytes that — rendered verbatim into a terminal — reposition
// the cursor, recolor the screen, rewrite the window title, or tear the TUI's
// layout. This package is the single render-boundary chokepoint that makes
// those bytes inert. It is the TUI analog of the old web UI's HTML-escaping
// budget (design.md "Hostile-string sanitation at the render boundary"):
// centralizing it in one exhaustively-tested package is what makes the
// guarantee auditable.
//
// The scanner works on RAW BYTES with UTF-8 decoding, not on a pre-decoded
// []rune. That distinction is load-bearing: a lone C1 control byte
// (0x80–0x9F) is not valid UTF-8, so decoding to runes first would silently
// turn it into U+FFFD and hide it from the state machine — leaving the C1
// introducer's trailing parameter bytes to leak as text. Scanning bytes lets a
// raw C1 CSI/OSC/DCS introducer be recognized and its whole sequence consumed,
// while a genuine multi-byte rune (whose lead byte was already consumed) is
// never misread.
//
// The guarantee is that nothing which can STEER a terminal survives: no C0/C1
// control byte, no ESC introducer, no U+FFFD residue, and no escape sequence.
// It is NOT that every trace of a mangled sequence vanishes. When a hostile CSI
// introducer is interrupted by a control byte before its final (e.g.
// "ESC [ <newline> 3 1 m"), the trailing "31m" survives as literal text —
// deliberately. That matches how a real terminal renders it (a control aborts
// the CSI; the tail is plain text), the introducer is already stripped so it is
// inert, and greedily dropping the tail would corrupt legitimate body content
// that happens to follow a hostile prefix (a real message "Dear Bob…" after an
// "ESC [ <newline>" would lose its first bytes to CSI-grammar matching). Inert
// residue is the safe choice; content loss is not.
//
// Two entry points cover the two rendering contexts:
//
//   - Line: single-line contexts (index rows, the status line, help hints).
//     Strips ALL control characters including newline and tab so a value can
//     never break out of its row.
//   - Block: multi-line contexts (the message pager). Preserves newlines as
//     row breaks and expands tabs to spaces, but strips every other control
//     and every escape sequence.
//
// Governing: ADR-0025 (Bubble Tea TUI), SPEC-0005 REQ "Terminal Discipline"
// ("Untrusted strings ... MUST be sanitized of terminal control/escape
// sequences before rendering, so a crafted message cannot inject escapes
// through the TUI").
package sanitize

import (
	"strings"
	"unicode/utf8"
)

// tabWidth is the number of spaces a tab expands to in Block contexts.
const tabWidth = 4

// Line returns s with every C0/C1 control character and every escape sequence
// removed, collapsed to a single safe line. Newlines and tabs are dropped (not
// expanded) so the result cannot span or break a row. Printable Unicode —
// including combining marks, emoji, and CJK — passes through unchanged.
func Line(s string) string {
	return sanitize(s, false)
}

// Block returns s with every C0/C1 control character and every escape sequence
// removed, but with newlines preserved as row breaks and tabs expanded to
// spaces. Use it for the pager, where a cached message body legitimately spans
// many lines. Carriage returns are dropped so a lone CR cannot rewind the
// cursor to the start of a rendered line.
func Block(s string) string {
	return sanitize(s, true)
}

// sanitize is the shared byte-level scanner. At each position it either
// dispatches an escape sequence (ESC- or C1-introduced) to be consumed and
// discarded in full, drops a bare control byte, or emits a printable rune. It
// never decodes the whole input up front, so a raw C1 introducer byte is
// recognized instead of being pre-neutralized to U+FFFD.
func sanitize(s string, block bool) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		c := s[i]

		// ESC-introduced sequences (C0 0x1B). skipEscape consumes the whole
		// sequence and returns the index just past it.
		if c == 0x1B {
			i = skipEscape(s, i)
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])

		// An invalid byte (size==1, RuneError) is either a raw C1 introducer —
		// which must consume its sequence — or plain garbage, which is dropped.
		if r == utf8.RuneError && size == 1 {
			switch c {
			case 0x9B: // C1 CSI
				i = skipCSI(s, i+1)
			case 0x9D, 0x90, 0x98, 0x9E, 0x9F: // C1 OSC / DCS / SOS / PM / APC
				i = skipString(s, i+1)
			default: // other C1 controls and invalid bytes: drop
				i++
			}
			continue
		}

		// Valid rune. C1 introducers can also arrive as well-formed UTF-8
		// (e.g. U+009B encoded C2 9B); handle those the same as their raw-byte
		// forms before the generic control drop.
		switch {
		case r == 0x9B:
			i = skipCSI(s, i+size)
		case r == 0x9D || r == 0x90 || r == 0x98 || r == 0x9E || r == 0x9F:
			i = skipString(s, i+size)
		case block && r == '\n':
			b.WriteByte('\n')
			i += size
		case block && r == '\t':
			b.WriteString(strings.Repeat(" ", tabWidth))
			i += size
		case isControl(r):
			// C0 (incl. CR, and — in line mode — LF/TAB), DEL, and C1: dropped.
			i += size
		default:
			b.WriteString(s[i : i+size])
			i += size
		}
	}
	return b.String()
}

// isControl reports whether r is a C0 control (0x00–0x1F), DEL (0x7F), or a C1
// control (0x80–0x9F). These are the bytes that steer a terminal rather than
// print a glyph.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F)
}

// skipEscape consumes an ESC-introduced sequence starting at s[i] (which is
// ESC) and returns the index just past it. It recognizes CSI (ESC [ … final),
// the string controls OSC/DCS/SOS/PM/APC (ESC ] | P | X | ^ | _ … ST|BEL), and
// the two-character forms (ESC + one intermediate/final byte 0x20–0x7E). A bare
// ESC — at end of input, or followed by a control byte such as a layout-bearing
// newline/tab — consumes ONLY the ESC, so the following byte is re-examined and
// handled on its own (this keeps a crafted "ESC \n" from swallowing a row break
// in Block mode).
func skipEscape(s string, i int) int {
	if i+1 >= len(s) {
		return i + 1 // lone trailing ESC — nothing follows to consume
	}
	switch c := s[i+1]; {
	case c == '[': // CSI
		return skipCSI(s, i+2)
	case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_':
		// OSC and the DCS/SOS/PM/APC string controls: body runs to ST or BEL.
		return skipString(s, i+2)
	case c >= 0x20 && c <= 0x7E:
		// Two-character escape (e.g. ESC c reset, ESC ( charset select): the
		// ESC plus one intermediate/final byte.
		return i + 2
	default:
		// ESC followed by a control (newline, tab, another ESC, …): drop only
		// the ESC and let the loop re-examine the following byte.
		return i + 1
	}
}

// skipCSI consumes a CSI body. p indexes the first byte AFTER the introducer
// (ESC's '[' or a C1 0x9B). Parameter and intermediate bytes (0x20–0x3F) are
// consumed until a final byte (0x40–0x7E) ends the sequence. On a malformed
// byte (a control, or a byte outside the CSI grammar) it stops and returns that
// byte's index so the caller re-examines it — a truncated CSI must not swallow
// a following control or newline.
func skipCSI(s string, p int) int {
	for p < len(s) {
		c := s[p]
		if c >= 0x40 && c <= 0x7E { // final byte ends the CSI
			return p + 1
		}
		if c < 0x20 || c > 0x3F { // not a valid param/intermediate byte
			return p
		}
		p++
	}
	return len(s)
}

// skipString consumes an OSC/DCS/SOS/PM/APC body. p indexes the first byte
// AFTER the introducer. The body runs until BEL (0x07) or the ST terminator
// (ESC \). Returns the index just past the terminator, or end-of-input if the
// sequence is never terminated.
func skipString(s string, p int) int {
	for p < len(s) {
		if s[p] == 0x07 { // BEL terminates
			return p + 1
		}
		if s[p] == 0x1B && p+1 < len(s) && s[p+1] == '\\' { // ST = ESC \
			return p + 2
		}
		p++
	}
	return len(s)
}
