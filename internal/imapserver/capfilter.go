// Wire-level capability filter. The emersion/go-imap v2 server
// unconditionally appends `IDLE`, `UNSELECT`, `ENABLE`, and
// `UTF8=ACCEPT` to the CAPABILITY response once a session is
// authenticated (see capability.go availableCaps in the upstream
// library). There is no Options knob to suppress these.
//
// Reduit must NOT advertise IDLE until story #20 wires the live-update
// pubsub bus — until then, `Idle` blocks indefinitely on its `<-stop`
// channel and any client that issues IDLE after SELECT will sit on a
// dead socket for ~35 minutes (the upstream idle read timeout) before
// reconnecting. That looks broken to Apple Mail, Thunderbird, and
// every other real-world client. Better to not advertise the capability
// at all so the client falls back to NOOP polling.
//
// Implementation: wrap the underlying net.Conn at Accept time with a
// writer that scans each Write call for the byte sequence ` IDLE ` (or
// trailing ` IDLE]`) inside a CAPABILITY response and removes it. We
// intentionally do NOT touch UNSELECT / ENABLE / UTF8=ACCEPT — those
// extensions are functionally complete in the upstream library and
// safe to advertise.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates" (deferred
// to story #20 — until then, advertise nothing).

package imapserver

import (
	"bytes"
	"net"
)

// capFilterConn wraps a net.Conn and rewrites outgoing CAPABILITY
// responses to strip the IDLE token. Non-CAPABILITY traffic flows
// through unchanged.
//
// The emersion encoder flushes each protocol response in a single
// Write call (the bufio.Writer.Flush at end of `CRLF`), so a CAPABILITY
// response always arrives here as one contiguous slice unless it
// exceeds bufio's default 4KiB. CAPABILITY responses are well under
// 4KiB in practice (we advertise ~10 atoms), so the single-Write
// invariant holds for our use.
type capFilterConn struct {
	net.Conn
}

// Unwrap exposes the wrapped net.Conn so callers (notably the backend
// `*tls.Conn` type assertion in NewSession) can drill through this
// layer. Mirrors the convention used by net/http's response writers.
func (c *capFilterConn) Unwrap() net.Conn { return c.Conn }

// Write inspects p for an IMAP CAPABILITY response and strips the
// `IDLE` capability token before forwarding to the underlying conn.
// Three forms are recognised:
//
//   - CAPABILITY ... IDLE ...\r\n
//     <tag> OK [CAPABILITY ... IDLE ...] ...\r\n
//   - OK [CAPABILITY ... IDLE ...] ...\r\n  (greeting variant)
//
// Anything else passes through verbatim.
func (c *capFilterConn) Write(p []byte) (int, error) {
	if !bytes.Contains(p, []byte("CAPABILITY")) || !bytes.Contains(p, []byte("IDLE")) {
		return c.Conn.Write(p)
	}
	rewritten := stripIdleCapability(p)
	if _, err := c.Conn.Write(rewritten); err != nil {
		return 0, err
	}
	// Report the original length so the bufio writer's accounting
	// stays consistent — we have written every logical byte the caller
	// handed us, even though the on-wire payload is shorter.
	return len(p), nil
}

// stripIdleCapability removes ` IDLE` (with leading space) from any
// CAPABILITY response found in p. Operates byte-wise so it does not
// allocate when the payload contains no IDLE token.
func stripIdleCapability(p []byte) []byte {
	// Cheap exit: only act on lines that look like a CAPABILITY response.
	// We search byte-by-byte for the ` IDLE` token surrounded by an
	// IMAP atom delimiter (space or `]`) so partial matches like
	// `IDLECMD` (hypothetical future cap) are not corrupted.
	out := make([]byte, 0, len(p))
	i := 0
	for i < len(p) {
		// Look for " IDLE" with a following space or ']' (atom terminator).
		if i+5 <= len(p) && p[i] == ' ' &&
			p[i+1] == 'I' && p[i+2] == 'D' && p[i+3] == 'L' && p[i+4] == 'E' {
			if i+5 == len(p) {
				// Token at end of buffer — drop it.
				i += 5
				continue
			}
			next := p[i+5]
			if next == ' ' || next == ']' || next == '\r' {
				// Drop the leading space and the IDLE atom; keep the
				// terminator (next char).
				i += 5
				continue
			}
		}
		out = append(out, p[i])
		i++
	}
	return out
}

// capFilterListener wraps each accepted connection with capFilterConn.
// We install this between tls.Listen and the emersion server so the
// upstream library writes through the filter without knowing about it.
type capFilterListener struct {
	net.Listener
}

func (l *capFilterListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &capFilterConn{Conn: c}, nil
}
