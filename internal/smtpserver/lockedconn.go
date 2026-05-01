// lockedConn serialises Write calls to an underlying net.Conn via a
// mutex. It exists for one specific reason: emersion/go-smtp@v0.24.0
// does NOT acquire its `c.locker` mutex from `writeResponse` — the
// library relies on the single-handler-goroutine invariant for write
// ordering. Multi-line responses (250-EHLO, multi-line errors, etc.)
// emit one bufio flush per continuation line.
//
// Our suspension fan-out goroutine (`session.dropWith421`) needs to
// inject a `421 4.7.1 Account suspended\r\n` line onto a live wire
// without that single-handler invariant holding. *tls.Conn.Write is
// goroutine-safe at the byte level (Go runtime serialises writes on a
// connected socket so bytes don't tear), but it is NOT logical-line
// safe — a 250-line PrintfLine flush from the handler can interleave
// with our 421 PrintfLine flush from the suspension goroutine and
// produce visibly garbled framing on the wire (e.g. a `421 ...` line
// embedded between two `250-...` continuations of an EHLO response).
//
// By wrapping every accepted *tls.Conn in a lockedConn at the listener
// layer, ALL writes through the underlying socket — go-smtp's
// bufio.Writer flushes from the handler goroutine, AND our
// dropWith421 from the suspension goroutine — go through the same
// mutex. The 421 either arrives before or after a 250-line response,
// never inside one.
//
// Read is NOT serialised: go-smtp owns the read side from a single
// goroutine (the per-conn handler) and there is no second reader.
// We embed the underlying net.Conn so Read, deadlines, addresses, and
// Close pass through unchanged; only Write is overridden.
//
// Governing: SPEC-0004 REQ "Per-Session Authentication Lifetime" —
// the suspension drop must be observable on the wire without
// corrupting any handler response in flight.

package smtpserver

import (
	"net"
	"sync"
)

// lockedConn wraps a net.Conn and serialises Write calls via a mutex.
// All other net.Conn methods forward to the embedded conn unchanged.
type lockedConn struct {
	net.Conn
	writeMu sync.Mutex
}

// newLockedConn returns a lockedConn wrapping c. Returns c unchanged
// (typed as net.Conn) when c is already a *lockedConn — wrapping
// twice would just add a second redundant mutex on top of the first.
func newLockedConn(c net.Conn) net.Conn {
	if c == nil {
		return nil
	}
	if _, ok := c.(*lockedConn); ok {
		return c
	}
	return &lockedConn{Conn: c}
}

// Write takes the per-conn mutex, writes the buffer in one shot, and
// releases. *tls.Conn.Write is itself goroutine-safe at the byte
// level so we don't need to subdivide; we just need every logical
// "line" or "response" the handler or the suspension goroutine emits
// to land atomically against any other writer's output.
func (l *lockedConn) Write(p []byte) (int, error) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return l.Conn.Write(p)
}

// Unwrap returns the underlying net.Conn. Provided so callers that
// truly need the raw *tls.Conn (e.g. for TLSConnectionState
// introspection) can reach it without going through the mutex.
//
// IMPORTANT: any write performed on the unwrapped conn bypasses the
// serialisation mutex and re-introduces the interleave race the
// wrapper was designed to prevent. Use Unwrap only for read-only
// inspection (state, peer cert, etc.) — never for direct Write.
func (l *lockedConn) Unwrap() net.Conn {
	return l.Conn
}

// lockedListener wraps a net.Listener so every Accepted connection is
// returned as a *lockedConn. Wired into Server.Start after tls.Listen
// returns the raw TLS listener.
type lockedListener struct {
	net.Listener
}

// Accept proxies to the underlying listener and wraps the returned
// conn in a lockedConn. Errors pass through verbatim.
func (l *lockedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newLockedConn(c), nil
}
