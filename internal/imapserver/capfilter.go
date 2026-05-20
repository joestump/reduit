// Wire-level capability filter. The emersion/go-imap v2 server
// unconditionally appends `IDLE`, `UNSELECT`, `ENABLE`, and
// `UTF8=ACCEPT` to the CAPABILITY response once a session is
// authenticated (see capability.go availableCaps in the upstream
// library). There is no Options knob to suppress these.
//
// Story #20 wired the live-update pubsub bus, so IDLE is now fully
// implemented. The capFilterConn / capFilterListener types are
// retained because Backend.NewSession's isTLSConn drill-through
// relies on Unwrap() being present on the accepted connection and
// because removing the types would break callers that already depend
// on the TLS-unwrap contract. However, Write no longer strips IDLE
// from CAPABILITY responses — it passes all bytes through verbatim.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates" (now
// implemented — IDLE is correctly advertised and functional).

package imapserver

import (
	"net"
)

// capFilterConn wraps a net.Conn. It was previously a wire-level
// rewriter that stripped IDLE from CAPABILITY responses; since story
// #20 implemented IDLE, the rewriting is gone and the wrapper is now a
// thin pass-through whose sole role is to provide Unwrap() so that
// Backend.NewSession's isTLSConn drill-through can see through it to
// the underlying *tls.Conn.
type capFilterConn struct {
	net.Conn
}

// Unwrap exposes the wrapped net.Conn so callers (notably the backend
// `*tls.Conn` type assertion in NewSession) can drill through this
// layer. Mirrors the convention used by net/http's response writers.
func (c *capFilterConn) Unwrap() net.Conn { return c.Conn }

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
