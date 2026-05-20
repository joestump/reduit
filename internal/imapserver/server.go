// Server wires the emersion/go-imap v2 Server with Reduit's Backend
// and a TLS-only listener using the hot-reloading cert loader. The
// listener is the public entrypoint; lifecycle is Start / Shutdown
// in the same shape the v0.1 HTTP server uses.
//
// Governing: ADR-0007 (emersion go-imap v2), ADR-0009 (TLS via disk
// loader with hot reload), SPEC-0003.

package imapserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/joestump/reduit/internal/pubsub"
)

// DefaultIMAPSAddress is the listen address used when neither
// configuration nor the REDUIT_IMAPS_ADDR env var is set.
//
// Governing: SPEC-0003 REQ "TLS Required, IMAPS Only" — port 993 is
// the IANA-assigned IMAPS port; we bind it by default.
const DefaultIMAPSAddress = ":993"

// EnvIMAPSAddr is the environment variable an operator can set to
// override the listen address without editing the config file.
const EnvIMAPSAddr = "REDUIT_IMAPS_ADDR"

// Config bundles the construction-time knobs for Server. All fields
// other than the empty-string defaults are required.
type Config struct {
	// Addr is the TCP address to bind. Empty means "use the env var
	// REDUIT_IMAPS_ADDR if set, otherwise DefaultIMAPSAddress".
	Addr string

	// GetCertificate is the tls.Config callback that hands out the
	// active certificate. In production this is loader.GetCertificate
	// from internal/tlsloader; tests may pass a static callback.
	//
	// Governing: ADR-0009 — wiring `GetCertificate` lets the cert
	// rotate without restarting the IMAP server.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// Accounts is the slice of account.Service the IMAP backend
	// needs (alias lookup + password verify).
	Accounts AccountLookup

	// Sessions is the live-session registry. Suspension code paths
	// hold a reference and call DropForAccount when an account
	// transitions to Suspended or SoftDeleted.
	Sessions *Sessions

	// Mailboxes is the per-account mailbox service. Required for the
	// Session's List/Select/Status/Fetch/Move methods to surface real
	// data; absent, those methods fall back to the SPEC-0003-compatible
	// "no such mailbox" stub.
	//
	// Governing: SPEC-0003 REQ "UID Stability", SPEC-0003 REQ "Folder
	// Hierarchy and Mapping", SPEC-0003 REQ "Account Isolation in IMAP
	// Operations".
	Mailboxes MailboxService

	// Proton resolves an account ID to its live Proton client. Required
	// for Move / Copy to translate IMAP folder transitions into Proton
	// label adjustments. Absent, Move returns a transient `NO` so the
	// client retries.
	Proton ProtonClientLookup

	// Bus is the in-process pubsub bus that the sync worker publishes
	// to after each committed Proton event batch. When wired, IDLE
	// sessions subscribe to it and emit EXISTS/EXPUNGE/FETCH updates
	// within 1 second of the sync event. When nil, IDLE still works
	// but delivers no live updates.
	//
	// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
	Bus *pubsub.Bus

	// Logger is the slog.Logger used for connection-level events.
	// nil falls back to slog.Default().
	Logger *slog.Logger
}

// resolveAddr returns the bind address with env-var fallback.
func (c Config) resolveAddr() string {
	if c.Addr != "" {
		return c.Addr
	}
	if env := os.Getenv(EnvIMAPSAddr); env != "" {
		return env
	}
	return DefaultIMAPSAddress
}

// Server is the IMAPS listener. The zero value is not usable;
// construct via New.
type Server struct {
	cfg      Config
	backend  *Backend
	imapSrv  *imapserver.Server
	logger   *slog.Logger
	sessions *Sessions

	mu       sync.Mutex
	listener net.Listener
	started  bool
	closed   bool
}

// New constructs (but does not start) a Server. Call Start to bind
// the listener; Shutdown for a graceful close.
func New(cfg Config) (*Server, error) {
	if cfg.GetCertificate == nil {
		return nil, errors.New("imapserver: GetCertificate is required")
	}
	if cfg.Accounts == nil {
		return nil, errors.New("imapserver: Accounts is required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("imapserver: Sessions registry is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	backendOpts := []BackendOption{}
	if cfg.Mailboxes != nil {
		backendOpts = append(backendOpts, WithMailboxes(cfg.Mailboxes))
	}
	if cfg.Proton != nil {
		backendOpts = append(backendOpts, WithProton(cfg.Proton))
	}
	if cfg.Bus != nil {
		backendOpts = append(backendOpts, WithBus(cfg.Bus))
	}
	backend, err := NewBackend(cfg.Accounts, cfg.Sessions, logger, backendOpts...)
	if err != nil {
		return nil, err
	}

	imapSrv := imapserver.New(&imapserver.Options{
		NewSession: backend.NewSession,
		// Caps explicitly contains IMAP4rev1 only. We do NOT advertise
		// STARTTLS (TLSConfig left nil) so the spec's "STARTTLS-from-
		// cleartext is not supported" requirement is structurally
		// enforced. We also do NOT supply IMAP4rev2 because v2 implies
		// MOVE / NAMESPACE / etc. that we have not yet implemented.
		//
		// Governing: SPEC-0003 REQ "TLS Required, IMAPS Only",
		// SPEC-0003 REQ "PLAIN is the only advertised SASL mechanism".
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
		},
		// TLSConfig is nil ON PURPOSE: this disables STARTTLS in the
		// emersion server's CAPABILITY response. The actual TLS
		// handshake happens at the listener layer (tls.Listen below)
		// before the IMAP bytes flow.
		//
		// Governing: SPEC-0003 REQ "TLS Required, IMAPS Only".
		TLSConfig: nil,
		// InsecureAuth = true is a deliberate concession to the
		// capFilter wrapper layer. The emersion library's canAuth()
		// does a hard `_, ok := c.conn.(*tls.Conn)` type assertion
		// (conn.go:418-424). Our capFilterConn wraps each accepted
		// conn so we can strip `IDLE` from the post-auth CAPABILITY
		// response (see capfilter.go), and that wrapping defeats the
		// hard type assertion.
		//
		// Cleartext auth is STILL structurally impossible:
		//   1. The listener is `tls.Listen` (Start() below) — every
		//      accepted conn is a *tls.Conn under our wrapper.
		//   2. `Backend.NewSession` runs `isTLSConn` (backend.go) which
		//      drills through `Unwrap() net.Conn` chains and rejects
		//      any conn that does not eventually resolve to *tls.Conn.
		//   3. We do not advertise STARTTLS (TLSConfig=nil below) so
		//      no client can attempt to upgrade a cleartext socket.
		//
		// Three independent guards remain. Flipping InsecureAuth to
		// true only relaxes the type-assertion-based check that the
		// capFilter wrapper would otherwise defeat outright.
		//
		// Governing: SPEC-0003 REQ "TLS Required, IMAPS Only".
		InsecureAuth: true,
		Logger:       slogAdapter{logger: logger},
	})

	return &Server{
		cfg:      cfg,
		backend:  backend,
		imapSrv:  imapSrv,
		logger:   logger,
		sessions: cfg.Sessions,
	}, nil
}

// Sessions returns the live-session registry. The supervisor /
// admin handler holds a reference and calls
// `Sessions().DropForAccount(id, reason)` on suspension.
func (s *Server) Sessions() *Sessions { return s.sessions }

// Addr returns the resolved listen address (post env-var fallback).
// Useful for logging at startup.
func (s *Server) Addr() string { return s.cfg.resolveAddr() }

// LocalAddr returns the actual bound address once Start has been
// called. Panics if called before Start. Mostly useful for tests
// that bind on :0 and need to know the resolved port.
func (s *Server) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Start binds the TLS listener and serves the IMAP protocol on it.
// The call blocks until Shutdown is invoked or the listener fails;
// callers typically invoke it in a dedicated goroutine.
//
// Returns nil on graceful shutdown, an error otherwise.
func (s *Server) Start() error {
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.cfg.GetCertificate,
		// Advertise IMAP as the ALPN protocol. emersion's client also
		// uses "imap"; mainstream mail clients ignore ALPN over IMAPS
		// so this is harmless additional metadata for any tooling
		// that does inspect it.
		NextProtos: []string{"imap"},
	}
	addr := s.cfg.resolveAddr()
	rawLn, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("imapserver: listen %s: %w", addr, err)
	}
	// Wrap each accepted conn with capFilterConn so Backend.NewSession's
	// isTLSConn drill-through can see through to the underlying *tls.Conn
	// via capFilterConn.Unwrap(). The wrapper no longer strips IDLE from
	// CAPABILITY responses — IDLE is fully implemented since story #20.
	//
	// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
	ln := &capFilterListener{Listener: rawLn}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("imapserver: server is shut down")
	}
	s.listener = ln
	s.started = true
	s.mu.Unlock()

	s.logger.Info("imap server listening",
		slog.String("addr", ln.Addr().String()))

	if err := s.imapSrv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("imapserver: serve: %w", err)
	}
	return nil
}

// Shutdown closes the listener and every active connection. It is
// safe to call before Start (in which case it just marks the server
// closed) and idempotent.
//
// The provided context bounds the wait for active connections to
// drain; this implementation closes connections immediately because
// the underlying emersion Server.Close has no graceful-drain
// semantics. The ctx parameter is retained for API symmetry with the
// HTTP server and for a future per-session graceful-bye pass.
func (s *Server) Shutdown(_ context.Context) error {
	s.mu.Lock()
	closed := s.closed
	s.closed = true
	started := s.started
	s.mu.Unlock()
	if closed || !started {
		return nil
	}
	return s.imapSrv.Close()
}

// slogAdapter bridges emersion/go-imap's `Logger` (a tiny `Printf`
// interface) to slog. Errors land at the `Warn` level — they are
// almost always benign client misbehaviour (truncated commands,
// dropped TLS handshakes) but worth surfacing.
type slogAdapter struct {
	logger *slog.Logger
}

func (a slogAdapter) Printf(format string, args ...interface{}) {
	a.logger.Warn("imap server log", slog.String("msg", fmt.Sprintf(format, args...)))
}
