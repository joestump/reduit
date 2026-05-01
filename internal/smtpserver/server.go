// Server wires the emersion/go-smtp Server with Reduit's Backend and
// a TLS-only listener using the hot-reloading cert loader. The
// listener is the public entrypoint; lifecycle is Start / Shutdown
// in the same shape the v0.1 HTTP and IMAPS servers use.
//
// Governing: ADR-0007 (emersion go-smtp), ADR-0009 (TLS via disk
// loader with hot reload), SPEC-0004.

package smtpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	smtp "github.com/emersion/go-smtp"
)

// DefaultSMTPSAddress is the listen address used when neither
// configuration nor the REDUIT_SMTPS_ADDR env var is set.
//
// Governing: SPEC-0004 REQ "TLS Required, SMTPS Only" — port 465 is
// the IANA-assigned SMTPS port; we bind it by default.
const DefaultSMTPSAddress = ":465"

// Environment variable overrides. An operator can set these without
// editing the config file.
const (
	EnvSMTPSAddr        = "REDUIT_SMTPS_ADDR"
	EnvMaxRecipients    = "REDUIT_SMTP_MAX_RECIPIENTS"
	EnvMaxMessageBytes  = "REDUIT_SMTP_MAX_MESSAGE_BYTES"
	EnvSubmitTimeout    = "REDUIT_SMTP_SUBMIT_TIMEOUT"
	EnvServerDomainName = "REDUIT_SMTP_DOMAIN"
)

// Default limits per SPEC-0004 REQ "Recipient and Message Size Limits".
const (
	DefaultMaxRecipients   = 100
	DefaultMaxMessageBytes = 25 * 1024 * 1024 // 25 MiB
	DefaultSubmitTimeout   = 60 * time.Second
)

// Config bundles the construction-time knobs for Server. All fields
// other than the empty-string / zero defaults are required; defaults
// fall back to env vars then the package-level constants.
type Config struct {
	// Addr is the TCP address to bind. Empty means "use the env var
	// REDUIT_SMTPS_ADDR if set, otherwise DefaultSMTPSAddress".
	Addr string

	// Domain is advertised in the EHLO greeting line. Empty means
	// "use REDUIT_SMTP_DOMAIN if set, otherwise the local hostname".
	Domain string

	// MaxRecipients caps the number of RCPT TO recipients per
	// transaction. Zero means "use the env var override or
	// DefaultMaxRecipients".
	MaxRecipients int

	// MaxMessageBytes caps the DATA payload size. Zero means "use the
	// env var override or DefaultMaxMessageBytes". Enforced DURING
	// streaming via the upstream library's dataReader so a large
	// attempt fails fast.
	MaxMessageBytes int64

	// SubmitTimeout is the per-DATA timeout. Wired into the upstream
	// library's WriteTimeout to bound a slow client. Outbox-side
	// submission timeouts land in #22.
	SubmitTimeout time.Duration

	// GetCertificate is the tls.Config callback that hands out the
	// active certificate. In production this is loader.GetCertificate
	// from internal/tlsloader; tests may pass a static callback.
	//
	// Governing: ADR-0009 — wiring `GetCertificate` lets the cert
	// rotate without restarting the SMTP server.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// Accounts is the slice of account.Service the SMTP backend
	// needs (alias lookup + password verify).
	Accounts AccountLookup

	// Sessions is the live-session registry. Suspension code paths
	// hold a reference and call DropForAccount when an account
	// transitions to Suspended or SoftDeleted.
	Sessions *Sessions

	// Logger is the slog.Logger used for connection-level events.
	// nil falls back to slog.Default().
	Logger *slog.Logger
}

// resolveAddr returns the bind address with env-var fallback.
func (c Config) resolveAddr() string {
	if c.Addr != "" {
		return c.Addr
	}
	if env := os.Getenv(EnvSMTPSAddr); env != "" {
		return env
	}
	return DefaultSMTPSAddress
}

func (c Config) resolveDomain() string {
	if c.Domain != "" {
		return c.Domain
	}
	if env := os.Getenv(EnvServerDomainName); env != "" {
		return env
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "reduit"
}

func (c Config) resolveMaxRecipients() int {
	if c.MaxRecipients > 0 {
		return c.MaxRecipients
	}
	if env := os.Getenv(EnvMaxRecipients); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			return n
		}
	}
	return DefaultMaxRecipients
}

func (c Config) resolveMaxMessageBytes() int64 {
	if c.MaxMessageBytes > 0 {
		return c.MaxMessageBytes
	}
	if env := os.Getenv(EnvMaxMessageBytes); env != "" {
		if n, err := strconv.ParseInt(env, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return DefaultMaxMessageBytes
}

func (c Config) resolveSubmitTimeout() time.Duration {
	if c.SubmitTimeout > 0 {
		return c.SubmitTimeout
	}
	if env := os.Getenv(EnvSubmitTimeout); env != "" {
		if d, err := time.ParseDuration(env); err == nil && d > 0 {
			return d
		}
	}
	return DefaultSubmitTimeout
}

// Server is the SMTPS listener. The zero value is not usable;
// construct via New.
type Server struct {
	cfg      Config
	backend  *Backend
	smtpSrv  *smtp.Server
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
		return nil, errors.New("smtpserver: GetCertificate is required")
	}
	if cfg.Accounts == nil {
		return nil, errors.New("smtpserver: Accounts is required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("smtpserver: Sessions registry is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	backend, err := NewBackend(cfg.Accounts, cfg.Sessions, logger)
	if err != nil {
		return nil, err
	}

	smtpSrv := smtp.NewServer(backend)
	smtpSrv.Domain = cfg.resolveDomain()
	smtpSrv.MaxRecipients = cfg.resolveMaxRecipients()
	smtpSrv.MaxMessageBytes = cfg.resolveMaxMessageBytes()
	// ReadTimeout / WriteTimeout bound a slow client. Submit timeout
	// applies per-DATA write; the value is generous so legitimate
	// large attachments can flow.
	smtpSrv.WriteTimeout = cfg.resolveSubmitTimeout()
	smtpSrv.ReadTimeout = cfg.resolveSubmitTimeout()
	// AllowInsecureAuth = false ON PURPOSE: the upstream library's
	// `authAllowed()` check refuses AUTH on non-TLS connections when
	// this flag is unset. Combined with the tls.Listen wrapper below
	// AND the *tls.Conn assertion in NewSession, this is a third
	// independent guard against cleartext auth.
	//
	// Governing: SPEC-0004 REQ "TLS Required, SMTPS Only".
	smtpSrv.AllowInsecureAuth = false
	// TLSConfig is left nil so the upstream library does NOT advertise
	// STARTTLS in EHLO. The TLS handshake happens at the listener
	// layer (tls.Listen below) before any SMTP bytes flow.
	//
	// Governing: SPEC-0004 REQ "TLS Required, SMTPS Only".
	smtpSrv.TLSConfig = nil
	smtpSrv.ErrorLog = slogAdapter{logger: logger}

	return &Server{
		cfg:      cfg,
		backend:  backend,
		smtpSrv:  smtpSrv,
		logger:   logger,
		sessions: cfg.Sessions,
	}, nil
}

// Sessions returns the live-session registry. The supervisor / admin
// handler holds a reference and calls
// `Sessions().DropForAccount(id, reason)` on suspension.
func (s *Server) Sessions() *Sessions { return s.sessions }

// Addr returns the resolved listen address (post env-var fallback).
func (s *Server) Addr() string { return s.cfg.resolveAddr() }

// LocalAddr returns the actual bound address once Start has been
// called. Returns nil if called before Start. Mostly useful for tests
// that bind on :0 and need to know the resolved port.
func (s *Server) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Start binds the TLS listener and serves SMTP on it. The call blocks
// until Shutdown is invoked or the listener fails; callers typically
// invoke it in a dedicated goroutine.
//
// Returns nil on graceful shutdown, an error otherwise.
func (s *Server) Start() error {
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.cfg.GetCertificate,
		// ALPN tag for SMTPS. Mainstream clients ignore ALPN over 465
		// so this is harmless additional metadata for any tooling that
		// does inspect it.
		NextProtos: []string{"smtp"},
	}
	addr := s.cfg.resolveAddr()
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtpserver: listen %s: %w", addr, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("smtpserver: server is shut down")
	}
	s.listener = ln
	s.started = true
	s.mu.Unlock()

	s.logger.Info("smtp server listening",
		slog.String("addr", ln.Addr().String()))

	if err := s.smtpSrv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("smtpserver: serve: %w", err)
	}
	return nil
}

// Shutdown closes the listener and every active connection. Safe to
// call before Start (in which case it just marks the server closed)
// and idempotent.
//
// The provided context bounds the wait for active connections to
// drain — the upstream emersion server's Shutdown blocks until every
// open connection finishes its current command.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	closed := s.closed
	s.closed = true
	started := s.started
	s.mu.Unlock()
	if closed || !started {
		return nil
	}
	return s.smtpSrv.Shutdown(ctx)
}

// slogAdapter bridges emersion/go-smtp's `Logger` (a tiny `Printf` /
// `Println` interface) to slog. Errors land at the `Warn` level —
// they are almost always benign client misbehaviour (truncated
// commands, dropped TLS handshakes) but worth surfacing.
type slogAdapter struct {
	logger *slog.Logger
}

func (a slogAdapter) Printf(format string, args ...interface{}) {
	a.logger.Warn("smtp server log", slog.String("msg", fmt.Sprintf(format, args...)))
}

func (a slogAdapter) Println(args ...interface{}) {
	a.logger.Warn("smtp server log", slog.String("msg", fmt.Sprintln(args...)))
}
