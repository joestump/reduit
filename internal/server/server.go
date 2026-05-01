// Package server hosts Reduit's HTTPS control-plane server. v0.1
// scope is intentionally minimal: /healthz, /readyz, and a
// metrics-listener stub. OIDC, admin UI routes, MCP, and SSE come in
// later milestones.
//
// Governing: SPEC-0005 REQ "Authentication Gating" (allowlist of
// unauthenticated routes — /healthz, /readyz, /metrics).
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/joestump/reduit/internal/store"
)

// Deps are the dependencies a Server needs to start. Wired by
// internal/cli/serve at startup.
type Deps struct {
	Store          *store.Store
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Logger         *slog.Logger
	Version        string // for /healthz response body
}

// Server holds an http.Server pre-configured with TLS and the
// allowlist routes from SPEC-0005.
type Server struct {
	addr    string
	srv     *http.Server
	deps    Deps
	stopped chan struct{}
}

// New constructs a *Server bound to addr. Routes are mounted via the
// returned Server's mux. TLS is wired through deps.GetCertificate.
func New(addr string, deps Deps) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	mux := http.NewServeMux()
	s := &Server{
		addr:    addr,
		deps:    deps,
		stopped: make(chan struct{}),
	}
	s.routes(mux)

	tlsCfg := &tls.Config{
		GetCertificate: deps.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(deps.Logger.Handler(), slog.LevelError),
	}
	return s
}

// Start begins serving. It returns when the listener exits (typically
// after Shutdown). Start blocks; run it from a dedicated goroutine.
func (s *Server) Start() error {
	defer close(s.stopped)
	s.deps.Logger.Info("http server starting",
		slog.String("addr", s.addr))
	err := s.srv.ListenAndServeTLS("", "") // certs come from GetCertificate
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("server: ListenAndServeTLS: %w", err)
}

// Shutdown asks the underlying http.Server to gracefully stop. It
// returns once shutdown completes or ctx fires.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// Stopped returns a channel closed when Start has returned.
func (s *Server) Stopped() <-chan struct{} { return s.stopped }

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
}

// handleHealthz returns 200 OK if the process is up. It does not
// touch the database — that's /readyz.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "ok %s\n", s.deps.Version)
}

// handleReadyz pings the database. Returns 503 if the DB is
// unreachable so a load balancer can stop sending traffic.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.deps.Store == nil {
		http.Error(w, "no store", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.deps.Store.DB.PingContext(ctx); err != nil {
		http.Error(w, "store unreachable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, _ = fmt.Fprintln(w, "ready")
}
