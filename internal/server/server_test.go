// Server lifecycle tests for the New / Start / Shutdown trio. The
// route + middleware coverage lives in auth_handlers_test.go and
// the per-feature handler tests; this file exercises the listener
// branch added in PR #84 (HTTP mode for reverse-proxy fronting).

package server_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/server"
)

// TestServer_StartPlaintextWhenNoCertificate asserts that the
// tls.disabled deploy path actually wires up to a plain-HTTP listener.
// We bind to :0, hit /healthz over plain HTTP, and assert a 200.
//
// Governing: PR #84 -- ADR-0011 (HTTP mode for reverse-proxy
// fronting). Without this test the only signal that the new branch
// works is integration-time; this catches regressions where a future
// refactor reintroduces an unconditional ListenAndServeTLS.
func TestServer_StartPlaintextWhenNoCertificate(t *testing.T) {
	t.Parallel()

	// Pick a free port by binding to :0, capturing the addr, and
	// closing -- New + Start will rebind. Small race window but fine
	// for a parallel test suite where each case grabs its own port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := server.New(addr, server.Deps{
		// GetCertificate intentionally nil -- production wire from
		// cli/serve.go does this when cfg.TLS.Disabled is true.
		GetCertificate: nil,
		Version:        "test-plaintext",
	})

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Wait for the listener to come up. ListenAndServe binds before
	// returning so a brief poll is enough.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	c := &http.Client{Timeout: 1 * time.Second}
	for time.Now().Before(deadline) {
		resp, err = c.Get("http://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("empty body")
	}

	// HTTPS should fail -- this confirms the listener is genuinely
	// plain-HTTP and not opportunistically accepting TLS handshakes.
	tlsClient := &http.Client{
		Timeout: 500 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	if _, err := tlsClient.Get("https://" + addr + "/healthz"); err == nil {
		t.Error("https GET succeeded against a plaintext listener; the branch did not actually disable TLS")
	}
}
