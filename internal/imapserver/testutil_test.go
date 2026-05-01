// Test helpers shared across imapserver tests. Construct a Server
// bound to 127.0.0.1:0 with a self-signed cert so tests can speak
// real TLS without requiring on-disk PKI material.

package imapserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
)

// stubAccounts is the in-memory AccountLookup we wire into the
// Backend so tests don't need a real SQLite. Each call to
// addAccount registers an alias→(id, password, state) row.
type stubAccounts struct {
	mu         sync.Mutex
	byAlias    map[string]string // normalised alias -> account id
	byID       map[string]*stubAccount
	verifyHook func() // optional; used by tests that want to inject latency
}

type stubAccount struct {
	ID       string
	Alias    string
	Password string
	State    account.State
}

func newStubAccounts() *stubAccounts {
	return &stubAccounts{
		byAlias: make(map[string]string),
		byID:    make(map[string]*stubAccount),
	}
}

func (s *stubAccounts) addAccount(id, alias, password string, state account.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &stubAccount{ID: id, Alias: alias, Password: password, State: state}
	s.byID[id] = a
	if alias != "" {
		s.byAlias[alias] = id
	}
}

func (s *stubAccounts) GetByPrimaryAlias(_ context.Context, alias string) (*account.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byAlias[alias]
	if !ok {
		return nil, account.ErrAccountNotFound
	}
	a := s.byID[id]
	return &account.Account{
		ID:           a.ID,
		PrimaryAlias: a.Alias,
		State:        a.State,
	}, nil
}

func (s *stubAccounts) VerifyIMAPPassword(_ context.Context, accountID string, candidate []byte) error {
	if s.verifyHook != nil {
		s.verifyHook()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.byID[accountID]
	if !ok {
		return account.ErrAccountNotFound
	}
	if string(candidate) != a.Password {
		return errors.New("stubAccounts: password mismatch")
	}
	return nil
}

// generateTestCert mints a fresh self-signed P-256 cert valid for
// 127.0.0.1 / localhost. Cheap enough to call per-test.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "reduit-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        nil,
	}
}

// testServer is a started Server plus a function to address it. The
// returned cleanup shuts the server down with a 1s grace.
type testServer struct {
	server *Server
	addr   string
}

// startTestServer constructs a Backend wired to the supplied stub,
// binds the listener on 127.0.0.1:0, and returns once the server is
// accepting connections. The returned cleanup is registered with
// t.Cleanup so the caller does not need to remember to close.
func startTestServer(t *testing.T, accounts AccountLookup, sessions *Sessions) *testServer {
	t.Helper()
	cert := generateTestCert(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv, err := New(Config{
		Addr:     "127.0.0.1:0",
		Accounts: accounts,
		Sessions: sessions,
		Logger:   logger,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	})
	if err != nil {
		t.Fatalf("imapserver.New: %v", err)
	}
	doneCh := make(chan error, 1)
	go func() { doneCh <- srv.Start() }()

	// Wait briefly for the listener to bind. We poll LocalAddr instead
	// of sleeping a fixed duration so slow CI runners don't flake.
	deadline := time.Now().Add(2 * time.Second)
	for srv.LocalAddr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("server did not bind within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		select {
		case <-doneCh:
		case <-time.After(2 * time.Second):
			t.Errorf("server.Start did not return within 2s of Shutdown")
		}
	})
	return &testServer{server: srv, addr: srv.LocalAddr().String()}
}

// dialTLSClient opens a TLS connection to the test server with
// InsecureSkipVerify; tests speak the IMAP wire protocol directly
// against this conn so they can assert on raw bytes.
func dialTLSClient(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}
