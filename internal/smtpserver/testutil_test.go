// Test helpers shared across smtpserver tests. Construct a Server
// bound to 127.0.0.1:0 with a self-signed cert so tests can speak
// real TLS without requiring on-disk PKI material. Mirrors
// internal/imapserver/testutil_test.go.

package smtpserver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/joestump/reduit/internal/account"
)

// stubAccounts is the in-memory AccountLookup we wire into the
// Backend so tests don't need a real SQLite.
type stubAccounts struct {
	mu      sync.Mutex
	byAlias map[string]string // normalised alias -> account id
	byID    map[string]*stubAccount
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
		s.byAlias[strings.ToLower(strings.TrimSpace(alias))] = id
	}
}

func (s *stubAccounts) GetByPrimaryAlias(_ context.Context, alias string) (*account.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byAlias[strings.ToLower(strings.TrimSpace(alias))]
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

// bcryptStubAccounts mirrors stubAccounts but stores bcrypt hashes
// (cost 12) so VerifyIMAPPassword has the same wall-clock cost as
// production. Used by the timing-side-channel test.
type bcryptStubAccounts struct {
	mu      sync.Mutex
	byAlias map[string]string
	byID    map[string]*bcryptStubAccount
}

type bcryptStubAccount struct {
	ID    string
	Alias string
	Hash  []byte
	State account.State
}

func newBcryptStubAccounts() *bcryptStubAccounts {
	return &bcryptStubAccounts{
		byAlias: make(map[string]string),
		byID:    make(map[string]*bcryptStubAccount),
	}
}

func (s *bcryptStubAccounts) addAccount(t *testing.T, id, alias, password string, state account.State) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		t.Fatalf("bcrypt generate: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &bcryptStubAccount{ID: id, Alias: alias, Hash: hash, State: state}
	s.byID[id] = a
	if alias != "" {
		s.byAlias[strings.ToLower(strings.TrimSpace(alias))] = id
	}
}

func (s *bcryptStubAccounts) GetByPrimaryAlias(_ context.Context, alias string) (*account.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byAlias[strings.ToLower(strings.TrimSpace(alias))]
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

func (s *bcryptStubAccounts) VerifyIMAPPassword(_ context.Context, accountID string, candidate []byte) error {
	s.mu.Lock()
	a, ok := s.byID[accountID]
	s.mu.Unlock()
	if !ok {
		return account.ErrAccountNotFound
	}
	if err := bcrypt.CompareHashAndPassword(a.Hash, candidate); err != nil {
		return err
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

// testServer is a started Server plus a function to address it.
type testServer struct {
	server *Server
	addr   string
}

func (s *testServer) disableRateLimit() {
	s.server.backend.disableRateLimitForTest()
}

// startTestServer constructs a Backend wired to the supplied stub,
// binds the listener on 127.0.0.1:0, and returns once the server is
// accepting connections.
func startTestServer(t *testing.T, accounts AccountLookup, sessions *Sessions, opts ...func(*Config)) *testServer {
	t.Helper()
	cert := generateTestCert(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := Config{
		Addr:     "127.0.0.1:0",
		Domain:   "reduit-test",
		Accounts: accounts,
		Sessions: sessions,
		Logger:   logger,
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("smtpserver.New: %v", err)
	}
	doneCh := make(chan error, 1)
	go func() { doneCh <- srv.Start() }()

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
// InsecureSkipVerify; tests speak the SMTP wire protocol directly
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
	// Generous deadline because every auth-failure path now burns one
	// real bcrypt comparison (~250ms at cost 12) for uniform-time auth.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	return conn
}

// readSMTPLine reads one CRLF-terminated line from r. SMTP responses
// may be multi-line (continuations begin with `<code>-` instead of
// `<code> `); the caller is responsible for looping.
func readSMTPLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// readSMTPResponse reads a complete SMTP response (one or more lines
// of the same status code, terminated by the `<code> ` continuation
// marker on the last line). Returns the slice of raw lines including
// the final line.
func readSMTPResponse(t *testing.T, r *bufio.Reader) []string {
	t.Helper()
	var lines []string
	for {
		line := readSMTPLine(t, r)
		lines = append(lines, line)
		if len(line) >= 4 && line[3] == ' ' {
			return lines
		}
		if len(line) < 4 {
			t.Fatalf("malformed SMTP response line: %q", line)
		}
	}
}

// writeSMTPCmd sends a CRLF-terminated SMTP command.
func writeSMTPCmd(t *testing.T, w io.Writer, cmd string) {
	t.Helper()
	if _, err := fmt.Fprintf(w, "%s\r\n", cmd); err != nil {
		t.Fatalf("write %q: %v", cmd, err)
	}
}

// saslPlainInitialResponse builds the canonical
// "\x00<authzid omitted>\x00<authcid>\x00<password>" PLAIN payload.
func saslPlainInitialResponse(username, password string) string {
	var b []byte
	b = append(b, 0x00)
	b = append(b, username...)
	b = append(b, 0x00)
	b = append(b, password...)
	return base64.StdEncoding.EncodeToString(b)
}

// ehlo runs the SMTP greeting + EHLO exchange and returns the EHLO
// response lines. Uses the test fixture's local ESMTP domain in the
// HELO arg.
func ehlo(t *testing.T, conn *tls.Conn, r *bufio.Reader) []string {
	t.Helper()
	// Drain greeting (single 220 line in the upstream library).
	greet := readSMTPLine(t, r)
	if !strings.HasPrefix(greet, "220 ") {
		t.Fatalf("expected `220 ...` greeting, got %q", greet)
	}
	writeSMTPCmd(t, conn, "EHLO test.local")
	return readSMTPResponse(t, r)
}

// authPlain runs EHLO + AUTH PLAIN and returns the final AUTH
// response line. Tests assert on the line.
func authPlain(t *testing.T, addr, username, password string) string {
	t.Helper()
	conn := dialTLSClient(t, addr)
	r := bufio.NewReader(conn)
	_ = ehlo(t, conn, r)
	writeSMTPCmd(t, conn, "AUTH PLAIN "+saslPlainInitialResponse(username, password))
	return readSMTPLine(t, r)
}

// authMech runs EHLO + AUTH <mech> with no SASL payload. Used by the
// timing test to confirm a non-PLAIN mechanism rejection burns the
// same bcrypt cost as a wrong-password attempt.
func authMech(t *testing.T, addr, mech string) string {
	t.Helper()
	conn := dialTLSClient(t, addr)
	r := bufio.NewReader(conn)
	_ = ehlo(t, conn, r)
	writeSMTPCmd(t, conn, "AUTH "+mech)
	return readSMTPLine(t, r)
}

// loginPlain runs EHLO + AUTH PLAIN, asserts success, and returns
// the open conn + reader so the caller can drive further commands.
func loginPlain(t *testing.T, addr, username, password string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn := dialTLSClient(t, addr)
	r := bufio.NewReader(conn)
	_ = ehlo(t, conn, r)
	writeSMTPCmd(t, conn, "AUTH PLAIN "+saslPlainInitialResponse(username, password))
	resp := readSMTPLine(t, r)
	if !strings.HasPrefix(resp, "235 ") {
		t.Fatalf("loginPlain: expected 235, got %q", resp)
	}
	// Disable the deadline so the caller can wait an arbitrary time
	// for an asynchronous 421.
	_ = conn.SetDeadline(time.Time{})
	return conn, r
}
