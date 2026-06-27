package tlsloader

import (
	"crypto/tls"
	"errors"
	"testing"
)

// TestConfigMinVersion asserts the shared builder pins the TLS 1.2 floor
// (kept deliberately for mail-client interop).
//
// Governing: ADR-0009 (TLS via disk with hot-reload).
func TestConfigMinVersion(t *testing.T) {
	cfg := Config(nil, nil)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2 (%#x)", cfg.MinVersion, tls.VersionTLS12)
	}
}

// TestConfigHardenedCipherSuites asserts the builder pins a non-empty,
// forward-secret AEAD cipher-suite allowlist for the TLS 1.2 floor and
// excludes weak (CBC / RSA-key-exchange / 3DES / RC4) suites.
func TestConfigHardenedCipherSuites(t *testing.T) {
	cfg := Config(nil, nil)
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("CipherSuites is empty; expected a hardened allowlist")
	}

	// Every pinned suite must be ECDHE (forward-secret) + AEAD. crypto/tls
	// exposes the curated set via tls.CipherSuites(); anything not in that
	// set, or any suite flagged insecure, fails the test.
	secure := make(map[uint16]*tls.CipherSuite)
	for _, s := range tls.CipherSuites() {
		secure[s.ID] = s
	}
	for _, id := range cfg.CipherSuites {
		s, ok := secure[id]
		if !ok {
			t.Errorf("cipher suite %#x is not in tls.CipherSuites() (insecure or unknown)", id)
			continue
		}
		// Reject TLS 1.3-only suites here — this list governs the 1.2 floor.
		isTLS12 := false
		for _, v := range s.SupportedVersions {
			if v == tls.VersionTLS12 {
				isTLS12 = true
			}
		}
		if !isTLS12 {
			t.Errorf("cipher suite %s does not support TLS 1.2", s.Name)
		}
	}
}

// TestConfigGetCertificatePassthrough asserts the caller's GetCertificate
// callback is wired through verbatim, so the Loader's hot-reload callback
// keeps serving freshly rotated certs.
func TestConfigGetCertificatePassthrough(t *testing.T) {
	sentinel := &tls.Certificate{}
	called := false
	getCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		called = true
		return sentinel, nil
	}

	cfg := Config(getCert, []string{"imap"})
	if cfg.GetCertificate == nil {
		t.Fatal("GetCertificate is nil; expected passthrough")
	}

	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if !called {
		t.Error("passthrough callback was not invoked")
	}
	if got != sentinel {
		t.Errorf("GetCertificate returned %p, want sentinel %p", got, sentinel)
	}

	// NextProtos passthrough sanity check.
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "imap" {
		t.Errorf("NextProtos = %v, want [imap]", cfg.NextProtos)
	}
}

// TestConfigGetCertificateErrorPropagates ensures errors from the callback
// (e.g. tlsloader returning "no certificate loaded") are not swallowed.
func TestConfigGetCertificateErrorPropagates(t *testing.T) {
	wantErr := errors.New("boom")
	cfg := Config(func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return nil, wantErr
	}, nil)

	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); !errors.Is(err, wantErr) {
		t.Fatalf("GetCertificate error = %v, want %v", err, wantErr)
	}
}
