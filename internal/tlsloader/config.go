package tlsloader

import "crypto/tls"

// hardenedTLS12CipherSuites is the explicit cipher-suite allowlist for the
// TLS 1.2 floor. We pin forward-secret AEAD suites only (ECDHE key exchange
// with AES-GCM or ChaCha20-Poly1305) and deliberately exclude CBC-mode and
// RSA-key-exchange suites. TLS 1.3 cipher suites are NOT configurable in Go
// (crypto/tls always negotiates its fixed TLS 1.3 set) and are always on when
// a client offers TLS 1.3, so this list governs only the TLS 1.2 fallback.
//
// Governing: ADR-0009 (TLS via disk with hot-reload).
var hardenedTLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// Config returns the shared, hardened *tls.Config used by every
// TLS-terminating listener in reduit (HTTPS admin/MCP, IMAPS, SMTPS). It
// centralizes the security posture so the three listeners cannot drift:
//
//   - MinVersion is pinned to TLS 1.2. We keep a TLS 1.2 floor (rather than
//     1.3) deliberately for mail-client interop — older IMAP/SMTP clients
//     still in the wild negotiate 1.2.
//   - CipherSuites is the explicit forward-secret AEAD allowlist above; this
//     only affects the TLS 1.2 fallback (TLS 1.3 suites are fixed in Go).
//     Suite ordering is not configurable: crypto/tls has selected the cipher
//     by its own hardware-aware preference since Go 1.17, ignoring
//     PreferServerCipherSuites, so we do not set that deprecated no-op field.
//   - GetCertificate is the caller's callback — passing the Loader's
//     GetCertificate keeps hot-reload working: new handshakes pick up a
//     rotated cert without rebuilding the config.
//
// nextProtos sets the ALPN protocol list (e.g. []string{"imap"} for IMAPS,
// []string{"smtp"} for SMTPS, or nil for HTTPS where net/http manages ALPN).
//
// Governing: ADR-0009 (TLS via disk with hot-reload).
func Config(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), nextProtos []string) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		CipherSuites:   hardenedTLS12CipherSuites,
		GetCertificate: getCertificate,
		NextProtos:     nextProtos,
	}
}
