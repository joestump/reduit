package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsValidate(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	// Defaults are missing OIDC settings — Validate should complain.
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected default config to fail validation (missing OIDC)")
	}
}

func TestValidateMinimalValid(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.OIDC.IssuerURL = "https://idp.example.com"
	cfg.OIDC.ClientID = "reduit"
	cfg.OIDC.RedirectURL = "https://reduit.example.com/auth/callback"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config to validate, got %v", err)
	}
}

func TestValidateRejectsBadLogLevel(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.OIDC.IssuerURL = "https://idp.example.com"
	cfg.OIDC.ClientID = "reduit"
	cfg.OIDC.RedirectURL = "https://reduit.example.com/auth/callback"
	cfg.Logger.Level = "loud"
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for bad log level")
	}
	if !strings.Contains(err.Error(), "logger.level") {
		t.Fatalf("expected error to mention logger.level, got %q", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "reduit.yaml")
	yaml := `server:
  http_addr: ":8443"
oidc:
  issuer_url: https://idp.test
  client_id: my-reduit
  redirect_url: https://reduit.test/auth/callback
logger:
  level: debug
  format: json
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.HTTPAddr != ":8443" {
		t.Errorf("http_addr: got %q", cfg.Server.HTTPAddr)
	}
	if cfg.OIDC.ClientID != "my-reduit" {
		t.Errorf("client_id: got %q", cfg.OIDC.ClientID)
	}
	if cfg.Logger.Level != "debug" || cfg.Logger.Format != "json" {
		t.Errorf("logger: got %+v", cfg.Logger)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected loaded config to validate, got %v", err)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	// Cannot run in parallel because os.Setenv is process-global.
	t.Setenv("REDUIT_OIDC_CLIENT_SECRET", "shhh")
	t.Setenv("REDUIT_LOGGER_LEVEL", "warn")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDC.ClientSecret != "shhh" {
		t.Errorf("client_secret: got %q (env override should have applied)", cfg.OIDC.ClientSecret)
	}
	if cfg.Logger.Level != "warn" {
		t.Errorf("logger.level: got %q", cfg.Logger.Level)
	}
}

func TestLoadFileEnvSecret(t *testing.T) {
	// Cannot run in parallel — exercises process-global env state.
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "oidc_client_secret")
	if err := os.WriteFile(secretPath, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("REDUIT_OIDC_CLIENT_SECRET_FILE", secretPath)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDC.ClientSecret != "file-secret" {
		t.Errorf("client_secret: got %q, want %q (trailing newline must be stripped)",
			cfg.OIDC.ClientSecret, "file-secret")
	}
}

func TestLoadFileEnvOverridesDirectEnv(t *testing.T) {
	// When both the direct env var and the _FILE variant are set, the
	// _FILE variant wins. File-based delivery is the more deliberate
	// path and should take precedence (see ADR-0006/0017 in the
	// stumpcloud Ansible role).
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("REDUIT_OIDC_CLIENT_SECRET", "from-direct-env")
	t.Setenv("REDUIT_OIDC_CLIENT_SECRET_FILE", secretPath)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDC.ClientSecret != "from-file" {
		t.Errorf("client_secret: got %q, want %q (_FILE should win)",
			cfg.OIDC.ClientSecret, "from-file")
	}
}

func TestLoadFileEnvMissingFile(t *testing.T) {
	// A _FILE pointer to a missing file is a hard error. Silently
	// falling back to empty would mask a deployment misconfiguration.
	t.Setenv("REDUIT_OIDC_CLIENT_SECRET_FILE", "/nonexistent/path/to/secret")

	_, err := Load("")
	if err == nil {
		t.Fatalf("expected Load to fail when _FILE points at a missing file")
	}
	if !strings.Contains(err.Error(), "REDUIT_OIDC_CLIENT_SECRET_FILE") {
		t.Errorf("expected error to mention the offending env var name, got %q", err)
	}
}

func TestLoadFileEnvDirectStillWorks(t *testing.T) {
	// With no _FILE variant set, the direct env var is honored as
	// before — adding _FILE support must not break the existing path.
	t.Setenv("REDUIT_OIDC_CLIENT_SECRET", "direct-only")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDC.ClientSecret != "direct-only" {
		t.Errorf("client_secret: got %q, want %q", cfg.OIDC.ClientSecret, "direct-only")
	}
}

func TestLoadFileEnvEmptyValueIsNoop(t *testing.T) {
	// An empty _FILE value should be treated as unset, not as an
	// attempt to read the file at "". This lets operators clear the
	// variable defensively (e.g. in compose `_FILE: ""`).
	t.Setenv("REDUIT_OIDC_CLIENT_SECRET_FILE", "")
	t.Setenv("REDUIT_OIDC_CLIENT_SECRET", "fallback")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDC.ClientSecret != "fallback" {
		t.Errorf("client_secret: got %q, want %q", cfg.OIDC.ClientSecret, "fallback")
	}
}

func TestLoadFileEnvTrimsTrailingWhitespaceOnly(t *testing.T) {
	// Trailing whitespace (the newline Docker secrets append, plus
	// stray CR/space/tab) is trimmed. Leading whitespace is preserved
	// — secrets are opaque blobs and a leading space could be
	// significant.
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte(" not-trimmed-leading \r\n\t"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("REDUIT_OIDC_CLIENT_SECRET_FILE", secretPath)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDC.ClientSecret != " not-trimmed-leading" {
		t.Errorf("client_secret: got %q (trailing-only trim expected)", cfg.OIDC.ClientSecret)
	}
}

func TestLoadFileEnvEmptyFileIsHardError(t *testing.T) {
	// A zero-byte or whitespace-only secret file is rejected at startup.
	// Otherwise the trim would yield "" and the service would silently
	// boot with an empty secret -- e.g. OIDC.ClientSecret="" degrades
	// to public-client mode without warning.
	cases := map[string]string{
		"zero-byte":             "",
		"newline-only":          "\n",
		"whitespace-with-crlfs": " \t\r\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			secretPath := filepath.Join(dir, "secret")
			if err := os.WriteFile(secretPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("REDUIT_OIDC_CLIENT_SECRET_FILE", secretPath)

			_, err := Load("")
			if err == nil {
				t.Fatalf("expected Load to reject empty-after-trim secret file")
			}
			if !strings.Contains(err.Error(), "empty after trim") {
				t.Errorf("expected error to mention 'empty after trim', got %q", err)
			}
		})
	}
}

func TestValidateTLSDisabledAcceptsHTTPOnly(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.TLS.Disabled = true
	cfg.TLS.CertPath = ""
	cfg.TLS.KeyPath = ""
	cfg.Server.IMAPAddr = ""
	cfg.Server.SMTPAddr = ""
	cfg.OIDC.IssuerURL = "https://idp.example.com"
	cfg.OIDC.ClientID = "reduit"
	cfg.OIDC.RedirectURL = "https://reduit.example.com/auth/callback"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tls.disabled HTTP-only config should validate, got %v", err)
	}
}

func TestValidateTLSDisabledRejectsMailListeners(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.TLS.Disabled = true
	cfg.TLS.CertPath = ""
	cfg.TLS.KeyPath = ""
	cfg.OIDC.IssuerURL = "https://idp.example.com"
	cfg.OIDC.ClientID = "reduit"
	cfg.OIDC.RedirectURL = "https://reduit.example.com/auth/callback"
	// Defaults() leaves IMAPAddr=":993" and SMTPAddr=":465" set, so the
	// disabled-TLS check should reject the combination.
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected tls.disabled+mail-listeners to fail validation")
	}
	if !strings.Contains(err.Error(), "tls.disabled") {
		t.Fatalf("expected error to mention tls.disabled, got %q", err)
	}
}

func TestResolveConfigPathPrecedence(t *testing.T) {
	t.Parallel()
	if got := ResolveConfigPath("/explicit/flag.yaml"); got != "/explicit/flag.yaml" {
		t.Errorf("flag override: got %q", got)
	}
}

func TestParseDuration(t *testing.T) {
	t.Parallel()

	const fallback = 0 // unused for non-empty inputs; empty input returns it

	type tc struct {
		input     string
		wantErr   bool
		wantValue time.Duration
	}

	cases := []tc{
		// Day-suffix expansion: "30d" must become 720h, not 30720h.
		{input: "30d", wantErr: false, wantValue: 30 * 24 * time.Hour},
		// Single-day expansion.
		{input: "1d", wantErr: false, wantValue: 24 * time.Hour},
		// Native Go duration bypasses expansion entirely.
		{input: "720h", wantErr: false, wantValue: 720 * time.Hour},
		// Ordinary short duration.
		{input: "1h", wantErr: false, wantValue: time.Hour},
		// Empty string returns the fallback (no error).
		{input: "", wantErr: false, wantValue: fallback},
		// Invalid duration string must error.
		{input: "abc", wantErr: true},
		// "0d" expands to "0h" which is not positive — must error.
		{input: "0d", wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseDuration(c.input, fallback)
			if c.wantErr {
				if err == nil {
					t.Errorf("ParseDuration(%q): expected error, got %v", c.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q): unexpected error: %v", c.input, err)
			}
			if got != c.wantValue {
				t.Errorf("ParseDuration(%q): got %v, want %v", c.input, got, c.wantValue)
			}
		})
	}
}
