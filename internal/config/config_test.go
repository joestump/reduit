package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
