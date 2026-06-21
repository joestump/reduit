// Package config holds Reduit's runtime configuration.
//
// Configuration is loaded from a YAML file (path resolved by precedence:
// --config flag, REDUIT_CONFIG env, /etc/reduit/reduit.yaml,
// ./reduit.yaml) with environment-variable overrides via the REDUIT_
// prefix and underscore-to-dot mapping (REDUIT_OIDC_CLIENT_SECRET ->
// oidc.client_secret).
//
// Governing: SPEC-0001 REQ "Account Identity" (config carries OIDC
// admin allowlist), ADR-0006 (sqlite path), ADR-0009 (TLS paths).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is the top-level runtime configuration.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	TLS       TLSConfig       `mapstructure:"tls"`
	MasterKey MasterKeyConfig `mapstructure:"master_key"`
	Store     StoreConfig     `mapstructure:"store"`
	OIDC      OIDCConfig      `mapstructure:"oidc"`
	Logger    LoggerConfig    `mapstructure:"logger"`
}

// ServerConfig groups the network listener addresses.
type ServerConfig struct {
	// HTTPAddr is the admin / MCP / OIDC HTTPS listener (e.g. ":443").
	HTTPAddr string `mapstructure:"http_addr"`
	// IMAPAddr is the IMAPS listener (e.g. ":993").
	IMAPAddr string `mapstructure:"imap_addr"`
	// SMTPAddr is the SMTPS submission listener (e.g. ":465").
	SMTPAddr string `mapstructure:"smtp_addr"`
	// MetricsAddr is the Prometheus metrics listener, intended for an
	// internal-only interface (e.g. "127.0.0.1:9090"). Empty disables.
	MetricsAddr string `mapstructure:"metrics_addr"`
	// TrustedProxies lists the reverse-proxy addresses (bare IPs or CIDR
	// ranges, e.g. "10.0.0.0/8") whose X-Forwarded-For / X-Real-IP
	// headers the admin listener trusts when deriving the real client
	// IP for audit logging. Reduit typically runs behind a TLS-
	// terminating proxy (tls.disabled = true) per ADR-0011, so without
	// this the audit log records the proxy's address. Empty (the
	// default) trusts no proxy and logs the immediate peer -- the safe
	// default for a directly-exposed listener.
	//
	// Governing: ADR-0011 (reverse-proxy fronting), ADR-0009.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

// TLSConfig holds the cert + key file paths read by the hot-reloading
// loader (per ADR-0009).
type TLSConfig struct {
	CertPath string `mapstructure:"cert_path"`
	KeyPath  string `mapstructure:"key_path"`
	// Disabled, when true, makes the HTTP admin/MCP listener serve
	// plaintext instead of HTTPS. Use only when reduit sits behind a
	// TLS-terminating reverse proxy (Caddy / Traefik / nginx) on the
	// same host or trusted network -- the listener still expects
	// browser sessions and OIDC redirects, so the upstream MUST be
	// served over TLS to the public.
	//
	// IMAPS and SMTPS cannot be reverse-proxied (they're TCP, not
	// HTTP), so the mail listeners still require real certs. Setting
	// Disabled while imap_addr or smtp_addr is non-empty is a
	// configuration error caught at Validate() time.
	Disabled bool `mapstructure:"disabled"`
}

// MasterKeyConfig holds the path to the service master key file.
type MasterKeyConfig struct {
	Path string `mapstructure:"path"`
}

// StoreConfig holds SQLite database options.
type StoreConfig struct {
	// Path to the sqlite database file.
	Path string `mapstructure:"path"`
	// MigrationsDir overrides the embedded migrations source. Empty =
	// use the binary's embedded migrations.
	MigrationsDir string `mapstructure:"migrations_dir"`
	// RetentionPeriod is the minimum age past which soft-deleted accounts
	// are hard-deleted by the retention sweep job. Accepts Go duration
	// strings (e.g. "720h", "30d" after suffix expansion). Empty = 720h
	// (30 days).
	//
	// Governing: SPEC-0001 REQ "Account Hard Delete After Retention".
	RetentionPeriod string `mapstructure:"retention_period"`
	// SweepInterval controls how often the retention sweep job runs.
	// Accepts Go duration strings. Empty = 1h.
	//
	// Governing: SPEC-0001 REQ "Account Hard Delete After Retention".
	SweepInterval string `mapstructure:"sweep_interval"`
}

// OIDCConfig configures the OIDC Relying Party.
type OIDCConfig struct {
	IssuerURL     string   `mapstructure:"issuer_url"`
	ClientID      string   `mapstructure:"client_id"`
	ClientSecret  string   `mapstructure:"client_secret"`
	RedirectURL   string   `mapstructure:"redirect_url"`
	Scopes        []string `mapstructure:"scopes"`
	AdminSubjects []string `mapstructure:"admin_subjects"`
	AutoCreate    bool     `mapstructure:"auto_create"`
}

// LoggerConfig configures the structured logger.
type LoggerConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `mapstructure:"level"`
	// Format is "text" (human-readable) or "json".
	Format string `mapstructure:"format"`
}

// Defaults returns a Config populated with sensible defaults. Callers
// typically Defaults() then layer YAML + env on top via Load.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			HTTPAddr:    ":443",
			IMAPAddr:    ":993",
			SMTPAddr:    ":465",
			MetricsAddr: "",
		},
		TLS: TLSConfig{
			CertPath: "/etc/reduit/tls/fullchain.pem",
			KeyPath:  "/etc/reduit/tls/privkey.pem",
		},
		MasterKey: MasterKeyConfig{
			Path: "/var/lib/reduit/master.key",
		},
		Store: StoreConfig{
			Path:            "/var/lib/reduit/reduit.db",
			RetentionPeriod: "720h",
			SweepInterval:   "1h",
		},
		OIDC: OIDCConfig{
			Scopes:     []string{"openid", "profile", "email"},
			AutoCreate: true,
		},
		Logger: LoggerConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// Validate returns an error describing every problem with the
// configuration, joined with errors.Join. A nil return means the
// configuration is usable.
func (c Config) Validate() error {
	var errs []error

	if c.Server.HTTPAddr == "" && c.Server.IMAPAddr == "" && c.Server.SMTPAddr == "" {
		errs = append(errs, errors.New("server: at least one of http_addr / imap_addr / smtp_addr must be set"))
	}
	// TLS is required for any listener that handles mail (IMAPS,
	// SMTPS) -- those are TCP and cannot be reverse-proxied. The HTTP
	// admin listener can opt out via tls.disabled when reduit sits
	// behind a TLS-terminating proxy.
	if c.TLS.Disabled {
		if c.Server.IMAPAddr != "" || c.Server.SMTPAddr != "" {
			errs = append(errs, errors.New("tls.disabled: imap_addr and smtp_addr require TLS; leave them empty when running behind a reverse proxy that does not terminate mail TLS"))
		}
	} else {
		if c.TLS.CertPath == "" {
			errs = append(errs, errors.New("tls.cert_path is required"))
		}
		if c.TLS.KeyPath == "" {
			errs = append(errs, errors.New("tls.key_path is required"))
		}
	}
	if c.MasterKey.Path == "" {
		errs = append(errs, errors.New("master_key.path is required"))
	}
	if c.Store.Path == "" {
		errs = append(errs, errors.New("store.path is required"))
	}

	// OIDC is only required if the HTTP listener is enabled.
	if c.Server.HTTPAddr != "" {
		if c.OIDC.IssuerURL == "" {
			errs = append(errs, errors.New("oidc.issuer_url is required when server.http_addr is set"))
		} else if _, err := url.Parse(c.OIDC.IssuerURL); err != nil {
			errs = append(errs, fmt.Errorf("oidc.issuer_url: %w", err))
		}
		if c.OIDC.ClientID == "" {
			errs = append(errs, errors.New("oidc.client_id is required when server.http_addr is set"))
		}
		if c.OIDC.RedirectURL == "" {
			errs = append(errs, errors.New("oidc.redirect_url is required when server.http_addr is set"))
		}
	}

	switch strings.ToLower(c.Logger.Level) {
	case "", "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("logger.level: %q must be one of debug, info, warn, error", c.Logger.Level))
	}
	switch strings.ToLower(c.Logger.Format) {
	case "", "text", "json":
	default:
		errs = append(errs, fmt.Errorf("logger.format: %q must be one of text, json", c.Logger.Format))
	}

	return errors.Join(errs...)
}

// ParseDuration parses a duration string with optional "d" (day) suffix
// expansion before passing to time.ParseDuration. "30d" becomes "720h",
// which time.ParseDuration understands. Empty string returns fallback.
//
// This is used to parse store.retention_period and store.sweep_interval
// from YAML config so operators can write "30d" instead of "720h".
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention" —
// configuration accepts human-friendly day values.
func ParseDuration(s string, fallback time.Duration) (time.Duration, error) {
	if s == "" {
		return fallback, nil
	}
	// Expand "Nd" suffix: "30d" -> "720h".
	expanded := expandDaySuffix(s)
	d, err := time.ParseDuration(expanded)
	if err != nil {
		return 0, fmt.Errorf("config: parse duration %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: duration %q must be positive", s)
	}
	return d, nil
}

// expandDaySuffix replaces a trailing "d" unit with the equivalent
// number of hours. Only the last unit is expanded so "1d12h" stays
// valid (the "d" is in the middle, not trailing). The expansion is
// purely textual: "30d" -> "720h", "1d" -> "24h".
func expandDaySuffix(s string) string {
	if !strings.HasSuffix(s, "d") {
		return s
	}
	// Ensure what precedes the trailing "d" is all digits (i.e. "30d"
	// not "1h30d" or "1day"). If not, leave it for time.ParseDuration
	// to error on.
	prefix := s[:len(s)-1]
	allDigits := len(prefix) > 0
	for _, r := range prefix {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if !allDigits {
		return s
	}
	// Multiply by 24 hours. We avoid strconv.Atoi to keep the import
	// list minimal; the string form is enough for ParseDuration.
	return multiplyHours(prefix)
}

// multiplyHours multiplies the decimal string `s` by 24 and returns
// the result as a string suffixed with "h". Used only by expandDaySuffix.
func multiplyHours(s string) string {
	// Parse the digits manually (avoids strconv import).
	var n int
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	hours := n * 24
	// Format back to string.
	result := ""
	if hours == 0 {
		return "0h"
	}
	tmp := hours
	digits := ""
	for tmp > 0 {
		digits = string(rune('0'+tmp%10)) + digits
		tmp /= 10
	}
	return result + digits + "h"
}

// ResolveConfigPath returns the path of the configuration file Reduit
// should load, following the documented precedence. An empty return
// means no config file was located; the caller should proceed with
// defaults + env overrides.
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	if env := os.Getenv("REDUIT_CONFIG"); env != "" {
		return env
	}
	for _, candidate := range []string{"/etc/reduit/reduit.yaml", "./reduit.yaml"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
