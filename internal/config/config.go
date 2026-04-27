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
}

// TLSConfig holds the cert + key file paths read by the hot-reloading
// loader (per ADR-0009).
type TLSConfig struct {
	CertPath string `mapstructure:"cert_path"`
	KeyPath  string `mapstructure:"key_path"`
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
			Path: "/var/lib/reduit/reduit.db",
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
	if c.TLS.CertPath == "" {
		errs = append(errs, errors.New("tls.cert_path is required"))
	}
	if c.TLS.KeyPath == "" {
		errs = append(errs, errors.New("tls.key_path is required"))
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
