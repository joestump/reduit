package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// envPrefix is the prefix viper uses for environment-variable
// overrides. Exported as a constant so the *_FILE resolver below uses
// the same value.
const envPrefix = "REDUIT"

// fileSuffix is appended to any env var name to indicate that the
// value should be read from the file at that path rather than used
// directly. This follows the file-based secret delivery convention
// used by Docker secrets (`/run/secrets/<name>`) and codified in the
// stumpcloud Ansible role contract (ADR-0006 / ADR-0017).
const fileSuffix = "_FILE"

// Load reads configuration from `path` (if non-empty) and overlays
// environment-variable overrides under the REDUIT_ prefix. Defaults
// are applied first, so a missing file just returns the defaults +
// any env overrides.
//
// The env mapping uses underscore-to-dot translation. Examples:
//
//	REDUIT_OIDC_CLIENT_SECRET -> oidc.client_secret
//	REDUIT_STORE_PATH         -> store.path
//	REDUIT_LOGGER_LEVEL       -> logger.level
//
// Any env var ending in `_FILE` (e.g. REDUIT_OIDC_CLIENT_SECRET_FILE)
// is resolved by reading the file at that path; the file's trimmed
// contents become the value of the corresponding non-`_FILE` env var.
// This mirrors the Docker secrets convention where the secret value
// arrives as a file at /run/secrets/<name> rather than as an env
// string. If the `_FILE` variant is set but unreadable, Load fails.
func Load(path string) (Config, error) {
	if err := resolveFileEnv(envPrefix); err != nil {
		return Config{}, fmt.Errorf("resolve _FILE env vars: %w", err)
	}

	v := viper.New()
	v.SetEnvPrefix(envPrefix)
	// Map dotted config keys ("oidc.client_secret") to env names
	// ("REDUIT_OIDC_CLIENT_SECRET").
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	cfg := Defaults()
	if err := bindDefaults(v, cfg); err != nil {
		return Config{}, fmt.Errorf("bind defaults: %w", err)
	}

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}
	}

	var loaded Config
	if err := v.Unmarshal(&loaded); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	return loaded, nil
}

// resolveFileEnv walks the process environment looking for variables
// of the form "<prefix>_<NAME>_FILE" and, for each one, reads the
// referenced file and sets "<prefix>_<NAME>" in the environment to
// the file's trimmed contents. Existing direct values are overwritten
// when the `_FILE` variant is present, on the principle that file-
// based delivery (Docker secrets, Kubernetes secrets, systemd
// LoadCredential) is the more deliberate, more secure path and should
// take precedence when both are set.
//
// A non-empty `<NAME>_FILE` whose target is missing or unreadable is
// a hard error: silently falling back to "" would mask a deployment
// misconfiguration and leave the service running without the secret.
//
// Trailing whitespace (including the newline Docker secrets append)
// is stripped from the file contents.
func resolveFileEnv(prefix string) error {
	suffix := fileSuffix
	prefixUnderscore := prefix + "_"

	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		name := kv[:eq]
		path := kv[eq+1:]

		if !strings.HasPrefix(name, prefixUnderscore) {
			continue
		}
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		if path == "" {
			// An empty _FILE value is treated as unset; no-op so
			// callers can clear the variable defensively.
			continue
		}
		baseName := strings.TrimSuffix(name, suffix)
		if baseName == prefix {
			// The bare "REDUIT_FILE" doesn't map to anything; skip.
			continue
		}

		data, err := os.ReadFile(path) //nolint:gosec // path is operator-controlled config
		if err != nil {
			return fmt.Errorf("%s=%q: %w", name, path, err)
		}
		value := strings.TrimRight(string(data), " \t\r\n")
		if value == "" {
			// A whitespace-only or zero-byte file is treated as a
			// hard error rather than silently substituting an empty
			// secret -- a botched secret mount would otherwise let
			// the service boot with e.g. OIDC.ClientSecret="" and
			// degrade to public-client mode without warning.
			return fmt.Errorf("%s=%q: file is empty after trim", name, path)
		}
		if err := os.Setenv(baseName, value); err != nil {
			return fmt.Errorf("set %s from %s: %w", baseName, name, err)
		}
	}
	return nil
}

// bindDefaults sets each known key as a viper default so AutomaticEnv
// can find it (viper requires the key to be known before it will look
// up the env var).
func bindDefaults(v *viper.Viper, cfg Config) error {
	defaults := map[string]any{
		"server.http_addr":     cfg.Server.HTTPAddr,
		"server.imap_addr":     cfg.Server.IMAPAddr,
		"server.smtp_addr":     cfg.Server.SMTPAddr,
		"server.metrics_addr":  cfg.Server.MetricsAddr,
		"tls.cert_path":        cfg.TLS.CertPath,
		"tls.key_path":         cfg.TLS.KeyPath,
		"tls.disabled":         cfg.TLS.Disabled,
		"master_key.path":      cfg.MasterKey.Path,
		"store.path":           cfg.Store.Path,
		"store.migrations_dir": cfg.Store.MigrationsDir,
		"oidc.issuer_url":      cfg.OIDC.IssuerURL,
		"oidc.client_id":       cfg.OIDC.ClientID,
		"oidc.client_secret":   cfg.OIDC.ClientSecret,
		"oidc.redirect_url":    cfg.OIDC.RedirectURL,
		"oidc.scopes":          cfg.OIDC.Scopes,
		"oidc.admin_subjects":  cfg.OIDC.AdminSubjects,
		"oidc.auto_create":     cfg.OIDC.AutoCreate,
		"logger.level":         cfg.Logger.Level,
		"logger.format":        cfg.Logger.Format,
	}
	for k, val := range defaults {
		v.SetDefault(k, val)
	}
	return nil
}
