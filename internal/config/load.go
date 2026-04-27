package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

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
func Load(path string) (Config, error) {
	v := viper.New()
	v.SetEnvPrefix("REDUIT")
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
