// Package cli wires Reduit's cobra commands. The root command holds
// global flags (--config, --verbose); subcommands implement serve,
// migrate, and master-key management.
package cli

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/config"
)

// Version is set at build time via -ldflags. Default value here so
// the binary still runs in a developer's `go run`.
var Version = "0.1.0-dev"

// NewRootCmd returns the root command tree with all subcommands
// registered. It is the public entry point used by cmd/reduit/main.go.
func NewRootCmd() *cobra.Command {
	var (
		cfgPath string
		verbose bool
	)

	root := &cobra.Command{
		Use:   "reduit",
		Short: "A sovereign Proton Mail relay for self-hosters",
		Long: `Reduit is a multi-user, headless Proton Mail relay.
It serves several Proton accounts as standard SMTP+IMAPS endpoints
on the network, includes an OIDC-gated control plane, and exposes
an MCP server for AI agents.`,
		Version:           Version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error { return nil },
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "",
		"path to reduit.yaml (default: $REDUIT_CONFIG, /etc/reduit/reduit.yaml, ./reduit.yaml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable debug-level logging (overrides logger.level config)")

	// Subcommands. They reach the global config and logger via the
	// helper loaders below.
	root.AddCommand(newServeCmd(&cfgPath, &verbose))
	root.AddCommand(newMigrateCmd(&cfgPath, &verbose))
	root.AddCommand(newMasterKeyCmd(&cfgPath, &verbose))

	return root
}

// loadConfig returns the resolved config and a logger ready for use
// by a subcommand. Runs full Validate() -- callers that need a
// minimum-viable config (e.g. `master-key generate`, which only
// needs master_key.path) should call loadConfigUnchecked instead.
func loadConfig(cfgPathPtr *string, verbosePtr *bool) (config.Config, *slog.Logger, error) {
	cfg, logger, err := loadConfigUnchecked(cfgPathPtr, verbosePtr)
	if err != nil {
		return config.Config{}, nil, err
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, logger, nil
}

// loadConfigUnchecked is loadConfig minus the Validate() call.
// Bootstrap-time subcommands (master-key generate / migrate) only
// care about a small subset of the config (master_key.path, store
// .path) and shouldn't be blocked by missing serve-time fields like
// oidc.issuer_url -- the bootstrap typically runs BEFORE the OIDC
// client has been provisioned.
func loadConfigUnchecked(cfgPathPtr *string, verbosePtr *bool) (config.Config, *slog.Logger, error) {
	path := config.ResolveConfigPath(*cfgPathPtr)
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, nil, fmt.Errorf("load config: %w", err)
	}
	if *verbosePtr {
		cfg.Logger.Level = "debug"
	}
	logger := buildLogger(cfg.Logger)
	if path != "" {
		logger.Debug("loaded config from file", slog.String("path", path))
	} else {
		logger.Debug("no config file found; using defaults + env overrides")
	}
	return cfg, logger, nil
}

func buildLogger(cfg config.LoggerConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}
