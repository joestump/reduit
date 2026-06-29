// Package cli wires Reduit's cobra commands.
package cli

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/config"
)

// Version is set at build time via -ldflags.
var Version = "0.1.0-dev"

// NewRootCmd returns the root command tree. Subcommands are added here
// as foundation stories complete.
//
// Governing: ADR-0012 (single-user local-first, no relay, no OIDC).
func NewRootCmd() *cobra.Command {
	var (
		cfgPath string
		verbose bool
	)

	root := &cobra.Command{
		Use:   "reduit",
		Short: "Local-first Proton Mail CLI with semantic search and MCP",
		Long: `Reduit caches Proton Mail locally, embeds messages for semantic
search, and exposes a stdio MCP server for AI agents. It is a
per-person, local-first tool — not an IMAP/SMTP relay.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "",
		"path to reduit.yaml (default: $REDUIT_CONFIG, ~/.config/reduit/reduit.yaml, ./reduit.yaml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable debug-level logging")

	root.AddCommand(newMigrateCmd(&cfgPath, &verbose))

	return root
}

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
