// Package cli wires Reduit's cobra commands.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/config"
)

// Version is set at build time via -ldflags.
var Version = "0.1.0-dev"

// NewRootCmd returns the root command tree. Subcommands are added here
// as foundation stories complete.
//
// Governing: ADR-0012 (single-user local-first).
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
per-person, local-first tool that runs entirely on your machine.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "",
		"path to reduit.yaml (default: $REDUIT_CONFIG, ~/.config/reduit/reduit.yaml, ./reduit.yaml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable debug-level logging")

	root.AddCommand(newMigrateCmd(&cfgPath, &verbose))
	root.AddCommand(newAuthCmd(&cfgPath, &verbose))
	root.AddCommand(newLabelsCmd(&cfgPath, &verbose))
	root.AddCommand(newSyncCmd(&cfgPath, &verbose))
	root.AddCommand(newEmbedCmd(&cfgPath, &verbose))
	root.AddCommand(newFactsCmd(&cfgPath, &verbose))
	root.AddCommand(newSendCmd(&cfgPath, &verbose))
	root.AddCommand(newMCPCmd(&cfgPath, &verbose))
	root.AddCommand(newTUICmd(&cfgPath, &verbose))
	root.AddCommand(newServeCmd(&cfgPath, &verbose))
	root.AddCommand(newDenylistCmd(&cfgPath, &verbose))
	root.AddCommand(newContactsCmd(&cfgPath, &verbose))

	return root
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

// buildLogger constructs reduit's structured logger. The backend is
// github.com/charmbracelet/log used *as an slog.Handler* (ADR-0022): the
// slog API surface and the secret-redaction discipline (SPEC-0007 "No
// Secret Leakage") are unchanged — only the handler differs from the
// stdlib text/JSON handlers we used before. Logs go to stderr so stdout
// stays clean for the MCP JSON-RPC transport and auth prompts.
func buildLogger(cfg config.LoggerConfig) *slog.Logger {
	return buildLoggerTo(os.Stderr, cfg)
}

// buildLoggerTo is buildLogger with an explicit sink, split out so tests
// can capture output. Production always writes to os.Stderr.
func buildLoggerTo(w io.Writer, cfg config.LoggerConfig) *slog.Logger {
	opts := charmlog.Options{
		Level:           charmLevel(cfg.Level),
		ReportTimestamp: true,
	}
	// "text" (default) → charm's human-readable formatter; "json" → machine JSON.
	if strings.EqualFold(cfg.Format, "json") {
		opts.Formatter = charmlog.JSONFormatter
	}
	// Wrap the charm handler so slog.LogValuer attrs are resolved before it
	// formats them (see resolvingHandler) — the secret-redaction defense.
	return slog.New(resolvingHandler{inner: charmlog.NewWithOptions(w, opts)})
}

// resolvingHandler wraps an slog.Handler and resolves slog.LogValuer
// attributes before delegating. charmbracelet/log v1.0.0's text formatter
// does NOT resolve LogValuer (the stdlib TextHandler we replaced did), so a
// secret-bearing type whose LogValue() returns a redacted placeholder would
// otherwise render its raw fields in the default text format — defeating the
// SPEC-0007 "No Secret Leakage" defense-in-depth. Resolving here restores that
// guarantee in BOTH text and json (ADR-0022).
type resolvingHandler struct {
	inner slog.Handler
}

func (h resolvingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle rebuilds the record with every attr resolved, then delegates.
func (h resolvingHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, rec.Message, rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(resolveAttr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

// WithAttrs resolves attrs attached via logger.With before they reach the
// inner handler — those persist across records and must be redacted too.
func (h resolvingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	resolved := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		resolved[i] = resolveAttr(a)
	}
	return resolvingHandler{inner: h.inner.WithAttrs(resolved)}
}

func (h resolvingHandler) WithGroup(name string) slog.Handler {
	return resolvingHandler{inner: h.inner.WithGroup(name)}
}

// resolveAttr resolves a LogValuer attr value, recursing into group values so
// nested attrs are resolved too.
func resolveAttr(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		resolved := make([]slog.Attr, len(group))
		for i, g := range group {
			resolved[i] = resolveAttr(g)
		}
		a.Value = slog.GroupValue(resolved...)
	}
	return a
}

// charmLevel maps a LoggerConfig.Level string (debug/info/warn/error) to a
// charmbracelet/log level. Any unrecognized value falls back to info.
func charmLevel(level string) charmlog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return charmlog.DebugLevel
	case "warn":
		return charmlog.WarnLevel
	case "error":
		return charmlog.ErrorLevel
	default:
		return charmlog.InfoLevel
	}
}
