// Package cli — mcp command: start the stdio MCP server.
//
// The MCP server is Reduit's primary surface (ADR-0017). This command opens
// the local cache, brings it to the current schema, and serves the MCP tool
// surface over stdio. It opens NO network listener and requires NO auth — it
// runs with the authority of the local OS user (ADR-0012). All logging goes to
// stderr (buildLogger writes there) so stdout carries only the JSON-RPC stream.
//
// Governing: ADR-0017 (stdio MCP and hybrid RAG), ADR-0012 (single-user
//
//	local-first), SPEC-0006 REQ "Stdio Transport, No Auth".
package cli

import (
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/mcp"
)

func newMCPCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start the stdio MCP server",
		Long: `Starts the Model Context Protocol server on stdio for AI agent
integration. The server is spawned by your MCP client (Claude Desktop /
Claude Code); it opens no network listener and requires no authentication —
it runs with your local user's authority. All logs go to stderr so stdout
carries only the JSON-RPC protocol stream.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Only the data_dir is needed to derive the DB path; skip full
			// Validate() so the server starts even when llm.base_url is unset
			// (the status/list tools do not touch the LLM).
			cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}

			// openStore creates the data dir (owner-only 0700) before opening,
			// since modernc.org/sqlite will not create parent directories and
			// on a clean machine (~/.local/share/reduit absent) Open would fail.
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			// Bring the cache to HEAD before serving so `status` reports a
			// healthy, migrated schema on a first run. Route goose's migration
			// output through reduit's logger (ADR-0022) so it lands on stderr in
			// the same format — never on stdout, which carries JSON-RPC.
			st.SetLogger(logger)
			if err := st.Migrate(""); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}

			srv := mcp.NewServer(st, mcp.Options{
				Version: Version,
				Logger:  logger, // writes to stderr (see buildLogger)
			})

			// Stop cleanly on SIGINT/SIGTERM (the MCP client closing stdin
			// also ends the stdio transport's Run).
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			logger.Info("starting MCP stdio server", "db_path", st.Path())
			return srv.RunStdio(ctx)
		},
	}
}
