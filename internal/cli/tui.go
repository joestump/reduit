// Package cli — tui command: launch the local Bubble Tea TUI.
//
// This is Reduit's human-facing surface (ADR-0025): a full-screen, mutt-style
// terminal UI over the local cache, read-only. It follows the same bootstrap as
// `mcp` — load config without a full Validate() (the TUI reads the cache and
// does not need llm.base_url), create the data dir, open the store, and bring
// it to HEAD — then hands a read-only facade to the TUI. It opens no network
// listener and makes no Proton calls (SPEC-0005 REQ "No Web Surface", "Read-Only
// Shared-Store Access").
//
// Governing: ADR-0025 (Bubble Tea TUI is the human surface), ADR-0012
// (single-user local-first), SPEC-0005 REQ "Bubble Tea Application, Mutt Design
// Language".
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/tui"
	tuistore "github.com/joestump/reduit/internal/tui/store"
)

func newTUICmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Browse the local cache in a full-screen terminal UI",
		Long: `Launches Reduit's local TUI: a full-screen, keyboard-first terminal
interface over your cached mail, styled after mutt. It is read-only — it
reads the same cache your MCP tools do and never writes, syncs, or contacts
Proton. It requires an interactive terminal.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Only the data_dir is needed to derive the DB path; skip full
			// Validate() so the TUI opens even when llm.base_url is unset (it
			// reads the cache, not the LLM), mirroring `mcp`.
			cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			// Bring the cache to HEAD before reading so a first run opens on a
			// migrated schema rather than erroring, mirroring `mcp` (ADR-0022
			// routes goose output through the logger onto stderr).
			st.SetLogger(logger)
			if err := st.Migrate(""); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}

			return tui.Run(cmd.Context(), tuistore.New(st))
		},
	}
}
