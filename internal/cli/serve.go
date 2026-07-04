// Package cli — serve command: reserved non-UI stub.
//
// The human-facing surface is the Bubble Tea TUI (ADR-0025, `reduit tui`), not
// this command. `serve` is retained as a stub, explicitly not a UI, reserved
// for possible future MCP-over-HTTP transport or a loopback media-companion
// endpoint. It currently returns an error and ships no HTTP handlers.
//
// Governing: ADR-0025 (TUI is the human surface; serve is not a UI),
// ADR-0012 (loopback default, no auth).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newServeCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Reserved non-UI stub (ADR-0025)",
		Long:  "Reserved for future MCP-over-HTTP or a loopback media-companion endpoint. The human surface is `reduit tui`; `serve` is not a UI and currently does nothing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "", "override serve listen address from config (default: from config)")

	return cmd
}
