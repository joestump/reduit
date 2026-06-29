// Package cli — mcp command: start the stdio MCP server.
//
// Governing: ADR-0017 (stdio MCP and hybrid RAG).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newMCPCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start the stdio MCP server",
		Long:  "Starts the Model Context Protocol server on stdio for AI agent integration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}
}
