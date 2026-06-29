// Package cli — serve command: start the local browse UI.
//
// Governing: ADR-0005 (frontend stack), ADR-0012 (loopback default, no auth).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newServeCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the local browse UI",
		Long:  "Starts the optional local loopback HTTP server for browsing mail in a browser.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "", "override UI listen address from config (default: from config)")

	return cmd
}
