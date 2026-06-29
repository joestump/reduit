// Package cli — sync command: sync Proton mailboxes to the local cache.
//
// Governing: ADR-0014 (sync-and-cache).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newSyncCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var (
		mailbox string
		full    bool
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync Proton mailboxes to the local cache",
		Long:  "Fetch new and updated messages from Proton and write them to the local SQLite cache.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&mailbox, "mailbox", "", "sync a specific mailbox only (default: all)")
	cmd.Flags().BoolVar(&full, "full", false, "force a full resync from the beginning")

	return cmd
}
