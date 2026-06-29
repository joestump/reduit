// Package cli — facts command: run the contact-facts extraction pass.
//
// Governing: ADR-0019 (contact-facts extraction).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newFactsCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var (
		mailbox string
		limit   int
	)

	cmd := &cobra.Command{
		Use:   "facts",
		Short: "Run the contact-facts extraction pass",
		Long:  "Extract and store contact facts from cached messages using the configured LLM.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&mailbox, "mailbox", "", "process a specific mailbox only (default: all)")
	cmd.Flags().IntVar(&limit, "limit", 0, "max messages to process per run (default: 0 = unlimited)")

	return cmd
}
