// Package cli — embed command: run the embedding pass over cached messages.
//
// Governing: ADR-0015 (embeddings and vector backend), ADR-0018 (LLM egress).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newEmbedCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var (
		mailbox string
		model   string
	)

	cmd := &cobra.Command{
		Use:   "embed",
		Short: "Run the embedding pass over cached messages",
		Long:  "Generate vector embeddings for messages and attachments not yet embedded.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&mailbox, "mailbox", "", "embed a specific mailbox only (default: all)")
	cmd.Flags().StringVar(&model, "model", "", "override the text embedding model from config")

	return cmd
}
