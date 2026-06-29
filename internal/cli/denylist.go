// Package cli — denylist command: manage the LLM denylist.
//
// Governing: ADR-0018 (LLM egress and denylist).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newDenylistCmd(cfgPath *string, verbose *bool) *cobra.Command {
	deny := &cobra.Command{
		Use:   "denylist",
		Short: "Manage the LLM denylist",
		Long:  "Add or remove senders and conversations from LLM processing.",
	}

	deny.AddCommand(newDenylistAddCmd(cfgPath, verbose))
	deny.AddCommand(newDenylistRemoveCmd(cfgPath, verbose))
	deny.AddCommand(newDenylistListCmd(cfgPath, verbose))

	return deny
}

func newDenylistAddCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var (
		kind    string
		value   string
		mailbox string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add an entry to the LLM denylist",
		Long:  "Prevent a sender or conversation from being processed by the LLM.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "entry kind: conversation or sender (required)")
	cmd.Flags().StringVar(&value, "value", "", "the address or conversation ID to deny (required)")
	cmd.Flags().StringVar(&mailbox, "mailbox", "", "scope to a specific mailbox (default: all)")

	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("value")

	return cmd
}

func newDenylistRemoveCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var (
		kind    string
		value   string
		mailbox string
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove an entry from the LLM denylist",
		Long:  "Allow a previously-denied sender or conversation to be processed by the LLM again.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "entry kind: conversation or sender (required)")
	cmd.Flags().StringVar(&value, "value", "", "the address or conversation ID to remove (required)")
	cmd.Flags().StringVar(&mailbox, "mailbox", "", "scope to a specific mailbox (default: all)")

	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("value")

	return cmd
}

func newDenylistListCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var mailbox string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all denylist entries",
		Long:  "Print all senders and conversations excluded from LLM processing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&mailbox, "mailbox", "", "filter by mailbox (default: all)")

	return cmd
}
