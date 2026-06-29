// Package cli — contacts command: manage contacts.
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newContactsCmd(cfgPath *string, verbose *bool) *cobra.Command {
	contacts := &cobra.Command{
		Use:   "contacts",
		Short: "Manage contacts",
		Long:  "List contacts and inspect cited facts.",
	}

	contacts.AddCommand(newContactsListCmd(cfgPath, verbose))
	contacts.AddCommand(newContactsShowCmd(cfgPath, verbose))

	return contacts
}

func newContactsListCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var mailbox string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all known contacts",
		Long:  "Print contacts derived from cached mail, optionally filtered by mailbox.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&mailbox, "mailbox", "", "filter by mailbox (default: all)")

	return cmd
}

func newContactsShowCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "show ADDRESS",
		Short: "Show a contact and their cited facts",
		Long:  "Display a contact's details and all extracted facts attributed to them.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}
}
