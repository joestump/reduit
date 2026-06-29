// Package cli — auth command: manage configured Proton mailboxes.
//
// Governing: ADR-0013 (secrets in OS keychain), ADR-0012 (single-user local-first).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newAuthCmd(cfgPath *string, verbose *bool) *cobra.Command {
	auth := &cobra.Command{
		Use:   "auth",
		Short: "Manage configured Proton mailboxes",
		Long:  "Add, list, remove, and re-authenticate Proton mailboxes.",
	}

	auth.AddCommand(newAuthAddCmd(cfgPath, verbose))
	auth.AddCommand(newAuthListCmd(cfgPath, verbose))
	auth.AddCommand(newAuthRemoveCmd(cfgPath, verbose))
	auth.AddCommand(newAuthRefreshCmd(cfgPath, verbose))

	return auth
}

func newAuthAddCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "add [address]",
		Short: "Add a new Proton mailbox",
		Long:  "Authenticate a Proton account and store credentials in the OS keychain.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}
}

func newAuthListCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured mailboxes",
		Long:  "Print all Proton mailbox addresses that have been added to Reduit.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}
}

func newAuthRemoveCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "remove [address]",
		Short: "Remove a mailbox and its keychain secrets",
		Long:  "Deregister a Proton mailbox and delete its credentials from the OS keychain.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}
}

func newAuthRefreshCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh [address]",
		Short: "Re-authenticate an existing mailbox",
		Long:  "Refresh the session tokens for a previously-added Proton mailbox.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}
}
