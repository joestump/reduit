// Package cli — send command: send a Proton message.
//
// Governing: ADR-0020 (outbound send via go-proton-api), SPEC-0010 (outbound send).
package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

func newSendCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var (
		from    string
		to      []string
		subject string
		body    string
		yes     bool
	)

	cmd := &cobra.Command{
		Use:   "send",
		Short: "Send a Proton message",
		Long: `Compose and send an email via a configured Proton mailbox.

The --from flag is required and must be one of the mailbox addresses added
via 'reduit auth add'. See SPEC-0010 for the full outbound-send contract.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVar(&from, "from", "", "mailbox address to send from (required)")
	cmd.Flags().StringArrayVar(&to, "to", nil, "recipient address(es) (required, repeatable)")
	cmd.Flags().StringVar(&subject, "subject", "", "message subject (required)")
	cmd.Flags().StringVar(&body, "body", "", "message body (plain text)")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip interactive confirmation before sending")

	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")
	_ = cmd.MarkFlagRequired("subject")

	return cmd
}
