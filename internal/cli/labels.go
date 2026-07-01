// Package cli — labels command: the live Proton connection test.
//
// `reduit labels` resumes a configured mailbox from its stored refresh token
// and lists its labels/folders/system mailboxes. It exercises the full stack —
// keychain read → Resume → authenticated API call — end to end, so it is the
// command the user runs to confirm a freshly-added mailbox actually works.
//
// Governing: SPEC-0007 (auth flow, Re-Auth path), ADR-0013 (secrets in keychain).
package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

func newLabelsCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var mailbox string
	cmd := &cobra.Command{
		Use:   "labels",
		Short: "List a mailbox's labels (live Proton connection test)",
		Long: `Resume a configured mailbox from its stored refresh token and list its
labels, folders, and system mailboxes. This is a quick end-to-end check that
authentication and connectivity to Proton are working.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			dialer := dialProton(protonConfig(cmd.Context(), cfg, logger))
			defer dialer.Close()

			return runLabels(cmd.Context(), st, openKeychain(), dialer, mailbox, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&mailbox, "mailbox", "", "mailbox address (required only when several are configured)")
	return cmd
}

// runLabels is the testable core: resolve the mailbox, read its refresh token,
// Resume, persist any rotated token, fetch labels, and print them. It proves
// live connectivity; with the Fake injected it verifies the wiring.
func runLabels(ctx context.Context, st *store.Store, ks keychain.Store, dialer proton.Dialer, mailbox string, out io.Writer) error {
	m, err := resolveMailbox(ctx, st, mailbox)
	if err != nil {
		return err
	}
	if m.ProtonUserID == nil {
		return fmt.Errorf("mailbox %q has never authenticated; run 'reduit auth add %s'", m.Address, m.Address)
	}

	refreshToken, err := ks.Get(m.ID, keychain.RefreshToken)
	if err != nil {
		return fmt.Errorf("read refresh token: %w", actionableKeyringErr(err))
	}

	client, err := dialer.Resume(ctx, *m.ProtonUserID, refreshToken)
	if err != nil {
		return fmt.Errorf("resume session: %w", err)
	}
	defer client.Close()

	// Resume may rotate the token; persist it so the next use isn't stale. A
	// failed write flags the mailbox needs_reauth (the old token is now spent).
	if err := persistRotatedTokenOrFlag(ctx, st, ks, m.ID, refreshToken, client.RefreshToken()); err != nil {
		return fmt.Errorf("store rotated token: %w", err)
	}

	labels, err := client.Labels(ctx)
	if err != nil {
		return fmt.Errorf("fetch labels: %w", err)
	}

	fmt.Fprintf(out, "Labels for %s (%d):\n", m.Address, len(labels))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tID")
	for _, l := range labels {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", l.Name, l.Type, l.ID)
	}
	return tw.Flush()
}
