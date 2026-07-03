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
	"errors"
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

	// The session UID is required to resume — Proton identifies the session by it,
	// and a lazy refresh without it yields a raw 10013 "Invalid refresh token". A
	// row added before session-uid tracking has none; `labels` cannot re-login, so
	// surface an actionable message instead of that opaque code.
	if m.SessionUID == nil || *m.SessionUID == "" {
		return fmt.Errorf("mailbox %q predates session-uid tracking and cannot resume; re-add it: 'reduit auth remove %s' then 'reduit auth add %s'", m.Address, m.Address, m.Address)
	}
	storedUID := *m.SessionUID

	// The access token is required to resume: Resume REUSES the cached session
	// (go-proton-api's NewClient) to preserve the 2FA-elevated scope rather than
	// eagerly refreshing into a reduced scope that fails key/salt access with 403
	// code 9101. A row added before access-token tracking has none; `labels`
	// cannot re-login, so surface an actionable message instead of silently
	// resuming into a scope that would later break sync.
	accessToken, err := ks.Get(m.ID, keychain.AccessToken)
	if errors.Is(err, keychain.ErrNotFound) {
		return fmt.Errorf("mailbox %q predates full-scope resume (no stored access token); re-authenticate it: 'reduit auth refresh %s' (or remove and re-add it)", m.Address, m.Address)
	} else if err != nil {
		return fmt.Errorf("read access token: %w", actionableKeyringErr(err))
	}

	client, err := dialer.Resume(ctx, *m.ProtonUserID, storedUID, accessToken, refreshToken)
	if err != nil {
		return fmt.Errorf("resume session: %w", err)
	}
	defer client.Close()

	// Labels is both the connection test and the first real API call: Resume
	// itself makes no network call, so this is where an expired cached access
	// token triggers the scope-preserving lazy refresh that rotates the tokens.
	labels, err := client.Labels(ctx)
	if err != nil {
		return fmt.Errorf("fetch labels: %w", err)
	}

	// A lazy refresh during the fetch may have rotated the access/refresh token
	// or the session UID; persist any that changed so the next resume matches. A
	// failed refresh-token write flags the mailbox needs_reauth (the old token is
	// now spent).
	if err := persistRotatedAccessToken(ks, m.ID, accessToken, client.AccessToken()); err != nil {
		return fmt.Errorf("store rotated access token: %w", err)
	}
	if err := persistRotatedTokenOrFlag(ctx, st, ks, m.ID, refreshToken, client.RefreshToken()); err != nil {
		return fmt.Errorf("store rotated token: %w", err)
	}
	if err := persistRotatedSessionUID(ctx, st, m.ID, storedUID, client.SessionUID()); err != nil {
		return fmt.Errorf("store rotated session uid: %w", err)
	}

	fmt.Fprintf(out, "Labels for %s (%d):\n", m.Address, len(labels))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tID")
	for _, l := range labels {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", l.Name, l.Type, l.ID)
	}
	return tw.Flush()
}
