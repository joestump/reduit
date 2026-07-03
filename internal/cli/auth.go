// Package cli — auth command: manage configured Proton mailboxes.
//
// Governing: SPEC-0007 (onboarding & auth), SPEC-0001 (mailbox model),
// ADR-0013 (secrets in OS keychain), ADR-0012 (single-user local-first).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/config"
	"github.com/joestump/reduit/internal/keychain"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// dialerCloser is the live dialer plus the Close that releases its pooled
// connections. The seam below returns it so the cobra layer can both drive the
// auth flow (proton.Dialer) and tear the Manager down afterward.
type dialerCloser interface {
	proton.Dialer
	Close()
}

// Test seams. Production wiring builds the OS keychain and a go-proton-api
// dialer; tests override these to inject an in-memory keychain and a Fake-backed
// dialer so the whole add/labels flow runs without a live account or TTY.
var (
	openKeychain = func() keychain.Store { return keychain.New() }
	dialProton   = func(cfg proton.Config) dialerCloser { return proton.NewDialer(cfg) }
	newPrompter  = func() prompter { return newTerminalPrompter() }
	// detectAppVersion resolves Proton's current web app-version when the
	// operator leaves proton.app_version unset (or "auto"). Overridable in
	// tests to assert an explicit configured value bypasses the network fetch.
	detectAppVersion = proton.DetectAppVersion
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

// protonConfig builds the non-secret dialer config from the operator's config.
// HostURL is operator-overridable (proton.host_url / REDUIT_PROTON_HOST_URL);
// the logger is the shim that never receives secret values (gpa_client.go).
//
// AppVersion resolution (order matters — the DEFAULT deliberately avoids the
// web client's human-verification wall):
//   - explicit proton.app_version / REDUIT_PROTON_APP_VERSION → used verbatim.
//   - the literal "auto" → auto-detect Proton's current "web-mail@<version>"
//     (proton.DetectAppVersion). NOTE this presents as the web client, which
//     Proton reliably challenges with a 9001 CAPTCHA — opt-in only.
//   - unset (the default) → proton.DefaultAppVersion ("macos-bridge@3.21.2").
//     Proton's anti-abuse waves the Bridge client family through without a
//     CAPTCHA (the mechanism the old relay Reduit relied on).
//
// The SAME value must be presented at mint (auth) and at resume (labels/sync),
// because Proton binds the session to the app-version that created it —
// resuming under a different client yields 10013 "invalid refresh token". A
// single default satisfies that for the normal path; an operator who overrides
// must do so consistently across commands.
func protonConfig(ctx context.Context, cfg config.Config, logger *slog.Logger) proton.Config {
	appVersion := cfg.Proton.AppVersion
	switch {
	case appVersion == "":
		appVersion = proton.DefaultAppVersion
	case strings.EqualFold(appVersion, "auto"):
		detected, err := detectAppVersion(ctx)
		if err != nil {
			logger.Warn("proton app-version auto-detect failed; using fallback",
				"app_version", detected, "error", err)
		} else {
			logger.Debug("proton app-version auto-detected", "app_version", detected)
		}
		appVersion = detected
	}
	return proton.Config{
		AppVersion: appVersion,
		HostURL:    cfg.Proton.HostURL,
		Logger:     logger,
	}
}

func newAuthAddCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "add [address]",
		Short: "Add a new Proton mailbox",
		Long:  "Authenticate a Proton account and store credentials in the OS keychain.",
		Args:  cobra.ExactArgs(1),
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

			return authAdd(cmd.Context(), st, openKeychain(), dialer, newPrompter(),
				args[0], cmd.OutOrStdout())
		},
	}
}

// authAdd is the testable core of `reduit auth add`. It owns the SPEC-0007 add
// flow: duplicate check, interactive login (+ optional TOTP), passphrase unlock,
// mailbox-row creation under a fresh UUIDv7, secret writes, and activation. On
// any failure after the row is written it cleans up so no half-written mailbox
// or orphaned secret remains (SPEC-0007 REQ "Multi-Mailbox Add", "Secret Write,
// Read, and Delete").
func authAdd(ctx context.Context, st *store.Store, ks keychain.Store, dialer proton.Dialer, p prompter, address string, out io.Writer) error {
	// Reject a duplicate address before touching the network or prompting.
	if _, err := st.GetMailboxByAddress(ctx, address); err == nil {
		return fmt.Errorf("mailbox %q is already configured", address)
	} else if !errors.Is(err, store.ErrMailboxNotFound) {
		return err
	}

	client := dialer.NewClient()
	defer client.Close()

	passphrase, err := interactiveAuth(ctx, client, p, address, out)
	if err != nil {
		return err
	}
	defer zero(passphrase)

	// The proton_user_id is known only after Unlock. Reject a second add of the
	// SAME Proton account under a different address here — before inserting a
	// row — so the user gets a clear message instead of a raw UNIQUE-constraint
	// error (SPEC-0001/0007 "Multi-Mailbox Add").
	protonUserID := client.ProtonUserID()
	if existing, err := mailboxByProtonUserID(ctx, st, protonUserID); err != nil {
		return err
	} else if existing != nil {
		return fmt.Errorf("that Proton account is already configured as %s (%s); use 'reduit auth refresh %s' to re-authenticate it",
			existing.Address, existing.State, existing.Address)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate mailbox id: %w", err)
	}
	mailboxID := id.String()

	if err := st.InsertMailbox(ctx, mailboxID, address); err != nil {
		return err
	}
	// From here on a failure must not leave a half-written mailbox or orphaned
	// secrets behind (SPEC-0007 "Multi-Mailbox Add" — adds are atomic). Cleanup
	// runs on a fresh background context with a short deadline so it still fires
	// when the failure was the request context being cancelled (e.g. Ctrl-C).
	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ks.DeleteAll(mailboxID)
		_ = st.DeleteMailbox(cctx, mailboxID)
	}

	if err := st.SetProtonUserID(ctx, mailboxID, protonUserID); err != nil {
		cleanup()
		return err
	}
	if err := writeMailboxSecrets(ks, mailboxID, client.RefreshToken(), string(passphrase)); err != nil {
		cleanup()
		return fmt.Errorf("store secrets: %w", err)
	}
	// Persist the session UID (non-secret session state → the store, ADR-0013)
	// in the same cleanup-guarded region as the secrets. Without it a later
	// cross-process Resume has no UID to identify the session and Proton returns
	// 10013 (the bug this fixes) — so a failure here must roll the add back too.
	if err := st.SetSessionUID(ctx, mailboxID, client.SessionUID()); err != nil {
		cleanup()
		return err
	}
	if err := st.SetMailboxState(ctx, mailboxID, store.MailboxStateActive); err != nil {
		cleanup()
		return err
	}

	fmt.Fprintf(out, "Added mailbox %s\n  id:    %s\n  state: %s\n", address, mailboxID, store.MailboxStateActive)
	return nil
}

// interactiveAuth drives the SPEC-0007 interactive sequence on a fresh,
// unauthenticated client: password → Login → optional TOTP → passphrase →
// Unlock. It returns the mailbox passphrase so the caller can persist it (and
// must zero it). Secrets are read without echo and never logged. The default
// Bridge app-version avoids Proton's human-verification wall; if a non-Bridge
// app-version is configured and Proton returns a 9001, Login surfaces a clear
// app-version error (humanVerificationError) rather than attempting an in-app
// solve (ADR-0021). Shared by the add flow and the refresh fallback re-login.
func interactiveAuth(ctx context.Context, client proton.Client, p prompter, address string, out io.Writer) ([]byte, error) {
	password, err := p.secret(fmt.Sprintf("Proton password for %s: ", address))
	if err != nil {
		return nil, err
	}
	defer zero(password)

	status, err := client.Login(ctx, address, password)
	if err != nil {
		// Proton's anti-abuse wall (code 9001) demands human verification before
		// it will run the 2FA/password exchange. reduit AVOIDS this by identifying
		// as a Proton Bridge client by default (proton.DefaultAppVersion), which
		// Proton waves through with no challenge; reaching an HV here means a
		// non-Bridge app-version is configured. There is no in-app CAPTCHA solver
		// (all solve paths were falsified live — ADR-0021); return a clear,
		// actionable error pointing back at the app-version knob rather than
		// rendering/embedding/capturing the challenge (SPEC-0007 "Human
		// verification / CAPTCHA is requested").
		if hv, ok := proton.AsHVRequired(err); ok {
			return nil, humanVerificationError(hv)
		}
		return nil, fmt.Errorf("login failed: %w", err)
	}
	zero(password) // no longer needed once the SRP exchange is done.

	switch status.TwoFA {
	case proton.TwoFATOTP:
		code, err := p.line("TOTP code: ")
		if err != nil {
			return nil, err
		}
		if err := client.SubmitTOTP(ctx, code); err != nil {
			return nil, fmt.Errorf("2FA failed: %w", err)
		}
	case proton.TwoFAUnsupported:
		return nil, errors.New("this account requires a second factor reduit does not support (only TOTP is supported)")
	}

	passphrase, err := p.secret("Mailbox passphrase: ")
	if err != nil {
		return nil, err
	}
	if err := client.Unlock(ctx, passphrase); err != nil {
		zero(passphrase)
		return nil, fmt.Errorf("unlock failed: %w", err)
	}
	return passphrase, nil
}

// writeMailboxSecrets persists a mailbox's two live secrets to the keychain,
// keyed by mailbox id (#85, the store↔keychain seam). It never logs the values.
func writeMailboxSecrets(ks keychain.Store, mailboxID, refreshToken, passphrase string) error {
	if err := ks.Set(mailboxID, keychain.RefreshToken, refreshToken); err != nil {
		return actionableKeyringErr(err)
	}
	if err := ks.Set(mailboxID, keychain.MailboxPassphrase, passphrase); err != nil {
		return actionableKeyringErr(err)
	}
	return nil
}

// actionableKeyringErr enriches a locked/unavailable-keyring error with a hint
// the user can act on, while leaving other errors untouched. The keychain layer
// never embeds a secret in its errors (SPEC-0007 "No Secret Leakage"), so this
// wrap is safe to print.
func actionableKeyringErr(err error) error {
	if errors.Is(err, keychain.ErrUnavailable) {
		return fmt.Errorf("%w — unlock your login keychain (macOS) or start/unlock the Secret Service collection (Linux: gnome-keyring/KWallet) and retry", err)
	}
	return err
}

// mailboxByProtonUserID returns the configured mailbox owning protonUserID, or
// nil if none does. It backs the "same Proton account, different address"
// duplicate guard (SPEC-0001 "proton_user_id is immutable / one account one
// mailbox"). An empty protonUserID never matches.
func mailboxByProtonUserID(ctx context.Context, st *store.Store, protonUserID string) (*store.Mailbox, error) {
	if protonUserID == "" {
		return nil, nil
	}
	mboxes, err := st.ListMailboxes(ctx)
	if err != nil {
		return nil, err
	}
	for i := range mboxes {
		if mboxes[i].ProtonUserID != nil && *mboxes[i].ProtonUserID == protonUserID {
			return &mboxes[i], nil
		}
	}
	return nil, nil
}

func newAuthListCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured mailboxes",
		Long:  "Print all Proton mailbox addresses that have been added to Reduit.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()
			return authList(cmd.Context(), st, cmd.OutOrStdout())
		},
	}
}

// authList prints the configured mailboxes as a table. No secrets are read or
// shown; the proton_user_id and timestamps come straight from the store row.
func authList(ctx context.Context, st *store.Store, out io.Writer) error {
	mboxes, err := st.ListMailboxes(ctx)
	if err != nil {
		return err
	}
	if len(mboxes) == 0 {
		fmt.Fprintln(out, "No mailboxes configured. Add one with 'reduit auth add <address>'.")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS\tSTATE\tPROTON USER ID\tLAST SYNC")
	for _, m := range mboxes {
		uid := "-"
		if m.ProtonUserID != nil {
			uid = *m.ProtonUserID
		}
		last := "never"
		if m.LastSyncAt != nil {
			last = m.LastSyncAt.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.Address, m.State, uid, last)
	}
	return tw.Flush()
}

func newAuthRemoveCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "remove [address]",
		Short: "Remove a mailbox and its keychain secrets",
		Long:  "Deregister a Proton mailbox and delete its credentials from the OS keychain.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()
			return authRemove(cmd.Context(), st, openKeychain(), args[0], cmd.OutOrStdout())
		},
	}
}

// authRemove deletes a mailbox's keychain secrets first, then its row, so a
// crash between the two leaves at worst an orphaned row (re-addable) rather than
// orphaned secrets. It is clear, not silent, when the address is unknown
// (SPEC-0007 scenario "Secrets deleted on mailbox removal").
func authRemove(ctx context.Context, st *store.Store, ks keychain.Store, address string, out io.Writer) error {
	m, err := st.GetMailboxByAddress(ctx, address)
	if errors.Is(err, store.ErrMailboxNotFound) {
		return fmt.Errorf("no mailbox configured for %q", address)
	} else if err != nil {
		return err
	}
	if err := ks.DeleteAll(m.ID); err != nil {
		return fmt.Errorf("delete secrets: %w", err)
	}
	if err := st.DeleteMailbox(ctx, m.ID); err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed mailbox %s\n", address)
	return nil
}

func newAuthRefreshCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh [address]",
		Short: "Re-authenticate an existing mailbox",
		Long:  "Refresh the session tokens for a previously-added Proton mailbox.",
		Args:  cobra.ExactArgs(1),
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

			return authRefresh(cmd.Context(), st, openKeychain(), dialer, newPrompter(), args[0], cmd.OutOrStdout())
		},
	}
}

// authRefresh re-authenticates an existing mailbox (SPEC-0007 REQ "Re-Auth
// Flow"). It first tries the cheap path — Resume from the stored refresh token —
// and on success persists any rotated token and returns the mailbox to active.
// When Resume fails (a dead/revoked token, exactly why a mailbox sits in
// needs_reauth), it falls back to a full interactive re-login that REUSES the
// existing row and id: password → Login → optional TOTP → passphrase → Unlock,
// then verifies the re-login resolved the SAME Proton account (immutable
// proton_user_id) before rewriting both secrets and reactivating. This is the
// only path back to active for a dead-token mailbox, since `auth add` rejects
// existing addresses.
func authRefresh(ctx context.Context, st *store.Store, ks keychain.Store, dialer proton.Dialer, p prompter, address string, out io.Writer) error {
	m, err := st.GetMailboxByAddress(ctx, address)
	if errors.Is(err, store.ErrMailboxNotFound) {
		return fmt.Errorf("no mailbox configured for %q", address)
	} else if err != nil {
		return err
	}
	if m.ProtonUserID == nil {
		return fmt.Errorf("mailbox %q has never authenticated; run 'reduit auth add %s'", address, address)
	}

	// Cheap path: resume from the stored token if we have BOTH a token and the
	// session UID it was minted with. A pre-migration row has no session_uid;
	// resuming without it yields 10013, so treat a missing UID like a missing
	// token and fall through to the interactive re-login — which rewrites both
	// secrets AND the session_uid, self-healing the row (no remove/re-add needed).
	refreshToken, err := ks.Get(m.ID, keychain.RefreshToken)
	storedUID := ""
	if m.SessionUID != nil {
		storedUID = *m.SessionUID
	}
	switch {
	case errors.Is(err, keychain.ErrNotFound):
		// No token to resume from — go straight to interactive re-login.
	case err != nil:
		return actionableKeyringErr(err)
	case storedUID == "":
		// No stored session UID (pre-migration row) — go straight to re-login.
	default:
		if client, rerr := dialer.Resume(ctx, *m.ProtonUserID, storedUID, refreshToken); rerr == nil {
			defer client.Close()
			if err := persistRotatedTokenOrFlag(ctx, st, ks, m.ID, refreshToken, client.RefreshToken()); err != nil {
				return fmt.Errorf("store rotated token: %w", err)
			}
			// Resume may rotate the UID too; persist it so the next resume matches.
			if err := persistRotatedSessionUID(ctx, st, m.ID, storedUID, client.SessionUID()); err != nil {
				return fmt.Errorf("store rotated session uid: %w", err)
			}
			if err := st.SetMailboxState(ctx, m.ID, store.MailboxStateActive); err != nil {
				return err
			}
			fmt.Fprintf(out, "Refreshed mailbox %s\n", address)
			return nil
		}
		// Resume failed: the stored token is dead. Fall through to re-login.
	}

	// Recovery path: the token is dead or absent. The mailbox cannot serve until
	// it is re-authenticated; reflect that while we prompt.
	_ = st.SetMailboxState(ctx, m.ID, store.MailboxStateNeedsReauth)

	client := dialer.NewClient()
	defer client.Close()

	passphrase, err := interactiveAuth(ctx, client, p, address, out)
	if err != nil {
		return err
	}
	defer zero(passphrase)

	// proton_user_id is immutable (SPEC-0001): the re-login must resolve the same
	// account this row was first authenticated against.
	if client.ProtonUserID() != *m.ProtonUserID {
		return fmt.Errorf("this address now maps to a different Proton account than before; remove and re-add it ('reduit auth remove %s' then 'reduit auth add %s')", address, address)
	}

	if err := writeMailboxSecrets(ks, m.ID, client.RefreshToken(), string(passphrase)); err != nil {
		return fmt.Errorf("store secrets: %w", err)
	}
	// Record the session UID minted by this re-login so the next Resume can
	// identify the session (ADR-0013). This also repairs a pre-migration row
	// whose session_uid was NULL.
	if err := st.SetSessionUID(ctx, m.ID, client.SessionUID()); err != nil {
		return err
	}
	if err := st.SetMailboxState(ctx, m.ID, store.MailboxStateActive); err != nil {
		return err
	}
	fmt.Fprintf(out, "Re-authenticated mailbox %s\n", address)
	return nil
}

// persistRotatedToken writes the new refresh token only when it actually
// changed, avoiding a needless keychain write (and prompt on some platforms)
// when the token was not rotated.
func persistRotatedToken(ks keychain.Store, mailboxID, old, current string) error {
	if current == "" || current == old {
		return nil
	}
	return ks.Set(mailboxID, keychain.RefreshToken, current)
}

// persistRotatedTokenOrFlag persists a rotated token and, if that keychain write
// fails, marks the mailbox needs_reauth. Proton's refresh tokens are
// one-time-use: a successful Resume has already spent the old token, so a failed
// write of the new one leaves the mailbox unable to resume next time. Flagging it
// keeps `auth list` honest instead of showing a silently-broken "active" row.
func persistRotatedTokenOrFlag(ctx context.Context, st *store.Store, ks keychain.Store, mailboxID, old, current string) error {
	if err := persistRotatedToken(ks, mailboxID, old, current); err != nil {
		_ = st.SetMailboxState(ctx, mailboxID, store.MailboxStateNeedsReauth)
		return err
	}
	return nil
}

// persistRotatedSessionUID writes the session UID back to the mailbox row only
// when a resume actually rotated it, avoiding a needless write when it is
// unchanged. Unlike the refresh token, the UID lives in the store (non-secret
// session state, ADR-0013), so no keychain write is involved. An empty current
// value is ignored — a resume that did not surface a UID must not clobber the
// stored one to "".
func persistRotatedSessionUID(ctx context.Context, st *store.Store, mailboxID, old, current string) error {
	if current == "" || current == old {
		return nil
	}
	return st.SetSessionUID(ctx, mailboxID, current)
}

// resolveMailbox selects the mailbox to operate on. When address is non-empty
// it matches that address; otherwise it returns the sole mailbox, or an error
// listing the choices when there are several (used by `reduit labels`).
func resolveMailbox(ctx context.Context, st *store.Store, address string) (store.Mailbox, error) {
	if address != "" {
		m, err := st.GetMailboxByAddress(ctx, address)
		if errors.Is(err, store.ErrMailboxNotFound) {
			return store.Mailbox{}, fmt.Errorf("no mailbox configured for %q", address)
		}
		return m, err
	}
	mboxes, err := st.ListMailboxes(ctx)
	if err != nil {
		return store.Mailbox{}, err
	}
	switch len(mboxes) {
	case 0:
		return store.Mailbox{}, errors.New("no mailboxes configured; add one with 'reduit auth add <address>'")
	case 1:
		return mboxes[0], nil
	default:
		var b []byte
		for _, m := range mboxes {
			b = append(b, "  "+m.Address+"\n"...)
		}
		return store.Mailbox{}, fmt.Errorf("multiple mailboxes configured; choose one with --mailbox <address>:\n%s", string(b))
	}
}
