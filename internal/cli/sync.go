// Package cli — sync command: sync Proton mailboxes to the local cache.
//
// `reduit sync` is the triggered-execution surface over the sync engine
// (internal/sync): it wires the store, keychain, and Proton dialer into a
// syncengine.Engine and drives one bootstrap-then-tail pass per mailbox. It is
// meant to be run from cron / a systemd timer / launchd; with --watch it can
// also run as an optional FOREGROUND loop that re-syncs on an interval and
// stops on a signal. It opens NO network listener and is NOT an always-on
// daemon (SPEC-0002 "Triggered Execution").
//
// Governing: SPEC-0002 (Sync & Local Cache — "Triggered Execution",
// "Bookkeeping And Observability"), ADR-0014 (sync-and-cache), #88.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/store"
	syncengine "github.com/joestump/reduit/internal/sync"
)

// syncEngine is the engine surface the command drives, expressed as an interface
// so tests inject a real *syncengine.Engine over a Fake-backed dialer (no live
// account, no network). The production engine is built in RunE below.
type syncEngine interface {
	SyncAll(ctx context.Context) ([]syncengine.RunSummary, error)
	SyncMailbox(ctx context.Context, mailboxID string) (syncengine.RunSummary, error)
}

// syncOptions carries the parsed flags into the testable core.
type syncOptions struct {
	mailbox string        // "" = all mailboxes; else a mailbox id or address
	full    bool          // reset the cursor first so the engine re-bootstraps
	watch   time.Duration // 0 = one-shot; >0 = foreground re-sync interval
}

func newSyncCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var (
		mailbox string
		full    bool
		watch   time.Duration
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync Proton mailboxes to the local cache",
		Long: `Fetch new and updated messages from Proton and write them to the local
SQLite cache. With no flags it syncs every active mailbox once and exits —
suitable for cron, a systemd timer, or launchd.

  --mailbox <id|address>  sync only that mailbox, leaving the others untouched
  --full                  reset the mailbox's cursor first, forcing a fresh
                          bounded backfill (re-applied idempotently)
  --watch <interval>      stay in the foreground and re-sync on the interval,
                          stopping cleanly on Ctrl-C / SIGTERM (no daemon,
                          no network listener)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}

			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer st.Close()

			// Bring the cache to HEAD before syncing so a fresh or stale DB does
			// not error out mid-run (the auto-migrate gap, #140) — mirrors `mcp`.
			if err := st.Migrate(""); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}

			dialer := dialProton(protonConfig(cmd.Context(), cfg, logger))
			defer dialer.Close()

			eng := syncengine.New(syncengine.Deps{
				Store:    st,
				Keychain: openKeychain(),
				Dialer:   dialer, // dialerCloser satisfies syncengine.Dialer (Resume)
				Logger:   logger,
				Config: syncengine.Config{
					BackfillWindow: cfg.Sync.BackfillWindow,
					Concurrency:    cfg.Sync.Concurrency,
				},
			})

			// Stop cleanly on SIGINT/SIGTERM: for a one-shot run this cancels an
			// in-flight sync; for --watch it ends the loop between iterations.
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			return runSync(ctx, st, eng, syncOptions{mailbox: mailbox, full: full, watch: watch}, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&mailbox, "mailbox", "", "sync only this mailbox (id or address); default: all active mailboxes")
	cmd.Flags().BoolVar(&full, "full", false, "reset the cursor first and re-run the bounded backfill (full rescan); with --watch this re-backfills every interval")
	cmd.Flags().DurationVar(&watch, "watch", 0, "foreground: re-sync on this interval until interrupted (e.g. 5m); default: one-shot")

	return cmd
}

// runSync is the testable core. It runs one sync pass (runSyncOnce) and, when
// opts.watch > 0, keeps re-running it on that interval in the foreground until
// ctx is cancelled (SIGINT/SIGTERM) — never opening a listener or backgrounding
// (SPEC-0002 "Optional foreground watch loop"). A one-shot pass propagates its
// error so the process exits non-zero when a mailbox run failed; the watch loop
// keeps going across failures (the cause is already printed) and exits 0 when
// the signal stops it.
func runSync(ctx context.Context, st *store.Store, eng syncEngine, opts syncOptions, out io.Writer) error {
	for {
		err := runSyncOnce(ctx, st, eng, opts, out)
		if opts.watch <= 0 {
			return err
		}
		// Don't print a misleading "retrying" line when the failure IS the
		// signal that stops the loop — ctx.Done() below returns cleanly.
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(out, "sync iteration failed: %v (retrying in %s)\n", err, opts.watch)
		}
		timer := time.NewTimer(opts.watch)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// runSyncOnce runs a single sync pass: optionally reset cursors for --full, then
// SyncAll or SyncMailbox, print the per-mailbox summary and total, and return a
// non-nil error when the mailbox set could not be enumerated OR any mailbox's
// run recorded a fatal cause (RunSummary.Err) — the latter is the exit-code
// contract, since SyncAll's own return only signals an enumerate failure.
func runSyncOnce(ctx context.Context, st *store.Store, eng syncEngine, opts syncOptions, out io.Writer) error {
	var summaries []syncengine.RunSummary

	if opts.mailbox != "" {
		m, err := resolveSyncMailbox(ctx, st, opts.mailbox)
		if err != nil {
			return err
		}
		if opts.full {
			if err := st.ResetSyncCursor(ctx, m.ID); err != nil {
				return fmt.Errorf("reset cursor for %s: %w", m.Address, err)
			}
		}
		s, err := eng.SyncMailbox(ctx, m.ID)
		// Normally err == s.Err and printSummaries surfaces it. But SyncMailbox
		// can fail BEFORE recording a cause (e.g. the mailbox is deleted between
		// resolve and run), returning a non-nil err with an empty s.Err — surface
		// that too so the process doesn't exit 0 on a silent failure.
		if err != nil && s.Err == nil {
			return err
		}
		summaries = []syncengine.RunSummary{s}
	} else {
		if opts.full {
			if err := resetActiveCursors(ctx, st); err != nil {
				return err
			}
		}
		var err error
		summaries, err = eng.SyncAll(ctx)
		if err != nil {
			return err
		}
	}

	return printSummaries(out, summaries)
}

// resolveSyncMailbox resolves a --mailbox selector to a mailbox row, accepting
// either the mailbox UUID or its Proton address (SPEC-0002 "Mailbox selection").
func resolveSyncMailbox(ctx context.Context, st *store.Store, sel string) (store.Mailbox, error) {
	if m, err := st.GetMailbox(ctx, sel); err == nil {
		return m, nil
	} else if !errors.Is(err, store.ErrMailboxNotFound) {
		return store.Mailbox{}, err
	}
	if m, err := st.GetMailboxByAddress(ctx, sel); err == nil {
		return m, nil
	} else if !errors.Is(err, store.ErrMailboxNotFound) {
		return store.Mailbox{}, err
	}
	return store.Mailbox{}, fmt.Errorf("no mailbox configured matching %q (by id or address)", sel)
}

// resetActiveCursors clears the sync cursor of every ACTIVE mailbox so a --full
// SyncAll re-bootstraps each one. Non-active mailboxes never sync, so leaving
// their (absent) cursors alone matches SyncAll's own active-only selection.
func resetActiveCursors(ctx context.Context, st *store.Store) error {
	mboxes, err := st.ListMailboxes(ctx)
	if err != nil {
		return err
	}
	for _, m := range mboxes {
		if m.State != store.MailboxStateActive {
			continue
		}
		if err := st.ResetSyncCursor(ctx, m.ID); err != nil {
			return fmt.Errorf("reset cursor for %s: %w", m.Address, err)
		}
	}
	return nil
}

// printSummaries writes a concise per-mailbox line plus a total, and returns a
// non-nil error if any mailbox's run carried a fatal cause — so runSyncOnce can
// exit non-zero. A clean set of summaries returns nil.
func printSummaries(out io.Writer, summaries []syncengine.RunSummary) error {
	if len(summaries) == 0 {
		fmt.Fprintln(out, "No active mailboxes to sync. Add one with 'reduit auth add <address>'.")
		return nil
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MAILBOX\tADDED\tUPDATED\tDELETED\tATTACH\tERRORS\tSTATUS")

	var totAdded, totUpdated, totDeleted, totAttach, totErrors, failed int
	for _, s := range summaries {
		status := "ok"
		if s.Err != nil {
			status = "FAILED: " + s.Err.Error()
			failed++
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
			s.Address, s.Added, s.Updated, s.Deleted, s.Attachments, s.Errors, status)
		totAdded += s.Added
		totUpdated += s.Updated
		totDeleted += s.Deleted
		totAttach += s.Attachments
		totErrors += s.Errors
	}
	fmt.Fprintf(tw, "TOTAL (%d)\t%d\t%d\t%d\t%d\t%d\t\n",
		len(summaries), totAdded, totUpdated, totDeleted, totAttach, totErrors)
	if err := tw.Flush(); err != nil {
		return err
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d mailbox(es) failed to sync", failed, len(summaries))
	}
	return nil
}
