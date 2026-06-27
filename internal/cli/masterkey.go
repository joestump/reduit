package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/filelock"
	"github.com/joestump/reduit/internal/store"
)

// masterKeyLockName is the lockfile basename placed next to the master
// key. `master-key rotate` and `serve` both acquire it (see
// rotateLockPath / MasterKeyLockPath) so a rotation cannot race a running
// daemon — the daemon holds the OLD key in memory while serving, and an
// overlapping rotation swapping the key file underneath it would corrupt
// envelopes.
//
// Governing: ADR-0003 (envelope encryption); #50.
const masterKeyLockName = ".reduit-master-key.lock"

// MasterKeyLockPath returns the advisory-lock path for a given master-key
// file path. It is a sibling of the key file so it lives in the same
// (operator-controlled, 0700) directory. Exported so `serve` acquires the
// exact same lock `master-key rotate` does.
func MasterKeyLockPath(masterKeyPath string) string {
	return filepath.Join(filepath.Dir(masterKeyPath), masterKeyLockName)
}

func newMasterKeyCmd(cfgPath *string, verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "master-key",
		Short: "Manage the service master key (envelope-encryption root)",
		Long: `The service master key seals every account's per-account data key.
Loss of the master key = total data loss. Back it up out of band.`,
	}
	cmd.AddCommand(newMasterKeyGenerateCmd(cfgPath, verbose))
	cmd.AddCommand(newMasterKeyRotateCmd(cfgPath, verbose))
	return cmd
}

func newMasterKeyGenerateCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "generate",
		Short: "Generate a new master key and write it to the configured path",
		Long: `Refuses to overwrite an existing master key — protects against
accidental rotation that would orphan every account's data key.
Use the rotate subcommand for a controlled rotation.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// loadConfigUnchecked: master-key generate runs at
			// bootstrap, before OIDC client + endpoints exist.
			// Only master_key.path is needed.
			cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}
			exists, err := cryptenv.MasterKeyExists(cfg.MasterKey.Path)
			if err != nil {
				return err
			}
			if exists {
				return fmt.Errorf("master key already exists at %s; refusing to overwrite",
					cfg.MasterKey.Path)
			}
			k, err := cryptenv.GenerateMasterKey()
			if err != nil {
				return fmt.Errorf("generate: %w", err)
			}
			if err := cryptenv.WriteMasterKey(cfg.MasterKey.Path, k); err != nil {
				return fmt.Errorf("write: %w", err)
			}
			logger.Info("master key generated",
				slog.String("path", cfg.MasterKey.Path),
				slog.String("note", "back this file up out of band; loss = total data loss"))
			return nil
		},
	}
}

// newMasterKeyRotateCmd implements `reduit master-key rotate`.
//
// Rotation re-wraps every account's per-account data key from the
// current master key to a freshly generated one, then swaps the
// master-key file. The per-account data keys and all secret ciphertexts
// are untouched — only the envelope encrypting each data key is
// re-encrypted, so rotation is cheap (one row UPDATE per account) and
// never decrypts a single secret field.
//
// ORDERING (the crux of crash safety): we DB-commit the re-wrapped
// envelopes FIRST, force them to durable storage with a WAL checkpoint,
// then swap the key file. The two resources (the accounts table and the
// key file) cannot be updated in one atomic step, so we pick the order
// that fails safe:
//
//   - Crash AFTER the file swap but BEFORE commit is impossible: commit
//     happens first.
//   - Crash AFTER commit but BEFORE the file swap leaves the DB holding
//     NEW-key envelopes while the file still holds the OLD key. The
//     daemon would then fail to unseal on next boot — but NO DATA IS
//     LOST: re-running `master-key rotate` is a no-op-or-resume because
//     the loaded (old) key no longer unseals the (new) envelopes, which
//     surfaces as ErrMasterKeyMismatch rather than corruption. Recovery
//     is to restore the just-written new key. To make that recovery
//     trivial we keep a uniquely-named `.bak` of the OLD key (so the
//     operator can roll the DB back if they prefer) AND the new key is
//     fsynced to its temp file before the swap, so the bytes survive a
//     crash. We deliberately do NOT delete the .bak — the operator
//     removes it once they have confirmed the rotation took.
//
// WAL DURABILITY (the reason for the explicit checkpoint): the store
// opens SQLite with synchronous=NORMAL + WAL, under which a COMMIT is
// durable against an application crash but NOT against power loss until
// the next checkpoint — committed frames can still live only in the
// -wal file. Without forcing a checkpoint, "DB committed before key
// swap" would be FALSE on power loss: the new-key envelopes could roll
// back to old-key state while the file already holds the new key,
// leaving the daemon unable to unseal. So after RewrapEnvelopes commits
// and BEFORE swapping the key file we run PRAGMA wal_checkpoint(TRUNCATE)
// (store.CheckpointTruncate) and proceed to the swap ONLY if it reports
// success. A busy/failed checkpoint aborts the rotation with the DB
// already re-wrapped under the new key but the old key still live — the
// fail-safe state (re-running rotate surfaces ErrMasterKeyMismatch, no
// data lost).
//
// EMPTY-DB GUARD: the ErrMasterKeyMismatch verification only fires
// inside the per-account re-wrap loop, so a DB with zero accounts would
// "succeed" with 0 re-wraps and swap to a brand-new key WITHOUT ever
// proving the operator's current key was correct — silently orphaning
// nothing yet, but normalising a key swap that skipped verification. We
// REFUSE to swap when 0 accounts were re-wrapped, unless --allow-empty
// is passed for the legitimate fresh-install case.
//
// CONCURRENCY LOCK: rotate acquires an advisory flock
// (filelock, on MasterKeyLockPath) before doing any work and holds it
// across the whole operation, so two rotations cannot race and a running
// `serve` (which acquires the same lock at startup) makes rotate refuse
// — and vice-versa.
//
// The mismatched-key guard (ErrMasterKeyMismatch) makes the whole thing
// idempotent-ish: pointing rotate at an already-rotated DB refuses
// cleanly instead of double-wrapping.
//
// Governing: ADR-0003 (service-master-key envelope encryption),
// ADR-0006 (SQLite + WAL, synchronous=NORMAL); #50.
func newMasterKeyRotateCmd(cfgPath *string, verbose *bool) *cobra.Command {
	var allowEmpty bool
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the master key, re-wrapping every account's data-key envelope",
		Long: `Generates a new master key, re-encrypts every account's data-key
envelope under it in a single database transaction, checkpoints the WAL
so the commit is durable against power loss, then atomically swaps the
master-key file (keeping a uniquely-named .bak of the old key).

Per-account data keys and all secret ciphertexts are unchanged — only
the envelope wrapping each data key is re-encrypted. Refuses to run if
the current master key cannot unseal an existing envelope, and refuses
to swap the key on a zero-account database (where no envelope verifies
the current key) unless --allow-empty is passed.

The daemon must be stopped during rotation: rotate acquires an advisory
lock that a running serve process also holds, so the two cannot race.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMasterKeyRotate(cmd, cfgPath, verbose, allowEmpty)
		},
	}
	cmd.Flags().BoolVar(&allowEmpty, "allow-empty", false,
		"allow rotating on a zero-account database (fresh install); without "+
			"this, rotate refuses to swap the key when no account envelope "+
			"verifies the current master key")
	return cmd
}

func runMasterKeyRotate(cmd *cobra.Command, cfgPath *string, verbose *bool, allowEmpty bool) error {
	// loadConfigUnchecked: rotate is a bootstrap/maintenance op like
	// generate + migrate; it needs only master_key.path and store.path,
	// not the serve-time OIDC fields.
	cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
	if err != nil {
		return err
	}
	return rotateMasterKey(cmd.Context(), logger, rotateParams{
		MasterKeyPath: cfg.MasterKey.Path,
		StorePath:     cfg.Store.Path,
		MigrationsDir: cfg.Store.MigrationsDir,
		AllowEmpty:    allowEmpty,
	})
}

// rotateParams carries the explicit inputs rotateMasterKey needs, so the
// rotation core is testable without plumbing a full config file.
type rotateParams struct {
	MasterKeyPath string
	StorePath     string
	MigrationsDir string
	AllowEmpty    bool
}

// rotateMasterKey is the rotation core extracted from the cobra command
// so tests can drive it with explicit paths. See newMasterKeyRotateCmd's
// docstring for the full crash-safety / locking / empty-DB rationale.
func rotateMasterKey(ctx context.Context, logger *slog.Logger, p rotateParams) error {
	// Concurrency lock: refuse if a daemon (or another rotation) holds
	// the same advisory lock. Acquired before any key material is loaded
	// so we bail early on contention. Held for the whole operation.
	//
	// Governing: ADR-0003 (envelope encryption); #50.
	lock, err := filelock.Acquire(MasterKeyLockPath(p.MasterKeyPath))
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			return fmt.Errorf("master-key rotate: another process holds the master-key lock at %s; stop the reduit daemon (and any other rotation) before rotating: %w",
				MasterKeyLockPath(p.MasterKeyPath), err)
		}
		return fmt.Errorf("acquire master-key lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	exists, err := cryptenv.MasterKeyExists(p.MasterKeyPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("master key not found at %s; run `reduit master-key generate` first",
			p.MasterKeyPath)
	}
	oldKey, err := cryptenv.LoadMasterKey(p.MasterKeyPath)
	if err != nil {
		return fmt.Errorf("load current master key: %w", err)
	}
	// Zero both master keys when we're done — they are the most sensitive
	// bytes this process touches. Mirrors the zeroDataKey discipline in
	// internal/account. (#50)
	defer oldKey.Zero()
	newKey, err := cryptenv.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("generate new master key: %w", err)
	}
	defer newKey.Zero()

	st, err := store.Open(p.StorePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(p.MigrationsDir); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}

	// Service is constructed with the OLD key so RewrapEnvelopes unseals
	// existing envelopes with it and re-seals under newKey.
	svc := account.New(st, oldKey)
	n, err := svc.RewrapEnvelopes(ctx, newKey)
	if err != nil {
		// On ErrMasterKeyMismatch (or any other error) the transaction
		// already rolled back and the key file is untouched — the system
		// is exactly as it was before the command ran.
		return fmt.Errorf("rewrap envelopes: %w", err)
	}

	// Empty-DB guard: with zero accounts, RewrapEnvelopes never opened a
	// single envelope, so nothing verified that oldKey is actually the
	// live key. Swapping anyway would normalise an unverified key change.
	// Refuse unless the operator opts in for a genuine fresh install.
	//
	// Governing: ADR-0003 (envelope encryption); #50.
	if n == 0 && !p.AllowEmpty {
		return errors.New("master-key rotate: no accounts to re-wrap; refusing to rotate master key without verifying the current key unsealed an existing envelope — pass --allow-empty to override (fresh-install case)")
	}

	// Envelopes are committed under newKey, but under synchronous=NORMAL +
	// WAL a COMMIT is not yet durable against power loss — force a full
	// checkpoint so the committed frames hit the main DB file BEFORE we
	// swap the key. Only proceed if the checkpoint succeeded; otherwise
	// the "DB before file" crash-safety ordering would be a lie. The DB
	// is already re-wrapped under the new key here, so a failed checkpoint
	// leaves the fail-safe state (old key live, ErrMasterKeyMismatch on
	// re-run, no data lost).
	//
	// Governing: ADR-0006 (SQLite + WAL, synchronous=NORMAL); #50.
	if err := st.CheckpointTruncate(); err != nil {
		return fmt.Errorf("checkpoint WAL before key swap (DB re-wrapped under the NEW key but durability unconfirmed; the OLD key is still live, so re-running rotate is safe): %w", err)
	}

	// Back up the OLD key, then atomically swap the file to newKey. See
	// the command docstring for why this ordering fails safe. The .bak
	// name carries a UTC timestamp AND a random hex suffix: a second-
	// granularity timestamp alone collides if two rotations land in the
	// same second, and because WriteMasterKey is O_EXCL that collision
	// would abort AFTER the DB commit + checkpoint — manufacturing the
	// exact split-brain (DB on new key, file never swapped) the ordering
	// is meant to avoid. The random suffix makes the backup name unique
	// so the swap never fails on a name clash.
	suffix, err := randHex(4)
	if err != nil {
		return fmt.Errorf("generate backup suffix: %w", err)
	}
	bakPath := fmt.Sprintf("%s.%s.%s.bak", p.MasterKeyPath, time.Now().UTC().Format("20060102T150405Z"), suffix)
	if err := cryptenv.WriteMasterKey(bakPath, oldKey); err != nil {
		return fmt.Errorf("back up old master key to %s (DB already re-wrapped under the NEW key; restore the new key manually before serving): %w", bakPath, err)
	}
	if err := cryptenv.WriteMasterKeyAtomic(p.MasterKeyPath, newKey); err != nil {
		return fmt.Errorf("swap master key file (DB already re-wrapped under the NEW key; old key backed up at %s): %w", bakPath, err)
	}

	logger.Info("master key rotated",
		slog.String("path", p.MasterKeyPath),
		slog.String("old_key_backup", bakPath),
		slog.Int("accounts_rewrapped", n),
		slog.String("note", "verify the daemon starts, then delete the .bak; back the new key up out of band"))
	return nil
}

// randHex returns n random bytes hex-encoded (2n chars). Used to make
// the old-key .bak filename collision-proof within a single second.
func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
