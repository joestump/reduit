// Package retention implements the periodic hard-delete sweep for
// soft-deleted accounts that have exceeded the configured retention
// window.
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention",
// ADR-0006 (SQLite as persistent store).
package retention

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jmoiron/sqlx"
)

// Governing: SPEC-0001 REQ "Account Hard Delete After Retention", ADR-0006 (SQLite)

// DefaultRetentionPeriod is the minimum age a soft-deleted account must
// have reached before the sweep will hard-delete it. 30 days gives
// ample time for operators to notice an accidental deletion and restore
// the row from a backup before cascade fires.
const DefaultRetentionPeriod = 30 * 24 * time.Hour

// DefaultSweepInterval is how often the sweep runs. One hour is
// frequent enough to bound orphan accumulation while keeping the
// per-tick query load trivial against a single SQLite file.
const DefaultSweepInterval = time.Hour

// deletedAccountInfo carries the minimal fields we need to log a
// hard-delete at INFO level without including any PII beyond what
// SPEC-0001 requires (account_id + owning user's oidc_subject).
type deletedAccountInfo struct {
	AccountID   string `db:"account_id"`
	OIDCSubject string `db:"oidc_subject"`
}

// Sweeper runs a periodic hard-delete sweep that removes soft-deleted
// accounts whose deleted_at is older than RetentionPeriod. The cascade
// on every per-account FK (sync_state, mailbox_uids, outbox, etc.) fires
// automatically via ON DELETE CASCADE so the sweep only needs to touch
// the accounts table.
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention",
// ADR-0006 (SQLite + ON DELETE CASCADE).
type Sweeper struct {
	db              *sqlx.DB
	retentionPeriod time.Duration
	sweepInterval   time.Duration
	logger          *slog.Logger
	now             func() time.Time // injectable for tests
}

// Config holds the Sweeper's tunables. Zero values use the package
// defaults. Callers MUST supply a non-nil DB; Logger defaults to the
// process-wide slog default if nil.
type Config struct {
	// DB is the read/write SQLite handle. Required.
	DB *sqlx.DB
	// RetentionPeriod is the minimum age past which soft-deleted accounts
	// are hard-deleted. Defaults to DefaultRetentionPeriod (30d).
	RetentionPeriod time.Duration
	// SweepInterval is how often the sweep runs.
	// Defaults to DefaultSweepInterval (1h).
	SweepInterval time.Duration
	// Logger is used for INFO-level deletion audit records and WARN-level
	// errors. nil means slog.Default().
	Logger *slog.Logger
	// Now overrides the clock. nil means time.Now (production).
	Now func() time.Time
}

// New constructs a Sweeper from the given Config. Panics if cfg.DB is
// nil — a missing database is a programming error the caller cannot
// recover from at runtime.
func New(cfg Config) *Sweeper {
	if cfg.DB == nil {
		panic("retention.New: cfg.DB is nil")
	}
	rp := cfg.RetentionPeriod
	if rp <= 0 {
		rp = DefaultRetentionPeriod
	}
	si := cfg.SweepInterval
	if si <= 0 {
		si = DefaultSweepInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Sweeper{
		db:              cfg.DB,
		retentionPeriod: rp,
		sweepInterval:   si,
		logger:          logger,
		now:             now,
	}
}

// Run starts the sweep loop. It returns when ctx is cancelled. The
// first sweep fires immediately so a freshly-restarted daemon clears
// accumulated expired rows without waiting a full SweepInterval.
//
// Run is intended to be called as a goroutine from the serve command:
//
//	go sweeper.Run(ctx)
//
// Errors from individual sweep ticks are logged-and-swallowed so a
// transient DB error does NOT bring down the daemon; the next tick will
// pick up the same rows.
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention".
func (s *Sweeper) Run(ctx context.Context) {
	tick := time.NewTicker(s.sweepInterval)
	defer tick.Stop()

	s.sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.sweep(ctx)
		}
	}
}

// sweep performs one pass of the hard-delete sweep. It first selects
// expired soft-deleted accounts (with their owning user's oidc_subject
// for audit logging), hard-deletes them one by one, and logs each
// deletion at INFO level.
//
// Governing: SPEC-0001 REQ "Account Hard Delete After Retention" —
// "SHALL delete those rows, which SHALL cascade to all per-account
// tables, and SHALL log the deletion at INFO level with the account ID
// and the owning user's oidc_subject (no other PII)".
func (s *Sweeper) sweep(ctx context.Context) {
	// Derive from parent ctx so a SIGINT mid-query cancels the SQL
	// call. 30s is generous for a bulk query against a single SQLite
	// file; the deadline only matters if the DB is wedged.
	opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cutoff := s.now().UTC().Add(-s.retentionPeriod)

	// Select candidates first so we can log each deletion individually
	// with the account_id + oidc_subject before the row is gone.
	// Joining users here avoids a second query per row.
	//
	// Governing: SPEC-0001 REQ "Account Hard Delete After Retention" —
	// "log the deletion at INFO level with the account ID and the owning
	// user's oidc_subject (no other PII)".
	const selectQ = `
		SELECT a.id AS account_id, u.oidc_subject
		FROM accounts a
		JOIN users u ON u.id = a.user_id
		WHERE a.state = 'soft_deleted'
		  AND a.deleted_at IS NOT NULL
		  AND a.deleted_at < ?
		ORDER BY a.deleted_at ASC`

	var candidates []deletedAccountInfo
	if err := s.db.SelectContext(opCtx, &candidates, selectQ, cutoff); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		s.logger.Warn("retention sweep: candidate query failed",
			slog.String("error", err.Error()))
		return
	}

	if len(candidates) == 0 {
		return
	}

	// Hard-delete each candidate individually so we log each one at INFO
	// before the row is gone. A bulk DELETE would be more efficient but
	// would make per-row audit logging impossible without a second query.
	// Candidate counts are expected to be tiny (tens per sweep at most);
	// the individual-row cost is negligible.
	//
	// Governing: SPEC-0001 REQ "Account Hard Delete After Retention" —
	// cascade fires via ON DELETE CASCADE on every per-account FK.
	const deleteQ = `DELETE FROM accounts WHERE id = ? AND state = 'soft_deleted' AND deleted_at < ?`

	for _, c := range candidates {
		res, err := s.db.ExecContext(opCtx, deleteQ, c.AccountID, cutoff)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			s.logger.Warn("retention sweep: hard-delete failed",
				slog.String("account_id", c.AccountID),
				slog.String("error", err.Error()))
			continue
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			// Another sweep or admin action beat us to it — no-op.
			continue
		}
		// Governing: SPEC-0001 REQ "Account Hard Delete After Retention" —
		// log INFO with account_id + oidc_subject; no other PII.
		s.logger.Info("retention sweep: hard-deleted soft-deleted account",
			slog.String("account_id", c.AccountID),
			slog.String("oidc_subject", c.OIDCSubject))
	}
}
