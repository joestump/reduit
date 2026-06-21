package cli

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/account"
	"github.com/joestump/reduit/internal/auth"
	"github.com/joestump/reduit/internal/auth/mcptoken"
	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	authsession "github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/config"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/imapserver"
	"github.com/joestump/reduit/internal/mcpserver"
	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/protonlive"
	"github.com/joestump/reduit/internal/pubsub"
	"github.com/joestump/reduit/internal/retention"
	"github.com/joestump/reduit/internal/server"
	"github.com/joestump/reduit/internal/smtpserver"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/tlsloader"
	"github.com/joestump/reduit/internal/users"
)

func newServeCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the Reduit daemon",
		Long: `Starts the Reduit daemon: opens the SQLite store, loads the
master key, hot-reloads TLS certificates, and serves HTTPS.
v0.1 ships only the HTTPS listener with /healthz and /readyz; IMAPS,
SMTPS, and MCP wire up in subsequent milestones.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), cfgPath, verbose)
		},
	}
}

func runServe(ctx context.Context, cfgPath *string, verbose *bool) error {
	cfg, logger, err := loadConfig(cfgPath, verbose)
	if err != nil {
		return err
	}

	logger.Info("reduit starting", slog.String("version", Version))

	// Master key — fail fast if it isn't on disk yet (operator must
	// have run `reduit master-key generate` before first serve).
	exists, err := cryptenv.MasterKeyExists(cfg.MasterKey.Path)
	if err != nil {
		return fmt.Errorf("master key check: %w", err)
	}
	if !exists {
		return fmt.Errorf("master key not found at %s; run `reduit master-key generate` first",
			cfg.MasterKey.Path)
	}
	masterKey, err := cryptenv.LoadMasterKey(cfg.MasterKey.Path)
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}
	logger.Info("master key loaded", slog.String("path", cfg.MasterKey.Path))

	// Store — open + migrate.
	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(cfg.Store.MigrationsDir); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}
	logger.Info("store ready", slog.String("path", st.Path()))

	// TLS loader. Skipped entirely when tls.disabled is set -- in that
	// mode reduit serves plaintext HTTP from the admin/MCP listener
	// and assumes a TLS-terminating reverse proxy (Caddy/Traefik) sits
	// in front. Mail listeners (IMAPS/SMTPS) cannot run in this mode;
	// config.Validate enforces that constraint.
	var loader *tlsloader.Loader
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if cfg.TLS.Disabled {
		logger.Info("tls disabled; admin/MCP listener will serve plaintext HTTP -- reverse proxy MUST terminate TLS in front")
		// SCS session cookie + the OIDC bind cookie (`__Host-Reduit-
		// Bind`) are both written with Secure=true. Browsers honor that
		// only when the page is served over HTTPS. With tls.disabled
		// set, that's the upstream proxy's job: the public URL MUST be
		// HTTPS or the browser silently drops the cookie and login
		// fails with no useful error. Loud warning here so the
		// operator sees it on every restart -- there is no programmatic
		// signal we can interlock against without parsing the proxy's
		// inbound headers.
		logger.Warn("tls.disabled: the upstream reverse proxy MUST present HTTPS to the browser -- HTTP-direct access will silently drop session cookies (Secure flag) and break login")
	} else {
		loader, err = tlsloader.New(cfg.TLS.CertPath, cfg.TLS.KeyPath, logger)
		if err != nil {
			return fmt.Errorf("tls loader: %w", err)
		}
		logger.Info("tls cert loaded",
			slog.String("cert_path", cfg.TLS.CertPath),
			slog.String("key_path", cfg.TLS.KeyPath))

		// Watcher in a goroutine.
		go func() {
			if err := loader.Watch(ctx); err != nil {
				logger.Error("tls watcher exited", slog.String("error", err.Error()))
			}
		}()
	}

	// Defense-in-depth: refuse to start mail listeners when the TLS
	// loader is nil. config.Validate already enforces the
	// tls.disabled + (imap_addr|smtp_addr) mutual exclusion at config
	// load, but a future code path that constructs the IMAPS/SMTPS
	// servers here without consulting `loader` would silently bypass
	// that check. Keep this guard adjacent to the loader construction
	// so the invariant is local to anyone wiring up new mail
	// listeners.
	//
	// Governing: config.Validate companion (tls.disabled + mail-addr
	// exclusion in internal/config/config.go); issue #86.
	if loader == nil && (cfg.Server.IMAPAddr != "" || cfg.Server.SMTPAddr != "") {
		return errors.New("runServe: refusing to start mail listeners without TLS; tls.disabled=true forbids imap_addr and smtp_addr")
	}

	// Session manager — backed by the same SQLite handle as the rest
	// of the store. The migration created the `sessions` table; the
	// scs sweep goroutine owns expiry cleanup.
	//
	// Governing: ADR-0004 (OIDC sessions in SCS over SQLite),
	// SPEC-0005 REQ "Authentication Gating".
	scsMgr, sessionCleanup, err := authsession.New(st.DB.DB, authsession.Options{})
	if err != nil {
		return fmt.Errorf("session manager: %w", err)
	}
	defer sessionCleanup()
	logger.Info("session manager ready",
		slog.String("cookie", authsession.CookieName))

	// OIDC client — only constructed when the HTTP listener is active.
	// config.Validate already enforces issuer/client/redirect presence
	// when http_addr is set, so a nil OIDC.Client here means "no HTTP
	// server", not "misconfiguration".
	//
	// Governing: ADR-0004 (OIDC), SPEC-0005 REQ "OIDC Login Flow".
	var (
		oidcClient  *authoidc.Client
		preSessions *authoidc.PreSessionStore
	)
	if cfg.Server.HTTPAddr != "" {
		oidcClient, err = authoidc.New(ctx, authoidc.Config{
			IssuerURL:    cfg.OIDC.IssuerURL,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
			Scopes:       cfg.OIDC.Scopes,
		})
		if err != nil {
			return fmt.Errorf("oidc client: %w", err)
		}
		logger.Info("oidc client ready",
			slog.String("issuer", cfg.OIDC.IssuerURL),
			slog.String("client_id", cfg.OIDC.ClientID))
		preSessions = authoidc.NewPreSessionStore(authoidc.DefaultPreSessionTTL)
	}

	// Users + account services feed the dashboard, the OIDC callback,
	// and the wizard (#24). Constructed here (rather than per-request)
	// so the underlying *sqlx.DB / master key stay singletons.
	usersService := users.New(st)
	accountService := account.New(st, masterKey)

	// Status bus + transition publisher for the admin-UI SSE stream.
	// The account service fires a post-commit callback on every
	// lifecycle transition (suspend, reactivate, delete, ...); we
	// republish each as a pubsub StateChanged update keyed on the
	// account's status topic, which the SSE handler at
	// GET /sse/accounts/{id}/status fans out to subscribed dashboard
	// cards. The callback is bounded (a single non-blocking Publish)
	// per the OnTransition contract. The bus is Closed on shutdown so
	// any open SSE streams terminate cleanly.
	//
	// A dedicated bus (rather than the IMAP IDLE bus) keeps the status
	// topic ("status:<id>") disjoint from the IDLE topic
	// ("<id>:<mailbox>"); the sync supervisor and IMAP server are wired
	// in a later milestone and will get their own bus instance.
	//
	// Governing: SPEC-0005 REQ "Sync Status via SSE", ADR-0005
	// (HTMX + SSE).
	statusBus := pubsub.New()
	defer statusBus.Close()
	unsubscribeStatus := accountService.OnTransition(
		func(_ context.Context, prev, next account.State, a *account.Account) {
			statusBus.Publish(pubsub.StatusKey(a.ID), pubsub.Update{
				Kind: pubsub.StateChanged,
				From: string(prev),
				To:   string(next),
			})
		})
	defer unsubscribeStatus()

	// Pending-account retention sweep. The wizard creates a row in
	// state pending_proton_setup before Proton login completes; if
	// the wizard's in-memory session expires (or the operator never
	// finishes the flow), the row stays in the DB indefinitely. This
	// goroutine runs hourly and soft-deletes any pending row older
	// than pendingProtonSetupRetention. Pre-alpha: hardcoded; lift
	// to config when retention windows become operator-tunable.
	//
	// The first sweep fires immediately so a freshly-restarted
	// daemon clears accumulated orphans without waiting an hour;
	// subsequent sweeps follow the ticker.
	//
	// Governing: SPEC-0001 REQ "Account Lifecycle States"; SPEC-0005
	// REQ "Add-Proton-Account Wizard"; issue #82.
	go runPendingAccountSweep(ctx, accountService, logger)

	// Retention sweep job — hard-deletes soft-deleted accounts that have
	// exceeded the configured retention window (default 30d). Cascade
	// fires on all per-account FK tables via ON DELETE CASCADE. Each
	// deletion is logged at INFO with account_id + oidc_subject per
	// SPEC-0001 REQ "Account Hard Delete After Retention".
	//
	// Governing: SPEC-0001 REQ "Account Hard Delete After Retention",
	// ADR-0006 (SQLite).
	{
		retentionPeriod, err := config.ParseDuration(cfg.Store.RetentionPeriod, retention.DefaultRetentionPeriod)
		if err != nil {
			return fmt.Errorf("store.retention_period: %w", err)
		}
		sweepInterval, err := config.ParseDuration(cfg.Store.SweepInterval, retention.DefaultSweepInterval)
		if err != nil {
			return fmt.Errorf("store.sweep_interval: %w", err)
		}
		sweeper := retention.New(retention.Config{
			DB:              st.DB,
			RetentionPeriod: retentionPeriod,
			SweepInterval:   sweepInterval,
			Logger:          logger,
		})
		logger.Info("retention sweeper started",
			slog.Duration("retention_period", retentionPeriod),
			slog.Duration("sweep_interval", sweepInterval))
		go sweeper.Run(ctx)
	}

	// Orphan session_owners sweep. Re-logins through the same browser
	// leave the prior token's session_owners row stranded because
	// SCS's RenewToken mints a fresh token for subsequent writes
	// (and we can't FK-cascade off sessions(token) because SCS
	// commits via REPLACE INTO, which would clobber the bind
	// mid-handler -- see migration 20260502000005's commentary).
	// Single bulk DELETE keyed on tokens not present in the sessions
	// table; tiny rows so an hourly cadence keeps bloat trivial.
	//
	// First sweep runs immediately so a freshly-restarted daemon
	// clears accumulated orphans without waiting a full hour.
	//
	// Governing: ADR-0010, SPEC-0005 REQ "OIDC Login Flow"; issue #70.
	go runSessionOwnersSweep(ctx, st.DB.DB, logger)

	// Proton client manager + wizard session store (#24). The manager
	// is process-scoped (one resty client, many minted Clients); the
	// wizard store keeps in-memory partial-credentials state with a
	// 30-min idle TTL. Both are nil-safe in NewForTest fixtures that
	// don't exercise /accounts/setup.
	//
	// Governing: ADR-0001, SPEC-0005 REQ "Add-Proton-Account Wizard".
	// Proton's API rejects unknown X-Pm-Appversion values:
	//   - "go-proton-api" (the lib default) -> Code=2064 platform
	//     not valid
	//   - "Bridge_<sha>" -> Code=5002 invalid app version
	// Proton expects Bridge_<semver>+<suffix> -- they regex-match
	// the semver shape, then check the prefix is a known platform.
	// We identify as a Bridge variant (semantically honest: Reduit
	// is bridge-like, relays a Proton mailbox to IMAP/SMTP
	// clients). The +reduit suffix records the client identity.
	// Pin a fixed semver -- bumping it on every release is
	// pointless because Proton doesn't accept arbitrary versions
	// on the manifest anyway.
	protonMgr := proton.NewManager(
		proton.WithLogger(logger),
		proton.WithAppVersion("Bridge_3.0.0+reduit"),
	)
	defer protonMgr.Close()
	wizardSessions := server.NewWizardSessionStore(server.DefaultWizardIdleTimeout)

	// Live-client registry: the process-wide account-ID -> unlocked
	// proton.Client map (#28). The wizard registers an account's client
	// here on a successful unlock; the IMAP backend, MCP resolver, and
	// SMTP outbox resolve the same live client out of it so FETCH BODY[]
	// (#13) and MCP get_message (#14) can decrypt bodies in the daemon.
	//
	// The Lifecycle drop callback is registered on the account service's
	// transition stream so an account leaving `active` has its unlocked
	// keyring dropped (and its upstream session revoked), mirroring where
	// the sync supervisor stops the worker.
	//
	// NOTE: boot-time re-unlock of already-active accounts is NOT wired
	// here yet. ReUnlock needs the Proton *session UID*, which Reduit
	// does not persist today (only the refresh token + mailbox passphrase
	// are sealed). Until a session-UID column + accessor land, a daemon
	// restart leaves already-active accounts without an unlocked keyring
	// until the operator re-runs the wizard; body fetches return a
	// transient IMAP NO / MCP auth_required in the meantime. The
	// Lifecycle is constructed with a nil UIDSource so the gap is
	// explicit and logged per-account at WARN if a boot re-unlock is ever
	// attempted.
	//
	// Governing: ADR-0003, ADR-0001, SPEC-0002 REQ "One Worker Per Active
	// Account"; issue #28.
	liveClients := protonlive.New(logger)
	defer func() {
		closeCtx, cancelClose := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelClose()
		liveClients.CloseAll(closeCtx)
	}()
	liveLifecycle := protonlive.NewLifecycle(liveClients, protonMgr, accountService, nil, accountService, logger)
	unsubscribeLive := accountService.OnTransition(func(cbCtx context.Context, prev, next account.State, a *account.Account) {
		if a == nil {
			return
		}
		liveLifecycle.OnAccountStateChange(cbCtx, prev, next, a.ID)
	})
	defer unsubscribeLive()

	// MCP server (per ADR-0008): mounted at `/mcp` on the same admin
	// HTTPS listener, behind its own bearer-auth + per-account
	// concurrency-cap middleware. Constructed only when the HTTP
	// listener is active (no http_addr -> no admin surface, so no
	// MCP either). The bearer validator is shared with any other
	// future bearer surface; MCP is the only consumer today.
	//
	// Per-account concurrency cap is read from MCP_PER_ACCOUNT_CONCURRENCY
	// (default 4) per SPEC-0006; queue depth is fixed at 16. The
	// validator's SubjectResolver is wired against the account/user
	// services so MCP-token Principals carry an OIDC subject for log
	// correlation alongside the OIDC-bearer Principals.
	//
	// Governing: ADR-0008, SPEC-0006 REQ "Bearer Authentication
	// Required", SPEC-0006 REQ "Per-Account Concurrency Limit".
	var mcpHandler http.Handler
	if cfg.Server.HTTPAddr != "" {
		mcpTokens := mcptoken.NewRepository(st.DB)
		validator := auth.NewBearerValidator(oidcClient, mcpTokens).
			WithSubjectResolver(makeSubjectResolver(accountService, usersService))
		// Tools is intentionally left nil here: the read/write/send tool
		// surface (issue #14, SPEC-0006 REQ "Required Tool Set") is fully
		// implemented behind mcpserver.ToolDeps, but its ClientResolver
		// (account ID -> session-bearing proton.Client) and Outbox
		// dependencies require the account->Proton-client hydration path
		// and the SPEC-0004 SMTP outbox, both of which are wired in the
		// sync/outbox milestone (the same milestone that constructs
		// imapserver.Backend's ProtonClientLookup and smtpserver). Until
		// that path exists in this composition root, /mcp serves auth +
		// concurrency + an empty tools/list. Flip Tools to a populated
		// *mcpserver.ToolDeps once the resolver + outbox are available.
		//
		// Governing: SPEC-0006 REQ "Required Tool Set", ADR-0008.
		mcpSrv := mcpserver.New(mcpserver.Deps{
			Validator: validator,
			Accounts:  accountService,
			Users:     usersService,
			Limiter: mcpserver.NewConcurrencyLimiter(
				mcpserver.PerAccountConcurrencyFromEnv(os.Getenv),
				mcpserver.DefaultQueueDepth,
			),
			Logger: logger,
			Tools:  nil,
		})
		mcpHandler = mcpSrv.Handler()
		logger.Info("mcp server ready",
			slog.Int("per_account_concurrency",
				mcpserver.PerAccountConcurrencyFromEnv(os.Getenv)),
			slog.Int("queue_depth", mcpserver.DefaultQueueDepth))
	}

	// IMAP session registry — constructed here so action handlers can
	// call DropForAccount on credential rotation or account suspension
	// per SPEC-0005 REQ "Per-User IMAP/SMTP Credentials" and REQ "Admin
	// Account Management". The IMAP server (imapserver.New) is wired in
	// a later milestone; for now the registry is created standalone and
	// passed via server.Deps.IMAPSessions so the drop path is live as
	// soon as any real IMAP sessions register themselves.
	//
	// TODO(serve-wiring): when imapserver.New AND the sync Supervisor are
	// wired here, the sync.Config MUST set Reconciler =
	// sync.NewMoveReconciler(mailbox.New(st), logger). The IMAP MOVE
	// handler records `pending_unlabels` rows when a Proton source-unlabel
	// fails; the MoveReconciler is the ONLY drainer for that table. Wiring
	// the IMAP server without the reconciler would let those rows
	// accumulate and leave messages stuck in two mailboxes.
	//
	// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials",
	// REQ "Admin Account Management",
	// SPEC-0003 REQ "Moving between system folders changes Proton system
	// flag".
	imapSessions := imapserver.NewSessions()

	// SMTP session registry — mirrors imapSessions. SPEC-0005 requires
	// both IMAP and SMTP sessions to be dropped within 1s on credential
	// rotation and account suspension. The SMTP server is wired in a
	// later milestone; the registry is created here so the drop path is
	// live as soon as any SMTP sessions register themselves.
	//
	// Governing: SPEC-0005 REQ "Per-User IMAP/SMTP Credentials",
	// REQ "Admin Account Management".
	smtpSessions := smtpserver.NewSessions()

	// HTTP server. GetCertificate is nil when tls.disabled — server.New
	// detects that and skips ListenAndServeTLS in favor of plain HTTP.
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if loader != nil {
		getCert = loader.GetCertificate
	}
	srv := server.New(cfg.Server.HTTPAddr, server.Deps{
		Store:          st,
		GetCertificate: getCert,
		Logger:         logger,
		Version:        Version,
		SessionManager: scsMgr,
		OIDC:           oidcClient,
		PreSessions:    preSessions,
		UsersService:   usersService,
		AccountService: accountService,
		ProtonManager:  protonMgr,
		WizardSessions: wizardSessions,
		LiveClients:    liveClients,
		AdminSubjects:  cfg.OIDC.AdminSubjects,
		AutoCreate:     cfg.OIDC.AutoCreate,
		TrustedProxies: cfg.Server.TrustedProxies,
		MCPHandler:     mcpHandler,
		IMAPSessions:   imapSessions,
		SMTPSessions:   smtpSessions,
		StatusBus:      statusBus,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining...")
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown error", slog.String("error", err.Error()))
	}

	logger.Info("reduit stopped")
	return nil
}

// noteEnv is reserved for future use — it will summarize the env-var
// overrides applied at startup so operators can debug "why is the
// config not what I expect".
var _ = os.Getenv

// makeSubjectResolver returns a SubjectResolver suitable for the
// bearer validator's MCP-token branch. It chains accounts.GetByID ->
// users.GetByID(account.UserID) -> users.OIDCSubject so an MCP-token
// Principal's Subject field is populated for log correlation,
// matching the OIDC-bearer Principal shape. Errors are intentionally
// surfaced -- the validator swallows them per its docstring (Subject
// is audit metadata, not an authz key, so a transient DB error MUST
// NOT 401 the caller).
//
// Governing: SPEC-0006 REQ "Bearer Authentication Required" (Subject
// audit metadata for MCP-token bearers); ADR-0010 (OIDC sub lives
// on users, not accounts).
func makeSubjectResolver(accounts account.Service, usrs users.Service) func(ctx context.Context, accountID string) (string, error) {
	return func(ctx context.Context, accountID string) (string, error) {
		acct, err := accounts.GetByID(ctx, accountID)
		if err != nil {
			return "", err
		}
		u, err := usrs.GetByID(ctx, acct.UserID)
		if err != nil {
			return "", err
		}
		return u.OIDCSubject, nil
	}
}

// pendingAccountSweepInterval is how often the retention sweep runs.
// One hour gives the system rapid-enough cleanup that orphan rows do
// not pile up between restarts, while keeping the per-tick query
// volume trivial against a single bulk UPDATE.
const pendingAccountSweepInterval = time.Hour

// pendingProtonSetupRetention is the age past which an account row
// stuck in state pending_proton_setup is considered abandoned and
// gets soft-deleted. 24h gives a generous human window for an
// operator to resume an interrupted wizard (e.g., started Friday
// evening, finished Monday morning) while still bounding orphan
// growth. Pre-alpha: hardcoded; lift to config when retention
// windows become operator-tunable.
//
// Governing: SPEC-0005 REQ "Add-Proton-Account Wizard"; issue #82.
const pendingProtonSetupRetention = 24 * time.Hour

// runPendingAccountSweep is the goroutine body for the sweep
// scheduled out of runServe. It exits when ctx is cancelled (i.e.,
// SIGINT/SIGTERM during shutdown). Errors from the sweep itself are
// logged-and-swallowed: a transient DB error here MUST NOT take
// down the daemon, and the next tick will pick up the same backlog.
//
// Each sweep runs against context.Background() with a 30s timeout
// so a slow query cannot stall shutdown -- the parent ctx cancellation
// is observed between ticks, not inside the SQL call. 30s is generous
// for a single bulk UPDATE on the accounts table.
//
// Governing: SPEC-0001 REQ "Account Lifecycle States"; SPEC-0005 REQ
// "Add-Proton-Account Wizard"; issue #82.
func runPendingAccountSweep(ctx context.Context, svc account.Service, logger *slog.Logger) {
	tick := time.NewTicker(pendingAccountSweepInterval)
	defer tick.Stop()

	sweep := func() {
		// Derive from parent ctx so a SIGINT mid-query cancels the
		// SQL call instead of letting it linger past defer st.Close()
		// in runServe. 30s is generous for a single bulk UPDATE; the
		// deadline only matters if the DB is wedged.
		opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		n, err := svc.SoftDeleteOldPending(opCtx, pendingProtonSetupRetention)
		if err != nil {
			// Cancellation during shutdown is expected; demote to debug
			// so we don't pollute shutdown logs.
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Warn("pending-account sweep failed",
				slog.String("error", err.Error()))
			return
		}
		if n > 0 {
			logger.Info("pending-account sweep soft-deleted orphans",
				slog.Int64("count", n),
				slog.Duration("older_than", pendingProtonSetupRetention))
		}
	}

	// First sweep runs immediately so a freshly-restarted daemon
	// clears accumulated orphans without waiting a full interval.
	sweep()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sweep()
		}
	}
}

// sessionOwnersSweepInterval matches pendingAccountSweepInterval --
// orphan rows are tiny (~50 bytes) so we don't need to chase them
// urgently, but an hourly cadence keeps the per-tick work trivial
// and bounds index bloat well below anything an operator would
// notice. Pre-alpha: hardcoded.
//
// Governing: issue #70.
const sessionOwnersSweepInterval = time.Hour

// runSessionOwnersSweep is the goroutine body for the orphan
// session_owners cleanup scheduled out of runServe. Mirrors
// runPendingAccountSweep:
//
//   - first sweep fires immediately so a fresh restart clears
//     accumulated orphans without waiting the full interval
//   - subsequent sweeps follow the ticker
//   - each call gets a 30s deadline derived from parent ctx so a
//     SIGINT mid-query cancels rather than lingering past
//     `defer st.Close()` in runServe
//   - context.Canceled during shutdown is silenced so it doesn't
//     pollute shutdown logs
//   - any other error is logged-and-swallowed; a transient DB error
//     MUST NOT take the daemon down, and the next tick retries
//
// Governing: ADR-0010, SPEC-0005 REQ "OIDC Login Flow"; issue #70.
func runSessionOwnersSweep(ctx context.Context, db *sql.DB, logger *slog.Logger) {
	tick := time.NewTicker(sessionOwnersSweepInterval)
	defer tick.Stop()

	sweep := func() {
		opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		n, err := authsession.SweepOrphanSessionOwners(opCtx, db)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Warn("session_owners sweep failed",
				slog.String("error", err.Error()))
			return
		}
		if n > 0 {
			logger.Info("session_owners sweep deleted orphans",
				slog.Int64("count", n))
		}
	}

	sweep()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			sweep()
		}
	}
}
