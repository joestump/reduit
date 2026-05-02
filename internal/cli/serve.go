package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	authoidc "github.com/joestump/reduit/internal/auth/oidc"
	authsession "github.com/joestump/reduit/internal/auth/session"
	"github.com/joestump/reduit/internal/cryptenv"
	"github.com/joestump/reduit/internal/server"
	"github.com/joestump/reduit/internal/store"
	"github.com/joestump/reduit/internal/tlsloader"
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
	if _, err := cryptenv.LoadMasterKey(cfg.MasterKey.Path); err != nil {
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

	// TLS loader.
	loader, err := tlsloader.New(cfg.TLS.CertPath, cfg.TLS.KeyPath, logger)
	if err != nil {
		return fmt.Errorf("tls loader: %w", err)
	}
	logger.Info("tls cert loaded",
		slog.String("cert_path", cfg.TLS.CertPath),
		slog.String("key_path", cfg.TLS.KeyPath))

	// Signal-driven graceful shutdown context.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Watcher in a goroutine.
	go func() {
		if err := loader.Watch(ctx); err != nil {
			logger.Error("tls watcher exited", slog.String("error", err.Error()))
		}
	}()

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

	// HTTP server.
	srv := server.New(cfg.Server.HTTPAddr, server.Deps{
		Store:          st,
		GetCertificate: loader.GetCertificate,
		Logger:         logger,
		Version:        Version,
		SessionManager: scsMgr,
		OIDC:           oidcClient,
		PreSessions:    preSessions,
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
