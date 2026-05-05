package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/store"
)

func newMigrateCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run pending database migrations",
		Long: `Opens the configured SQLite database and runs all pending goose
migrations. Idempotent — safe to run on every deploy.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// migrate runs at bootstrap; OIDC client + endpoints
			// don't exist yet. Only store.path is needed.
			cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}
			st, err := store.Open(cfg.Store.Path)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			if err := st.Migrate(cfg.Store.MigrationsDir); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			logger.Info("migrations applied", slog.String("path", st.Path()))
			return nil
		},
	}
}
