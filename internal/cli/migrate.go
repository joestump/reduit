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
			// migrate runs at bootstrap; only the data_dir is needed to
			// derive the DB path. Skip full Validate() so callers without
			// llm.base_url configured can still run migrations.
			cfg, logger, err := loadConfigUnchecked(cfgPath, verbose)
			if err != nil {
				return err
			}
			st, err := store.Open(cfg.DBPath())
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			if err := st.Migrate(""); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			logger.Info("migrations applied", slog.String("path", st.Path()))
			return nil
		},
	}
}
