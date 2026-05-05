package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/joestump/reduit/internal/cryptenv"
)

func newMasterKeyCmd(cfgPath *string, verbose *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "master-key",
		Short: "Manage the service master key (envelope-encryption root)",
		Long: `The service master key seals every account's per-account data key.
Loss of the master key = total data loss. Back it up out of band.`,
	}
	cmd.AddCommand(newMasterKeyGenerateCmd(cfgPath, verbose))
	return cmd
}

func newMasterKeyGenerateCmd(cfgPath *string, verbose *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "generate",
		Short: "Generate a new master key and write it to the configured path",
		Long: `Refuses to overwrite an existing master key — protects against
accidental rotation that would orphan every account's data key.
Use the (deferred) rotate subcommand for a controlled rotation.`,
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
