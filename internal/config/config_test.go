package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.DataDir == "" {
		t.Error("DataDir should not be empty")
	}
	if cfg.LLM.BaseURL == "" {
		t.Error("LLM.BaseURL should not be empty")
	}
	if cfg.Logger.Level == "" {
		t.Error("Logger.Level should not be empty")
	}
	if cfg.UI.ListenAddr == "" {
		t.Error("UI.ListenAddr should not be empty")
	}
}

func TestValidate(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Defaults should be valid: %v", err)
	}
}

func TestValidate_MissingDataDir(t *testing.T) {
	cfg := Defaults()
	cfg.DataDir = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing DataDir")
	}
}

func TestDBPath(t *testing.T) {
	cfg := Defaults()
	cfg.DataDir = "/tmp/test-reduit"
	want := filepath.Join("/tmp/test-reduit", "reduit.db")
	if got := cfg.DBPath(); got != want {
		t.Errorf("DBPath() = %q, want %q", got, want)
	}
}

func TestResolveConfigPath_Flag(t *testing.T) {
	got := ResolveConfigPath("/custom/path.yaml")
	if got != "/custom/path.yaml" {
		t.Errorf("ResolveConfigPath with flag: got %q, want /custom/path.yaml", got)
	}
}

func TestResolveConfigPath_Env(t *testing.T) {
	t.Setenv("REDUIT_CONFIG", "/env/path.yaml")
	got := ResolveConfigPath("")
	if got != "/env/path.yaml" {
		t.Errorf("ResolveConfigPath from env: got %q, want /env/path.yaml", got)
	}
}

func TestLoad_NoFile(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with no file: %v", err)
	}
	if cfg.DataDir == "" {
		t.Error("Load with no file should return defaults")
	}
}

func TestDefaults_LLMTwoRoles(t *testing.T) {
	cfg := Defaults()
	// Text/embedding role has sensible local defaults out of the box.
	if cfg.LLM.TextModel == "" {
		t.Error("LLM.TextModel should default")
	}
	if cfg.LLM.EmbedModel != "nomic-embed-text" {
		t.Errorf("LLM.EmbedModel = %q, want nomic-embed-text", cfg.LLM.EmbedModel)
	}
	// Multimodal role is opt-in: disabled by default (ADR-0018).
	if cfg.LLM.MultimodalModel != "" || cfg.LLM.MultimodalBaseURL != "" {
		t.Errorf("multimodal role should be unconfigured by default, got base=%q model=%q",
			cfg.LLM.MultimodalBaseURL, cfg.LLM.MultimodalModel)
	}
}

func TestLoad_LLMEnvOverrides(t *testing.T) {
	t.Setenv("REDUIT_LLM_API_KEY", "text-secret")
	t.Setenv("REDUIT_LLM_EMBED_MODEL", "custom-embed")
	t.Setenv("REDUIT_LLM_MULTIMODAL_BASE_URL", "http://mm:4001/v1")
	t.Setenv("REDUIT_LLM_MULTIMODAL_API_KEY", "mm-secret")
	t.Setenv("REDUIT_LLM_MULTIMODAL_MODEL", "vision-pro")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLM.APIKey != "text-secret" {
		t.Errorf("LLM.APIKey = %q", cfg.LLM.APIKey)
	}
	if cfg.LLM.EmbedModel != "custom-embed" {
		t.Errorf("LLM.EmbedModel = %q", cfg.LLM.EmbedModel)
	}
	if cfg.LLM.MultimodalBaseURL != "http://mm:4001/v1" {
		t.Errorf("LLM.MultimodalBaseURL = %q", cfg.LLM.MultimodalBaseURL)
	}
	if cfg.LLM.MultimodalAPIKey != "mm-secret" {
		t.Errorf("LLM.MultimodalAPIKey = %q", cfg.LLM.MultimodalAPIKey)
	}
	if cfg.LLM.MultimodalModel != "vision-pro" {
		t.Errorf("LLM.MultimodalModel = %q", cfg.LLM.MultimodalModel)
	}
}

func TestDefaults_ProtonAppVersion(t *testing.T) {
	cfg := Defaults()
	if cfg.Proton.AppVersion != "" {
		t.Errorf("Proton.AppVersion = %q, want empty (auto-detect)", cfg.Proton.AppVersion)
	}
	if cfg.Proton.HostURL != "" {
		t.Errorf("Proton.HostURL = %q, want empty (production default)", cfg.Proton.HostURL)
	}
}

func TestLoad_ProtonEnvOverrides(t *testing.T) {
	t.Setenv("REDUIT_PROTON_APP_VERSION", "macos-mail@4.0.0")
	t.Setenv("REDUIT_PROTON_HOST_URL", "https://proton.test")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proton.AppVersion != "macos-mail@4.0.0" {
		t.Errorf("Proton.AppVersion = %q", cfg.Proton.AppVersion)
	}
	if cfg.Proton.HostURL != "https://proton.test" {
		t.Errorf("Proton.HostURL = %q", cfg.Proton.HostURL)
	}
}

func TestDefaults_Sync(t *testing.T) {
	cfg := Defaults()
	if cfg.Sync.BackfillWindow != 365*24*time.Hour {
		t.Errorf("Sync.BackfillWindow = %v, want 8760h", cfg.Sync.BackfillWindow)
	}
	if cfg.Sync.Concurrency != 3 {
		t.Errorf("Sync.Concurrency = %d, want 3", cfg.Sync.Concurrency)
	}
}

func TestLoad_SyncEnvOverrides(t *testing.T) {
	t.Setenv("REDUIT_SYNC_BACKFILL_WINDOW", "720h")
	t.Setenv("REDUIT_SYNC_CONCURRENCY", "5")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Sync.BackfillWindow != 720*time.Hour {
		t.Errorf("Sync.BackfillWindow = %v, want 720h", cfg.Sync.BackfillWindow)
	}
	if cfg.Sync.Concurrency != 5 {
		t.Errorf("Sync.Concurrency = %d, want 5", cfg.Sync.Concurrency)
	}
}

func TestValidate_SyncNegative(t *testing.T) {
	cfg := Defaults()
	cfg.Sync.Concurrency = -1
	if err := cfg.Validate(); err == nil {
		t.Error("negative sync.concurrency should be rejected")
	}
	cfg = Defaults()
	cfg.Sync.BackfillWindow = -time.Hour
	if err := cfg.Validate(); err == nil {
		t.Error("negative sync.backfill_window should be rejected")
	}
}

func TestLoad_LLMKeyFromFile(t *testing.T) {
	// _FILE indirection delivers the API key from a secret file, the
	// preferred path for secret delivery (ADR-0018).
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "llm.key")
	if err := os.WriteFile(keyPath, []byte("file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDUIT_LLM_API_KEY_FILE", keyPath)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLM.APIKey != "file-secret" {
		t.Errorf("LLM.APIKey = %q, want file-secret (trimmed from file)", cfg.LLM.APIKey)
	}
}

func TestLoad_WithFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reduit.yaml")
	if err := os.WriteFile(path, []byte("data_dir: /tmp/test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir != "/tmp/test" {
		t.Errorf("DataDir = %q, want /tmp/test", cfg.DataDir)
	}
}
