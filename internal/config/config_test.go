package config

import (
	"os"
	"path/filepath"
	"testing"
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
