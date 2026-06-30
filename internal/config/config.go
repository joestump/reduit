// Package config holds Reduit's runtime configuration.
//
// Configuration is loaded from a YAML file (path resolved by precedence:
// --config flag, REDUIT_CONFIG env, ~/.config/reduit/reduit.yaml,
// ./reduit.yaml) with environment-variable overrides via the REDUIT_
// prefix.
//
// Governing: ADR-0012 (single-user local-first), ADR-0006 (SQLite path),
// ADR-0018 (one LLM egress, two model roles).
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Config is the top-level runtime configuration.
type Config struct {
	// DataDir is the directory where Reduit stores the SQLite cache and
	// other local data. Defaults to ~/.local/share/reduit.
	//
	// Governing: ADR-0006 (SQLite cache), ADR-0013 (keychain — secrets
	// live in the OS keychain, not here).
	DataDir string `mapstructure:"data_dir"`

	// LLM configures the single LLM egress and the two model roles.
	//
	// Governing: ADR-0018 (one OpenAI-compatible client, two model roles).
	LLM LLMConfig `mapstructure:"llm"`

	// Logger configures the structured logger.
	Logger LoggerConfig `mapstructure:"logger"`

	// UI configures the optional local browse UI.
	//
	// Governing: ADR-0005 (loopback HTMX UI).
	UI UIConfig `mapstructure:"ui"`
}

// LLMConfig configures the single OpenAI-compatible LLM egress and its
// two independently-configured model roles (ADR-0018):
//
//   - Text/embedding role — the embedding model (Embed) and the text
//     chat model (search, summarise, contact-facts extraction, RAG).
//     Local by default; BaseURL/APIKey back both.
//   - Multimodal role — the OCR/vision/audio model (opt-in). Its base
//     URL, model, and key are configured independently of the text role
//     so the operator can keep text fully local while routing only media
//     to a hosted model, by deliberate choice. Pointing it at a hosted
//     endpoint is Reduit's heaviest, most sensitive egress (raw
//     image/audio bytes).
//
// API keys come from the environment (REDUIT_LLM_API_KEY,
// REDUIT_LLM_MULTIMODAL_API_KEY), with `_FILE` indirection for
// secret-file delivery; they are never committed and never logged.
//
// Governing: ADR-0018 (one LLM egress, two model roles, secrets via env),
// SPEC-0008 (text/embedding role), SPEC-0009 (multimodal role).
type LLMConfig struct {
	// BaseURL is the OpenAI-compatible endpoint for the text/embedding
	// role (e.g. LiteLLM proxy → Ollama). Defaults to
	// http://localhost:4000/v1.
	BaseURL string `mapstructure:"base_url"`
	// APIKey authenticates the text/embedding role. Sourced from
	// REDUIT_LLM_API_KEY (or REDUIT_LLM_API_KEY_FILE). Empty is allowed:
	// local proxies/Ollama accept any or no key. Never committed.
	APIKey string `mapstructure:"api_key"`
	// TextModel is the chat model for text-only tasks (search,
	// summarise, contact-facts extraction, RAG).
	TextModel string `mapstructure:"text_model"`
	// EmbedModel is the embedding model for the text/embedding role.
	// Defaults to nomic-embed-text (ADR-0018, on-device out of the box).
	EmbedModel string `mapstructure:"embed_model"`

	// MultimodalBaseURL is the OpenAI-compatible endpoint for the
	// multimodal role. Empty disables the role (opt-in); set it to route
	// OCR/vision/audio to a separate endpoint from the text role.
	MultimodalBaseURL string `mapstructure:"multimodal_base_url"`
	// MultimodalAPIKey authenticates the multimodal role. Sourced from
	// REDUIT_LLM_MULTIMODAL_API_KEY (or ..._FILE). Never committed.
	MultimodalAPIKey string `mapstructure:"multimodal_api_key"`
	// MultimodalModel is the model name for OCR/vision/audio extraction.
	// Empty disables multimodal extraction.
	MultimodalModel string `mapstructure:"multimodal_model"`
}

// LoggerConfig configures the structured logger.
type LoggerConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `mapstructure:"level"`
	// Format is "text" (human-readable) or "json".
	Format string `mapstructure:"format"`
}

// UIConfig configures the optional local browse UI.
type UIConfig struct {
	// ListenAddr is the address the local browse UI listens on.
	// Defaults to 127.0.0.1:8787. Non-loopback binds are allowed
	// but log a loud warning (no auth is shipped).
	//
	// Governing: ADR-0005, ADR-0012 (no auth, loopback default).
	ListenAddr string `mapstructure:"listen_addr"`
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() Config {
	home, _ := os.UserHomeDir()
	return Config{
		DataDir: filepath.Join(home, ".local", "share", "reduit"),
		LLM: LLMConfig{
			BaseURL:    "http://localhost:4000/v1",
			TextModel:  "ollama/llama3.2",
			EmbedModel: "nomic-embed-text",
			// Multimodal role is opt-in (ADR-0018): left unconfigured by
			// default so nothing media-related leaves the box until the
			// operator deliberately points it somewhere.
		},
		Logger: LoggerConfig{
			Level:  "info",
			Format: "text",
		},
		UI: UIConfig{
			ListenAddr: "127.0.0.1:8787",
		},
	}
}

// DBPath returns the absolute path to the SQLite database file inside
// DataDir.
func (c Config) DBPath() string {
	return filepath.Join(c.DataDir, "reduit.db")
}

// Validate returns an error describing every problem with the
// configuration. A nil return means the configuration is usable.
func (c Config) Validate() error {
	var errs []error
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required"))
	}
	if c.LLM.BaseURL == "" {
		errs = append(errs, errors.New("llm.base_url is required"))
	}
	switch strings.ToLower(c.Logger.Level) {
	case "", "debug", "info", "warn", "error":
	default:
		errs = append(errs, errors.New("logger.level must be one of debug, info, warn, error"))
	}
	switch strings.ToLower(c.Logger.Format) {
	case "", "text", "json":
	default:
		errs = append(errs, errors.New("logger.format must be one of text, json"))
	}
	return errors.Join(errs...)
}

// ResolveConfigPath returns the path of the configuration file to load,
// following the documented precedence. An empty return means no config
// file was found; the caller proceeds with defaults + env overrides.
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	if env := os.Getenv("REDUIT_CONFIG"); env != "" {
		return env
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".config", "reduit", "reduit.yaml"),
		"/etc/reduit/reduit.yaml",
		"./reduit.yaml",
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}
