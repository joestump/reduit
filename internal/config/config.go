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
	"time"
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

	// Proton configures the go-proton-api client used by auth/sync/send.
	//
	// Governing: SPEC-0007 (onboarding & auth), ADR-0001 (go-proton-api edge).
	Proton ProtonConfig `mapstructure:"proton"`

	// Sync configures the sync engine (per-mailbox bootstrap-then-tail).
	//
	// Governing: SPEC-0002 (Sync & Local Cache), ADR-0014 (sync-and-cache).
	Sync SyncConfig `mapstructure:"sync"`

	// Logger configures the structured logger.
	Logger LoggerConfig `mapstructure:"logger"`

	// UI holds the listen address for the reserved-for-future `serve` stub.
	// The web UI is retired (ADR-0025); the field survives because ADR-0025
	// keeps `serve` as a stub for possible MCP-over-HTTP or media-companion
	// use. The name stays for now to avoid churning the config schema before
	// serve's real shape is decided.
	//
	// Governing: ADR-0025 (TUI is the human surface; `serve` is not a UI).
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

// ProtonConfig configures the go-proton-api client. Both fields are non-secret.
//
// Governing: SPEC-0007 (onboarding & auth), ADR-0001 (go-proton-api edge).
type ProtonConfig struct {
	// AppVersion is the app-version string presented to Proton as the
	// x-pm-appversion header. Proton VALIDATES this and rejects unacceptable
	// values (code 5001 missing, 5003 bad).
	//
	// It defaults to empty, which resolves to proton.DefaultAppVersion
	// ("macos-bridge@3.21.2"). Identifying as a Bridge variant is deliberate:
	// Proton's anti-abuse challenges the web client with a CAPTCHA but waves the
	// Bridge family through, so this avoids human verification (see
	// proton.DefaultAppVersion / ADR-0021). The literal "auto" instead
	// auto-detects "web-mail@<version>" — which Proton WILL challenge, so it is
	// opt-in only. Any other value is used verbatim. Whatever value is chosen
	// must be used consistently across auth and later commands (Proton binds the
	// session to it; a mismatch yields 10013 invalid refresh token). Sourced from
	// config (proton.app_version) or REDUIT_PROTON_APP_VERSION.
	AppVersion string `mapstructure:"app_version"`
	// HostURL is the Proton API base URL. Empty targets go-proton-api's default
	// production host; set it only to point at a test/self-hosted server.
	// Sourced from REDUIT_PROTON_HOST_URL.
	HostURL string `mapstructure:"host_url"`
}

// SyncConfig configures the sync engine (SPEC-0002). Both fields are
// non-secret and safe to commit.
//
// Governing: SPEC-0002 REQ "Bootstrap Then Tail", "Rate-Limit Respect".
type SyncConfig struct {
	// BackfillWindow bounds a mailbox's FIRST sync: only messages whose
	// Proton timestamp is at or after (now - BackfillWindow) are backfilled
	// (SPEC-0002 "First sync backfills a bounded window"). A ZERO window means
	// "no bound" — backfill the FULL mailbox. Defaults to 8760h (one year).
	// Sourced from sync.backfill_window / REDUIT_SYNC_BACKFILL_WINDOW; accepts
	// any Go duration string ("720h", "0" for the full mailbox).
	BackfillWindow time.Duration `mapstructure:"backfill_window"`

	// Concurrency bounds how many mailboxes sync in parallel in one
	// invocation, capping in-flight Proton requests so a multi-mailbox run
	// does not surge Proton's API (SPEC-0002 "Bounded concurrency"). Defaults
	// to 3. Sourced from sync.concurrency / REDUIT_SYNC_CONCURRENCY.
	Concurrency int `mapstructure:"concurrency"`
}

// LoggerConfig configures the structured logger.
type LoggerConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `mapstructure:"level"`
	// Format is "text" (human-readable) or "json".
	Format string `mapstructure:"format"`
}

// UIConfig configures the reserved-for-future `serve` stub. The web UI it
// originally described was retired by ADR-0025; the field remains so the
// serve stub has a listen address if it ever ships (MCP-over-HTTP or a
// loopback media-companion endpoint).
type UIConfig struct {
	// ListenAddr is the address the reserved `serve` stub would listen on
	// if it ever ships. Defaults to 127.0.0.1:8787. Non-loopback binds are
	// allowed but log a loud warning (no auth is shipped).
	//
	// Governing: ADR-0025 (serve is not a UI), ADR-0012 (loopback default,
	// no auth).
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
		Proton: ProtonConfig{
			// Empty resolves to proton.DefaultAppVersion ("macos-bridge@3.21.2")
			// in protonConfig() — the Bridge client family avoids Proton's
			// CAPTCHA. The literal "auto" instead detects "web-mail@<version>"
			// (opt-in; Proton challenges the web client). An explicit value wins.
			AppVersion: "",
		},
		Sync: SyncConfig{
			// One year of history on first sync, three parallel mailboxes —
			// bounded defaults that keep the first backfill and Proton request
			// pressure sane out of the box (SPEC-0002). Zero window (full
			// mailbox) is opt-in.
			BackfillWindow: 365 * 24 * time.Hour,
			Concurrency:    3,
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
	if c.Sync.BackfillWindow < 0 {
		errs = append(errs, errors.New("sync.backfill_window must not be negative (use 0 for the full mailbox)"))
	}
	if c.Sync.Concurrency < 0 {
		errs = append(errs, errors.New("sync.concurrency must not be negative"))
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
