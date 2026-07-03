package cli

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	charmlog "github.com/charmbracelet/log"

	"github.com/joestump/reduit/internal/config"
)

// TestBuildLogger_IsCharmBacked asserts the root logger builder returns a
// usable *slog.Logger backed by charmbracelet/log — the backend swap of
// ADR-0022. The handler is the resolvingHandler redaction wrapper around a
// *charmbracelet/log.Logger; both layers are asserted. The slog API surface
// is preserved; only the backend differs from the old stdlib text/JSON handlers.
func TestBuildLogger_IsCharmBacked(t *testing.T) {
	for _, format := range []string{"text", "json", ""} {
		logger := buildLoggerTo(&bytes.Buffer{}, config.LoggerConfig{Level: "info", Format: format})
		if logger == nil {
			t.Fatalf("format %q: buildLoggerTo returned nil", format)
		}
		wrapper, ok := logger.Handler().(resolvingHandler)
		if !ok {
			t.Fatalf("format %q: handler is %T, want resolvingHandler", format, logger.Handler())
		}
		if _, ok := wrapper.inner.(*charmlog.Logger); !ok {
			t.Errorf("format %q: wrapped handler is %T, want *charmlog.Logger", format, wrapper.inner)
		}
	}
}

// TestBuildLogger_TextFormatProducesOutput verifies the default (text)
// formatter emits a human-readable line carrying the message and a
// structured field, going to the provided sink (stderr in production).
func TestBuildLogger_TextFormatProducesOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := buildLoggerTo(&buf, config.LoggerConfig{Level: "info", Format: "text"})

	logger.Info("sync started", "mailbox_id", "mb-1")

	out := buf.String()
	if !strings.Contains(out, "sync started") {
		t.Errorf("text output missing message: %q", out)
	}
	if !strings.Contains(out, "mailbox_id") || !strings.Contains(out, "mb-1") {
		t.Errorf("text output missing structured field: %q", out)
	}
}

// TestBuildLogger_JSONFormatProducesOutput verifies the "json" format emits
// parseable JSON with the message and structured field intact — the shape a
// machine consumer relies on.
func TestBuildLogger_JSONFormatProducesOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := buildLoggerTo(&buf, config.LoggerConfig{Level: "info", Format: "json"})

	logger.Info("sync started", "mailbox_id", "mb-1")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("json output not parseable: %v (%q)", err, buf.String())
	}
	if rec["msg"] != "sync started" {
		t.Errorf("json msg = %v, want %q", rec["msg"], "sync started")
	}
	if rec["mailbox_id"] != "mb-1" {
		t.Errorf("json mailbox_id = %v, want %q", rec["mailbox_id"], "mb-1")
	}
}

// TestCharmLevel_Parsing pins the level mapping, including the documented
// fallback: any unrecognized value (and the empty string) maps to info.
func TestCharmLevel_Parsing(t *testing.T) {
	cases := map[string]charmlog.Level{
		"debug":    charmlog.DebugLevel,
		"DEBUG":    charmlog.DebugLevel,
		"info":     charmlog.InfoLevel,
		"warn":     charmlog.WarnLevel,
		"error":    charmlog.ErrorLevel,
		"":         charmlog.InfoLevel,
		"nonsense": charmlog.InfoLevel,
	}
	for in, want := range cases {
		if got := charmLevel(in); got != want {
			t.Errorf("charmLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// secretToken is a secret-bearing type whose LogValue() returns a redacted
// placeholder — the SPEC-0007 leak defense that design.md tells devs to add.
type secretToken struct {
	value string
}

func (secretToken) LogValue() slog.Value { return slog.StringValue("REDACTED") }

// TestBuildLogger_RedactsLogValuerInBothFormats is the regression test for the
// charmbracelet/log swap: v1.0.0's text formatter does not resolve slog
// LogValuer, so without the resolvingHandler wrapper a secret logged as an attr
// would render its raw fields in the DEFAULT text format (leak), while json
// redacted correctly. This asserts the placeholder is present and the secret
// is absent through BOTH formats, and via both the per-record attr and the
// logger.With path (SPEC-0007, ADR-0022).
func TestBuildLogger_RedactsLogValuerInBothFormats(t *testing.T) {
	const secret = "SUPERSECRETtokenvalue"
	tok := secretToken{value: secret}

	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			// Per-record attr.
			var buf bytes.Buffer
			logger := buildLoggerTo(&buf, config.LoggerConfig{Level: "info", Format: format})
			logger.Info("auth step", "token", tok)
			out := buf.String()
			if strings.Contains(out, secret) {
				t.Errorf("%s: secret leaked in per-record attr: %q", format, out)
			}
			if !strings.Contains(out, "REDACTED") {
				t.Errorf("%s: redacted placeholder missing in per-record attr: %q", format, out)
			}

			// logger.With path (attrs persisted on the handler).
			var wbuf bytes.Buffer
			wlogger := buildLoggerTo(&wbuf, config.LoggerConfig{Level: "info", Format: format}).With("token", tok)
			wlogger.Info("auth step")
			wout := wbuf.String()
			if strings.Contains(wout, secret) {
				t.Errorf("%s: secret leaked via logger.With: %q", format, wout)
			}
			if !strings.Contains(wout, "REDACTED") {
				t.Errorf("%s: redacted placeholder missing via logger.With: %q", format, wout)
			}
		})
	}
}

// TestBuildLogger_LevelGating verifies parsed levels actually gate output:
// at warn level an Info record is suppressed while a Warn record is emitted.
func TestBuildLogger_LevelGating(t *testing.T) {
	var buf bytes.Buffer
	logger := buildLoggerTo(&buf, config.LoggerConfig{Level: "warn", Format: "json"})

	logger.Info("suppressed")
	if buf.Len() != 0 {
		t.Errorf("info record leaked at warn level: %q", buf.String())
	}

	logger.Warn("emitted")
	if !strings.Contains(buf.String(), "emitted") {
		t.Errorf("warn record missing at warn level: %q", buf.String())
	}

	// Sanity: the logger is a real *slog.Logger.
	var _ *slog.Logger = logger
}
