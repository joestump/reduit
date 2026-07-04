// Package cli — the benign-scope notice handler for interactive auth.
//
// On `reduit auth refresh`, the cheap-resume probe reuses the stored session and
// hits a scope-downgraded 403 / Proton code 9101 on the salts endpoint. That is
// the EXPECTED signal that the resumed session cannot unlock and the flow will
// escalate to an interactive re-login (SPEC-0007 "Re-Auth Flow") — but
// go-proton-api's resty logger emits it at ERROR, so a perfectly normal refresh
// prints a scary red line before recovering.
//
// noticeHandler is a slog.Handler wrapper that reclassifies exactly that benign
// diagnostic into a calm notice (a gold WARN with a friendly message), while
// leaving genuine errors untouched. It is installed ONLY on the logger handed to
// the proton dialer for the auth commands (see runAuthTUI / authRefresh), never
// on the sync engine's logger. Working on the slog.Record BEFORE it is formatted
// makes the reclassification independent of logger.format (text or json), which
// SPEC-0013 "Benign-Scope Notice" requires.
//
// Governing: ADR-0026 (interactive auth TUI — benign-scope notice), SPEC-0013
// REQ "Benign-Scope Notice", SPEC-0007 (Re-Auth Flow escalation).
package cli

import (
	"context"
	"log/slog"
	"strings"
)

// noticeMessage is the friendly line shown in place of the raw salts-scope 403.
// It carries no secret (the source message never does — internal/proton/logger.go)
// and explains the escalation the operator is about to see.
const noticeMessage = "stored session expired — re-authenticating (this is expected)"

// noticeHandler wraps another slog.Handler and rewrites the benign salts-scope
// 403 / 9101 diagnostic into a gold notice.
type noticeHandler struct {
	inner slog.Handler
}

// isBenignScopeNotice reports whether a record is the expected scope-downgrade
// diagnostic from the cheap-resume probe. The match is narrow — Proton's 9101
// code, or the "sufficient scope" phrase — so a genuine auth failure (a wrong
// password yields a different code) is never painted as a notice (SPEC-0013
// "A real auth error is still an error").
func isBenignScopeNotice(rec slog.Record) bool {
	if rec.Level < slog.LevelWarn {
		return false
	}
	msg := rec.Message
	return strings.Contains(msg, "9101") || strings.Contains(strings.ToLower(msg), "sufficient scope")
}

func (h noticeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle reclassifies a benign salts-scope record into a WARN-level notice with a
// friendly message; everything else passes through unchanged. The rewritten
// record preserves the original attrs and adds notice=true so a consumer can
// style it distinctly.
func (h noticeHandler) Handle(ctx context.Context, rec slog.Record) error {
	if !isBenignScopeNotice(rec) {
		return h.inner.Handle(ctx, rec)
	}
	nr := slog.NewRecord(rec.Time, slog.LevelWarn, noticeMessage, rec.PC)
	nr.AddAttrs(slog.Bool("notice", true))
	return h.inner.Handle(ctx, nr)
}

func (h noticeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return noticeHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h noticeHandler) WithGroup(name string) slog.Handler {
	return noticeHandler{inner: h.inner.WithGroup(name)}
}

// withNoticeHandler wraps a logger so the auth commands' proton diagnostics get
// the benign-scope reclassification. Scoped to auth: the sync engine's logger is
// built without it, so `reduit sync` is unaffected (SPEC-0013 "Notice
// reclassification does not touch sync").
func withNoticeHandler(logger *slog.Logger) *slog.Logger {
	return slog.New(noticeHandler{inner: logger.Handler()})
}
