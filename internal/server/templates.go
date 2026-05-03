// Template loading + render helpers for the dashboard surface.
//
// Templates ship embedded in the binary so a `reduit serve` is a
// single-file deploy. The template tree is parsed once at server-
// construction time and cached on the *Server.
//
// The CSS framework (Tailwind 4 + DaisyUI 5) is loaded via CDN
// in the v1 templates -- the proper build pipeline lands when the
// asset-pipeline ADR is filed (tracked separately). Acceptable for
// the pre-alpha MVP; the visual identity matches the mockups in
// docs/mockups/spec-0005/.
//
// Governing: ADR-0005 (HTMX + SSE + Tailwind 4 + DaisyUI + Heroicons),
// SPEC-0005 REQ "Account Dashboard".

package server

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"unicode"

	"github.com/joestump/reduit/internal/auth/session"
)

//go:embed templates/*.html
var templateFS embed.FS

// loadTemplates parses every .html file under templates/ as a single
// template tree. The base layout's {{template "content" .}} slot is
// filled by whichever page-specific template defines `content`.
func loadTemplates() (*template.Template, error) {
	tmpl, err := template.New("").ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("server: parse templates: %w", err)
	}
	return tmpl, nil
}

// pageData is the common shape every page template consumes.
// Page-specific data extends this through embedded composition (see
// accountsPageData below).
type pageData struct {
	Title    string
	Identity identityView
	IsAdmin  bool
}

// identityView renders the top-bar identity badge. Computed from the
// session.Identity at handler time so templates don't need to reach
// into auth context themselves.
type identityView struct {
	DisplayName string
	Email       string
	Initials    string
}

func newIdentityView(id session.Identity) identityView {
	display := id.Email
	if display == "" {
		display = id.Subject
	}
	return identityView{
		DisplayName: display,
		Email:       id.Email,
		Initials:    initialsFor(display),
	}
}

// initialsFor returns at most two initials suitable for an avatar
// disc, with the first uppercased. Iterates RUNES rather than bytes
// so non-ASCII names ("Söphia", "Łukasz", "名前") survive intact --
// byte-indexing would emit a malformed leading byte for any
// multi-byte UTF-8 codepoint. Falls back to "?" for empty input.
func initialsFor(s string) string {
	if s == "" {
		return "?"
	}
	// Strip after @ so an email "joe@stump.rocks" becomes "joe".
	for i, r := range s {
		if r == '@' {
			s = s[:i]
			break
		}
	}
	if s == "" {
		return "?"
	}
	runes := []rune(s)
	out := []rune{unicode.ToUpper(runes[0])}
	// Look for a separator and take the next rune as the second
	// initial, uppercased -- this picks up "Joe Stump" -> "JS",
	// "joe.stump" -> "JS", "joe_stump" -> "JS", "joe-stump" -> "JS".
	for i := 1; i < len(runes) && len(out) < 2; i++ {
		switch runes[i] {
		case '.', '_', '-', ' ':
			if i+1 < len(runes) {
				out = append(out, unicode.ToUpper(runes[i+1]))
			}
		}
	}
	// No separator found -- fall back to the second rune lowercased
	// so "Sophia" -> "So", "名前" -> "名前" (already 2 runes).
	if len(out) == 1 && len(runes) > 1 {
		out = append(out, runes[1])
	}
	return string(out)
}

// renderPage executes the named page template wrapped in the base
// layout. Errors flow as 500s with the operator detail in the log;
// the user sees an opaque "internal error".
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, data any) {
	if s.tmpl == nil {
		http.Error(w, "templates not loaded", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		s.deps.Logger.Error("template execute: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}
