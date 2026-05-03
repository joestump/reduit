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

// initialsFor returns at most two uppercase initials suitable for an
// avatar disc. Falls back to "?" for an empty input rather than
// rendering an empty disc.
func initialsFor(s string) string {
	if s == "" {
		return "?"
	}
	// Strip after @ so an email "joe@stump.rocks" becomes "joe".
	for i := 0; i < len(s); i++ {
		if s[i] == '@' {
			s = s[:i]
			break
		}
	}
	if s == "" {
		return "?"
	}
	out := []byte{}
	upper := func(b byte) byte {
		if b >= 'a' && b <= 'z' {
			return b - 32
		}
		return b
	}
	out = append(out, upper(s[0]))
	for i := 1; i < len(s) && len(out) < 2; i++ {
		c := s[i]
		// Take the byte after a separator as the second initial.
		if c == '.' || c == '_' || c == '-' || c == ' ' {
			if i+1 < len(s) {
				out = append(out, upper(s[i+1]))
				break
			}
		}
	}
	if len(out) == 1 && len(s) > 1 {
		// No separator -> use the next letter, lower-case.
		out = append(out, s[1])
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
