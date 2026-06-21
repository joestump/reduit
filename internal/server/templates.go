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
	"io/fs"
	"net/http"
	"strings"
	"unicode"

	"github.com/joestump/reduit/internal/auth/session"
)

//go:embed templates/*.html templates/fragments/*.html
var templateFS embed.FS

// staticFS embeds the static asset tree the layout needs:
//   - static/favicon.svg              brand mark
//   - static/vendor/app.css           pre-built Tailwind 4 + DaisyUI 5
//   - static/vendor/htmx-*.min.js     HTMX core + SSE extension
//   - static/vendor/InterVariable.woff2  Inter variable font
//
// Per ADR-0005 the frontend ships pre-built committed assets served
// from the binary -- no runtime CDN, no bundler at `go build` time.
// The app.css bundle is produced by `make css` (Tailwind standalone
// CLI over web/app.css) and committed; the JS/font are vendored from
// the same pinned versions base.html previously loaded via CDN (their
// bytes match the SRI hashes that were trusted there -- see web/ and
// the commit that vendored them).
//
// Lives in this file because //go:embed directives compile against the
// surrounding package; there is no separate static subpackage today.
//
// Routes that serve from staticFS (/favicon.svg and /static/vendor/*)
// are allowlisted so an unauthenticated browser can fetch them on the
// login page -- /static/* is already in auth.Allowlist.
//
// Governing: ADR-0005 (pre-built committed CSS/JS, no runtime CDN);
// SPEC-0005 REQ "Authentication Gating" (Allowlist bypasses auth --
// these are unprivileged brand/chrome assets).
//
//go:embed static/favicon.svg static/vendor
var staticFS embed.FS

// faviconBytes is the favicon payload read once at package init so
// the handler hot path is a single Write rather than an embed.FS
// round trip per request. The asset is small (a couple hundred
// bytes) and the same bytes for every request, so caching the slice
// is cheap and keeps the handler trivially correct.
var faviconBytes []byte

// vendorFS is the static/vendor subtree, rooted so paths like
// "app.css" and "htmx-2.0.4.min.js" resolve directly. Computed once at
// init; an error here means the //go:embed pattern above failed to
// capture static/vendor -- a build-time wiring error, so we panic.
var vendorFS fs.FS

// staticVendorHandler serves the embedded /static/vendor tree. The
// caller mounts it under "/static/vendor/" with the prefix stripped.
// A long immutable Cache-Control is set on every asset: the filenames
// are version-pinned (app.css is regenerated+recommitted on change,
// the JS/font carry versions in their names), so cached copies never
// go stale under a fixed URL.
//
// Governing: ADR-0005 (pre-built committed assets served from the
// binary, no runtime CDN).
func (s *Server) staticVendorHandler() http.Handler {
	fileServer := http.FileServerFS(vendorFS)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fileServer.ServeHTTP(w, r)
	})
}

func init() {
	sub, err := fs.Sub(staticFS, "static/vendor")
	if err != nil {
		// The //go:embed directive lists static/vendor explicitly; a
		// failure here means the directory was renamed or dropped from
		// the embed pattern -- the binary cannot serve its frontend.
		panic("server: sub static/vendor FS: " + err.Error())
	}
	vendorFS = sub

	b, err := staticFS.ReadFile("static/favicon.svg")
	if err != nil {
		// embed.FS reports "file not found" only when the //go:embed
		// pattern matched no files -- a build-time wiring error. If
		// we hit it at runtime the binary is corrupt; the favicon is
		// non-load-bearing for service correctness, but the panic
		// message is loud enough to surface quickly.
		panic("server: read embedded favicon: " + err.Error())
	}
	faviconBytes = b
}

// templateSet holds one parsed *template.Template per page. Each tree
// contains base.html plus one page-specific file, so each page's
// {{define "content"}} block is the only one in its tree -- we don't
// have to fight Go's "last-define-wins" semantics when more than one
// page wants its own content slot.
//
// Fragments live in templates/fragments/ and are parsed standalone
// (no base.html wrap) so HTMX endpoints can return targeted HTML
// snippets without the chrome. Lookup is by file basename (sans
// .html) for both pages and fragments.
//
// Lookup is by page name (the bare filename, sans .html). renderPage
// takes the page name explicitly so a typo surfaces as a 500 with a
// log line, not as the wrong page rendering silently.
type templateSet struct {
	pages     map[string]*template.Template
	fragments map[string]*template.Template
}

func (ts *templateSet) get(name string) (*template.Template, bool) {
	if ts == nil {
		return nil, false
	}
	t, ok := ts.pages[name]
	return t, ok
}

// getFragment returns a parsed fragment (no base wrap) by basename.
// Used by HTMX endpoints that respond with a partial HTML snippet.
func (ts *templateSet) getFragment(name string) (*template.Template, bool) {
	if ts == nil {
		return nil, false
	}
	t, ok := ts.fragments[name]
	return t, ok
}

// loadTemplates discovers every page-* file under templates/ and parses
// each one alongside base.html into its own tree. Files that are
// shared partials (currently only base.html) are NOT parsed as pages;
// the convention is "every templates/*.html file other than base.html
// is a page".
func loadTemplates() (*templateSet, error) {
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, fmt.Errorf("server: read templates dir: %w", err)
	}
	ts := &templateSet{
		pages:     make(map[string]*template.Template),
		fragments: make(map[string]*template.Template),
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".html") || name == "base.html" {
			continue
		}
		page := strings.TrimSuffix(name, ".html")
		t, err := template.New("").ParseFS(templateFS, "templates/base.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("server: parse template %s: %w", name, err)
		}
		ts.pages[page] = t
	}

	// Fragments: standalone HTMX snippets, no base wrap.
	fragEntries, err := fs.ReadDir(templateFS, "templates/fragments")
	if err == nil {
		for _, e := range fragEntries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".html") {
				continue
			}
			frag := strings.TrimSuffix(name, ".html")
			t, err := template.New("").ParseFS(templateFS, "templates/fragments/"+name)
			if err != nil {
				return nil, fmt.Errorf("server: parse fragment %s: %w", name, err)
			}
			ts.fragments[frag] = t
		}
	}

	return ts, nil
}

// pageData is the common shape every page template consumes.
// Page-specific data extends this through embedded composition (see
// accountsPageData below).
type pageData struct {
	Title    string
	Identity identityView
	IsAdmin  bool
	// CSRFToken is the per-session CSRF token. It is made available on
	// every base-layout page (populated centrally in renderPage so no
	// construction site has to remember it) and consumed two ways:
	//
	//   - base.html sets it as the X-CSRF-Token header on every HTMX
	//     request via the <body> hx-headers attribute (the HTMX path).
	//   - Each state-changing <form> embeds it as a hidden csrf_token
	//     input (the no-JS path).
	//
	// The csrfProtect middleware (csrf.go) validates the token from
	// EITHER source on every state-changing POST (issue #26 extended
	// this from logout-only to all destructive POSTs). Empty on
	// fragments (which render outside the base layout) -- fragments are
	// only ever returned FROM an already-CSRF-validated POST, so they
	// carry no form that needs its own token.
	//
	// Governing: SPEC-0005 design "Content security and CSRF"; issue #26.
	CSRFToken string
}

// csrfSetter is implemented by every page-data value that embeds
// pageData by pointer-receiver promotion. renderPage uses it to inject
// the per-session CSRF token centrally rather than threading the token
// through each handler's data-construction site.
type csrfSetter interface {
	setCSRFToken(string)
}

// setCSRFToken satisfies csrfSetter for any struct embedding pageData
// (the method promotes to the embedder). Pointer receiver so the write
// lands on the addressable value renderPage holds.
func (p *pageData) setCSRFToken(tok string) { p.CSRFToken = tok }

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
//
// data SHOULD be a pointer to a value embedding pageData so renderPage
// can inject the per-session CSRF token centrally (the base layout's
// logout form needs it). A non-pointer or non-pageData value still
// renders -- it just won't carry a CSRF token, which is correct for
// any future page that has no state-changing form.
//
// Governing: SPEC-0005 design "Content security and CSRF".
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, page string, data any) {
	if s.tmpl == nil {
		http.Error(w, "templates not loaded", http.StatusInternalServerError)
		return
	}
	t, ok := s.tmpl.get(page)
	if !ok {
		s.deps.Logger.Error("template not found", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Inject the per-session CSRF token so base.html's logout form
	// carries it. Done here (not at each handler's data-construction
	// site) so a new page can't forget it. Requires a session manager
	// (always wired in production; nil only in narrow template tests).
	if setter, ok := data.(csrfSetter); ok && s.deps.SessionManager != nil {
		setter.setCSRFToken(session.CSRFToken(r.Context(), s.deps.SessionManager))
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		s.deps.Logger.Error("template execute: " + err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}
