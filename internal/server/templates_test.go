// Tests for the dashboard template helpers (initialsFor, formatLastSync).
//
// Pinned cases include non-ASCII names so a future regression that
// reverts to byte-indexing fails loudly rather than silently
// emitting a malformed leading byte.

package server

import (
	"testing"
	"time"
)

func TestInitialsFor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		// Empty / single-character.
		{"empty", "", "?"},
		{"only at", "@example.com", "?"},
		{"single letter", "j", "J"},

		// Email -> local part -> initials.
		{"plain email", "joe@stump.rocks", "Jo"},
		{"dotted email", "joe.stump@stump.rocks", "JS"},
		{"underscore email", "joe_stump@stump.rocks", "JS"},
		{"hyphen email", "joe-stump@stump.rocks", "JS"},
		{"space-separated name", "Joe Stump", "JS"},

		// Already uppercased.
		{"upper email", "JOE.STUMP@STUMP.ROCKS", "JS"},

		// Non-ASCII names. The byte-indexed implementation would
		// emit truncated multi-byte UTF-8 leading bytes for these.
		{"latin diacritic", "söphia@example.com", "Sö"},
		{"latin diacritic underscore", "söp_hia@example.com", "SH"},
		{"polish", "łukasz@example.com", "Łu"},
		{"japanese", "名前@example.com", "名前"},
		{"emoji-prefix", "🌲pine@example.com", "🌲p"},
		{"display name with accent", "Hannah Müller", "HM"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := initialsFor(tc.in); got != tc.want {
				t.Errorf("initialsFor(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFormatLastSync(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ptr := func(t time.Time) *time.Time { return &t }
	for _, tc := range []struct {
		name string
		in   *time.Time
		want string
	}{
		// nil and the zero value both render as "Never": a fresh row
		// has not yet been synced, and -- until the sync worker (#19)
		// lands -- every row has nil here. Pinning both inputs to the
		// same string makes a future regression that confuses the two
		// fail loudly.
		{"nil", nil, "Never"},
		{"zero", ptr(time.Time{}), "Never"},
		{"30s ago", ptr(now.Add(-30 * time.Second)), "just now"},
		{"5m ago", ptr(now.Add(-5 * time.Minute)), "5 min ago"},
		{"3h ago", ptr(now.Add(-3 * time.Hour)), "3 hr ago"},
		{"5d ago", ptr(now.Add(-5 * 24 * time.Hour)), "5 days ago"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := formatLastSync(tc.in); got != tc.want {
				t.Errorf("formatLastSync(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
