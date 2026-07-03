package syncengine

import (
	"testing"

	"github.com/joestump/reduit/internal/proton"
)

func TestExtractLinks(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"none", "no links here at all", nil},
		{"plain", "see https://example.com/report today", []string{"https://example.com/report"}},
		{"html href", `<a href="https://example.com/x?y=1">click</a>`, []string{"https://example.com/x?y=1"}},
		{"trailing punct", "go to https://example.com/a. Now.", []string{"https://example.com/a"}},
		{"dedup", "https://a.test and again https://a.test", []string{"https://a.test"}},
		{"two", "https://a.test then https://b.test", []string{"https://a.test", "https://b.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractLinks(tc.body)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d links %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i].URL != tc.want[i] {
					t.Errorf("link[%d] = %q, want %q", i, got[i].URL, tc.want[i])
				}
			}
		})
	}
}

func TestRenderPlaintext(t *testing.T) {
	cases := []struct {
		name, body, mime, want string
	}{
		{"plain", "  hello world  ", "text/plain", "hello world"},
		{"html tags stripped", "<p>Hello <b>there</b></p>", "text/html", "Hello there"},
		{"html entities", "a &amp; b &lt; c", "text/html", "a & b < c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderPlaintext(tc.body, tc.mime); got != tc.want {
				t.Errorf("renderPlaintext = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatAddress(t *testing.T) {
	cases := []struct {
		in   proton.Address
		want string
	}{
		{proton.Address{Name: "Joe", Email: "joe@x.test"}, "Joe <joe@x.test>"},
		{proton.Address{Email: "joe@x.test"}, "joe@x.test"},
		{proton.Address{Name: "Joe"}, "Joe"},
		{proton.Address{}, ""},
	}
	for _, tc := range cases {
		if got := formatAddress(tc.in); got != tc.want {
			t.Errorf("formatAddress(%+v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFolderResolver(t *testing.T) {
	r := newFolderResolver([]proton.Label{
		{ID: "0", Name: "Inbox", Type: proton.LabelTypeSystem},
		{ID: "fold-1", Name: "Projects", Type: proton.LabelTypeFolder},
		{ID: "lbl-1", Name: "Work", Type: proton.LabelTypeLabel},
	})
	cases := []struct {
		name string
		ids  []string
		want string
	}{
		{"system wins", []string{"0"}, "Inbox"},
		{"user folder", []string{"fold-1"}, "Projects"},
		{"label is not a folder", []string{"lbl-1"}, ""},
		{"label then folder picks folder", []string{"lbl-1", "fold-1"}, "Projects"},
		{"unknown id", []string{"nope"}, ""},
		{"none", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.resolve(tc.ids); got != tc.want {
				t.Errorf("resolve(%v) = %q, want %q", tc.ids, got, tc.want)
			}
		})
	}
}
