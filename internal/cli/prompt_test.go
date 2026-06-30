package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestTerminalPrompter_DoesNotEchoSecret verifies the prompter writes only the
// static label to its sink (stderr in production) and never the typed secret —
// closing the "does anything echo the secret?" leak question. The input here is
// a pipe (not a TTY), so secret() takes the non-echo fallback path; even there,
// the prompter itself writes nothing but the label.
func TestTerminalPrompter_DoesNotEchoSecret(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	go func() {
		_, _ = w.WriteString("supersecret\n")
		_ = w.Close()
	}()

	var sink bytes.Buffer
	p := terminalPrompter{in: r, out: &sink}

	got, err := p.secret("Password: ")
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if string(got) != "supersecret" {
		t.Errorf("secret value = %q, want supersecret", string(got))
	}
	if !strings.Contains(sink.String(), "Password: ") {
		t.Errorf("label not written to sink: %q", sink.String())
	}
	if strings.Contains(sink.String(), "supersecret") {
		t.Errorf("secret echoed to sink: %q", sink.String())
	}
}

func TestReadLine_Trims(t *testing.T) {
	got, err := readLine(strings.NewReader("  654321  \n"))
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if got != "654321" {
		t.Errorf("readLine = %q, want 654321", got)
	}
}
