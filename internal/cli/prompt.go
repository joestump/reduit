package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// prompter is the interactive-input seam the auth flow drives. The live
// implementation reads from the terminal (echoing nothing for secrets); tests
// supply a scripted prompter so the add flow — including the mid-flow 2FA and
// passphrase prompts — is exercised without a TTY (SPEC-0007 REQ "No Secret
// Leakage": secrets are read without terminal echo).
type prompter interface {
	// secret reads a sensitive value (password, passphrase, TOTP is not
	// secret) without echoing it. The returned buffer is the caller's to zero.
	secret(label string) ([]byte, error)
	// line reads a single visible line (e.g. a TOTP code), trimming the
	// trailing newline.
	line(label string) (string, error)
}

// terminalPrompter reads interactive input from a real terminal. Secrets are
// read with term.ReadPassword so nothing is echoed; the prompt label is written
// to out (stderr) so it never pollutes stdout/piped output.
type terminalPrompter struct {
	in  *os.File  // typically os.Stdin
	out io.Writer // prompt sink, typically os.Stderr
}

func newTerminalPrompter() terminalPrompter {
	return terminalPrompter{in: os.Stdin, out: os.Stderr}
}

func (t terminalPrompter) secret(label string) ([]byte, error) {
	fmt.Fprint(t.out, label)
	fd := int(t.in.Fd())
	if !term.IsTerminal(fd) {
		// No TTY to disable echo on; fall back to a line read so piped input
		// (e.g. in automation) still works, accepting the echo trade-off.
		s, err := readLine(t.in)
		fmt.Fprintln(t.out)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(t.out) // ReadPassword swallows the user's Enter; restore the newline.
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return b, nil
}

func (t terminalPrompter) line(label string) (string, error) {
	fmt.Fprint(t.out, label)
	return readLine(t.in)
}

// readLine reads one newline-terminated line and trims surrounding whitespace.
func readLine(r io.Reader) (string, error) {
	sc := bufio.NewReader(r)
	s, err := sc.ReadString('\n')
	if err != nil && s == "" {
		return "", fmt.Errorf("read line: %w", err)
	}
	return strings.TrimSpace(s), nil
}

// zero overwrites a secret buffer so it does not linger in memory after use
// (SPEC-0007 REQ "No Secret Leakage").
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
