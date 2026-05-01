package imapserver

import (
	"strings"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
)

// TestPostAuthCapabilityDoesNotAdvertiseIDLE confirms the wire-level
// capability filter strips IDLE from the post-auth CAPABILITY response.
// Until story #20 wires the live-update bus, IDLE is a 35-minute no-op
// — advertising it makes Apple Mail / Thunderbird sit on a dead socket
// instead of falling back to NOOP polling.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates" (deferred
// to story #20).
func TestPostAuthCapabilityDoesNotAdvertiseIDLE(t *testing.T) {
	t.Parallel()
	stub := newStubAccounts()
	stub.addAccount("acct-idle", "user@reduit.example", "pw", account.StateActive)
	srv := startTestServer(t, stub, NewSessions())

	conn, r := loginPlain(t, srv.addr, "user@reduit.example", "pw")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeCmd(t, conn, "b001", "CAPABILITY")
	var capLine string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read CAPABILITY response: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "* CAPABILITY ") {
			capLine = line
			continue
		}
		if strings.HasPrefix(line, "b001 ") {
			break
		}
	}
	if capLine == "" {
		t.Fatal("did not receive a `* CAPABILITY ...` line")
	}
	// IDLE must not appear as a standalone token. We accept only
	// strict atom-boundary matches — a hypothetical future cap that
	// happens to contain the substring `IDLE` (e.g. `IDLE-EXTRA`) is
	// fine; bare `IDLE` is not.
	for _, atom := range strings.Split(capLine, " ") {
		if atom == "IDLE" {
			t.Errorf("post-auth CAPABILITY must not advertise IDLE (deferred to story #20); got %q", capLine)
		}
	}
}
