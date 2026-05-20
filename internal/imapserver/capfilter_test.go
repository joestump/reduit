package imapserver

import (
	"strings"
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
)

// TestPostAuthCapabilityAdvertisesIDLE confirms the post-auth CAPABILITY
// response now includes IDLE. Story #20 wired the live-update pubsub bus,
// so IDLE is functional and should be advertised to clients.
//
// Governing: SPEC-0003 REQ "IDLE Support With Live Updates".
func TestPostAuthCapabilityAdvertisesIDLE(t *testing.T) {
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
	// IDLE must appear as a standalone token in the capability line now
	// that story #20 wired the live-update bus.
	found := false
	for _, atom := range strings.Split(capLine, " ") {
		if atom == "IDLE" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("post-auth CAPABILITY must advertise IDLE (story #20); got %q", capLine)
	}
}
