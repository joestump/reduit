// Build tag: skip the timing-side-channel test when -race is on.
// bcrypt at cost 12 takes ~250ms in normal mode and ~4s under the
// race detector. 30 samples × 5 cases at 4s each blows the default
// 10m test timeout. Mirrors internal/imapserver/auth_timing_test.go
// — see the doc comment there for the rationale.
//
//go:build !race

package smtpserver

import (
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
)

// TestAuthFailureIsConstantTime is the wall-clock companion to
// TestSASLPlainAuthFailuresAreIdentical. Asserts every failure mode's
// median is within ±20% of the bcrypt-bearing (wrong-password)
// baseline.
//
// Governing: SPEC-0004 REQ "SASL PLAIN Authentication Matching IMAP"
// (uniform-time auth — failure modes must not be timing-distinguishable).
func TestAuthFailureIsConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-side-channel test runs ~150 bcrypts at cost 12; skipped in -short mode")
	}

	stub := newBcryptStubAccounts()
	stub.addAccount(t, "acct-active", "alice@reduit.example", "alice-password", account.StateActive)
	stub.addAccount(t, "acct-suspended", "bob@reduit.example", "bob-password", account.StateSuspended)
	stub.addAccount(t, "acct-deleted", "carol@reduit.example", "carol-password", account.StateSoftDeleted)
	stub.addAccount(t, "acct-pending", "dave@reduit.example", "dave-password", account.StatePendingProtonSetup)
	srv := startTestServer(t, stub, NewSessions())
	srv.disableRateLimit()

	const samples = 30
	// Cases mirror IMAP's auth-timing cases plus the three branches
	// the hostile reviewer flagged as missing on the SMTP side:
	// non-PLAIN mechanism, soft-deleted account, pending-proton-setup
	// account. Every branch must hit `burnDummyBcrypt` so the wall-
	// clock cost matches the wrong-password baseline.
	cases := []struct {
		name     string
		username string
		password string
		mech     string // empty -> AUTH PLAIN; non-empty -> AUTH <mech>
	}{
		{name: "wrong-password", username: "alice@reduit.example", password: "definitely-wrong"},
		{name: "unknown-user", username: "ghost@reduit.example", password: "any-password"},
		{name: "suspended", username: "bob@reduit.example", password: "bob-password"},
		{name: "soft-deleted", username: "carol@reduit.example", password: "carol-password"},
		{name: "pending-proton-setup", username: "dave@reduit.example", password: "dave-password"},
		{name: "malformed-identity-no-at", username: "joeexample.com", password: "any-password"},
		{name: "malformed-identity-non-ascii", username: "jo\xc3\xa9@example.com", password: "any-password"},
		// Non-PLAIN mechanism: the server rejects with 504, but it
		// burns one bcrypt comparison along the way so the timing is
		// identical to a wrong-password attempt.
		{name: "non-plain-mech", username: "alice@reduit.example", password: "any-password", mech: "GSSAPI"},
	}

	medians := make(map[string]time.Duration, len(cases))
	for _, tc := range cases {
		durations := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			start := time.Now()
			if tc.mech == "" {
				_ = authPlain(t, srv.addr, tc.username, tc.password)
			} else {
				_ = authMech(t, srv.addr, tc.mech)
			}
			durations = append(durations, time.Since(start))
		}
		drop := samples / 10
		if drop < 1 {
			drop = 1
		}
		sortDurations(durations)
		kept := durations[:samples-drop]
		median := kept[len(kept)/2]
		medians[tc.name] = median
		t.Logf("%-35s median=%v p10=%v p90=%v",
			tc.name, median, kept[len(kept)/10], kept[len(kept)*9/10])
	}

	baseline := medians["wrong-password"]
	const toleranceFactor = 0.20
	lower := time.Duration(float64(baseline) * (1 - toleranceFactor))
	upper := time.Duration(float64(baseline) * (1 + toleranceFactor))
	for name, m := range medians {
		if m < lower || m > upper {
			t.Errorf("%s median=%v is outside baseline tolerance [%v, %v] (baseline=%v)",
				name, m, lower, upper, baseline)
		}
	}
}

// sortDurations is an in-place ascending sort. Avoids `sort.Slice` to
// keep the timing test free of interface-conversion noise.
func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		v := d[i]
		j := i - 1
		for j >= 0 && d[j] > v {
			d[j+1] = d[j]
			j--
		}
		d[j+1] = v
	}
}
