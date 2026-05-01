package imapserver

import (
	"testing"
	"time"

	"github.com/joestump/reduit/internal/account"
)

// TestAuthFailureIsConstantTime is the wall-clock companion to
// TestSASLPlainAuthFailuresAreIdentical. Byte-identical responses are
// not enough — if the wrong-password branch burns ~250ms in bcrypt
// while the unknown-account / suspended / malformed-identity branches
// return in microseconds, an attacker can enumerate which OIDC
// subjects exist and what state they are in by timing the responses.
//
// This test runs each failure mode N times, drops the worst 10% of
// samples (to absorb GC / scheduling noise), and asserts the median
// of every failure mode is within ~20% of the bcrypt-bearing
// (wrong-password) baseline.
//
// Governing: SPEC-0003 REQ "Authentication failure returns NO with
// no detail" — uniform-time auth.
func TestAuthFailureIsConstantTime(t *testing.T) {
	// Not t.Parallel(): timing tests are sensitive to scheduling and
	// CPU contention from other parallel tests on the same runner.

	// Skip in -short mode: the test runs 30+ real bcrypts per case
	// times five cases, ~30 seconds wall time. CI runs it; iterative
	// `go test -short` skips it.
	if testing.Short() {
		t.Skip("timing-side-channel test runs ~150 bcrypts at cost 12; skipped in -short mode")
	}

	stub := newBcryptStubAccounts()
	stub.addAccount(t, "acct-active", "alice@reduit.example", "alice-password", account.StateActive)
	stub.addAccount(t, "acct-suspended", "bob@reduit.example", "bob-password", account.StateSuspended)
	srv := startTestServer(t, stub, NewSessions())
	// Many sequential failures from 127.0.0.1 would otherwise trigger
	// the per-IP exponential back-off and dominate wall-clock cost.
	// The test is measuring bcrypt uniformity, not rate-limit timing.
	srv.disableRateLimit()

	const samples = 30
	cases := []struct {
		name     string
		username string
		password string
	}{
		// Baseline: real bcrypt verify against a wrong password.
		{"wrong-password", "alice@reduit.example", "definitely-wrong"},
		// Failure branches that previously skipped bcrypt entirely.
		{"unknown-user", "ghost@reduit.example", "any-password"},
		{"suspended", "bob@reduit.example", "bob-password"},
		{"malformed-identity-no-at", "joeexample.com", "any-password"},
		{"malformed-identity-non-ascii", "jo\xc3\xa9@example.com", "any-password"},
	}

	medians := make(map[string]time.Duration, len(cases))
	for _, tc := range cases {
		durations := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			start := time.Now()
			_ = authenticatePlain(t, srv.addr, tc.username, tc.password)
			durations = append(durations, time.Since(start))
		}
		// Drop the worst 10% to absorb GC / scheduler outliers.
		drop := samples / 10
		if drop < 1 {
			drop = 1
		}
		// Sort ascending and take the median of the kept range.
		sortDurations(durations)
		kept := durations[:samples-drop]
		median := kept[len(kept)/2]
		medians[tc.name] = median
		t.Logf("%-35s median=%v p10=%v p90=%v",
			tc.name, median, kept[len(kept)/10], kept[len(kept)*9/10])
	}

	// Baseline is the wrong-password branch (real bcrypt verify).
	baseline := medians["wrong-password"]
	// Tolerance: ±20% of baseline. The dummy and real bcrypt run at
	// the same cost (12) on different inputs; observed medians cluster
	// within ~5ms of each other (~2% spread), so 20% is generous but
	// still tight enough to catch a regression that drops bcrypt from
	// any one failure branch.
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

// sortDurations is an in-place ascending sort. We avoid `sort.Slice`
// to keep the timing test free of interface-conversion noise, though
// the cost is negligible at N=30.
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
