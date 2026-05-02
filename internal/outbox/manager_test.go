// Manager-level tests not covered by the worker_test.go suite. Today
// this is just env-var resolution for REDUIT_OUTBOX_PER_ACCOUNT_CAP;
// the larger lifecycle / Submit tests live in worker_test.go alongside
// their fakes.
//
// Governing: SPEC-0004 REQ "Per-Account Outbox Concurrency Limit".

package outbox

import (
	"context"
	"testing"
	"time"
)

// TestResolvePerAccountCap_EnvOverride covers the REDUIT_OUTBOX_PER_ACCOUNT_CAP
// pathway. The env var is documented in EnvPerAccountCap and was
// previously referenced by the worker.go package comment without ever
// being read — the spec-compliance review (PR #42 round 1) flagged
// this as drift. Verify each branch:
//
//	unset             → DefaultPerAccountCap
//	valid positive    → that integer
//	zero / negative   → DefaultPerAccountCap (fall back, never deadlock)
//	malformed         → DefaultPerAccountCap
func TestResolvePerAccountCap_EnvOverride(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want int
	}{
		{"unset", "", DefaultPerAccountCap},
		{"explicit-8", "8", 8},
		{"explicit-1", "1", 1},
		{"zero-falls-back", "0", DefaultPerAccountCap},
		{"negative-falls-back", "-2", DefaultPerAccountCap},
		{"malformed-falls-back", "not-a-number", DefaultPerAccountCap},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv with "" sets the var to an empty string; the
			// resolver branches on os.Getenv returning "" so this is
			// equivalent to unset for our purposes. Go test framework
			// restores the parent env when the test binary exits.
			t.Setenv(EnvPerAccountCap, tc.env)
			if got := resolvePerAccountCap(); got != tc.want {
				t.Errorf("resolvePerAccountCap() = %d, want %d (env=%q)", got, tc.want, tc.env)
			}
		})
	}
}

// TestNew_HonoursPerAccountCapEnv verifies the env-var resolution flows
// through outbox.New so a Manager constructed without an explicit
// PerAccountCap picks up the env override. Without this end-to-end
// check the env var would still be "vapor" — resolved by a function
// nobody calls. Not parallel because t.Setenv mutates process state.
func TestNew_HonoursPerAccountCapEnv(t *testing.T) {
	t.Setenv(EnvPerAccountCap, "7")
	mgr, err := New(Config{
		Resolver:     stubResolver{client: &alwaysInternalClient{}},
		Builder:      noopBuilder,
		PendingStore: DiscardPendingStore,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		_ = mgr.Shutdown(testShutdownContext(t))
	})
	// The PerAccountCap is held inside cfg.PerAccountCap. It is the
	// value used when a per-account worker is minted; reading it
	// directly is the lightest touch that proves the env var was read.
	if got, want := mgr.cfg.PerAccountCap, 7; got != want {
		t.Errorf("mgr.cfg.PerAccountCap = %d, want %d (env override)", got, want)
	}
}

// TestNew_ExplicitConfigBeatsEnv: a non-zero Config.PerAccountCap MUST
// take precedence over the env var. The composition root may layer its
// own overrides on top of env detection (e.g. Viper-bound CLI flag);
// preserving that ordering means callers can be deterministic.
func TestNew_ExplicitConfigBeatsEnv(t *testing.T) {
	t.Setenv(EnvPerAccountCap, "9999")
	mgr, err := New(Config{
		Resolver:      stubResolver{client: &alwaysInternalClient{}},
		Builder:       noopBuilder,
		PendingStore:  DiscardPendingStore,
		PerAccountCap: 3,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown(testShutdownContext(t)) })
	if got, want := mgr.cfg.PerAccountCap, 3; got != want {
		t.Errorf("mgr.cfg.PerAccountCap = %d, want %d (config wins)", got, want)
	}
}

// testShutdownContext is a 2-second-bounded ctx for cleanup-time
// Shutdown calls. Inlined here so manager_test.go does not depend on
// the worker_test.go helper.
func testShutdownContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
