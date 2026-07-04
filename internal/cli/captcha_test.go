package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/store"
)

// TestHumanVerificationError_Message confirms the HV error is clear and
// actionable — it points the operator at the app-version knob (the real remedy,
// since the default Bridge app-version avoids the challenge), names the Bridge
// default, lists the offered methods for diagnostics, and never echoes the
// challenge token.
func TestHumanVerificationError_Message(t *testing.T) {
	hv := &proton.HVRequiredError{Methods: []string{"captcha", "email"}, Token: "SECRET-CHALLENGE-TOKEN"}
	err := humanVerificationError(hv)
	msg := err.Error()

	for _, want := range []string{
		"human verification",
		"Bridge",
		"proton.app_version",
		"REDUIT_PROTON_APP_VERSION",
		proton.DefaultAppVersion,
		"captcha, email", // offered methods, for diagnostics
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("HV error %q missing %q", msg, want)
		}
	}
	if strings.Contains(msg, "SECRET-CHALLENGE-TOKEN") {
		t.Errorf("HV error echoed the challenge token: %q", msg)
	}
}

// TestHumanVerificationError_NoMethods confirms the message still reads cleanly
// (no dangling "offered methods" clause) when Proton offered no method list.
func TestHumanVerificationError_NoMethods(t *testing.T) {
	err := humanVerificationError(&proton.HVRequiredError{})
	if msg := err.Error(); strings.Contains(msg, "offered methods") {
		t.Errorf("empty-methods HV error should omit the methods clause: %q", msg)
	}
}

// TestInteractiveAuth_HVSurfacesClearError is the core behavior test: when Login
// returns Proton's 9001 human-verification challenge, interactiveAuth surfaces
// the clear app-version error — it does NOT panic, loop, or attempt an in-app
// solve (ADR-0021). It never reaches the passphrase prompt.
func TestInteractiveAuth_HVSurfacesClearError(t *testing.T) {
	fake := proton.NewFake()
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}
	// Only the password is read; the flow returns before the passphrase prompt.
	p := &scriptPrompter{secrets: []string{"hunter2"}}

	var out bytes.Buffer
	_, err := interactiveAuth(context.Background(), fake, p, "hv@proton.test", &out)
	if err == nil {
		t.Fatal("expected a human-verification error, got nil")
	}
	if !errors.Is(err, proton.ErrHumanVerification) && !strings.Contains(err.Error(), "human verification") {
		t.Fatalf("expected a human-verification error, got %v", err)
	}
	if !strings.Contains(err.Error(), "proton.app_version") {
		t.Errorf("HV error should point at the app-version knob, got %v", err)
	}
}

// TestAuthAdd_HumanVerification_ReturnsClearErrorAtomic drives the whole add flow
// into Proton's 9001 wall and confirms authAdd surfaces the clear app-version
// error AND leaves no half-written mailbox row behind (SPEC-0007 "adds are
// atomic"). The HV fires before any row is inserted, so this also guards that
// ordering. No browser, no in-app solve (ADR-0021).
func TestAuthAdd_HumanVerification_ReturnsClearErrorAtomic(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	// password only; the flow returns the HV error before the passphrase prompt.
	p := &scriptPrompter{secrets: []string{"hunter2"}}

	var out bytes.Buffer
	err := authAdd(ctx, st, ks, dialer, p, nil, "hv@proton.test", &out)
	if err == nil || !strings.Contains(err.Error(), "human verification") {
		t.Fatalf("expected a human-verification error from authAdd, got %v", err)
	}
	if _, gerr := st.GetMailboxByAddress(ctx, "hv@proton.test"); gerr == nil {
		t.Error("a mailbox row was left behind after the HV-rejected add")
	} else if !errors.Is(gerr, store.ErrMailboxNotFound) {
		t.Fatalf("unexpected lookup error: %v", gerr)
	}
}
