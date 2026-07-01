//go:build !webview

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

// TestSolveCaptchaHV_HeadlessReturnsDesktopError asserts the default/headless
// build cannot solve a CAPTCHA and returns the actionable desktop-build guidance
// (ADR-0021) rather than attempting a (removed) loopback solve. It must NOT even
// fetch the captcha challenge — there is nothing to render it in.
func TestSolveCaptchaHV_HeadlessReturnsDesktopError(t *testing.T) {
	fake := proton.NewFake()
	hv := &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "chal"}

	_, err := solveCaptchaHV(context.Background(), fake, "joe@proton.test", []byte("pw"), hv,
		&bytes.Buffer{}, &scriptPrompter{})
	if err == nil {
		t.Fatal("expected a desktop-build error on the headless path, got nil")
	}
	for _, want := range []string{"desktop build", "-tags webview", "auth import"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing guidance %q", err, want)
		}
	}
	if len(fake.CaptchaTokens) != 0 {
		t.Errorf("headless path fetched the captcha challenge: %v", fake.CaptchaTokens)
	}
}

// TestAuthAdd_HumanVerification_RequiresDesktopBuild drives the whole add flow
// into Proton's 9001 wall on the default build and confirms the HV plumbing
// (interactiveAuth → solveCaptchaHV) still routes correctly and surfaces the
// desktop-build error — and that no half-written mailbox row is left behind
// (SPEC-0007 "adds are atomic"). This is the default-build counterpart to the
// webview build's live-solve path.
func TestAuthAdd_HumanVerification_RequiresDesktopBuild(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ks := newTestKeychain(t)

	fake := proton.NewFake()
	fake.UserID = "proton-user-hv"
	fake.HVChallenge = &proton.HVRequiredError{Methods: []string{"captcha"}, Token: "hv-tok"}

	dialer := &fakeDialer{client: fake}
	p := &scriptPrompter{secrets: []string{"hunter2"}}

	var out bytes.Buffer
	err := authAdd(ctx, st, ks, dialer, p, "hv@proton.test", &out)
	if err == nil || !strings.Contains(err.Error(), "desktop build") {
		t.Fatalf("expected desktop-build error from authAdd, got %v", err)
	}
	if _, gerr := st.GetMailboxByAddress(ctx, "hv@proton.test"); gerr == nil {
		t.Error("a mailbox row was left behind after the failed HV add")
	} else if !errors.Is(gerr, store.ErrMailboxNotFound) {
		t.Fatalf("unexpected lookup error: %v", gerr)
	}
}
