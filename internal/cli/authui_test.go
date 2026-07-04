package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/tui/styles"
)

// updateAuthModel folds one message into the model and returns the concrete
// authModel (Update returns tea.Model). Mirrors updateModel for the sync UI.
func updateAuthModel(m authModel, msg tea.Msg) authModel {
	next, _ := m.Update(msg)
	return next.(authModel)
}

func newTestAuthModel(t *testing.T, startResume bool) authModel {
	t.Helper()
	return newAuthModel(context.Background(), proton.NewFake(), "joe@proton.test", "sign in", startResume, styles.New(), styles.NewGlyphs(false))
}

// TestAuthModel_PasswordToLogin verifies Enter on the password field dispatches
// the login step and moves to the logging-in spinner phase.
func TestAuthModel_PasswordToLogin(t *testing.T) {
	m := newTestAuthModel(t, false)
	if m.phase != phasePassword {
		t.Fatalf("start phase = %v, want password", m.phase)
	}
	if m.input.EchoMode != textinput.EchoPassword {
		t.Errorf("password field EchoMode = %v, want EchoPassword (masked)", m.input.EchoMode)
	}
	m.input.SetValue("hunter2")
	m = updateAuthModel(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.phase != phaseLoggingIn {
		t.Fatalf("after password enter: phase = %v, want loggingIn", m.phase)
	}
}

// TestAuthModel_LoginBranches verifies the Login result picks the next field:
// TOTP (echoed) when a code is required, passphrase (masked) otherwise.
func TestAuthModel_LoginBranches(t *testing.T) {
	t.Run("totp required", func(t *testing.T) {
		m := newTestAuthModel(t, false)
		m = updateAuthModel(m, loginResultMsg{status: proton.AuthStatus{TwoFA: proton.TwoFATOTP}})
		if m.phase != phaseTOTP {
			t.Fatalf("phase = %v, want totp", m.phase)
		}
		if m.input.EchoMode != textinput.EchoNormal {
			t.Errorf("totp field EchoMode = %v, want EchoNormal (echoed)", m.input.EchoMode)
		}
	})
	t.Run("no 2fa goes to passphrase", func(t *testing.T) {
		m := newTestAuthModel(t, false)
		m = updateAuthModel(m, loginResultMsg{status: proton.AuthStatus{TwoFA: proton.TwoFANone}})
		if m.phase != phasePassphrase {
			t.Fatalf("phase = %v, want passphrase", m.phase)
		}
		if m.input.EchoMode != textinput.EchoPassword {
			t.Errorf("passphrase field EchoMode = %v, want EchoPassword (masked)", m.input.EchoMode)
		}
	})
	t.Run("unsupported 2fa fails", func(t *testing.T) {
		m := newTestAuthModel(t, false)
		m = updateAuthModel(m, loginResultMsg{status: proton.AuthStatus{TwoFA: proton.TwoFAUnsupported}})
		if m.phase != phaseAuthFailed || !errors.Is(m.err, errUnsupported2FA) {
			t.Fatalf("unsupported 2FA: phase=%v err=%v, want failed + errUnsupported2FA", m.phase, m.err)
		}
	})
	t.Run("login error fails", func(t *testing.T) {
		m := newTestAuthModel(t, false)
		boom := errors.New("login failed: nope")
		m = updateAuthModel(m, loginResultMsg{err: boom})
		if m.phase != phaseAuthFailed || m.err != boom {
			t.Fatalf("login error: phase=%v err=%v, want failed + boom", m.phase, m.err)
		}
	})
}

// TestAuthModel_PassphraseSurvivesUnlock verifies the passphrase is stashed on
// submit and survives a successful unlock as the model's return value, and that
// a failed unlock zeroes it (SPEC-0013 "No Secret Leakage In The TUI").
func TestAuthModel_PassphraseSurvivesUnlock(t *testing.T) {
	m := newTestAuthModel(t, false)
	m = updateAuthModel(m, loginResultMsg{status: proton.AuthStatus{TwoFA: proton.TwoFANone}}) // → passphrase
	m.input.SetValue("s3cret-phrase")
	m = updateAuthModel(m, tea.KeyMsg{Type: tea.KeyEnter}) // → unlocking, passphrase stashed
	if m.phase != phaseUnlocking {
		t.Fatalf("after passphrase enter: phase = %v, want unlocking", m.phase)
	}
	if string(m.passphrase) != "s3cret-phrase" {
		t.Fatalf("stashed passphrase = %q, want s3cret-phrase", m.passphrase)
	}

	done := updateAuthModel(m, unlockResultMsg{err: nil})
	if done.phase != phaseAuthDone {
		t.Fatalf("unlock ok: phase = %v, want done", done.phase)
	}
	if string(done.passphrase) != "s3cret-phrase" {
		t.Errorf("passphrase after unlock = %q, want it to survive", done.passphrase)
	}

	failed := updateAuthModel(m, unlockResultMsg{err: errors.New("unlock failed")})
	if failed.phase != phaseAuthFailed {
		t.Fatalf("unlock err: phase = %v, want failed", failed.phase)
	}
	if failed.passphrase != nil {
		t.Errorf("passphrase after failed unlock = %q, want zeroed/nil", failed.passphrase)
	}
}

// TestAuthModel_AbortFails verifies Ctrl-C aborts to the failed phase with the
// abort sentinel.
func TestAuthModel_AbortFails(t *testing.T) {
	m := newTestAuthModel(t, false)
	m = updateAuthModel(m, tea.KeyMsg{Type: tea.KeyCtrlC})
	if m.phase != phaseAuthFailed || !errors.Is(m.err, errAuthAborted) {
		t.Fatalf("ctrl-c: phase=%v err=%v, want failed + errAuthAborted", m.phase, m.err)
	}
}

// TestAuthModel_ResumePhase verifies the refresh cheap-resume phase: success
// quits with resumeDone; fall-through opens the password field; a hard error
// fails.
func TestAuthModel_ResumePhase(t *testing.T) {
	t.Run("done", func(t *testing.T) {
		m := newTestAuthModel(t, true)
		if m.phase != phaseResume {
			t.Fatalf("start phase = %v, want resume", m.phase)
		}
		m = updateAuthModel(m, resumeResultMsg{done: true})
		if m.phase != phaseAuthDone || !m.resumeDone {
			t.Fatalf("resume done: phase=%v resumeDone=%v, want done + true", m.phase, m.resumeDone)
		}
	})
	t.Run("fall through to re-login", func(t *testing.T) {
		m := newTestAuthModel(t, true)
		m = updateAuthModel(m, resumeResultMsg{done: false})
		if m.phase != phasePassword {
			t.Fatalf("resume fall-through: phase = %v, want password", m.phase)
		}
	})
	t.Run("hard error fails", func(t *testing.T) {
		m := newTestAuthModel(t, true)
		boom := errors.New("keyring boom")
		m = updateAuthModel(m, resumeResultMsg{err: boom})
		if m.phase != phaseAuthFailed || m.err != boom {
			t.Fatalf("resume err: phase=%v err=%v, want failed + boom", m.phase, m.err)
		}
	})
}

// TestNoticeHandler_ReclassifiesBenignScope verifies the salts-scope 403/9101 is
// rewritten to a WARN notice, and a genuine error is left untouched (SPEC-0013
// "Benign-Scope Notice").
func TestNoticeHandler_ReclassifiesBenignScope(t *testing.T) {
	render := func(level slog.Level, msg string) string {
		var buf bytes.Buffer
		base := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		log := withNoticeHandler(base)
		log.LogAttrs(context.Background(), level, msg)
		return buf.String()
	}

	// The benign salts-scope error → downgraded to WARN, friendly message, no raw
	// 9101 code leaking.
	out := render(slog.LevelError, "403 GET https://mail.proton.me/api/core/v4/keys/salts: Access token does not have sufficient scope (Code=9101, Status=403)")
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("benign scope not downgraded to WARN: %q", out)
	}
	if !strings.Contains(out, noticeMessage) {
		t.Errorf("benign scope missing friendly notice: %q", out)
	}
	if strings.Contains(out, "9101") {
		t.Errorf("raw diagnostic leaked through the notice: %q", out)
	}

	// A genuine auth error stays an ERROR with its message intact.
	real := render(slog.LevelError, "login failed: invalid credentials")
	if !strings.Contains(real, "level=ERROR") || !strings.Contains(real, "invalid credentials") {
		t.Errorf("real error should be unchanged: %q", real)
	}
}

// TestRunInteractiveAuthGated_NonTTYUsesPrompter verifies the non-interactive
// gate never constructs a Bubble Tea program and drives the plain prompter path
// (SPEC-0013 "TTY Gate And Non-Interactive Fallback").
func TestRunInteractiveAuthGated_NonTTYUsesPrompter(t *testing.T) {
	origTTY, origProg := isTerminal, newAuthProgram
	t.Cleanup(func() { isTerminal, newAuthProgram = origTTY, origProg })
	isTerminal = func() bool { return false }
	built := false
	newAuthProgram = func(ctx context.Context, m tea.Model) *tea.Program {
		built = true
		return origProg(ctx, m)
	}

	fake := proton.NewFake()
	p := &scriptPrompter{secrets: []string{"pw", "pass"}}
	pass, err := runInteractiveAuthGated(context.Background(), fake, p, newSwitchWriter(io.Discard), "gate@proton.test", "sign in", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("gated auth: %v", err)
	}
	if built {
		t.Error("non-TTY path constructed a Bubble Tea program; it must not")
	}
	if string(pass) != "pass" {
		t.Errorf("returned passphrase = %q, want the prompter's 'pass'", pass)
	}
}
