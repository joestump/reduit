package tui

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// withGate temporarily forces the TTY gate to a known state and restores it.
func withGate(t *testing.T, stdin, stdout bool) {
	t.Helper()
	origIn, origOut := stdinIsTTY, stdoutIsTTY
	stdinIsTTY = func() bool { return stdin }
	stdoutIsTTY = func() bool { return stdout }
	t.Cleanup(func() { stdinIsTTY, stdoutIsTTY = origIn, origOut })
}

func TestRun_RefusesNonTTY(t *testing.T) {
	// A program must NEVER be constructed when the gate fails — otherwise ANSI
	// could leak into a pipe. We assert both the error and that newProgram was
	// not called.
	constructed := false
	origProg := newProgram
	newProgram = func(ctx context.Context, m tea.Model) *tea.Program {
		constructed = true
		return origProg(ctx, m)
	}
	t.Cleanup(func() { newProgram = origProg })

	cases := []struct{ in, out bool }{
		{false, false}, // both pipes (CI, cron)
		{true, false},  // stdout piped
		{false, true},  // stdin piped
	}
	for _, c := range cases {
		withGate(t, c.in, c.out)
		err := Run(context.Background(), fakeReader{})
		if !errors.Is(err, ErrNotATerminal) {
			t.Errorf("gate(stdin=%v,stdout=%v): err = %v, want ErrNotATerminal", c.in, c.out, err)
		}
	}
	if constructed {
		t.Error("a Bubble Tea program was constructed despite a failed TTY gate")
	}
}

func TestRun_TTYPassesGateAndRunsProgram(t *testing.T) {
	// With the gate satisfied, Run must construct and drive a program. We
	// substitute a program whose model quits immediately so the test does not
	// block on real terminal I/O.
	withGate(t, true, true)

	ran := false
	origProg := newProgram
	newProgram = func(ctx context.Context, m tea.Model) *tea.Program {
		ran = true
		// A program over an immediately-quitting model; WithInput(nil-ish) is
		// avoided by using a filtered model that sends Quit on Init.
		return tea.NewProgram(quitModel{}, tea.WithoutRenderer(), tea.WithInput(nil), tea.WithContext(ctx))
	}
	t.Cleanup(func() { newProgram = origProg })

	if err := Run(context.Background(), fakeReader{}); err != nil {
		t.Errorf("Run with satisfied gate returned %v, want nil", err)
	}
	if !ran {
		t.Error("newProgram was not called despite a satisfied gate")
	}
}

func TestRun_DoesNotSwallowPanics(t *testing.T) {
	// A model panic must NOT be reported as a clean exit: bubbletea wraps a
	// recovered panic as ErrProgramKilled+ErrProgramPanic, and Run must let it
	// propagate so the process exits non-zero (SPEC-0005 "Terminal Discipline").
	withGate(t, true, true)

	origProg := newProgram
	newProgram = func(ctx context.Context, m tea.Model) *tea.Program {
		return tea.NewProgram(panicModel{}, tea.WithoutRenderer(), tea.WithInput(nil), tea.WithContext(ctx))
	}
	t.Cleanup(func() { newProgram = origProg })

	err := Run(context.Background(), fakeReader{})
	if err == nil {
		t.Fatal("Run swallowed a model panic and returned nil (crash reported as success)")
	}
	if !errors.Is(err, tea.ErrProgramPanic) {
		t.Errorf("Run returned %v, want an error wrapping ErrProgramPanic", err)
	}
}

// quitModel is a trivial tea.Model that quits on its first update, so the gate
// test can drive Run to completion without real terminal I/O.
type quitModel struct{}

func (quitModel) Init() tea.Cmd                       { return tea.Quit }
func (quitModel) Update(tea.Msg) (tea.Model, tea.Cmd) { return quitModel{}, tea.Quit }
func (quitModel) View() string                        { return "" }

// panicModel panics on its first update so the swallow-guard test can assert a
// panic is surfaced, not masked.
type panicModel struct{}

func (panicModel) Init() tea.Cmd                       { return func() tea.Msg { return struct{}{} } }
func (panicModel) Update(tea.Msg) (tea.Model, tea.Cmd) { panic("boom") }
func (panicModel) View() string                        { return "" }
