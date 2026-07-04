// Package cli — the interactive auth TUI model.
//
// authModel is the Bubble Tea model behind `reduit auth add` / `auth refresh` in
// an interactive terminal (ADR-0026). Unlike the sync progress bar (which only
// observes an engine that runs to completion), auth is REQUEST/RESPONSE: the
// model collects a field, hands it to a network call, and the call's result
// decides the next field (TOTP only if the account has it; passphrase only after
// login succeeds). Each network call runs OFF the UI goroutine as a tea.Cmd that
// returns a typed result message; Update folds the result to pick the next phase.
//
// The model never owns the auth logic — it drives the shared loginStep /
// submitTOTPStep / unlockStep (auth.go), the same functions the plain prompter
// path uses, so the two front ends cannot diverge (SPEC-0013 "Network Steps
// Shared With Plain Path"). It never owns secrets either: password/TOTP are
// zeroed inside their commands; the passphrase is the only value that crosses
// teardown, held in the model and read back by the runner (SPEC-0013 "No Secret
// Leakage In The TUI").
//
// Governing: ADR-0026 (interactive auth TUI), ADR-0025 (design language),
// SPEC-0013, SPEC-0007 (No Secret Leakage).
package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/joestump/reduit/internal/proton"
	"github.com/joestump/reduit/internal/tui/styles"
)

// authPhase is the model's position in the request/response sequence.
type authPhase int

const (
	phaseResume     authPhase = iota // refresh only: cheap-resume probe running (spinner)
	phasePassword                    // collecting the password (masked)
	phaseLoggingIn                   // network: Login running (spinner)
	phaseTOTP                        // collecting the TOTP code (echoed)
	phaseSubmitTOTP                  // network: SubmitTOTP running (spinner)
	phasePassphrase                  // collecting the mailbox passphrase (masked)
	phaseUnlocking                   // network: Unlock running (spinner)
	phaseAuthDone                    // success — model quits, runner reads passphrase
	phaseAuthFailed                  // terminal error captured — model quits
)

// --- result messages (network step outcomes, folded by Update) --------------

// resumeResultMsg carries the outcome of the refresh cheap-resume probe, run by
// the runner on a background goroutine while the model shows a spinner. done
// means the probe reactivated the mailbox and no re-login is needed; a nil err
// with done=false means fall through to the interactive re-login.
type resumeResultMsg struct {
	done bool
	err  error
}
type loginResultMsg struct {
	status proton.AuthStatus
	err    error
}
type totpResultMsg struct{ err error }
type unlockResultMsg struct{ err error }

// --- model ------------------------------------------------------------------

// authModel drives the interactive auth flow. It is a value type threaded
// through Bubble Tea's Update; the fields that must survive teardown
// (passphrase, err) are read back off the final model by the runner.
type authModel struct {
	ctx     context.Context
	client  proton.Client
	address string
	verb    string // header subtitle: "sign in" (add) or "re-authenticate" (refresh)
	st      styles.Styles
	glyphs  styles.Glyphs

	input textinput.Model
	spin  spinner.Model
	phase authPhase

	// passphrase is the SURVIVOR: on a successful unlock it holds the mailbox
	// passphrase the runner returns to the caller (which persists and zeroes it).
	passphrase []byte
	// resumeDone is set when the refresh cheap-resume probe fully reactivated the
	// mailbox; the runner then returns without a re-login.
	resumeDone bool
	// err is the terminal cause when the flow fails or is aborted.
	err error
}

// newAuthModel builds the model. When startResume is true (refresh), it opens on
// the cheap-resume spinner phase and waits for a resumeResultMsg; otherwise (add)
// it opens focused on the password field.
func newAuthModel(ctx context.Context, client proton.Client, address, verb string, startResume bool, st styles.Styles, g styles.Glyphs) authModel {
	in := textinput.New()
	in.Prompt = "" // the header renders its own ❯ prompt

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = st.HelpKey // cyan

	m := authModel{
		ctx:     ctx,
		client:  client,
		address: address,
		verb:    verb,
		st:      st,
		glyphs:  g,
		input:   in,
		spin:    sp,
	}
	if startResume {
		m.phase = phaseResume
	} else {
		m.enterInput(phasePassword, true)
	}
	return m
}

func (m authModel) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, m.spin.Tick)
}

// isInputPhase reports whether the model is currently waiting on a field (vs. a
// network round-trip). Only in an input phase do keystrokes reach the textinput.
func (m authModel) isInputPhase() bool {
	return m.phase == phasePassword || m.phase == phaseTOTP || m.phase == phasePassphrase
}

// enterInput reconfigures the single textinput for a field phase: reset it, set
// echo masking for secrets, and focus it.
func (m *authModel) enterInput(phase authPhase, secret bool) {
	m.phase = phase
	m.input.Reset()
	if secret {
		m.input.EchoMode = textinput.EchoPassword
		m.input.EchoCharacter = '•'
	} else {
		m.input.EchoMode = textinput.EchoNormal
	}
	m.input.Focus()
}

func (m authModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		return m.handleKey(msg)

	case resumeResultMsg:
		if msg.err != nil {
			return m.fail(msg.err)
		}
		if msg.done {
			// The cheap-resume probe reactivated the mailbox; nothing more to do.
			m.resumeDone = true
			m.phase = phaseAuthDone
			return m, tea.Quit
		}
		// Fall through to the interactive re-login.
		m.enterInput(phasePassword, true)
		return m, textinput.Blink

	case loginResultMsg:
		return m.handleLogin(msg)

	case totpResultMsg:
		if msg.err != nil {
			return m.fail(msg.err)
		}
		m.enterInput(phasePassphrase, true)
		return m, textinput.Blink

	case unlockResultMsg:
		if msg.err != nil {
			return m.fail(msg.err)
		}
		m.phase = phaseAuthDone
		return m, tea.Quit
	}

	// Any other message (e.g. a blink) advances the field during input phases.
	if m.isInputPhase() {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

// handleKey routes keystrokes: Ctrl-C / Esc aborts; Enter submits the current
// field and dispatches its network step; anything else edits the field.
func (m authModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC, tea.KeyEsc:
		return m.fail(errAuthAborted)
	case tea.KeyEnter:
		if m.isInputPhase() {
			return m.submitField()
		}
		return m, nil
	}
	if m.isInputPhase() {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

// submitField reads the focused field, clears it, and dispatches the matching
// network command, transitioning to the corresponding spinner phase.
func (m authModel) submitField() (tea.Model, tea.Cmd) {
	switch m.phase {
	case phasePassword:
		pw := []byte(m.input.Value())
		m.input.Reset()
		m.phase = phaseLoggingIn
		return m, m.loginCmd(pw)
	case phaseTOTP:
		code := m.input.Value()
		m.input.Reset()
		m.phase = phaseSubmitTOTP
		return m, m.submitTOTPCmd(code)
	case phasePassphrase:
		pass := []byte(m.input.Value())
		m.input.Reset()
		// Stash the survivor BEFORE dispatching: the runner reads m.passphrase
		// back after teardown; the same slice is handed to Unlock (which does not
		// zero it — the caller owns that).
		m.passphrase = pass
		m.phase = phaseUnlocking
		return m, m.unlockCmd(pass)
	}
	return m, nil
}

// handleLogin folds the Login result: an error fails; TOTP moves to the code
// field; an unsupported second factor fails; otherwise straight to passphrase.
func (m authModel) handleLogin(msg loginResultMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		return m.fail(msg.err)
	}
	switch msg.status.TwoFA {
	case proton.TwoFATOTP:
		m.enterInput(phaseTOTP, false)
		return m, textinput.Blink
	case proton.TwoFAUnsupported:
		return m.fail(errUnsupported2FA)
	default: // proton.TwoFANone
		m.enterInput(phasePassphrase, true)
		return m, textinput.Blink
	}
}

// fail captures a terminal cause, zeroes any stashed passphrase, and quits. The
// runner surfaces m.err after teardown.
func (m authModel) fail(err error) (tea.Model, tea.Cmd) {
	if m.passphrase != nil {
		zero(m.passphrase)
		m.passphrase = nil
	}
	m.err = err
	m.phase = phaseAuthFailed
	return m, tea.Quit
}

// --- network commands (run off the UI goroutine) ----------------------------
//
// Each captures the values it needs and returns a typed result message. The
// password and TOTP are zeroed/dropped as soon as their step returns; the
// passphrase is not zeroed here (the model holds it as the survivor and the
// caller owns its lifecycle).

func (m authModel) loginCmd(password []byte) tea.Cmd {
	ctx, client, address := m.ctx, m.client, m.address
	return func() tea.Msg {
		status, err := loginStep(ctx, client, address, password)
		zero(password)
		return loginResultMsg{status: status, err: err}
	}
}

func (m authModel) submitTOTPCmd(code string) tea.Cmd {
	ctx, client := m.ctx, m.client
	return func() tea.Msg {
		return totpResultMsg{err: submitTOTPStep(ctx, client, code)}
	}
}

func (m authModel) unlockCmd(passphrase []byte) tea.Cmd {
	ctx, client := m.ctx, m.client
	return func() tea.Msg {
		return unlockResultMsg{err: unlockStep(ctx, client, passphrase)}
	}
}

// --- view -------------------------------------------------------------------

func (m authModel) View() string {
	// Once the flow is done or failed the program is quitting; render nothing so
	// no header lingers after teardown (SPEC-0013 "Clean Teardown"; mirrors
	// syncModel.View()). The caller prints the success line / error on the
	// restored terminal.
	if m.phase == phaseAuthDone || m.phase == phaseAuthFailed {
		return ""
	}

	header := m.st.Panel.Render(
		m.st.Title.Render("reduit") +
			m.st.Dim.Render("  "+m.verb+" · ") +
			m.st.Text.Render(m.address),
	)

	prompt := m.st.HelpKey.Render(m.glyphs.Prompt) // cyan ❯
	var line string
	switch m.phase {
	case phaseResume:
		line = fmt.Sprintf("%s %s", m.spin.View(), m.st.Dim.Render("checking saved session…"))
	case phasePassword:
		line = fmt.Sprintf("%s %s  %s", prompt, m.st.Dim.Render("proton password"), m.input.View())
	case phaseLoggingIn:
		line = fmt.Sprintf("%s %s", m.spin.View(), m.st.Dim.Render("signing in…"))
	case phaseTOTP:
		line = fmt.Sprintf("%s %s  %s", prompt, m.st.Dim.Render("totp code"), m.input.View())
	case phaseSubmitTOTP:
		line = fmt.Sprintf("%s %s", m.spin.View(), m.st.Dim.Render("verifying code…"))
	case phasePassphrase:
		line = fmt.Sprintf("%s %s  %s", prompt, m.st.Dim.Render("mailbox passphrase"), m.input.View())
	case phaseUnlocking:
		line = fmt.Sprintf("%s %s", m.spin.View(), m.st.Dim.Render("unlocking mailbox…"))
	}

	footer := m.helpFooter()
	return lipgloss.JoinVertical(lipgloss.Left, header, "", "  "+line, "", footer)
}

// helpFooter renders the dim `key • action` footer every view carries (ADR-0025).
func (m authModel) helpFooter() string {
	sep := m.st.HelpSep.Render(" • ")
	enter := m.st.HelpKey.Render("enter") + " " + m.st.Help.Render("submit")
	cancel := m.st.HelpKey.Render("^c") + " " + m.st.Help.Render("cancel")
	return "  " + enter + sep + cancel
}

// ensure the model satisfies tea.Model.
var _ tea.Model = authModel{}

// errAuthAborted is returned when the operator cancels the interactive TUI. It
// is a distinct sentinel so the caller can treat an abort differently from a
// network failure if needed; today both roll back an in-progress add.
var errAuthAborted = errors.New("authentication cancelled")
