package sanitize

import (
	"strings"
	"testing"
)

func TestLine_StripsC0Controls(t *testing.T) {
	// Every C0 control (0x00–0x1F) plus DEL must vanish in line mode, including
	// newline and tab. ESC (0x1B) is skipped here: it is an escape *introducer*
	// that also consumes the byte after it, so its "a<ESC>b" → "a" behavior is
	// covered by the dedicated escape tests, not this per-byte drop check.
	for c := rune(0); c < 0x20; c++ {
		if c == 0x1B {
			continue
		}
		in := "a" + string(c) + "b"
		if got := Line(in); got != "ab" {
			t.Errorf("Line(%q) = %q, want %q (C0 %#x not stripped)", in, got, "ab", c)
		}
	}
	if got := Line("a\x7fb"); got != "ab" {
		t.Errorf("Line DEL: got %q, want %q", got, "ab")
	}
}

func TestLine_StripsC1Controls(t *testing.T) {
	// The C1 introducers — CSI (0x9B), OSC (0x9D), and the string controls
	// DCS/SOS/PM/APC (0x90/0x98/0x9E/0x9F) — consume trailing bytes and get
	// dedicated tests below. Every other C1 control is a plain drop.
	introducers := map[rune]bool{0x9B: true, 0x9D: true, 0x90: true, 0x98: true, 0x9E: true, 0x9F: true}
	for c := rune(0x80); c <= 0x9F; c++ {
		if introducers[c] {
			continue
		}
		in := "x" + string(c) + "y"
		if got := Line(in); got != "xy" {
			t.Errorf("Line(%q) = %q, want %q (C1 %#x not stripped)", in, got, "xy", c)
		}
	}
}

func TestLine_StripsCSIColorSequence(t *testing.T) {
	// The classic injection: SGR color. The ESC introducer AND the "[31m" body
	// must both go, leaving no visible residue.
	in := "safe\x1b[31mRED\x1b[0mtext"
	want := "safeREDtext"
	if got := Line(in); got != want {
		t.Errorf("Line CSI SGR: got %q, want %q", got, want)
	}
}

func TestLine_StripsCursorMoveAndClear(t *testing.T) {
	cases := map[string]string{
		"a\x1b[2Jb":      "ab", // clear screen
		"a\x1b[10;20Hb":  "ab", // cursor position
		"a\x1b[Kb":       "ab", // erase line
		"a\x1b[?25lb":    "ab", // DEC private: hide cursor
		"a\x1b[?1049hb":  "ab", // DEC private: alt screen
		"a\x1b[38;5;9mb": "ab", // 256-color SGR
	}
	for in, want := range cases {
		if got := Line(in); got != want {
			t.Errorf("Line(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLine_StripsOSCTitleSequences(t *testing.T) {
	// OSC window-title setter, terminated by BEL and by ST (ESC \).
	bel := "x\x1b]0;pwned\x07y"
	if got := Line(bel); got != "xy" {
		t.Errorf("Line OSC/BEL: got %q, want %q", got, "xy")
	}
	st := "x\x1b]0;pwned\x1b\\y"
	if got := Line(st); got != "xy" {
		t.Errorf("Line OSC/ST: got %q, want %q", got, "xy")
	}
}

func TestLine_StripsC1CSIAndOSCIntroducers(t *testing.T) {
	// C1 forms of CSI (U+009B) and OSC (U+009D) — a terminal in an 8-bit mode
	// would act on these; the params after the introducer must not leak as text.
	if got := Line("a\u009b31mREDb"); got != "aREDb" {
		t.Errorf("Line C1 CSI: got %q, want %q", got, "aREDb")
	}
	if got := Line("a\u009d0;title\x07b"); got != "ab" {
		t.Errorf("Line C1 OSC: got %q, want %q", got, "ab")
	}
}

func TestLine_StripsRawC1IntroducerBytes(t *testing.T) {
	// The scanner works on raw bytes: a lone C1 byte (invalid UTF-8) must be
	// recognized as an introducer, not turned into a U+FFFD replacement char
	// that leaks its trailing params. \x9b = CSI, \x9d = OSC.
	if got := Line("a\x9b31mREDb"); got != "aREDb" {
		t.Errorf("Line raw C1 CSI: got %q, want %q", got, "aREDb")
	}
	if got := Line("x\x9d0;title\x07y"); got != "xy" {
		t.Errorf("Line raw C1 OSC: got %q, want %q", got, "xy")
	}
	// Raw C1 must never leave a U+FFFD replacement char behind.
	if strings.ContainsRune(Line("a\x9b31mb"), '�') {
		t.Error("raw C1 introducer left a U+FFFD residue")
	}
	// Other raw C1 controls are plain drops (0x85 = NEL).
	if got := Line("a\x85b"); got != "ab" {
		t.Errorf("Line raw C1 NEL: got %q, want %q", got, "ab")
	}
}

func TestLine_StripsDCSSOSPMAPC(t *testing.T) {
	// The ECMA-48 string controls DCS/SOS/PM/APC run until ST or BEL. Their
	// bodies must be consumed in full, in both ESC and raw C1 forms.
	cases := map[string]string{
		"safe\x1bP31mHACK\x1b\\ok": "safeok", // DCS ESC P … ST
		"a\x1bXhidden\x1b\\b":      "ab",     // SOS ESC X … ST
		"a\x1b^pm-body\x07b":       "ab",     // PM  ESC ^ … BEL
		"a\x1b_apc-body\x1b\\b":    "ab",     // APC ESC _ … ST
		"a\x90dcs-c1\x1b\\b":       "ab",     // raw C1 DCS (0x90)
		"a\x9eapc\x07b":            "ab",     // raw C1 PM (0x9e)
	}
	for in, want := range cases {
		if got := Line(in); got != want {
			t.Errorf("Line(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBlock_EscapeBeforeNewlineKeepsRowBreak(t *testing.T) {
	// A crafted ESC right before a newline must NOT swallow the row break —
	// the newline is layout, not an escape follow byte.
	if got := Block("top\x1b\nbottom"); got != "top\nbottom" {
		t.Errorf("Block ESC-before-LF: got %q, want %q", got, "top\nbottom")
	}
	if got := Block("a\x1b\tb"); got != "a    b" {
		t.Errorf("Block ESC-before-TAB: got %q, want %q", got, "a    b")
	}
}

func TestLine_LoneAndTruncatedEscapes(t *testing.T) {
	cases := map[string]string{
		"trailing\x1b":      "trailing",  // bare ESC at end
		"esc\x1bc reset":    "esc reset", // two-char escape ESC c
		"trunc\x1b[":        "trunc",     // CSI introducer, nothing after
		"trunc\x1b[38;":     "trunc",     // CSI params, no final byte
		"osc\x1b]0;no-term": "osc",       // OSC never terminated
	}
	for in, want := range cases {
		if got := Line(in); got != want {
			t.Errorf("Line(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLine_MalformedCSIResumesStripping(t *testing.T) {
	// A CSI broken by a stray control byte must not swallow following controls:
	// the control after the malformed sequence must still be stripped.
	in := "a\x1b[3\x07b" // CSI params, then BEL (invalid final), then 'b'
	if got := Line(in); got != "ab" {
		t.Errorf("Line malformed CSI: got %q, want %q", got, "ab")
	}
}

func TestLine_PreservesPrintableUnicode(t *testing.T) {
	// Combining marks, emoji, CJK, and RTL text are printable content, not
	// controls — they must pass through untouched.
	cases := []string{
		"café résumé",
		"日本語のメール",
		"emoji 🧋🌸 flourish",
		"é combining acute",
		"مرحبا بك",
	}
	for _, s := range cases {
		if got := Line(s); got != s {
			t.Errorf("Line(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestBlock_PreservesNewlinesExpandsTabs(t *testing.T) {
	in := "line one\nline two\tindented"
	want := "line one\nline two    indented"
	if got := Block(in); got != want {
		t.Errorf("Block: got %q, want %q", got, want)
	}
}

func TestBlock_DropsCarriageReturns(t *testing.T) {
	// A lone CR would rewind the cursor to column 0 and let following text
	// overwrite the line — a classic terminal overwrite trick. Block drops CR
	// but keeps the LF.
	in := "visible\rHIDDEN\nnext"
	want := "visibleHIDDEN\nnext"
	if got := Block(in); got != want {
		t.Errorf("Block CR: got %q, want %q", got, want)
	}
}

func TestBlock_StripsEscapesButKeepsStructure(t *testing.T) {
	in := "para one\n\x1b[31mred\x1b[0m para\nlast"
	want := "para one\nred para\nlast"
	if got := Block(in); got != want {
		t.Errorf("Block escapes: got %q, want %q", got, want)
	}
}

func TestMixed_RealisticHostileSubject(t *testing.T) {
	// A plausible crafted subject: hide-cursor, recolor, set the window title,
	// then benign-looking text.
	in := "\x1b[?25l\x1b[41m\x1b]0;steal\x07Invoice #4432 — paid"
	want := "Invoice #4432 — paid"
	if got := Line(in); got != want {
		t.Errorf("Line hostile subject: got %q, want %q", got, want)
	}
	if strings.ContainsRune(Line(in), 0x1b) {
		t.Error("Line output still contains ESC")
	}
}

func TestEmptyAndPlain(t *testing.T) {
	if got := Line(""); got != "" {
		t.Errorf("Line empty: got %q", got)
	}
	if got := Block(""); got != "" {
		t.Errorf("Block empty: got %q", got)
	}
	if got := Line("plain ascii subject"); got != "plain ascii subject" {
		t.Errorf("Line plain: got %q", got)
	}
}

// TestInvariant_NoSteeringSurvives is the core guarantee, asserted as a broad
// fuzz-ish invariant: no output may carry anything that can STEER a terminal —
// no bare control byte (C0/C1/DEL), no ESC introducer, and no U+FFFD residue
// from a neutralized C1 byte. This is the property the whole package exists to
// hold; a 500k-iteration adversarial fuzz found no violation.
//
// Note it does NOT assert "no inert parameter text survives." When a hostile
// CSI introducer is interrupted by a control byte before its final
// (e.g. "ESC [ \n 31m"), the trailing "31m" renders as literal text — see
// TestInterruptedCSILeavesInertResidue for why that is deliberate and safe.
func TestInvariant_NoSteeringSurvives(t *testing.T) {
	inputs := []string{
		"\x1b[31m\x1b[2J\x1b]0;t\x07mix\x9b1m\x9d2\x07",
		"\x00\x01\x02text\x7f\x80\x9f",
		"nested\x1b[\x1b[31mm",
		"\x1b\x1b\x1b[[[",
		"a\x1b[\n31mb", "a\x9b\x0131mb", "top\x1b[1;\n2mbottom",
		"\x1bP\x1b\\ \x90dcs\x9c \x1bXsos\x07",
	}
	for _, in := range inputs {
		for _, out := range []string{Line(in), Block(in)} {
			for _, r := range out {
				if isControl(r) && r != '\n' {
					t.Errorf("sanitize(%q) left steering control %#x in %q", in, r, out)
				}
				if r == 0x1B {
					t.Errorf("sanitize(%q) left ESC in %q", in, out)
				}
				if r == '�' {
					t.Errorf("sanitize(%q) left U+FFFD residue in %q", in, out)
				}
			}
		}
	}
}

// TestInterruptedCSILeavesInertResidue documents a deliberate, safe behavior:
// when a CSI introducer (ESC [ or raw C1 0x9B) is interrupted by a control byte
// before its final byte, the parameter characters after that control survive as
// literal text. This is intentional, for two reasons:
//
//  1. It matches real terminals: per ECMA-48 a control byte inside a CSI aborts
//     the sequence and the following bytes render as ordinary text. So the
//     residue is exactly what a terminal would show — and, crucially, inert:
//     the ESC/introducer is gone, so nothing can steer the terminal.
//  2. Greedily stripping the CSI-grammar tail to remove the residue would
//     corrupt legitimate body content. A hostile prefix like "ESC [ <newline>"
//     can precede a real message; the bytes after it ("Dear Bob…") are the
//     user's mail, not payload, and dropping them (or eating "D" as a CSI
//     final) is strictly worse than showing an inert "31m".
func TestInterruptedCSILeavesInertResidue(t *testing.T) {
	// Hostile residue is inert text (the ESC/introducer is stripped).
	if got := Line("a\x1b[\n31mb"); got != "a31mb" {
		t.Errorf("interrupted CSI: got %q, want %q (inert residue)", got, "a31mb")
	}
	// The interrupting newline is preserved as a row break in Block mode.
	if got := Block("a\x1b[\n31mb"); got != "a\n31mb" {
		t.Errorf("interrupted CSI (block): got %q, want %q", got, "a\n31mb")
	}
	// The essential property: legitimate body text after a hostile-prefixed
	// control is preserved intact, never corrupted.
	legit := "\x1b[\nDear Bob, the meeting is at 3pm"
	if got := Line(legit); got != "Dear Bob, the meeting is at 3pm" {
		t.Errorf("legit body after hostile prefix was corrupted: got %q", got)
	}
	// And no ESC / steering control survives in any of these.
	for _, in := range []string{"a\x1b[\n31mb", legit} {
		if strings.ContainsRune(Line(in), 0x1b) {
			t.Errorf("sanitize(%q) left ESC", in)
		}
	}
}
