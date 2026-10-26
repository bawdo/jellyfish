package output

import "testing"

func TestSanitiseTerminalStripsEveryControl(t *testing.T) {
	in := "a\x1b]0;pwned\x07b\tc\nd\re\x7ff\u009bg\x00h"
	if got, want := SanitiseTerminal(in), "a]0;pwnedbcdefgh"; got != want {
		t.Fatalf("SanitiseTerminal(%q) = %q, want %q", in, got, want)
	}
}

func TestSanitiseTerminalTextKeepsNewlines(t *testing.T) {
	in := "line one\x1b]0;pwned\x07\nline\ttwo\r\x7f\u009b31m\n"
	if got, want := SanitiseTerminalText(in), "line one]0;pwned\nlinetwo31m\n"; got != want {
		t.Fatalf("SanitiseTerminalText(%q) = %q, want %q", in, got, want)
	}
}

func TestSanitiseTerminalTextLeavesPrintableTextAlone(t *testing.T) {
	for _, s := range []string{"", "unknown flag: --bogus", "Keith’s Mac – 2024\nsecond line", "日本語"} {
		if got := SanitiseTerminalText(s); got != s {
			t.Fatalf("SanitiseTerminalText(%q) = %q, want unchanged", s, got)
		}
	}
}
