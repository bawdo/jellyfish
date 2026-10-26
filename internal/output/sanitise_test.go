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

// A lone 0x9b is CSI to an 8-bit terminal but decodes as RuneError, so it
// must be neutralised as invalid UTF-8 rather than relying on the C1 check.
func TestSanitiseTerminalNeutralisesInvalidUTF8(t *testing.T) {
	cases := map[string]string{
		"\x9b31m":           "�31m",
		"a\x9b31mb":         "a�31mb",
		"\x9d0;pwned\x9c":   "�0;pwned�",
		"\xff\xfe":          "�",
		"ok\xc3":            "ok�",
		"\x1b\x9b2J\u009b2": "�2J2",
	}
	for in, want := range cases {
		if got := SanitiseTerminal(in); got != want {
			t.Errorf("SanitiseTerminal(%q) = %q, want %q", in, got, want)
		}
		if got := SanitiseTerminalText(in); got != want {
			t.Errorf("SanitiseTerminalText(%q) = %q, want %q", in, got, want)
		}
	}
}
