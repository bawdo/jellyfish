package output

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzSanitiseTerminal drives both sanitisers with arbitrary bytes, standing
// in for server-controlled text (device names, API error detail) on its way
// to a terminal. Whatever goes in, the output must be valid UTF-8 with no
// terminal control left (newline aside, for the multi-line form), must only
// ever remove text, and must be a fixed point of a second pass.
//
// The oracle for "terminal control" is unicode.IsControl rather than the
// production isTerminalControl, so a change to that predicate can't also
// change what the fuzzer expects. Unicode category Cc is exactly C0
// (U+0000 to U+001F), DEL (U+007F) and C1 (U+0080 to U+009F).
func FuzzSanitiseTerminal(f *testing.F) {
	for _, s := range []string{
		"",
		"plain text",
		"Keith\u2019s Mac \u2013 2024\nsecond line",
		"日本語",
		"a\x1b]0;pwned\x07b\tc\nd\re\x7ff\u009bg\x00h",
		"\x1b[31mred\x1b[0m",
		"\x1b]8;;https://evil.test\x1b\\click\x1b]8;;\x1b\\",
		"line one\r\nline two\r",
		"lone C1 byte \x9b31m",
		"\xff\xfe\xc0\x80",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		normalised := strings.ToValidUTF8(in, "\uFFFD")
		for name, tc := range map[string]struct {
			fn   func(string) string
			keep func(rune) bool
		}{
			"SanitiseTerminal":     {SanitiseTerminal, func(rune) bool { return false }},
			"SanitiseTerminalText": {SanitiseTerminalText, func(r rune) bool { return r == '\n' }},
		} {
			out := tc.fn(in)
			if !utf8.ValidString(out) {
				t.Fatalf("%s(%q) = %q: invalid UTF-8", name, in, out)
			}
			for _, r := range out {
				if unicode.IsControl(r) && !tc.keep(r) {
					t.Fatalf("%s(%q) = %q: control %U survived", name, in, out, r)
				}
			}
			// Sanitising only ever removes runes, so it can't grow the
			// (UTF-8 normalised) input, and a newline is never dropped by
			// the multi-line form.
			if len(out) > len(normalised) {
				t.Fatalf("%s(%q) = %q: output longer than input", name, in, out)
			}
			if tc.keep('\n') && strings.Count(out, "\n") != strings.Count(in, "\n") {
				t.Fatalf("%s(%q) = %q: newline count changed", name, in, out)
			}
			if again := tc.fn(out); again != out {
				t.Fatalf("%s not idempotent: %q then %q", name, out, again)
			}
			if utf8.ValidString(in) && !strings.ContainsFunc(in, func(r rune) bool {
				return unicode.IsControl(r) && !tc.keep(r)
			}) && out != in {
				t.Fatalf("%s(%q) = %q: clean input was changed", name, in, out)
			}
		}
	})
}
