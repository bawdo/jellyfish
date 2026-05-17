package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestHelpBarewordOnEveryCommand asserts that "help" as the first positional
// argument prints help — same as --help — for every command in the tree.
// Idiomatic across the whole CLI: `jellyfish overview help` and
// `jellyfish overview --help` both produce help text.
func TestHelpBarewordOnEveryCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
		// expect names a token that must appear in the help text. Use the
		// command's own name to catch the case where help printed for the
		// wrong (parent) command.
		expect string
	}{
		{"root", []string{"help"}, "jellyfish"},
		{"version", []string{"version", "help"}, "version"},
		{"configure", []string{"configure", "help"}, "configure"},
		{"configure email", []string{"configure", "email", "help"}, "email"},
		{"vulns parent", []string{"vulns", "help"}, "vulns"},
		{"vulns list", []string{"vulns", "list", "help"}, "list"},
		{"vulns summary", []string{"vulns", "summary", "help"}, "summary"},
		{"user parent", []string{"user", "help"}, "user"},
		{"user show", []string{"user", "show", "help"}, "show"},
		{"users parent", []string{"users", "help"}, "users"},
		{"users send-email", []string{"users", "send-email", "help"}, "send-email"},
		{"overview", []string{"overview", "help"}, "overview"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			root.SetArgs(tc.args)
			var out, errBuf bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&errBuf)
			if err := root.Execute(); err != nil {
				t.Fatalf("Execute: %v\nstdout=%q\nstderr=%q", err, out.String(), errBuf.String())
			}
			combined := out.String() + errBuf.String()
			if !strings.Contains(combined, "Usage:") {
				t.Errorf("output does not look like help (missing 'Usage:'):\n%s", combined)
			}
			if !strings.Contains(combined, tc.expect) {
				t.Errorf("help printed for the wrong command (missing %q):\n%s", tc.expect, combined)
			}
		})
	}
}

// TestHelpBarewordDoesNotBreakPositionalArgs asserts that `user show <id>`
// still routes the positional arg as a user identifier when it is not the
// literal token "help".
func TestHelpBarewordDoesNotBreakPositionalArgs(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"user", "show", "alice@example.com"})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	// We don't run a real client here, so Execute will fail at the load-config
	// step. We just want to confirm the "alice@example.com" arg was NOT swallowed
	// as a help trigger — the help text "Usage:" should not appear in stdout.
	_ = root.Execute()
	if strings.Contains(out.String(), "Usage:\n  jellyfish user show") {
		t.Errorf("positional arg was swallowed as help; stdout:\n%s", out.String())
	}
}
