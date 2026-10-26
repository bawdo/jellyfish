package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/iru"
)

// runWithStubLeaf runs a root command carrying an extra "boom" leaf whose
// RunE returns err, and returns the exit code plus everything written to
// stdout and stderr.
func runWithStubLeaf(t *testing.T, err error, args ...string) (int, string, string) {
	t.Helper()
	root := newRootCmd()
	root.AddCommand(&cobra.Command{
		Use:  "boom",
		RunE: func(*cobra.Command, []string) error { return err },
	})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	code := runRoot(context.Background(), root, args)
	return code, out.String(), errBuf.String()
}

func TestRunRootSanitisesErrorText(t *testing.T) {
	apiErr := &iru.APIError{Status: 400, Message: "bad\x1b]0;pwned\x07request\u009b31m"}
	code, _, stderr := runWithStubLeaf(t, apiErr, "boom")
	if code != 1 {
		t.Errorf("exit code: got %d want 1", code)
	}
	for _, r := range stderr {
		if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("control character %U leaked into stderr: %q", r, stderr)
		}
	}
	want := "Error: " + expectSanitised(apiErr.Error()) + "\n"
	if stderr != want {
		t.Fatalf("stderr:\n got %q\nwant %q", stderr, want)
	}
}

// expectSanitised mirrors the expected sanitisation independently of the
// implementation: drop C0 (except newline), DEL and C1.
func expectSanitised(s string) string {
	var b []rune
	for _, r := range s {
		if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		b = append(b, r)
	}
	return string(b)
}

func TestRunRootKeepsNewlinesInErrorText(t *testing.T) {
	_, _, stderr := runWithStubLeaf(t, errors.New("first line\nsecond line"), "boom")
	if want := "Error: first line\nsecond line\n"; stderr != want {
		t.Fatalf("stderr: got %q want %q", stderr, want)
	}
}

func TestRunRootPlainErrorOutputUnchanged(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		args   []string
		code   int
		stderr string
	}{
		{"leaf error", errors.New("oops"), []string{"boom"}, 1, "Error: oops\n"},
		{"not found keeps exit 3", iru.ErrNotFound, []string{"boom"}, 3, "Error: " + iru.ErrNotFound.Error() + "\n"},
		{"unknown root flag", nil, []string{"--bogus"}, 1, "Error: unknown flag: --bogus\n"},
		{"unknown leaf flag", nil, []string{"vulns", "list", "--bogus"}, 1, "Error: unknown flag: --bogus\n"},
		{"unknown command", nil, []string{"bogus"}, 1,
			"Error: unknown command \"bogus\" for \"jellyfish\"\nRun 'jellyfish --help' for usage.\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runWithStubLeaf(t, tc.err, tc.args...)
			if code != tc.code {
				t.Errorf("exit code: got %d want %d", code, tc.code)
			}
			if stderr != tc.stderr {
				t.Errorf("stderr:\n got %q\nwant %q", stderr, tc.stderr)
			}
		})
	}
}

func TestRunRootSuccessPrintsNothingToStderr(t *testing.T) {
	code, _, stderr := runWithStubLeaf(t, nil, "boom")
	if code != 0 || stderr != "" {
		t.Fatalf("got code %d stderr %q, want 0 and empty", code, stderr)
	}
}

func TestRootSilencesCobraErrorPrinting(t *testing.T) {
	if !newRootCmd().SilenceErrors {
		t.Fatal("root SilenceErrors must be true so runRoot owns (sanitised) error printing")
	}
}
