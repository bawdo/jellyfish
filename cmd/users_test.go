package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsersSendEmailRegistered(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"users", "send-email", "--help"})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr=%q", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "send-email") {
		t.Fatalf("help output missing command name; got %q", out.String())
	}
	for _, flag := range []string{"--csv", "--emails", "--csv-email-column", "--email-to", "--message", "--message-file", "--dry-run", "--yes", "--no-cache"} {
		if !strings.Contains(out.String(), flag) {
			t.Errorf("help output missing flag %s; got:\n%s", flag, out.String())
		}
	}
}
