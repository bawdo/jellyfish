package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vulncovRunExecute calls Execute with os.Args set to args and the process
// stdout/stderr redirected to temp files, returning the exit code and what
// was written to each. The cmd tests never run in parallel, so swapping the
// os globals is safe; Cleanup puts them back.
func vulncovRunExecute(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	outF, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errF, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	origArgs, origOut, origErr := os.Args, os.Stdout, os.Stderr
	t.Cleanup(func() { os.Args, os.Stdout, os.Stderr = origArgs, origOut, origErr })
	os.Args = append([]string{"jellyfish"}, args...)
	os.Stdout, os.Stderr = outF, errF

	code = Execute()

	os.Args, os.Stdout, os.Stderr = origArgs, origOut, origErr
	_ = outF.Close()
	_ = errF.Close()
	// #nosec G304 - both paths are files this helper created under t.TempDir()
	o, _ := os.ReadFile(outF.Name())
	// #nosec G304 - as above
	e, _ := os.ReadFile(errF.Name())
	return code, string(o), string(e)
}

// Execute reads its arguments from os.Args (minus the program name) and
// returns the classified exit code rather than exiting.
func TestExecuteRunsOSArgs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		code, stdout, stderr := vulncovRunExecute(t, "version")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if !strings.HasPrefix(stdout, "jellyfish ") {
			t.Errorf("stdout: got %q, want the version line", stdout)
		}
	})
	t.Run("unknown command", func(t *testing.T) {
		code, stdout, stderr := vulncovRunExecute(t, "no-such-command")
		if code != 1 {
			t.Errorf("exit: got %d want 1", code)
		}
		if stdout != "" {
			t.Errorf("stdout should be empty, got %q", stdout)
		}
		if !strings.Contains(stderr, `Error: unknown command "no-such-command"`) ||
			!strings.Contains(stderr, "Run 'jellyfish --help' for usage.") {
			t.Errorf("stderr: got %q", stderr)
		}
	})
}
