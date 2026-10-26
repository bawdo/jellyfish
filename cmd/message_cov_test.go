package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// vulncovEditorScript writes an executable fake editor into dir. body runs
// under /bin/sh with the scratch file as $1. Only absolute paths and shell
// builtins are used, so the script still works when a test narrows PATH.
func vulncovEditorScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	// #nosec G306 - the fake editor has to be executable
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatalf("write fake editor: %v", err)
	}
	return path
}

// vulncovCaptureViaTerminal drives the production editor path (nil
// runEditor) through captureMessage.
func vulncovCaptureViaTerminal() (string, error) {
	return captureMessage(
		emailFlagValues{Message: true},
		true, "ops@example.com", "subj",
		strings.NewReader(""), &bytes.Buffer{},
		nil,
	)
}

// The terminal launcher picks $VISUAL, then $EDITOR, then vi from PATH, and
// hands the editor the scratch file, which is removed once read back.
func TestMessageEditorTerminalResolution(t *testing.T) {
	cases := []struct {
		name   string
		visual bool
		editor bool
		onPath bool
		want   string
	}{
		{name: "VISUAL wins over EDITOR", visual: true, editor: true, want: "from visual"},
		{name: "EDITOR when VISUAL unset", editor: true, want: "from editor"},
		{name: "vi when neither set", onPath: true, want: "from vi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seen := filepath.Join(dir, "seen-path")
			script := func(name, text string) string {
				return vulncovEditorScript(t, dir, name,
					`printf '%s' "$1" > '`+seen+`'`+"\n"+`printf '`+text+`\n' >> "$1"`)
			}
			t.Setenv("VISUAL", "")
			t.Setenv("EDITOR", "")
			if tc.visual {
				t.Setenv("VISUAL", script("visual.sh", "from visual"))
			}
			if tc.editor {
				t.Setenv("EDITOR", script("editor.sh", "from editor"))
			}
			if tc.onPath {
				script("vi", "from vi")
				t.Setenv("PATH", dir)
			}

			got, err := vulncovCaptureViaTerminal()
			if err != nil {
				t.Fatalf("capture: %v", err)
			}
			if got != tc.want {
				t.Errorf("message: got %q want %q", got, tc.want)
			}
			// #nosec G304 - seen is a file this test's fake editor wrote under t.TempDir()
			scratch, err := os.ReadFile(seen)
			if err != nil {
				t.Fatalf("fake editor did not record its argument: %v", err)
			}
			if !strings.HasPrefix(filepath.Base(string(scratch)), "jellyfish-message-") {
				t.Errorf("editor argument %q is not the scratch file", scratch)
			}
			if _, err := os.Stat(string(scratch)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("scratch file should be removed after capture, stat err %v", err)
			}
		})
	}
}

func TestMessageEditorTerminalFailures(t *testing.T) {
	cases := []struct {
		name    string
		visual  func(t *testing.T, dir string) string
		wantErr string
	}{
		{
			name: "non-zero exit",
			visual: func(t *testing.T, dir string) string {
				return vulncovEditorScript(t, dir, "quit.sh", "exit 3")
			},
			wantErr: "editor exited with status 3",
		},
		{
			name: "editor not found",
			visual: func(_ *testing.T, dir string) string {
				return filepath.Join(dir, "no-such-editor")
			},
			wantErr: "launch editor: ",
		},
		{
			// Found and executable, but the kernel cannot start it: the
			// error is a launch failure, not an exit status.
			name: "launch failure",
			visual: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "broken.sh")
				// #nosec G306 - the fake editor has to be executable
				if err := os.WriteFile(path, []byte("#!/no/such/interpreter\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				return path
			},
			wantErr: "launch editor: ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VISUAL", tc.visual(t, t.TempDir()))
			got, err := vulncovCaptureViaTerminal()
			if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) {
				t.Fatalf("got err %v, want prefix %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "exited with status") != strings.Contains(tc.wantErr, "exited with status") {
				t.Errorf("exit-status and launch failures must stay distinct, got %v", err)
			}
			if got != "" {
				t.Errorf("no message expected on failure, got %q", got)
			}
		})
	}
}

// When the scratch file can't be created the editor is never launched.
func TestMessageEditorScratchCreateFails(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	launched := false
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { launched = true; return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "create message scratch file") {
		t.Fatalf("got %v, want the scratch-create error", err)
	}
	if launched {
		t.Error("editor must not run without a scratch file")
	}
}

// An editor that deletes the scratch file (or saves elsewhere) surfaces a
// read error rather than an empty message.
func TestMessageEditorScratchGoneAfterEdit(t *testing.T) {
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		os.Remove,
	)
	if err == nil || !strings.Contains(err.Error(), "read message scratch file") {
		t.Fatalf("got %v, want the scratch-read error", err)
	}
}

func TestMessageFileStdinReadError(t *testing.T) {
	boom := errors.New("stdin went away")
	_, err := captureMessage(
		emailFlagValues{MessageFile: "-"},
		true, "", "",
		iotest.ErrReader(boom), &bytes.Buffer{},
		nil,
	)
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "read --message-file -") {
		t.Fatalf("got %v, want the wrapped stdin error", err)
	}
}
