package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMessageFlagsAcceptsNeither(t *testing.T) {
	if err := validateMessageFlags(emailFlagValues{}, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMessageFlagsAcceptsMessageWithEmailOutput(t *testing.T) {
	if err := validateMessageFlags(emailFlagValues{Message: true}, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMessageFlagsRejectsBoth(t *testing.T) {
	err := validateMessageFlags(emailFlagValues{Message: true, MessageFile: "x"}, true)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestValidateMessageFlagsRejectsMessageWithoutEmailOutput(t *testing.T) {
	err := validateMessageFlags(emailFlagValues{Message: true}, false)
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}

func TestValidateMessageFlagsRejectsMessageFileWithoutEmailOutput(t *testing.T) {
	err := validateMessageFlags(emailFlagValues{MessageFile: "x"}, false)
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}

func TestCaptureMessageRejectsBothFlags(t *testing.T) {
	_, err := captureMessage(
		emailFlagValues{Message: true, MessageFile: "some.txt"},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestCaptureMessageRejectsWithoutEmailOutput(t *testing.T) {
	_, err := captureMessage(
		emailFlagValues{Message: true},
		false, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}

func TestCaptureMessageReturnsEmptyWhenNeitherFlagSet(t *testing.T) {
	got, err := captureMessage(
		emailFlagValues{},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty result, got %q", got)
	}
}

func TestCaptureMessageReadsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte("hi from file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hi from file" {
		t.Fatalf("got %q want %q", got, "hi from file")
	}
}

func TestCaptureMessageReadsFromStdinDash(t *testing.T) {
	got, err := captureMessage(
		emailFlagValues{MessageFile: "-"},
		true, "", "",
		strings.NewReader("piped note\n"), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "piped note" {
		t.Fatalf("got %q want %q", got, "piped note")
	}
}

func TestCaptureMessageFileDoesNotStripHashLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte("# this is a literal hash\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "# this is a literal hash\nbody"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCaptureMessageFileEmptyAborts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte("   \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "empty message") {
		t.Fatalf("expected empty-message error, got %v", err)
	}
}

func TestCaptureMessageFileUnreadable(t *testing.T) {
	_, err := captureMessage(
		emailFlagValues{MessageFile: "/no/such/path/jellyfish-test.txt"},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "read --message-file") {
		t.Fatalf("expected file-read error, got %v", err)
	}
}

func TestCaptureMessageEditorStripsCommentLines(t *testing.T) {
	fake := func(path string) error {
		body := "# Jellyfish message\n# Subject: subj\n# To: a@b\n# Lines starting with '#' will be ignored.\n#\n\nHi team\n\nSee you Friday.\n"
		return os.WriteFile(path, []byte(body), 0o600)
	}
	got, err := captureMessage(
		emailFlagValues{Message: true},
		true, "a@b", "subj",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Hi team\n\nSee you Friday."
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCaptureMessageEditorAbortsOnEmpty(t *testing.T) {
	fake := func(path string) error {
		body := "# all comments\n# nothing else\n"
		return os.WriteFile(path, []byte(body), 0o600)
	}
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err == nil || !strings.Contains(err.Error(), "empty message") {
		t.Fatalf("expected empty-message error, got %v", err)
	}
}

func TestCaptureMessageEditorFailurePropagates(t *testing.T) {
	sentinel := errors.New("bang")
	fake := func(string) error { return sentinel }
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel to propagate via errors.Is; got %v", err)
	}
}

func TestCaptureMessageEditorTemplateContainsSubjectAndTo(t *testing.T) {
	var got string
	fake := func(path string) error {
		// #nosec G304 - path is the scratch file captureMessageViaEditor created under t.TempDir()
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got = string(b)
		// #nosec G304 G703 - same scratch path, writing back the edited body
		return os.WriteFile(path, append(b, []byte("\nthe body\n")...), 0o600)
	}
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "alice@example.com", "Weekly brief",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "# Subject: Weekly brief") {
		t.Errorf("template missing subject line; got:\n%s", got)
	}
	if !strings.Contains(got, "# To: alice@example.com") {
		t.Errorf("template missing recipient line; got:\n%s", got)
	}
	if !strings.Contains(got, "# Lines starting with '#' will be ignored.") {
		t.Errorf("template missing legend line; got:\n%s", got)
	}
}

func TestCaptureMessageEditorTemplateNoRecipient(t *testing.T) {
	var got string
	fake := func(path string) error {
		// #nosec G304 - path is the scratch file captureMessageViaEditor created under t.TempDir()
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got = string(b)
		// #nosec G304 G703 - same scratch path, writing back the edited body
		return os.WriteFile(path, append(b, []byte("\nbody\n")...), 0o600)
	}
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "subj",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "# To: (none)") {
		t.Errorf("template missing '(none)' recipient placeholder; got:\n%s", got)
	}
}

func TestCaptureMessageSoftCapWarning(t *testing.T) {
	long := strings.Repeat("x", 4001)
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	got, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &stderr,
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != long {
		t.Errorf("body should not be truncated; got %d chars want %d", len(got), len(long))
	}
	if !strings.Contains(stderr.String(), "warn:") || !strings.Contains(stderr.String(), "4001 chars") {
		t.Errorf("expected soft-cap warning on stderr; got %q", stderr.String())
	}
}

func TestCaptureMessageNoWarnAtCap(t *testing.T) {
	body := strings.Repeat("x", 4000)
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	_, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &stderr,
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("no warning expected at exactly 4000 chars; got %q", stderr.String())
	}
}
