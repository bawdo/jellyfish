package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const messageSoftCap = 4000

// validateMessageFlags runs cheap flag-shape checks that do NOT touch the
// filesystem or launch an editor. Callers invoke this at the top of cobra
// RunE, ahead of any network or expensive setup, so bad flag combinations
// fail fast. The full capture (which DOES read files / open the editor)
// happens later via captureMessage.
func validateMessageFlags(flags emailFlagValues, hasEmailOutput bool) error {
	if !flags.Message && flags.MessageFile == "" {
		return nil
	}
	if flags.Message && flags.MessageFile != "" {
		return errors.New("--message and --message-file are mutually exclusive")
	}
	if !hasEmailOutput {
		return errors.New("--message requires email output (-o email or --send-email)")
	}
	return nil
}

// captureMessage resolves a --message / --message-file capture into a final
// plain-text body. Returns "" when neither flag is set. Returns an error for:
// both flags set; either flag set without email output; unreadable file;
// editor non-zero exit; empty resulting message. Emits a soft-cap warning to
// stderr when the result exceeds messageSoftCap. The flag-shape checks are
// duplicated from validateMessageFlags so this function is safe to call
// without an earlier validate step (idempotent).
func captureMessage(
	flags emailFlagValues,
	hasEmailOutput bool,
	recipient, subject string,
	stdin io.Reader,
	stderr io.Writer,
	runEditor func(path string) error,
) (string, error) {
	if err := validateMessageFlags(flags, hasEmailOutput); err != nil {
		return "", err
	}
	if !flags.Message && flags.MessageFile == "" {
		return "", nil
	}

	var (
		raw       string
		stripHash bool
	)
	switch {
	case flags.MessageFile != "":
		body, err := readMessageFile(flags.MessageFile, stdin)
		if err != nil {
			return "", fmt.Errorf("read --message-file %s: %w", flags.MessageFile, err)
		}
		raw = body
	default:
		body, err := captureMessageViaEditor(recipient, subject, runEditor)
		if err != nil {
			return "", err
		}
		raw = body
		stripHash = true
	}

	cleaned := strings.TrimSpace(maybeStripHashLines(raw, stripHash))
	if cleaned == "" {
		return "", errors.New("--message produced an empty message; aborting")
	}
	if len(cleaned) > messageSoftCap {
		_, _ = fmt.Fprintf(stderr, "warn: --message is %d chars; long messages may be clipped by mail clients\n", len(cleaned))
	}
	return cleaned, nil
}

func readMessageFile(path string, stdin io.Reader) (string, error) {
	if path == "-" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// #nosec G304 - path is a user-provided message file
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func captureMessageViaEditor(recipient, subject string, runEditor func(path string) error) (string, error) {
	if runEditor == nil {
		runEditor = runEditorTerminal
	}
	display := recipient
	if display == "" {
		display = "(none)"
	}
	templateBody := fmt.Sprintf(
		"# Jellyfish message for: %s\n# To: %s\n# Lines starting with '#' will be ignored.\n#\n\n",
		subject, display,
	)
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("create message scratch file: %w", err)
	}
	scratch := filepath.Join(os.TempDir(), "jellyfish-message-"+hex.EncodeToString(nonce[:])+".txt")
	if err := os.WriteFile(scratch, []byte(templateBody), 0o600); err != nil {
		return "", fmt.Errorf("create message scratch file: %w", err)
	}
	defer func() { _ = os.Remove(scratch) }()
	if err := runEditor(scratch); err != nil {
		return "", err
	}
	// #nosec G304 - scratch path is one we just wrote inside os.TempDir()
	b, err := os.ReadFile(scratch)
	if err != nil {
		return "", fmt.Errorf("read message scratch file: %w", err)
	}
	return string(b), nil
}

func maybeStripHashLines(s string, strip bool) string {
	if !strip {
		return s
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// runEditorTerminal is the production implementation of the editor launcher.
// Lookup order: $VISUAL > $EDITOR > vi. The chosen command is treated as a
// single token (no shell word-splitting). Returns an error if the editor
// exits non-zero or cannot be launched.
func runEditorTerminal(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	bin, err := exec.LookPath(editor)
	if err != nil {
		return fmt.Errorf("launch editor: %w", err)
	}
	c := exec.Command(bin, path)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("editor exited with status %d", exitErr.ExitCode())
		}
		return fmt.Errorf("launch editor: %w", err)
	}
	return nil
}
