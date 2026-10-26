package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
// without an earlier validate step (idempotent). Pass nil for runEditor to
// use the production terminal launcher ($VISUAL/$EDITOR/vi).
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
	// validateMessageFlags above ensures exactly one of flags.MessageFile /
	// flags.Message is set when we reach here. The two branches are
	// disjoint.
	if flags.MessageFile != "" {
		body, err := readMessageFile(flags.MessageFile, stdin)
		if err != nil {
			return "", fmt.Errorf("read --message-file %s: %w", flags.MessageFile, err)
		}
		raw = body
	} else { // flags.Message == true
		body, err := captureMessageViaEditor(recipient, subject, runEditor)
		if err != nil {
			return "", err
		}
		raw = body
		stripHash = true
	}

	cleaned := strings.TrimSpace(maybeStripHashLines(raw, stripHash))
	if cleaned == "" {
		return "", errors.New("--message produced an empty message")
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
		"# Jellyfish message\n# Subject: %s\n# To: %s\n# Lines starting with '#' will be ignored.\n#\n\n",
		subject, display,
	)
	// CreateTemp opens the file O_EXCL with mode 0600 under os.TempDir().
	f, err := os.CreateTemp("", "jellyfish-message-*.txt")
	if err != nil {
		return "", fmt.Errorf("create message scratch file: %w", err)
	}
	scratch := f.Name()
	defer func() { _ = os.Remove(scratch) }()
	_, werr := f.WriteString(templateBody)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", fmt.Errorf("create message scratch file: %w", werr)
	}
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

// editorShellMeta are the characters that make an editor value need a shell,
// the same set git uses (prepare_shell_cmd in run-command.c).
const editorShellMeta = "|&;<>()$`\\\"' \t\n*?[#~=%"

// runEditorTerminal is the production implementation of the editor launcher.
// Lookup order: $VISUAL > $EDITOR > vi. As git does, a plain command name or
// path is exec'd directly, and anything with arguments or quoting (e.g.
// "code -w") runs as `sh -c '<editor> "$@"' <editor> <path>`, so the scratch
// file is always the final argument. Returns an error if the editor exits
// non-zero or cannot be launched.
func runEditorTerminal(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	viaShell := strings.ContainsAny(editor, editorShellMeta)
	var c *exec.Cmd
	if viaShell {
		// #nosec G204 G702 - editor is the invoking user's own $VISUAL/$EDITOR, run by
		// a shell on purpose (as git does); path is passed as "$1", never interpolated
		c = exec.Command("/bin/sh", "-c", editor+` "$@"`, editor, path)
	} else {
		bin, err := exec.LookPath(editor)
		if err != nil {
			return fmt.Errorf("launch editor: %w", err)
		}
		// #nosec G204 G702 - bin is the resolved $VISUAL/$EDITOR/vi path; path is the scratch file we just wrote
		c = exec.Command(bin, path)
	}
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// sh reports a command it couldn't find (127) or execute (126)
			// through its exit status; those are launch failures.
			if viaShell && (exitErr.ExitCode() == 126 || exitErr.ExitCode() == 127) {
				return fmt.Errorf("launch editor: %s: shell exit status %d", editor, exitErr.ExitCode())
			}
			return fmt.Errorf("editor exited with status %d", exitErr.ExitCode())
		}
		return fmt.Errorf("launch editor: %w", err)
	}
	return nil
}
