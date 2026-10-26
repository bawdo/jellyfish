package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
)

// gmailNewSender mirrors gmail.NewSender's signature so tests can inject a
// fake without dragging real Google credentials through the cmd layer.
type gmailNewSender func(ctx context.Context, saJSON []byte, subject string) (gmail.Sender, error)

// resolveSendOptions runs after resolveEmailOptions when --send-email is set.
// Returns the constructed Sender and the final recipient address per the
// precedence rules:
//
//	--email-to (already folded into eo.To)
//	email.default_to (already folded into eo.To)
//	userDefaultTo  (only non-empty for `user show`)
//	-> error
//
// User-facing exit-1 errors are returned for:
//   - profile.Email.GmailConfigured is false
//   - explicitOutput is non-empty and not "email"
//   - no recipient can be resolved
func resolveSendOptions(
	ctx context.Context,
	eo email.Options,
	explicitOutput string,
	profile config.Profile,
	userDefaultTo string,
	keychainGet func() ([]byte, error),
	newSender gmailNewSender,
) (gmail.Sender, string, error) {
	if explicitOutput != "" && explicitOutput != "email" {
		return nil, "", fmt.Errorf("--send-email implies email output; remove -o %s or set -o email", explicitOutput)
	}
	if !profile.Email.GmailConfigured {
		return nil, "", errors.New(`--send-email requires Gmail credentials. Run "jellyfish configure email" to install a service-account JSON`)
	}

	to := eo.To
	if to == "" {
		to = userDefaultTo
	}
	if to == "" {
		return nil, "", errors.New(`--send-email requires a recipient: pass --email-to, set email.default_to in config, or (for user show) target a user with an email address`)
	}

	sender, err := buildGmailSender(ctx, keychainGet, newSender, eo.From)
	if err != nil {
		return nil, "", err
	}
	return sender, to, nil
}

// errBulkGmailNotConfigured is the not-configured error for the bulk send
// paths (`users send-email`, `overview --send-email`), which also accept
// --dry-run. Single-report sends use resolveSendOptions' own message.
var errBulkGmailNotConfigured = errors.New(`sending email requires Gmail credentials. Run "jellyfish configure email" to install a service-account JSON, or pass --dry-run to preview without sending`)

// buildGmailSender reads the service-account JSON from the Keychain and
// constructs a Gmail sender impersonating from. Callers check
// profile.Email.GmailConfigured first so each can word that error for its
// own flags.
func buildGmailSender(ctx context.Context, keychainGet func() ([]byte, error), newSender gmailNewSender, from string) (gmail.Sender, error) {
	if keychainGet == nil {
		return nil, errors.New("internal: KeychainGet not wired")
	}
	if newSender == nil {
		return nil, errors.New("internal: NewSender not wired")
	}
	saJSON, err := keychainGet()
	if err != nil {
		return nil, fmt.Errorf(`read Gmail credentials from Keychain: %w. Run "jellyfish configure email" to reinstall`, err)
	}
	return newSender(ctx, saJSON, from)
}

// confirmSend prompts the operator before sending mail. Returns (true, nil)
// when the operator confirms (or the prompt is short-circuited by --yes or
// --dry-run). Returns (false, nil) on "n", blank, or EOF. Errors propagate
// only on truly broken I/O. prompt is written verbatim before reading.
func confirmSend(stderr io.Writer, in io.Reader, prompt string, dryRun, yes bool) (bool, error) {
	if dryRun {
		_, _ = fmt.Fprintln(stderr, "DRY RUN - no mail will be sent")
		return true, nil
	}
	if yes {
		return true, nil
	}
	_, _ = fmt.Fprint(stderr, prompt)
	br := bufio.NewReader(in)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
