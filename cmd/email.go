package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/version"
)

// emailFlagValues holds the literal flag inputs from cobra; empty string means
// the flag was not set. Send is true iff --send-email was passed. Message is
// true iff --message was passed; MessageFile is the literal --message-file
// value (empty when not set).
type emailFlagValues struct {
	To          string
	From        string
	Subject     string
	HeaderBG    string
	LogoPath    string
	Send        bool
	Message     bool
	MessageFile string
}

// gitEmailLookup is the function signature for "find a from address by asking
// git". Production passes gitUserEmail; tests inject a fixture.
type gitEmailLookup func() (string, error)

// emailFlagHelp overrides the per-command help text for the email flags that
// differ between commands. An empty field keeps the default text. OmitSend
// skips registering --send-email (for commands that always send).
type emailFlagHelp struct {
	To       string
	Send     string
	Message  string
	OmitSend bool
}

// addEmailFlags registers the email flags that readEmailFlags reads.
func addEmailFlags(c *cobra.Command, h emailFlagHelp) {
	to := firstNonEmpty(h.To, "Email To: header (default: email.default_to from config)")
	send := firstNonEmpty(h.Send, "Send the rendered email via Gmail (requires `jellyfish configure email` to be run first)")
	message := firstNonEmpty(h.Message, "Open $VISUAL/$EDITOR to compose a message rendered above the email body")

	c.Flags().String("email-to", "", to)
	c.Flags().String("email-from", "", "Email From: header (default: email.from from config, then git user.email)")
	c.Flags().String("email-subject", "", "Email Subject: header (default: rendered email.subject_template or a per-command default)")
	c.Flags().String("email-header-bg", "", "Email header background colour as #RRGGBB (default: email.header_bg or #2b3a55)")
	c.Flags().String("email-logo", "", "Path to a PNG to show in the email header (default: email.logo_path)")
	if !h.OmitSend {
		c.Flags().Bool("send-email", false, send)
	}
	c.Flags().Bool("message", false, message)
	c.Flags().String("message-file", "", "Read the email message body from a file (use - for stdin)")
}

// readEmailFlags pulls --email-to / --email-from / --email-subject /
// --email-header-bg / --email-logo / --send-email / --message / --message-file
// off a cobra command. Missing flags return zero values (no error).
func readEmailFlags(cmd *cobra.Command) emailFlagValues {
	to, _ := cmd.Flags().GetString("email-to")
	from, _ := cmd.Flags().GetString("email-from")
	subject, _ := cmd.Flags().GetString("email-subject")
	headerBG, _ := cmd.Flags().GetString("email-header-bg")
	logoPath, _ := cmd.Flags().GetString("email-logo")
	send, _ := cmd.Flags().GetBool("send-email")
	message, _ := cmd.Flags().GetBool("message")
	messageFile, _ := cmd.Flags().GetString("message-file")
	return emailFlagValues{
		To: to, From: from, Subject: subject,
		HeaderBG: headerBG, LogoPath: logoPath,
		Send: send, Message: message, MessageFile: messageFile,
	}
}

// resolveEmailOptions applies the precedence:
//
//	From     : flag > config.Email.From > git user.email > error
//	To       : flag > config.Email.DefaultTo > "" (renderer prints <unspecified>)
//	Subject  : flag > rendered config.Email.SubjectTemplate > "" (renderer's default)
//	HeaderBG : flag > config.Email.HeaderBG > "" (validates hex colour if non-empty)
//	LogoPath : flag > config.Email.LogoPath > ""
func resolveEmailOptions(flags emailFlagValues, prof config.Profile, lookupGit gitEmailLookup, now time.Time) (email.Options, error) {
	opts := email.Options{
		Tenant:           prof.Subdomain,
		GeneratedAt:      now,
		To:               firstNonEmpty(flags.To, prof.Email.DefaultTo),
		CVELinkPrimary:   prof.Email.CVELinkPrimary,
		CVELinkSecondary: prof.Email.CVELinkSecondary,
	}

	opts.HeaderBG = firstNonEmpty(flags.HeaderBG, prof.Email.HeaderBG)
	if opts.HeaderBG != "" {
		if err := email.ValidateHexColour(opts.HeaderBG); err != nil {
			return email.Options{}, fmt.Errorf("email header bg: %w", err)
		}
	}
	opts.LogoPath = firstNonEmpty(flags.LogoPath, prof.Email.LogoPath)
	opts.Version = version.Version
	opts.ListIDDomain = prof.Email.ListIDDomain

	opts.From = firstNonEmpty(flags.From, prof.Email.From)
	if opts.From == "" && lookupGit != nil {
		gitVal, err := lookupGit()
		if err == nil {
			opts.From = strings.TrimSpace(gitVal)
		}
	}
	if opts.From == "" {
		return email.Options{}, errors.New(`no email from address - set --email-from, email.from in config, or configure git user.email`)
	}

	switch {
	case flags.Subject != "":
		opts.Subject = flags.Subject
	case prof.Email.SubjectTemplate != "":
		rendered, err := renderSubjectTemplate(prof.Email.SubjectTemplate, now)
		if err != nil {
			return email.Options{}, fmt.Errorf("render email subject_template: %w", err)
		}
		opts.Subject = rendered
	}
	return opts, nil
}

func renderSubjectTemplate(tmplStr string, now time.Time) (string, error) {
	tmpl, err := template.New("subject").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	data := struct {
		Date string
		Time string
	}{
		Date: now.Format("2006-01-02"),
		Time: now.Format("15:04"),
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// gitUserEmail shells out to `git config user.email`. Returns "" with nil
// error when the command runs but produces no value; returns an error only
// when git itself cannot be invoked (PATH miss, etc.).
func gitUserEmail() (string, error) {
	cmd := exec.Command("git", "config", "user.email")
	out, err := cmd.Output()
	if err != nil {
		if _, lookErr := exec.LookPath("git"); lookErr != nil {
			return "", fmt.Errorf("git not found on PATH: %w", lookErr)
		}
		return "", nil
	}
	return strings.TrimSpace(string(out)), nil
}

// resolveNowAndGitLookup applies the defaults shared by every email render
// path: a zero now becomes time.Now(), and a nil git lookup becomes
// gitUserEmail. Both are test-injection seams on the per-command opts structs.
func resolveNowAndGitLookup(now time.Time, lookupGit gitEmailLookup) (time.Time, gitEmailLookup) {
	if now.IsZero() {
		now = time.Now()
	}
	if lookupGit == nil {
		lookupGit = gitUserEmail
	}
	return now, lookupGit
}

// prepareEmailOptions is the common front half of every email render and
// send path: apply the now/git defaults, resolve flag/config precedence and
// stamp the Report header.
func prepareEmailOptions(flags emailFlagValues, prof config.Profile, now time.Time, lookupGit gitEmailLookup, report string) (email.Options, error) {
	now, lookupGit = resolveNowAndGitLookup(now, lookupGit)
	eo, err := resolveEmailOptions(flags, prof, lookupGit, now)
	if err != nil {
		return email.Options{}, err
	}
	eo.Report = report
	return eo, nil
}

// attachMessage captures --message / --message-file into eo.Message. eo.To
// is shown as the recipient in the editor template, so call it after the
// final recipient is known.
func attachMessage(eo *email.Options, flags emailFlagValues, stdin io.Reader, stderr io.Writer) error {
	msg, err := captureMessage(flags, true, eo.To, eo.Subject, stdin, stderr, nil)
	if err != nil {
		return err
	}
	eo.Message = msg
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
