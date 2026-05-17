package cmd

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/keychain"
)

type usersSendEmailOpts struct {
	CSVPath        string
	Emails         string
	CSVEmailColumn string
	EmailFlags     emailFlagValues
	DryRun         bool
	Yes            bool
	NoCache        bool
	Profile        config.Profile
	EmailNow       time.Time
	// Injected for tests:
	gitEmail      gitEmailLookup
	KeychainGet   func() ([]byte, error)
	NewSender     gmailNewSender
	ConfirmReader io.Reader
}

func newUsersCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "users",
		Short: "Bulk user-scoped operations",
	}
	c.AddCommand(newUsersSendEmailCmd())
	return c
}

func newUsersSendEmailCmd() *cobra.Command {
	var opts usersSendEmailOpts
	c := &cobra.Command{
		Use:   "send-email",
		Short: "Send per-user vulnerability reports to a list of email addresses",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.EmailFlags = readEmailFlags(cmd)
			opts.EmailNow = time.Now()
			client, err := buildClient(cmd)
			if err != nil {
				return err
			}
			prof, err := activeProfile(cmd)
			if err != nil {
				return err
			}
			opts.Profile = prof
			if opts.KeychainGet == nil {
				opts.KeychainGet = keychain.GetGmailServiceAccount
			}
			if opts.NewSender == nil {
				opts.NewSender = gmail.NewSender
			}
			return runUsersSendEmail(cmd.Context(), client, cmd.ErrOrStderr(), opts)
		},
	}
	c.Flags().StringVar(&opts.CSVPath, "csv", "", "Path to a CSV file containing recipient emails")
	c.Flags().StringVar(&opts.Emails, "emails", "", "Comma-separated list of recipient emails")
	c.Flags().StringVar(&opts.CSVEmailColumn, "csv-email-column", "", "CSV column name holding the email address (default: auto-detect email/user_email/e-mail)")
	c.Flags().String("email-to", "", "Redirect every email to this address (test/audit mode)")
	c.Flags().String("email-from", "", "Email From: header (default: email.from from config, then git user.email)")
	c.Flags().String("email-subject", "", "Email Subject: header (default: rendered email.subject_template or a per-command default)")
	c.Flags().String("email-header-bg", "", "Email header background colour as #RRGGBB (default: email.header_bg or #2b3a55)")
	c.Flags().String("email-logo", "", "Path to a PNG to show in the email header (default: email.logo_path)")
	c.Flags().Bool("message", false, "Open $VISUAL/$EDITOR to compose a message rendered above the email body (shared across all recipients)")
	c.Flags().String("message-file", "", "Read the email message body from a file (use - for stdin)")
	c.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Resolve and filter but do not send any mail")
	c.Flags().BoolVar(&opts.Yes, "yes", false, "Skip the confirmation prompt")
	c.Flags().BoolVar(&opts.NoCache, "no-cache", false, "Skip the detection cache; always fetch fresh")
	return c
}

// runUsersSendEmail is the orchestration entry point for the bulk
// `users send-email` command. It resolves recipients, fetches detections
// once (cached or fresh), prompts for confirmation, and loops over each
// recipient sending a per-user vulnerability report via Gmail. The per-row
// outcomes are tallied in bulkCounters and surfaced as a final summary
// line on stderr; the worst-class error is wrapped as the exit error.
func runUsersSendEmail(ctx context.Context, client iruClient, stderr io.Writer, opts usersSendEmailOpts) error {
	if err := validateMessageFlags(opts.EmailFlags, true); err != nil {
		return err
	}
	if opts.EmailFlags.To != "" {
		if _, err := mail.ParseAddress(opts.EmailFlags.To); err != nil {
			return fmt.Errorf("--email-to %q: %w", opts.EmailFlags.To, err)
		}
	}

	recipients, err := readRecipientList(opts)
	if err != nil {
		return err
	}

	// Bulk does not consult email.default_to. Zero it so resolveEmailOptions
	// only honours flags, not config defaults.
	profForOpts := opts.Profile
	profForOpts.Email.DefaultTo = ""

	now := opts.EmailNow
	if now.IsZero() {
		now = time.Now()
	}
	gitLookup := opts.gitEmail
	if gitLookup == nil {
		gitLookup = gitUserEmail
	}
	baseEmailOpts, err := resolveEmailOptions(opts.EmailFlags, profForOpts, gitLookup, now)
	if err != nil {
		return err
	}
	baseEmailOpts.Report = "users-send"

	confirmIn := opts.ConfirmReader
	if confirmIn == nil {
		confirmIn = os.Stdin
	}
	ok, err := confirmSend(stderr, confirmIn, len(recipients), opts.DryRun, opts.Yes)
	if err != nil {
		return err
	}
	if !ok {
		_, _ = fmt.Fprintln(stderr, "aborted: no mail sent")
		return nil
	}

	templateDisplay := fmt.Sprintf("%d recipients", len(recipients))
	if opts.EmailFlags.To != "" {
		templateDisplay = opts.EmailFlags.To + " (redirect)"
	}
	message, err := captureMessage(opts.EmailFlags, true, templateDisplay, baseEmailOpts.Subject, os.Stdin, stderr, nil)
	if err != nil {
		return err
	}
	baseEmailOpts.Message = message

	var sender gmail.Sender
	if !opts.DryRun {
		if !opts.Profile.Email.GmailConfigured {
			return errors.New(`sending email requires Gmail credentials. Run "jellyfish configure email" to install a service-account JSON, or pass --dry-run to preview without sending`)
		}
		kchGet := opts.KeychainGet
		if kchGet == nil {
			return errors.New("internal: KeychainGet not wired")
		}
		newSender := opts.NewSender
		if newSender == nil {
			return errors.New("internal: NewSender not wired")
		}
		saJSON, kerr := kchGet()
		if kerr != nil {
			return fmt.Errorf(`read Gmail credentials from Keychain: %w. Run "jellyfish configure email" to reinstall`, kerr)
		}
		s, serr := newSender(ctx, saJSON, baseEmailOpts.From)
		if serr != nil {
			return serr
		}
		sender = s
	}

	allDetections, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache)
	if err != nil {
		return err
	}

	var counters bulkCounters
	for _, inputEmail := range recipients {
		bundle, rerr := resolveBundleForUser(ctx, client, inputEmail, allDetections)
		if rerr != nil {
			if errors.Is(rerr, iru.ErrNotFound) {
				_, _ = fmt.Fprintf(stderr, "error: %s user not found in Iru\n", inputEmail)
			} else {
				_, _ = fmt.Fprintf(stderr, "error: %s lookup: %v\n", inputEmail, rerr)
			}
			counters.recordError(rerr)
			continue
		}
		if len(bundle.Devices) == 0 {
			_, _ = fmt.Fprintf(stderr, "skip: %s no devices\n", inputEmail)
			counters.skipped++
			continue
		}
		hasDetections := false
		for _, d := range bundle.Devices {
			if len(d.Detections) > 0 {
				hasDetections = true
				break
			}
		}
		if !hasDetections {
			_, _ = fmt.Fprintf(stderr, "skip: %s no vulnerabilities\n", inputEmail)
			counters.skipped++
			continue
		}

		userOpts := baseEmailOpts
		if userOpts.To == "" {
			userOpts.To = bundle.User.Email
		}
		if userOpts.To == "" {
			_, _ = fmt.Fprintf(stderr, "error: %s no recipient address (user has no email and --email-to not set)\n", inputEmail)
			counters.recordError(fmt.Errorf("no recipient address for %s: %w", inputEmail, iru.ErrNotFound))
			continue
		}

		if opts.DryRun {
			_, _ = fmt.Fprintf(stderr, "would-send: %s to=%s\n", inputEmail, userOpts.To)
			counters.wouldSend++
			continue
		}

		id, serr := sendUserBundle(ctx, sender, userOpts, stderr, bundle)
		if serr != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s gmail: %v\n", inputEmail, serr)
			counters.recordError(serr)
			continue
		}
		_, _ = fmt.Fprintf(stderr, "sent: %s to=%s gmail-id=%s\n", inputEmail, userOpts.To, id)
		counters.sent++
	}

	if opts.DryRun {
		_, _ = fmt.Fprintf(stderr, "summary: would-send=%d skipped=%d errors=%d\n", counters.wouldSend, counters.skipped, counters.errs)
	} else {
		_, _ = fmt.Fprintf(stderr, "summary: sent=%d skipped=%d errors=%d\n", counters.sent, counters.skipped, counters.errs)
	}
	return counters.exitError()
}

// readCSVRecipients reads email addresses out of a CSV file. The CSV must
// have a header row. If columnOverride is non-empty, the column matching
// that exact name is used (case-insensitive). Otherwise, the first column
// whose header (case-insensitively) is "email", "user_email", or "e-mail"
// is used. Returns case-insensitively deduped emails in first-seen order.
// A leading UTF-8 BOM on the first cell is stripped transparently.
func readCSVRecipients(path, columnOverride string) ([]string, error) {
	// #nosec G304 - path is supplied by the operator via --csv
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate ragged rows

	header, err := r.Read()
	if err == io.EOF {
		return nil, fmt.Errorf("read %s: file is empty", path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s header: %w", path, err)
	}
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\xef\xbb\xbf")
	}

	idx := -1
	if columnOverride != "" {
		for i, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), columnOverride) {
				idx = i
				break
			}
		}
		if idx == -1 {
			return nil, fmt.Errorf("--csv-email-column %q not present in %s header %v", columnOverride, path, header)
		}
	} else {
		want := map[string]struct{}{"email": {}, "user_email": {}, "e-mail": {}}
		for i, h := range header {
			if _, ok := want[strings.ToLower(strings.TrimSpace(h))]; ok {
				idx = i
				break
			}
		}
		if idx == -1 {
			return nil, fmt.Errorf("no email column found in %s header %v (looked for email/user_email/e-mail; override with --csv-email-column)", path, header)
		}
	}

	seen := make(map[string]struct{})
	var out []string
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s row: %w", path, err)
		}
		if idx >= len(row) {
			continue
		}
		addr := strings.TrimSpace(row[idx])
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, "@") {
			return nil, fmt.Errorf("%s: not a valid email address: %q", path, addr)
		}
		key := strings.ToLower(addr)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no recipients after header", path)
	}
	return out, nil
}

// readRecipientList chooses between CSV and comma-list parsing based on
// which flag is set. Exactly one of opts.CSVPath / opts.Emails must be
// non-empty.
func readRecipientList(opts usersSendEmailOpts) ([]string, error) {
	switch {
	case opts.CSVPath != "" && opts.Emails != "":
		return nil, errors.New("--csv and --emails are mutually exclusive")
	case opts.CSVPath != "":
		return readCSVRecipients(opts.CSVPath, opts.CSVEmailColumn)
	case opts.Emails != "":
		return splitEmails(opts.Emails)
	default:
		return nil, errors.New("provide --csv or --emails")
	}
}

// splitEmails parses a comma-separated list of email addresses, trimming
// whitespace, skipping empty entries, deduping case-insensitively while
// preserving first-seen order, and rejecting any entry without an "@".
// Returns an error if no addresses remain after parsing.
func splitEmails(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		addr := strings.TrimSpace(p)
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, "@") {
			return nil, fmt.Errorf("not a valid email address: %q", addr)
		}
		key := strings.ToLower(addr)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, errors.New("no email addresses in --emails")
	}
	return out, nil
}

// bulkCounters tallies per-row outcomes in the bulk send loop. The
// worst value is a precedence indicator (higher = more severe);
// exitError() converts that back to a wrapped sentinel that
// classifyError understands.
type bulkCounters struct {
	sent, wouldSend, skipped, errs int
	worst                          bulkExitClass
}

type bulkExitClass int

const (
	bulkOK bulkExitClass = iota
	bulkRender
	bulkNotFound
	bulkUpstream
	bulkAuth
)

func (c *bulkCounters) recordError(err error) {
	c.errs++
	switch {
	case errors.Is(err, gmail.ErrUnauthorized), errors.Is(err, gmail.ErrForbidden),
		errors.Is(err, iru.ErrUnauthorized), errors.Is(err, iru.ErrForbidden):
		if c.worst < bulkAuth {
			c.worst = bulkAuth
		}
	case errors.Is(err, gmail.ErrRateLimited), errors.Is(err, gmail.ErrUpstream),
		errors.Is(err, iru.ErrRateLimited):
		if c.worst < bulkUpstream {
			c.worst = bulkUpstream
		}
	case errors.Is(err, iru.ErrNotFound):
		if c.worst < bulkNotFound {
			c.worst = bulkNotFound
		}
	case errors.Is(err, email.ErrRender):
		if c.worst < bulkRender {
			c.worst = bulkRender
		}
	default:
		if c.worst < bulkUpstream {
			c.worst = bulkUpstream
		}
	}
}

// exitError returns a sentinel error wrapped with the per-run error count.
// Returns nil when no errors were recorded. classifyError in root.go maps
// the wrapped sentinel back to the documented exit codes (1/2/3/4).
func (c *bulkCounters) exitError() error {
	switch c.worst {
	case bulkAuth:
		return fmt.Errorf("%d send(s) failed with auth/permission errors: %w", c.errs, gmail.ErrUnauthorized)
	case bulkUpstream:
		return fmt.Errorf("%d send(s) failed with upstream/rate-limit errors: %w", c.errs, gmail.ErrRateLimited)
	case bulkNotFound:
		return fmt.Errorf("%d user(s) not found in Iru: %w", c.errs, iru.ErrNotFound)
	case bulkRender:
		return fmt.Errorf("%d render(s) failed: %w", c.errs, email.ErrRender)
	default:
		return nil
	}
}

// confirmSend prompts the operator before sending mail. Returns (true, nil)
// when the operator confirms (or the prompt is short-circuited by --yes or
// --dry-run). Returns (false, nil) on "n", blank, or EOF. Errors propagate
// only on truly broken I/O.
func confirmSend(stderr io.Writer, in io.Reader, count int, dryRun, yes bool) (bool, error) {
	if dryRun {
		_, _ = fmt.Fprintln(stderr, "DRY RUN - no mail will be sent")
		return true, nil
	}
	if yes {
		return true, nil
	}
	_, _ = fmt.Fprintf(stderr, "About to send vulnerability reports to %d users. Continue? [y/N] ", count)
	br := bufio.NewReader(in)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
