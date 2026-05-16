package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
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
	gitEmail      gitEmailLookup //nolint:unused // wired in by runUsersSendEmail body (Task 9)
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
			// Orchestration lands in later tasks.
			return runUsersSendEmail(cmd.Context(), nil, cmd.ErrOrStderr(), opts)
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

// runUsersSendEmail is the orchestration entry point. Filled in by later
// tasks; current stub keeps the cobra wiring compilable.
func runUsersSendEmail(_ context.Context, _ iruClient, _ io.Writer, _ usersSendEmailOpts) error {
	return nil
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
