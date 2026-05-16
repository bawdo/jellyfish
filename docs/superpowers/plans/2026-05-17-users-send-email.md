# Users send-email bulk command — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `jellyfish users send-email` so an operator can mail per-user vulnerability reports to a CSV / comma-list of email addresses in one invocation, with safety rails (dry-run, confirm prompt), filtering (skip users with no device or no vulns), and a single optional message body shared across all sends.

**Architecture:** New `cmd/users.go` exposes the bulk command. The existing `user show --send-email` pipeline is refactored to expose two small helpers (`resolveBundleForUser`, `sendUserBundle`) so the bulk loop reuses the same render + send code. The detection walk runs once before the loop and is shared across users. Exit codes are carried back through `classifyError` by wrapping the worst sentinel error seen during the run.

**Tech Stack:** Go 1.21+, Cobra, `encoding/csv`, `net/mail`, existing `internal/iru` / `internal/email` / `internal/gmail` packages.

---

## File map

| Path | Action | Responsibility |
|---|---|---|
| `cmd/user.go` | modify | extract `resolveBundleForUser` + `sendUserBundle` helpers |
| `cmd/users.go` | create | bulk command: cobra wiring, opts, orchestration, parsers, helpers |
| `cmd/users_test.go` | create | unit + end-to-end tests for bulk command |
| `cmd/root.go` | modify | register `newUsersCmd()` |
| `README.md` | modify | new "Bulk send via `users send-email`" section under "Usage" |

---

## Task 1: Extract `resolveBundleForUser` helper from `runUserShow`

**Files:**
- Modify: `cmd/user.go:108-152`

- [ ] **Step 1: Establish baseline — existing tests pass**

Run: `make test`
Expected: all pass (we will rely on these as the safety net for the refactor)

- [ ] **Step 2: Add the helper at the bottom of `cmd/user.go`**

Append after the existing functions in `cmd/user.go`:

```go
// resolveBundleForUser fetches a user (by identifier — email or ID) plus
// their devices and buckets the supplied pre-fetched detection list by
// device ID. Returns iru.ErrNotFound when the user cannot be resolved.
// Used by both the single-user `user show` pipeline (with allDetections
// fetched per-call) and the bulk `users send-email` pipeline (where the
// same detection list is reused across many users).
func resolveBundleForUser(ctx context.Context, client iruClient, identifier string, allDetections []iru.Detection) (UserBundle, error) {
	user, err := resolveUser(ctx, client, identifier)
	if err != nil {
		return UserBundle{}, err
	}
	devices, err := client.ListDevices(ctx, iru.DeviceFilters{UserID: user.ID})
	if err != nil {
		return UserBundle{}, err
	}
	deviceIDs := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		deviceIDs[d.DeviceID] = struct{}{}
	}
	byDevice := make(map[string][]iru.Detection, len(devices))
	for _, det := range allDetections {
		if _, ok := deviceIDs[det.DeviceID]; ok {
			byDevice[det.DeviceID] = append(byDevice[det.DeviceID], det)
		}
	}
	bundle := UserBundle{User: user, Devices: make([]DeviceWithDetections, len(devices))}
	for i, d := range devices {
		bundle.Devices[i] = DeviceWithDetections{Device: d, Detections: byDevice[d.DeviceID]}
	}
	return bundle, nil
}
```

- [ ] **Step 3: Rewrite `runUserShow` to delegate to the helper**

Replace lines 108-152 of `cmd/user.go` (the body of `runUserShow`) so it calls `resolveBundleForUser`:

```go
func runUserShow(ctx context.Context, client iruClient, w, stderr io.Writer, opts userShowOpts) error {
	all, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache)
	if err != nil {
		return err
	}
	bundle, err := resolveBundleForUser(ctx, client, opts.Identifier, all)
	if err != nil {
		return err
	}
	if opts.EmailFlags.Send {
		return runSendUserShow(ctx, stderr, opts, bundle)
	}
	return renderUserBundle(w, stderr, opts, bundle)
}
```

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: all pass (refactor preserves behaviour)

- [ ] **Step 5: Commit**

```bash
git add cmd/user.go
git commit -m "refactor(user): extracted resolveBundleForUser helper"
```

---

## Task 2: Extract `sendUserBundle` helper from `runSendUserShow`

**Files:**
- Modify: `cmd/user.go:197-242`

- [ ] **Step 1: Add the helper after `resolveBundleForUser` in `cmd/user.go`**

```go
// sendUserBundle renders a single user's email and sends it via the supplied
// Gmail sender. Returns the gmail-id on success. Pre-condition: emailOpts.To
// and emailOpts.Message (if any) are already set by the caller.
func sendUserBundle(ctx context.Context, sender gmail.Sender, emailOpts email.Options, stderr io.Writer, b UserBundle) (string, error) {
	var buf bytes.Buffer
	if err := email.NewUserShowRendererWithStderr(emailOpts, stderr).Render(&buf, bundleToEmailInput(b)); err != nil {
		return "", err
	}
	return sender.Send(ctx, buf.Bytes())
}
```

- [ ] **Step 2: Rewrite `runSendUserShow` to delegate**

Replace the body of `runSendUserShow` (currently `cmd/user.go:197-242`) so the render+send pair lives in the helper:

```go
func runSendUserShow(ctx context.Context, stderr io.Writer, opts userShowOpts, b UserBundle) error {
	now := opts.EmailNow
	if now.IsZero() {
		now = time.Now()
	}
	gitLookup := opts.gitEmail
	if gitLookup == nil {
		gitLookup = gitUserEmail
	}
	emailOpts, err := resolveEmailOptions(opts.EmailFlags, opts.Profile, gitLookup, now)
	if err != nil {
		return err
	}

	sender, to, err := resolveSendOptions(
		ctx,
		emailOpts,
		opts.ExplicitOutput,
		opts.Profile,
		b.User.Email,
		opts.KeychainGet,
		opts.NewSender,
	)
	if err != nil {
		return err
	}
	emailOpts.To = to

	msg, err := captureMessage(opts.EmailFlags, true, emailOpts.To, emailOpts.Subject, os.Stdin, stderr, nil)
	if err != nil {
		return err
	}
	emailOpts.Message = msg

	id, err := sendUserBundle(ctx, sender, emailOpts, stderr, b)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "sent: to=%s from=%s gmail-id=%s\n", to, emailOpts.From, id)
	return nil
}
```

- [ ] **Step 3: Run tests**

Run: `make test`
Expected: all pass — `TestUserShowSendEmailDefaultsToUserEmail`, `TestUserShowSendEmailExplicitToOverridesUser`, `TestUserShowSendEmailPropagatesSenderError` exercise this path.

- [ ] **Step 4: Commit**

```bash
git add cmd/user.go
git commit -m "refactor(user): extracted sendUserBundle render-and-send helper"
```

---

## Task 3: Skeleton `cmd/users.go` + register in `cmd/root.go`

**Files:**
- Create: `cmd/users.go`
- Create: `cmd/users_test.go`
- Modify: `cmd/root.go:71`

- [ ] **Step 1: Write failing test asserting the command registers**

Create `cmd/users_test.go`:

```go
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
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `go test ./cmd -run TestUsersSendEmailRegistered -v`
Expected: FAIL with `unknown command "users"`.

- [ ] **Step 3: Create the skeleton `cmd/users.go`**

```go
package cmd

import (
	"context"
	"io"
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
```

- [ ] **Step 4: Register the command in `cmd/root.go`**

Modify `cmd/root.go:71` (after `root.AddCommand(newUserCmd())`):

```go
	root.AddCommand(newUserCmd())
	root.AddCommand(newUsersCmd())
```

- [ ] **Step 5: Run the test**

Run: `go test ./cmd -run TestUsersSendEmailRegistered -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/users.go cmd/users_test.go cmd/root.go
git commit -m "feat(users): registered users send-email skeleton command"
```

---

## Task 4: `splitEmails` parser for `--emails`

**Files:**
- Modify: `cmd/users.go`
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write failing table-driven tests**

Append to `cmd/users_test.go`:

```go
import (
	// add to existing import block:
	"reflect"
)

func TestSplitEmails(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr string
	}{
		{name: "single", in: "a@x.com", want: []string{"a@x.com"}},
		{name: "trimmed whitespace", in: "  a@x.com , b@x.com  ", want: []string{"a@x.com", "b@x.com"}},
		{name: "case-insensitive dedupe preserves first", in: "A@x.com,a@x.com,B@x.com", want: []string{"A@x.com", "B@x.com"}},
		{name: "empty entries skipped", in: "a@x.com,,b@x.com", want: []string{"a@x.com", "b@x.com"}},
		{name: "invalid no at-sign", in: "a@x.com,not-an-email", wantErr: "not-an-email"},
		{name: "empty input", in: "", wantErr: "no email addresses"},
		{name: "only whitespace", in: " , , ", wantErr: "no email addresses"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitEmails(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `go test ./cmd -run TestSplitEmails -v`
Expected: FAIL with `undefined: splitEmails`.

- [ ] **Step 3: Implement `splitEmails` in `cmd/users.go`**

Add to `cmd/users.go` (with `"errors"`, `"fmt"`, `"strings"` added to the imports):

```go
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
```

- [ ] **Step 4: Run the test**

Run: `go test ./cmd -run TestSplitEmails -v`
Expected: PASS (all subtests).

- [ ] **Step 5: Commit**

```bash
git add cmd/users.go cmd/users_test.go
git commit -m "feat(users): added splitEmails parser for --emails"
```

---

## Task 5: `readCSVRecipients` parser for `--csv`

**Files:**
- Modify: `cmd/users.go`
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write failing tests**

Append to `cmd/users_test.go`:

```go
import (
	// add to existing import block:
	"os"
	"path/filepath"
)

func writeCSV(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestReadCSVRecipientsAutoDetect(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"email column", "email,name\na@x.com,Alice\nb@x.com,Bob\n", []string{"a@x.com", "b@x.com"}},
		{"user_email column", "name,user_email\nAlice,a@x.com\n", []string{"a@x.com"}},
		{"e-mail column", "e-mail,dept\na@x.com,eng\n", []string{"a@x.com"}},
		{"mixed case header", "Name,EMAIL\nAlice,a@x.com\n", []string{"a@x.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeCSV(t, "in.csv", tc.body)
			got, err := readCSVRecipients(p, "")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestReadCSVRecipientsColumnOverride(t *testing.T) {
	body := "name,primary_contact,backup\nAlice,a@x.com,b@x.com\n"
	p := writeCSV(t, "in.csv", body)
	got, err := readCSVRecipients(p, "primary_contact")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"a@x.com"}) {
		t.Errorf("got %#v", got)
	}
}

func TestReadCSVRecipientsDedupePreservingOrder(t *testing.T) {
	body := "email\nA@x.com\na@x.com\nB@x.com\n"
	p := writeCSV(t, "in.csv", body)
	got, err := readCSVRecipients(p, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"A@x.com", "B@x.com"}) {
		t.Errorf("got %#v", got)
	}
}

func TestReadCSVRecipientsStripsBOMAndCRLF(t *testing.T) {
	body := "﻿email\r\na@x.com\r\nb@x.com\r\n"
	p := writeCSV(t, "in.csv", body)
	got, err := readCSVRecipients(p, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"a@x.com", "b@x.com"}) {
		t.Errorf("got %#v", got)
	}
}

func TestReadCSVRecipientsErrors(t *testing.T) {
	cases := []struct {
		name, body, column, wantErr string
	}{
		{"missing file", "", "", "open"},
		{"no header at all", "", "", "open"}, // exercises missing path branch via column=""
		{"no email column auto", "id,name\n1,Alice\n", "", "no email column"},
		{"override column missing", "name,phone\nAlice,555\n", "primary_contact", "primary_contact"},
		{"empty after header", "email\n", "", "no recipients"},
		{"row with non-email cell", "email\nnot-an-email\n", "", "not a valid email"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.body
			if tc.name != "missing file" && tc.name != "no header at all" {
				path = writeCSV(t, "in.csv", tc.body)
			} else if tc.name == "missing file" {
				path = filepath.Join(t.TempDir(), "does-not-exist.csv")
			} else {
				path = writeCSV(t, "empty.csv", "")
			}
			_, err := readCSVRecipients(path, tc.column)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `go test ./cmd -run TestReadCSVRecipients -v`
Expected: FAIL with `undefined: readCSVRecipients`.

- [ ] **Step 3: Implement `readCSVRecipients`**

Add to `cmd/users.go` (adding `"encoding/csv"`, `"io"`, `"os"` to imports):

```go
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
		header[0] = strings.TrimPrefix(header[0], "﻿")
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
```

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd -run TestReadCSVRecipients -v`
Expected: PASS (all subtests).

- [ ] **Step 5: Commit**

```bash
git add cmd/users.go cmd/users_test.go
git commit -m "feat(users): added CSV recipient parser with header auto-detect"
```

---

## Task 6: `readRecipientList` dispatcher

**Files:**
- Modify: `cmd/users.go`
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write failing tests**

Append to `cmd/users_test.go`:

```go
func TestReadRecipientListDispatches(t *testing.T) {
	csvPath := writeCSV(t, "in.csv", "email\na@x.com\n")

	t.Run("csv path", func(t *testing.T) {
		got, err := readRecipientList(usersSendEmailOpts{CSVPath: csvPath})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"a@x.com"}) {
			t.Errorf("got %#v", got)
		}
	})

	t.Run("emails string", func(t *testing.T) {
		got, err := readRecipientList(usersSendEmailOpts{Emails: "a@x.com,b@x.com"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"a@x.com", "b@x.com"}) {
			t.Errorf("got %#v", got)
		}
	})

	t.Run("both set", func(t *testing.T) {
		_, err := readRecipientList(usersSendEmailOpts{CSVPath: csvPath, Emails: "a@x.com"})
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err: got %v", err)
		}
	})

	t.Run("neither set", func(t *testing.T) {
		_, err := readRecipientList(usersSendEmailOpts{})
		if err == nil || !strings.Contains(err.Error(), "--csv or --emails") {
			t.Fatalf("err: got %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `go test ./cmd -run TestReadRecipientListDispatches -v`
Expected: FAIL with `undefined: readRecipientList`.

- [ ] **Step 3: Implement `readRecipientList`**

Add to `cmd/users.go`:

```go
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
```

- [ ] **Step 4: Run the test**

Run: `go test ./cmd -run TestReadRecipientListDispatches -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/users.go cmd/users_test.go
git commit -m "feat(users): added readRecipientList dispatcher"
```

---

## Task 7: `confirmSend` interactive prompt

**Files:**
- Modify: `cmd/users.go`
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write failing tests**

Append to `cmd/users_test.go`:

```go
func TestConfirmSend(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		dryRun  bool
		yes     bool
		count   int
		wantOK  bool
		wantOut string
	}{
		{name: "yes flag short-circuits", yes: true, count: 5, wantOK: true},
		{name: "dry run short-circuits", dryRun: true, count: 5, wantOK: true, wantOut: "DRY RUN"},
		{name: "answer y", input: "y\n", count: 3, wantOK: true, wantOut: "3 users"},
		{name: "answer Y", input: "Y\n", count: 3, wantOK: true},
		{name: "answer yes", input: "yes\n", count: 3, wantOK: true},
		{name: "answer n", input: "n\n", count: 3, wantOK: false},
		{name: "answer N", input: "N\n", count: 3, wantOK: false},
		{name: "blank line", input: "\n", count: 3, wantOK: false},
		{name: "EOF before answer", input: "", count: 3, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			ok, err := confirmSend(&out, strings.NewReader(tc.input), tc.count, tc.dryRun, tc.yes)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v want %v (stderr=%q)", ok, tc.wantOK, out.String())
			}
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Errorf("stderr missing %q; got %q", tc.wantOut, out.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `go test ./cmd -run TestConfirmSend -v`
Expected: FAIL with `undefined: confirmSend`.

- [ ] **Step 3: Implement `confirmSend`**

Add to `cmd/users.go` (adding `"bufio"` to imports):

```go
// confirmSend prompts the operator before sending mail. Returns (true, nil)
// when the operator confirms (or the prompt is short-circuited by --yes or
// --dry-run). Returns (false, nil) on "n", blank, or EOF. Errors propagate
// only on truly broken I/O.
func confirmSend(stderr io.Writer, in io.Reader, count int, dryRun, yes bool) (bool, error) {
	if dryRun {
		_, _ = fmt.Fprintln(stderr, "DRY RUN — no mail will be sent")
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
```

- [ ] **Step 4: Run the test**

Run: `go test ./cmd -run TestConfirmSend -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/users.go cmd/users_test.go
git commit -m "feat(users): added confirmSend interactive prompt helper"
```

---

## Task 8: `bulkCounters` with exit-code precedence

**Files:**
- Modify: `cmd/users.go`
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write failing tests**

Append to `cmd/users_test.go`:

```go
import (
	// add to existing import block:
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
)

func TestBulkCountersExitError(t *testing.T) {
	cases := []struct {
		name     string
		record   []error
		want     error
		wantNoOp bool
	}{
		{name: "no errors", wantNoOp: true},
		{name: "user not found alone", record: []error{iru.ErrNotFound}, want: iru.ErrNotFound},
		{name: "gmail auth alone", record: []error{gmail.ErrUnauthorized}, want: gmail.ErrUnauthorized},
		{name: "gmail rate alone", record: []error{gmail.ErrRateLimited}, want: gmail.ErrRateLimited},
		{name: "rate beats not-found", record: []error{iru.ErrNotFound, gmail.ErrRateLimited}, want: gmail.ErrRateLimited},
		{name: "auth beats rate", record: []error{gmail.ErrRateLimited, gmail.ErrUnauthorized}, want: gmail.ErrUnauthorized},
		{name: "auth beats not-found", record: []error{iru.ErrNotFound, gmail.ErrUnauthorized}, want: gmail.ErrUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c bulkCounters
			for _, e := range tc.record {
				c.recordError(e)
			}
			got := c.exitError()
			if tc.wantNoOp {
				if got != nil {
					t.Fatalf("expected nil; got %v", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("got %v; want errors.Is %v", got, tc.want)
			}
		})
	}
}
```

(Also add `"errors"` to the import block at the top of the test file if not already present.)

- [ ] **Step 2: Run the test and watch it fail**

Run: `go test ./cmd -run TestBulkCountersExitError -v`
Expected: FAIL with `undefined: bulkCounters` etc.

- [ ] **Step 3: Implement `bulkCounters`**

Add to `cmd/users.go` (adding `github.com/bawdo/jellyfish/internal/gmail` and `github.com/bawdo/jellyfish/internal/iru` to imports):

```go
// bulkCounters tallies per-row outcomes in the bulk send loop. The
// worstExitCode value is a precedence indicator (higher = more severe);
// exitError() converts that back to a wrapped sentinel that
// classifyError understands.
type bulkCounters struct {
	sent, wouldSend, skipped, errs int
	worst                          bulkExitClass
}

type bulkExitClass int

const (
	bulkOK bulkExitClass = iota
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
	default:
		if c.worst < bulkUpstream {
			c.worst = bulkUpstream
		}
	}
}

// exitError returns a sentinel error wrapped with the per-run error count.
// Returns nil when no errors were recorded. classifyError in root.go maps
// the wrapped sentinel back to the documented exit codes (2/3/4).
func (c *bulkCounters) exitError() error {
	switch c.worst {
	case bulkAuth:
		return fmt.Errorf("%d send(s) failed with auth/permission errors: %w", c.errs, gmail.ErrUnauthorized)
	case bulkUpstream:
		return fmt.Errorf("%d send(s) failed with upstream/rate-limit errors: %w", c.errs, gmail.ErrRateLimited)
	case bulkNotFound:
		return fmt.Errorf("%d user(s) not found in Iru: %w", c.errs, iru.ErrNotFound)
	default:
		return nil
	}
}
```

- [ ] **Step 4: Run the test**

Run: `go test ./cmd -run TestBulkCountersExitError -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/users.go cmd/users_test.go
git commit -m "feat(users): added bulkCounters with exit-code precedence"
```

---

## Task 9: `runUsersSendEmail` orchestration — happy path

**Files:**
- Modify: `cmd/users.go`
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write the failing happy-path test**

Append to `cmd/users_test.go`:

```go
import (
	// add to existing import block:
	"context"
	"net/mail"
	"time"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
)

func TestRunUsersSendEmailHappyPath(t *testing.T) {
	client := &fakeClient{
		users: []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{
			{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1", User: iru.User{ID: "u-1"}},
		},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5, Name: "x", Version: "1.0"},
		},
	}
	sender := &fakeGmailSender{returnID: "msg-xyz"}
	var stderr bytes.Buffer
	opts := usersSendEmailOpts{
		Emails:   "alice@example.com",
		Yes:      true,
		NoCache:  true,
		EmailNow: time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:  config.Profile{Email: config.EmailConfig{GmailConfigured: true, From: "ops@example.com"}},
		EmailFlags: emailFlagValues{
			From: "ops@example.com",
		},
		KeychainGet: func() ([]byte, error) { return []byte(`{"type":"service_account"}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return sender, nil },
		gitEmail:    fixedGitEmail("ops@example.com"),
	}
	if err := runUsersSendEmail(context.Background(), client, &stderr, opts); err != nil {
		t.Fatalf("run: %v\nstderr=%s", err, stderr.String())
	}
	want := []string{
		"sent: alice@example.com to=alice@example.com gmail-id=msg-xyz",
		"summary: sent=1 skipped=0 errors=0",
	}
	for _, w := range want {
		if !strings.Contains(stderr.String(), w) {
			t.Errorf("stderr missing %q; full:\n%s", w, stderr.String())
		}
	}
	if sender.sent == nil {
		t.Fatal("sender was not called")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(sender.sent))
	if err != nil {
		t.Fatalf("parse sent eml: %v", err)
	}
	if got := msg.Header.Get("To"); got != "alice@example.com" {
		t.Errorf("To: got %q", got)
	}
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `go test ./cmd -run TestRunUsersSendEmailHappyPath -v`
Expected: FAIL (the stub returns nil and never calls the sender).

- [ ] **Step 3: Replace the stub `runUsersSendEmail` with the full orchestration**

Replace the stub body in `cmd/users.go` with the real implementation. Add `"bytes"`, `"net/mail"`, `"github.com/bawdo/jellyfish/internal/email"`, `"github.com/bawdo/jellyfish/internal/gmail"` (gmail.Sender), and `"os"` to imports as needed.

```go
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
			return errors.New(`--send-email requires Gmail credentials. Run "jellyfish configure email" to install a service-account JSON`)
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
		userOpts.To = baseEmailOpts.To
		if userOpts.To == "" {
			userOpts.To = bundle.User.Email
		}
		if userOpts.To == "" {
			_, _ = fmt.Fprintf(stderr, "error: %s no recipient address (user has no email and --email-to not set)\n", inputEmail)
			counters.recordError(fmt.Errorf("no recipient"))
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
```

- [ ] **Step 4: Wire the cobra RunE to actually call runUsersSendEmail with a real client + profile**

Replace the placeholder RunE body in `newUsersSendEmailCmd` (in `cmd/users.go`) with:

```go
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
```

Add `"github.com/bawdo/jellyfish/internal/gmail"` and `"github.com/bawdo/jellyfish/internal/keychain"` to the imports.

- [ ] **Step 5: Run all tests**

Run: `make test`
Expected: all pass, including the new `TestRunUsersSendEmailHappyPath`.

- [ ] **Step 6: Commit**

```bash
git add cmd/users.go cmd/users_test.go
git commit -m "feat(users): wired runUsersSendEmail orchestration"
```

---

## Task 10: Per-user error paths + exit-code precedence

**Files:**
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write tests for each per-row outcome and precedence rule**

Append to `cmd/users_test.go`:

```go
func newOpts(t *testing.T, sender *fakeGmailSender) usersSendEmailOpts {
	t.Helper()
	return usersSendEmailOpts{
		Yes:      true,
		NoCache:  true,
		EmailNow: time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:  config.Profile{Email: config.EmailConfig{GmailConfigured: true, From: "ops@example.com"}},
		EmailFlags: emailFlagValues{
			From: "ops@example.com",
		},
		KeychainGet: func() ([]byte, error) { return []byte(`{"type":"service_account"}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return sender, nil },
		gitEmail:    fixedGitEmail("ops@example.com"),
	}
}

func TestRunUsersSendEmailUserNotFound(t *testing.T) {
	client := &fakeClient{} // no users
	sender := &fakeGmailSender{}
	var stderr bytes.Buffer
	opts := newOpts(t, sender)
	opts.Emails = "ghost@example.com"
	err := runUsersSendEmail(context.Background(), client, &stderr, opts)
	if !errors.Is(err, iru.ErrNotFound) {
		t.Fatalf("err: got %v want ErrNotFound", err)
	}
	for _, want := range []string{
		"error: ghost@example.com user not found in Iru",
		"summary: sent=0 skipped=0 errors=1",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q; got:\n%s", want, stderr.String())
		}
	}
	if sender.sent != nil {
		t.Error("sender should not have been called")
	}
}

func TestRunUsersSendEmailSkipNoDevices(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Email: "alice@example.com"}},
		devices: nil,
	}
	sender := &fakeGmailSender{}
	var stderr bytes.Buffer
	opts := newOpts(t, sender)
	opts.Emails = "alice@example.com"
	if err := runUsersSendEmail(context.Background(), client, &stderr, opts); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(stderr.String(), "skip: alice@example.com no devices") {
		t.Errorf("stderr: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "summary: sent=0 skipped=1 errors=0") {
		t.Errorf("stderr: %s", stderr.String())
	}
	if sender.sent != nil {
		t.Error("sender should not have been called")
	}
}

func TestRunUsersSendEmailSkipNoVulns(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP"}},
		// no detections for d-1
	}
	sender := &fakeGmailSender{}
	var stderr bytes.Buffer
	opts := newOpts(t, sender)
	opts.Emails = "alice@example.com"
	if err := runUsersSendEmail(context.Background(), client, &stderr, opts); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(stderr.String(), "skip: alice@example.com no vulnerabilities") {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestRunUsersSendEmailGmailAuthError(t *testing.T) {
	client := &fakeClient{
		users:      []iru.User{{ID: "u-1", Email: "alice@example.com"}},
		devices:    []iru.Device{{DeviceID: "d-1", DeviceName: "MBP"}},
		detections: []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5}},
	}
	sender := &fakeGmailSender{err: gmail.ErrUnauthorized}
	var stderr bytes.Buffer
	opts := newOpts(t, sender)
	opts.Emails = "alice@example.com"
	err := runUsersSendEmail(context.Background(), client, &stderr, opts)
	if !errors.Is(err, gmail.ErrUnauthorized) {
		t.Fatalf("err: got %v want gmail.ErrUnauthorized", err)
	}
	if !strings.Contains(stderr.String(), "error: alice@example.com gmail:") {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestRunUsersSendEmailExitCodePrecedence(t *testing.T) {
	// One user is missing (would be exit 3), one triggers gmail rate-limit
	// (exit 4). Expected wrapped sentinel: gmail.ErrRateLimited (4 beats 3).
	client := &fakeClient{
		users:      []iru.User{{ID: "u-1", Email: "alice@example.com"}},
		devices:    []iru.Device{{DeviceID: "d-1", DeviceName: "MBP"}},
		detections: []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5}},
	}
	sender := &fakeGmailSender{err: gmail.ErrRateLimited}
	var stderr bytes.Buffer
	opts := newOpts(t, sender)
	opts.Emails = "ghost@example.com,alice@example.com"
	err := runUsersSendEmail(context.Background(), client, &stderr, opts)
	if !errors.Is(err, gmail.ErrRateLimited) {
		t.Fatalf("err: got %v want gmail.ErrRateLimited (precedence 4 > 3)", err)
	}
	if !strings.Contains(stderr.String(), "summary: sent=0 skipped=0 errors=2") {
		t.Errorf("stderr summary: %s", stderr.String())
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./cmd -run TestRunUsersSendEmail -v`
Expected: PASS for all five subtests. The orchestration from Task 9 already implements these paths; this task locks them down.

- [ ] **Step 3: Commit**

```bash
git add cmd/users_test.go
git commit -m "test(users): covered per-user error paths and exit precedence"
```

---

## Task 11: `--email-to` redirect verification

**Files:**
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/users_test.go`:

```go
type recordingSender struct {
	tos []string
}

func (r *recordingSender) Send(_ context.Context, raw []byte) (string, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	r.tos = append(r.tos, msg.Header.Get("To"))
	return "msg-id", nil
}

func TestRunUsersSendEmailRedirectsAllToOverride(t *testing.T) {
	// fakeClient.ListDevices ignores the UserID filter and returns the same
	// slice for every call, so both alice and bob see the same device + CVE
	// list. That is fine for this test — we only care that both sends land
	// at the override To address.
	client := &fakeClient{
		users: []iru.User{
			{ID: "u-1", Email: "alice@example.com"},
			{ID: "u-2", Email: "bob@example.com"},
		},
		devices:    []iru.Device{{DeviceID: "d-1", DeviceName: "MBP"}},
		detections: []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5}},
	}

	rec := &recordingSender{}
	var stderr bytes.Buffer
	opts := usersSendEmailOpts{
		Emails:      "alice@example.com,bob@example.com",
		Yes:         true,
		NoCache:     true,
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true, From: "ops@example.com"}},
		EmailFlags:  emailFlagValues{From: "ops@example.com", To: "ops@example.com"},
		KeychainGet: func() ([]byte, error) { return []byte(`{}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return rec, nil },
		gitEmail:    fixedGitEmail(""),
	}
	if err := runUsersSendEmail(context.Background(), client, &stderr, opts); err != nil {
		t.Fatalf("run: %v\nstderr=%s", err, stderr.String())
	}
	if len(rec.tos) != 2 {
		t.Fatalf("want 2 sends; got %d\nstderr=%s", len(rec.tos), stderr.String())
	}
	for i, to := range rec.tos {
		if to != "ops@example.com" {
			t.Errorf("send[%d] To=%q; want ops@example.com", i, to)
		}
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./cmd -run TestRunUsersSendEmailRedirectsAllToOverride -v`
Expected: PASS (orchestration from Task 9 already honours `EmailFlags.To` as the override).

- [ ] **Step 3: Commit**

```bash
git add cmd/users_test.go
git commit -m "test(users): asserted --email-to redirects every recipient"
```

---

## Task 12: `--dry-run` mode

**Files:**
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/users_test.go`:

```go
func TestRunUsersSendEmailDryRun(t *testing.T) {
	client := &fakeClient{
		users:      []iru.User{{ID: "u-1", Email: "alice@example.com"}},
		devices:    []iru.Device{{DeviceID: "d-1", DeviceName: "MBP"}},
		detections: []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5}},
	}
	senderCalled := false
	var stderr bytes.Buffer
	opts := usersSendEmailOpts{
		Emails:   "alice@example.com",
		DryRun:   true,
		Yes:      true,
		NoCache:  true,
		EmailNow: time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		// Profile intentionally not Gmail-configured: dry-run must not require it.
		Profile:    config.Profile{Email: config.EmailConfig{From: "ops@example.com"}},
		EmailFlags: emailFlagValues{From: "ops@example.com"},
		KeychainGet: func() ([]byte, error) {
			t.Fatal("KeychainGet must not be called in dry-run")
			return nil, nil
		},
		NewSender: func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) {
			senderCalled = true
			return nil, nil
		},
		gitEmail: fixedGitEmail("ops@example.com"),
	}
	if err := runUsersSendEmail(context.Background(), client, &stderr, opts); err != nil {
		t.Fatalf("run: %v\nstderr=%s", err, stderr.String())
	}
	if senderCalled {
		t.Fatal("NewSender must not be called in dry-run")
	}
	for _, want := range []string{
		"DRY RUN",
		"would-send: alice@example.com to=alice@example.com",
		"summary: would-send=1 skipped=0 errors=0",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q; got:\n%s", want, stderr.String())
		}
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./cmd -run TestRunUsersSendEmailDryRun -v`
Expected: PASS (orchestration from Task 9 already gates sender construction on `!opts.DryRun`).

- [ ] **Step 3: Commit**

```bash
git add cmd/users_test.go
git commit -m "test(users): asserted --dry-run skips sender and uses would-send wording"
```

---

## Task 13: Confirm-prompt abort path

**Files:**
- Modify: `cmd/users_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/users_test.go`:

```go
func TestRunUsersSendEmailAbortsOnPromptNo(t *testing.T) {
	client := &fakeClient{
		users:      []iru.User{{ID: "u-1", Email: "alice@example.com"}},
		devices:    []iru.Device{{DeviceID: "d-1", DeviceName: "MBP"}},
		detections: []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5}},
	}
	sender := &fakeGmailSender{}
	var stderr bytes.Buffer
	opts := newOpts(t, sender)
	opts.Emails = "alice@example.com"
	opts.Yes = false
	opts.ConfirmReader = strings.NewReader("n\n")
	if err := runUsersSendEmail(context.Background(), client, &stderr, opts); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sender.sent != nil {
		t.Fatal("no mail should have been sent")
	}
	if !strings.Contains(stderr.String(), "aborted: no mail sent") {
		t.Errorf("stderr missing abort line; got:\n%s", stderr.String())
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./cmd -run TestRunUsersSendEmailAbortsOnPromptNo -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add cmd/users_test.go
git commit -m "test(users): asserted confirm-prompt 'n' aborts cleanly"
```

---

## Task 14: Editor template synthesised `# To:` display

**Files:**
- Modify: `cmd/users.go` (verify the existing implementation already passes this; only the test is new)
- Modify: `cmd/users_test.go`

This task locks the synthesised template-display string written to the editor scratch when `--message` is used in bulk mode.

- [ ] **Step 1: Write the failing test**

Append to `cmd/users_test.go`:

```go
// We exercise captureMessage's template-display by injecting a runEditor that
// reads back what was written to the scratch file. To keep the test focused on
// the synthesised display, we call captureMessage directly with the same
// template-display string that runUsersSendEmail computes.
func TestBulkTemplateDisplayCountOnly(t *testing.T) {
	var scratchContents string
	editor := func(path string) error {
		// #nosec G304 — scratch path is what captureMessageViaEditor wrote.
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scratchContents = string(b)
		return os.WriteFile(path, []byte("body text"), 0o600)
	}
	flags := emailFlagValues{Message: true}
	_, err := captureMessage(flags, true, "3 recipients", "Subject A", strings.NewReader(""), io.Discard, editor)
	if err != nil {
		t.Fatalf("captureMessage: %v", err)
	}
	if !strings.Contains(scratchContents, "# To: 3 recipients") {
		t.Fatalf("scratch missing '# To: 3 recipients'; got:\n%s", scratchContents)
	}
}

func TestBulkTemplateDisplayRedirect(t *testing.T) {
	var scratchContents string
	editor := func(path string) error {
		// #nosec G304
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scratchContents = string(b)
		return os.WriteFile(path, []byte("body text"), 0o600)
	}
	flags := emailFlagValues{Message: true}
	_, err := captureMessage(flags, true, "ops@example.com (redirect)", "Subject A", strings.NewReader(""), io.Discard, editor)
	if err != nil {
		t.Fatalf("captureMessage: %v", err)
	}
	if !strings.Contains(scratchContents, "# To: ops@example.com (redirect)") {
		t.Fatalf("scratch missing redirect display; got:\n%s", scratchContents)
	}
}
```

(`"io"` is already imported.)

- [ ] **Step 2: Run the tests**

Run: `go test ./cmd -run TestBulkTemplateDisplay -v`
Expected: PASS. The template-display string is already computed in `runUsersSendEmail` (Task 9 step 3) and passed straight through `captureMessage`.

- [ ] **Step 3: Commit**

```bash
git add cmd/users_test.go
git commit -m "test(users): locked editor-template To: display for bulk mode"
```

---

## Task 15: README — bulk send section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Find the insertion point**

The new section goes under "Usage", after the existing `#### Sending via Gmail (`--send-email`)` block (currently ends around line 361 in README.md). Locate the line that begins with `### Exit codes` — the new section sits just above it.

- [ ] **Step 2: Insert the new section**

Insert this block immediately before the `### Exit codes` heading:

```markdown
### Bulk send via `users send-email`

For mailing per-user vulnerability reports to a list of addresses in one
invocation. Each recipient gets a report for their own devices; users with
no devices or no active vulnerabilities are skipped (and logged to stderr).

```bash
# CSV with auto-detected `email` / `user_email` / `e-mail` column
jellyfish users send-email --csv fleet.csv

# CSV with a custom column
jellyfish users send-email --csv fleet.csv --csv-email-column primary_contact

# Comma-separated list
jellyfish users send-email --emails alice@example.com,bob@example.com

# Redirect every email to one address (test / audit mode)
jellyfish users send-email --csv fleet.csv --email-to me@example.com

# Dry-run: walk the list and print what would happen; no mail is sent
jellyfish users send-email --csv fleet.csv --dry-run

# Compose one message body, shared across every recipient
jellyfish users send-email --csv fleet.csv --message
```

`--csv` and `--emails` are mutually exclusive. Email addresses are
deduped case-insensitively (first-seen address wins for display). The
detection walk runs once at the start of the batch and is reused for
every recipient, so a 50-user run takes roughly the same wall time as
one `user show` plus the per-user Gmail sends.

By default the command prompts before sending:

```
About to send vulnerability reports to 47 users. Continue? [y/N]
```

Use `--yes` to skip the prompt in scripts.

Stderr emits one record per recipient and a final summary line:

```
sent: alice@example.com to=alice@example.com gmail-id=msg-abc
skip: bob@example.com no devices
skip: carol@example.com no vulnerabilities
error: dave@example.com user not found in Iru
summary: sent=1 skipped=2 errors=1
```

`<input-email>` (the first column of each line) is always the address as
supplied in the CSV / list, not the resolved recipient — useful for
tracing each line back to a row in the source file.

Unlike `user show --send-email`, the bulk command intentionally does not
honour `email.default_to` from config. If you want every email redirected
to one address, set `--email-to` explicitly so the redirect is visible
in the command line.

Exit codes follow the standard table below; the worst per-user outcome
wins (auth > upstream > not-found).
```

- [ ] **Step 3: Verify the file builds**

Run: `make test`
Expected: pass (README change does not affect Go tests).

- [ ] **Step 4: Spot-check the new heading**

Run: `grep -n "Bulk send" README.md`
Expected: matches the new heading exactly once.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs(readme): documented users send-email bulk command"
```

---

## Final verification

- [ ] **Run the full test suite**

Run: `make test && make lint`
Expected: both green.

- [ ] **Smoke-test the help output**

Run: `go run . users send-email --help`
Expected: all documented flags listed; the synopsis matches the README.

- [ ] **Spot-check command registration**

Run: `go run . users --help`
Expected: shows `send-email` as a subcommand.
