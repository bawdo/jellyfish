package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/mail"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
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
	body := "\xef\xbb\xbfemail\r\na@x.com\r\nb@x.com\r\n"
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
		{"no header at all", "", "", "empty"},
		{"no email column auto", "id,name\n1,Alice\n", "", "no email column"},
		{"override column missing", "name,phone\nAlice,555\n", "primary_contact", "primary_contact"},
		{"empty after header", "email\n", "", "no recipients"},
		{"row with non-email cell", "email\nnot-an-email\n", "", "not a valid email"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			switch tc.name {
			case "missing file":
				path = filepath.Join(t.TempDir(), "does-not-exist.csv")
			case "no header at all":
				path = writeCSV(t, "empty.csv", "")
			default:
				path = writeCSV(t, "in.csv", tc.body)
			}
			_, err := readCSVRecipients(path, tc.column)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

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
