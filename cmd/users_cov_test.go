package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
)

// usercovErrClient wraps fakeClient so a test can make one Iru call fail
// while the rest behave normally. A nil error field means "delegate".
type usercovErrClient struct {
	*fakeClient
	detectionsErr error // ListDetectionsStream
	findErr       error // FindUsersByEmail
	devicesErr    error // ListDevices
}

func (c *usercovErrClient) ListDetectionsStream(ctx context.Context, f iru.DetectionFilters, cb func(page []iru.Detection) error) error {
	if c.detectionsErr != nil {
		return c.detectionsErr
	}
	return c.fakeClient.ListDetectionsStream(ctx, f, cb)
}

func (c *usercovErrClient) FindUsersByEmail(ctx context.Context, e string) ([]iru.User, error) {
	if c.findErr != nil {
		return nil, c.findErr
	}
	return c.fakeClient.FindUsersByEmail(ctx, e)
}

func (c *usercovErrClient) ListDevices(ctx context.Context, f iru.DeviceFilters) ([]iru.Device, error) {
	if c.devicesErr != nil {
		return nil, c.devicesErr
	}
	return c.fakeClient.ListDevices(ctx, f)
}

// usercovReadErr is what usercovErrReader returns. It is a comparable
// struct, so errors.Is(err, usercovReadErr{}) shows the I/O error
// propagated unchanged.
type usercovReadErr struct{}

func (usercovReadErr) Error() string { return "usercov: read failed" }

// usercovErrReader fails every Read with a non-EOF error, simulating a
// broken stdin.
type usercovErrReader struct{}

func (usercovErrReader) Read([]byte) (int, error) { return 0, usercovReadErr{} }

// usercovAliceClient is a tenant with one user, one device and one
// detection: enough for the bulk send loop to reach the send step.
func usercovAliceClient() *fakeClient {
	return &fakeClient{
		users:      []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices:    []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", User: iru.User{ID: "u-1"}}},
		detections: []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5}},
	}
}

// Every pre-send failure must abort the run before any mail goes out and
// before the detection walk, so the operator gets the error straight away.
func TestRunUsersSendEmailPreflightErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	cases := []struct {
		name    string
		mutate  func(o *usersSendEmailOpts)
		wantErr string
		wantIs  error
	}{
		{
			name:    "message and message-file together",
			mutate:  func(o *usersSendEmailOpts) { o.EmailFlags.Message = true; o.EmailFlags.MessageFile = "x.txt" },
			wantErr: "mutually exclusive",
		},
		{
			name:    "malformed --email-to",
			mutate:  func(o *usersSendEmailOpts) { o.EmailFlags.To = "not an address" },
			wantErr: `--email-to "not an address"`,
		},
		{
			name:    "no recipient source",
			mutate:  func(o *usersSendEmailOpts) { o.Emails = "" },
			wantErr: "provide --csv or --emails",
		},
		{
			name: "no from address anywhere",
			mutate: func(o *usersSendEmailOpts) {
				o.EmailFlags.From = ""
				o.Profile.Email.From = ""
				o.gitEmail = fixedGitEmail("")
			},
			wantErr: "no email from address",
		},
		{
			name:    "confirm prompt read failure",
			mutate:  func(o *usersSendEmailOpts) { o.Yes = false; o.ConfirmReader = usercovErrReader{} },
			wantIs:  usercovReadErr{},
			wantErr: "read failed",
		},
		{
			name:    "unreadable --message-file",
			mutate:  func(o *usersSendEmailOpts) { o.EmailFlags.MessageFile = missing },
			wantErr: "read --message-file",
		},
		{
			name:    "gmail not configured",
			mutate:  func(o *usersSendEmailOpts) { o.Profile.Email.GmailConfigured = false },
			wantIs:  errBulkGmailNotConfigured,
			wantErr: "--dry-run",
		},
		{
			name: "keychain read failure",
			mutate: func(o *usersSendEmailOpts) {
				o.KeychainGet = func() ([]byte, error) { return nil, errors.New("locked") }
			},
			wantErr: "read Gmail credentials from Keychain: locked",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &streamCountingClient{fakeClient: usercovAliceClient()}
			sender := &fakeGmailSender{}
			opts := newOpts(t, sender)
			opts.Emails = "alice@example.com"
			tc.mutate(&opts)
			var stderr bytes.Buffer
			err := runUsersSendEmail(context.Background(), client, &stderr, opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("err: got %v, want errors.Is %v", err, tc.wantIs)
			}
			if code := classifyError(err); code != 1 {
				t.Errorf("exit code: got %d, want 1 (user error)", code)
			}
			if sender.sent != nil {
				t.Error("no mail should have been sent")
			}
			if client.detectionStreamCalls != 0 {
				t.Errorf("detection walk started %d time(s) before a preflight error", client.detectionStreamCalls)
			}
		})
	}
}

func TestRunUsersSendEmailDetectionWalkErrorPropagates(t *testing.T) {
	client := &usercovErrClient{fakeClient: usercovAliceClient(), detectionsErr: iru.ErrRateLimited}
	sender := &fakeGmailSender{}
	opts := newOpts(t, sender)
	opts.Emails = "alice@example.com"
	var stderr bytes.Buffer
	err := runUsersSendEmail(context.Background(), client, &stderr, opts)
	if !errors.Is(err, iru.ErrRateLimited) {
		t.Fatalf("err: got %v, want iru.ErrRateLimited", err)
	}
	if code := classifyError(err); code != 4 {
		t.Errorf("exit code: got %d, want 4", code)
	}
	if sender.sent != nil {
		t.Error("no mail should have been sent")
	}
	if strings.Contains(stderr.String(), "summary:") {
		t.Errorf("a failed walk must not print a summary; got:\n%s", stderr.String())
	}
}

// Per-row failures are logged and tallied rather than aborting the run; the
// worst failure class decides the exit code.
func TestRunUsersSendEmailPerRowErrors(t *testing.T) {
	cases := []struct {
		name     string
		client   iruClient
		wantLine string
		wantIs   error
		wantCode int
	}{
		{
			name:     "lookup upstream error",
			client:   &usercovErrClient{fakeClient: usercovAliceClient(), findErr: iru.ErrRateLimited},
			wantLine: "error input=alice@example.com lookup: " + iru.ErrRateLimited.Error(),
			wantIs:   gmail.ErrRateLimited,
			wantCode: 4,
		},
		{
			name:     "lookup forbidden",
			client:   &usercovErrClient{fakeClient: usercovAliceClient(), findErr: iru.ErrForbidden},
			wantLine: "error input=alice@example.com lookup: " + iru.ErrForbidden.Error(),
			wantIs:   gmail.ErrUnauthorized,
			wantCode: 2,
		},
		{
			name: "lookup returns empty slice",
			client: &fakeClient{
				usersByEmail: map[string][]iru.User{"alice@example.com": {}},
			},
			wantLine: "error input=alice@example.com reason=user-not-found",
			wantIs:   iru.ErrNotFound,
			wantCode: 3,
		},
		{
			name:     "device lookup failure",
			client:   &usercovErrClient{fakeClient: usercovAliceClient(), devicesErr: iru.ErrUnauthorized},
			wantLine: "error input=alice@example.com lookup: " + iru.ErrUnauthorized.Error(),
			wantIs:   gmail.ErrUnauthorized,
			wantCode: 2,
		},
		{
			name: "matched user has no email",
			client: &fakeClient{
				usersByEmail: map[string][]iru.User{"alice@example.com": {{ID: "u-1"}}},
				devices:      []iru.Device{{DeviceID: "d-1", User: iru.User{ID: "u-1"}}},
				detections:   []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "High", CVSSScore: 7}},
			},
			wantLine: "error input=alice@example.com reason=no-recipient",
			wantIs:   iru.ErrNotFound,
			wantCode: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeGmailSender{}
			opts := newOpts(t, sender)
			opts.Emails = "alice@example.com"
			var stderr bytes.Buffer
			err := runUsersSendEmail(context.Background(), tc.client, &stderr, opts)
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("err: got %v, want errors.Is %v", err, tc.wantIs)
			}
			if code := classifyError(err); code != tc.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tc.wantCode)
			}
			for _, want := range []string{tc.wantLine, "summary: sent=0 skipped=0 errors=1"} {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr missing %q; got:\n%s", want, stderr.String())
				}
			}
			if sender.sent != nil {
				t.Error("no mail should have been sent")
			}
		})
	}
}

// One bad row must not stop later rows from sending.
func TestRunUsersSendEmailErrorRowDoesNotBlockLaterRows(t *testing.T) {
	client := usercovAliceClient()
	rec := &recordingSender{}
	opts := newOpts(t, nil)
	opts.NewSender = func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return rec, nil }
	opts.Emails = "ghost@example.com,alice@example.com"
	var stderr bytes.Buffer
	err := runUsersSendEmail(context.Background(), client, &stderr, opts)
	if !errors.Is(err, iru.ErrNotFound) {
		t.Fatalf("err: got %v, want iru.ErrNotFound", err)
	}
	if !reflect.DeepEqual(rec.tos, []string{"alice@example.com"}) {
		t.Fatalf("sends: got %v, want only alice", rec.tos)
	}
	if !strings.Contains(stderr.String(), "summary: sent=1 skipped=0 errors=1") {
		t.Errorf("stderr summary; got:\n%s", stderr.String())
	}
}

// The cobra wiring must thread config (tenant, profile) and the flag values
// through to the run. A dry run proves it without touching the Keychain's
// Gmail entry.
func TestUsersSendEmailCmdDryRunThroughRoot(t *testing.T) {
	isolateCacheDir(t)
	cfg := writeProfileConfig(t, config.Profile{Subdomain: "acme", Region: "eu"})
	stubKeychainGet(t, func(string) (string, error) { return "tok", nil })
	stubNewIruClient(t, usercovAliceClient())

	_, stderr, err := execRootForTest(t, "users", "send-email",
		"--emails", "alice@example.com", "--dry-run", "--email-from", "ops@example.com",
		"--config", cfg)
	if err != nil {
		t.Fatalf("execute: %v\nstderr:\n%s", err, stderr)
	}
	for _, want := range []string{
		"DRY RUN",
		"would-send input=alice@example.com to=alice@example.com",
		"summary: would-send=1 skipped=0 errors=0",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q; got:\n%s", want, stderr)
		}
	}
}

func TestUsersSendEmailCmdMissingConfigErrors(t *testing.T) {
	isolateCacheDir(t)
	failIfKeychainRead(t)
	cfg := filepath.Join(t.TempDir(), "nope.yml")
	_, _, err := execRootForTest(t, "users", "send-email", "--emails", "a@x.com", "--dry-run", "--config", cfg)
	if err == nil || !strings.Contains(err.Error(), "no credentials found") {
		t.Fatalf("err: got %v, want no-credentials error", err)
	}
}

func TestReadCSVRecipientsMalformedAndSparseRows(t *testing.T) {
	t.Run("malformed header", func(t *testing.T) {
		p := writeCSV(t, "in.csv", "na\"me,email\nAlice,a@x.com\n")
		_, err := readCSVRecipients(p, "")
		if err == nil || !strings.Contains(err.Error(), "header") {
			t.Fatalf("err: got %v, want header read error", err)
		}
	})
	t.Run("malformed row", func(t *testing.T) {
		p := writeCSV(t, "in.csv", "email\na@x.com\nb\"@x.com\n")
		_, err := readCSVRecipients(p, "")
		if err == nil || !strings.Contains(err.Error(), "row") {
			t.Fatalf("err: got %v, want row read error", err)
		}
	})
	t.Run("short and blank rows skipped", func(t *testing.T) {
		p := writeCSV(t, "in.csv", "name,email\nAlice\nBob,  \nCarol,c@x.com\n")
		got, err := readCSVRecipients(p, "")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"c@x.com"}) {
			t.Errorf("got %#v, want only c@x.com", got)
		}
	})
}

// Each failure class must hold its rank regardless of arrival order, and an
// unclassified error counts as upstream (exit 4) rather than being dropped.
func TestBulkCountersRecordErrorPrecedence(t *testing.T) {
	renderErr := errors.Join(email.ErrRender, errors.New("bad template"))
	generic := errors.New("connection reset")
	cases := []struct {
		name     string
		record   []error
		wantIs   error
		wantCode int
	}{
		{"auth stays auth", []error{gmail.ErrForbidden, iru.ErrUnauthorized}, gmail.ErrUnauthorized, 2},
		{"iru forbidden is auth", []error{iru.ErrForbidden}, gmail.ErrUnauthorized, 2},
		{"rate after auth keeps auth", []error{gmail.ErrUnauthorized, gmail.ErrUpstream}, gmail.ErrUnauthorized, 2},
		{"iru rate limit is upstream", []error{iru.ErrRateLimited}, gmail.ErrRateLimited, 4},
		{"not-found after upstream keeps upstream", []error{gmail.ErrUpstream, iru.ErrNotFound}, gmail.ErrRateLimited, 4},
		{"render after not-found keeps not-found", []error{iru.ErrNotFound, renderErr}, iru.ErrNotFound, 3},
		{"render twice", []error{renderErr, renderErr}, email.ErrRender, 1},
		{"unclassified is upstream", []error{generic}, gmail.ErrRateLimited, 4},
		{"unclassified after auth keeps auth", []error{iru.ErrForbidden, generic}, gmail.ErrUnauthorized, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c bulkCounters
			for _, e := range tc.record {
				c.recordError(e)
			}
			if c.errs != len(tc.record) {
				t.Errorf("errs: got %d, want %d", c.errs, len(tc.record))
			}
			got := c.exitError()
			if !errors.Is(got, tc.wantIs) {
				t.Fatalf("got %v; want errors.Is %v", got, tc.wantIs)
			}
			if code := classifyError(got); code != tc.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tc.wantCode)
			}
		})
	}
}
