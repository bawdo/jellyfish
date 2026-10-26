package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/iru"
)

// usercovOverviewClient is a one-user tenant: Alice owns d1, which has a
// single High detection.
func usercovOverviewClient() *overviewFakeClient {
	return &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d1", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
}

// usercovAdminSendOpts is an admin --send-email setup that would send one
// copy to ops@example.com; tests break one piece of it.
func usercovAdminSendOpts(sender *fakeGmailSender) overviewOpts {
	return overviewOpts{
		Yes:         true,
		EmailFlags:  emailFlagValues{Send: true, To: "ops@example.com", From: "noreply@example.com"},
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		EmailNow:    time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		KeychainGet: stubKeychain("{}"),
		NewSender:   newFakeSenderFactory(sender),
		gitEmail:    fixedGitEmail(""),
	}
}

// Ownerless devices are left out of the roster and device totals (but still
// counted in the progress line), a nameless user is shown by email, and
// users tied on score and name are ordered by ID in both leaderboards.
func TestAssembleOverviewOwnerlessDevicesAndTieBreaks(t *testing.T) {
	c := &fakeClient{
		devices: []iru.Device{
			{DeviceID: "d-orphan"},
			{DeviceID: "d-b", User: iru.User{ID: "u-b", Name: "Same", Email: "b@x"}},
			{DeviceID: "d-a", User: iru.User{ID: "u-a", Name: "Same", Email: "a@x"}},
			{DeviceID: "d-c", User: iru.User{ID: "u-c", Email: "carol@x"}},
		},
	}
	var stderr bytes.Buffer
	view, err := assembleOverview(context.Background(), c, &stderr, true, nil, 0, "")
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}
	if !strings.Contains(stderr.String(), "fetching devices: 1 pages, 4 records...") {
		t.Errorf("progress line should count every device record; got:\n%s", stderr.String())
	}
	if view.Totals.UserCount != 3 || view.Totals.DeviceCount != 3 {
		t.Errorf("totals: got users=%d devices=%d, want 3 and 3 (orphan excluded)", view.Totals.UserCount, view.Totals.DeviceCount)
	}
	ids := func(rows []email.UserStats) string {
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r.UserID
		}
		return strings.Join(out, ",")
	}
	// All scores are zero, so order is name asc ("Same" < "carol@x") then ID asc.
	if got := ids(view.Users); got != "u-a,u-b,u-c" {
		t.Errorf("roster order: got %s, want u-a,u-b,u-c", got)
	}
	if got := ids(view.MostDangerousFive); got != "u-a,u-b,u-c" {
		t.Errorf("dangerous order: got %s, want u-a,u-b,u-c", got)
	}
	if view.Users[2].Name != "carol@x" {
		t.Errorf("nameless user should fall back to email; got %q", view.Users[2].Name)
	}
}

func TestAssembleOverviewDetectionWalkErrorPropagates(t *testing.T) {
	c := &usercovErrClient{fakeClient: usercovOverviewClient().fakeClient, detectionsErr: iru.ErrUnauthorized}
	_, err := assembleOverview(context.Background(), c, io.Discard, true, nil, 0, "")
	if !errors.Is(err, iru.ErrUnauthorized) {
		t.Fatalf("err: got %v, want iru.ErrUnauthorized", err)
	}
}

func TestRenderOverviewTableHeaderIncludesTenantAndTime(t *testing.T) {
	v := email.OverviewView{
		Tenant:      "acme",
		GeneratedAt: time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		Users:       []email.UserStats{{Rank: 1, Name: "Alice"}},
	}
	var buf bytes.Buffer
	if err := renderOverviewTable(&buf, v); err != nil {
		t.Fatalf("renderOverviewTable: %v", err)
	}
	first, _, _ := strings.Cut(buf.String(), "\n")
	if first != "SECURITY OVERVIEW · acme · 2026-05-17 10:30" {
		t.Errorf("header: got %q", first)
	}
}

func TestRenderOverviewStructuredRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := renderOverviewStructured(&buf, "xml", email.OverviewView{})
	if err == nil || !strings.Contains(err.Error(), `unsupported output format "xml"`) {
		t.Fatalf("err: got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("nothing should be written; got %q", buf.String())
	}
}

func TestRunOverviewOutputDispatch(t *testing.T) {
	cases := []struct {
		output  string
		want    string
		wantErr string
	}{
		{output: "", want: "ALL USERS (1)"},
		{output: "table", want: "SECURITY OVERVIEW"},
		{output: "csv", want: "name,email,devices_count,sec_score,total_issues,critical_issues,high_issues,medium_issues,low_issues\nAlice,alice@x,1,7.5,1,0,1,0,0\n"},
		{output: "xml", wantErr: `unsupported output format "xml"`},
	}
	for _, tc := range cases {
		t.Run("output="+tc.output, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runOverview(context.Background(), usercovOverviewClient(), &stdout, io.Discard, overviewOpts{Output: tc.output})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("runOverview: %v", err)
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Errorf("stdout missing %q; got:\n%s", tc.want, stdout.String())
			}
		})
	}
}

func TestRunOverviewEarlyErrors(t *testing.T) {
	cases := []struct {
		name    string
		client  iruClient
		opts    overviewOpts
		wantErr string
		wantIs  error
	}{
		{
			name:    "message and message-file together",
			client:  usercovOverviewClient(),
			opts:    overviewOpts{Output: "email", EmailFlags: emailFlagValues{Message: true, MessageFile: "x.txt"}},
			wantErr: "mutually exclusive",
		},
		{
			name:    "message without email output",
			client:  usercovOverviewClient(),
			opts:    overviewOpts{Output: "table", EmailFlags: emailFlagValues{MessageFile: "x.txt"}},
			wantErr: "requires email output",
		},
		{
			name:    "malformed --emails filter",
			client:  usercovOverviewClient(),
			opts:    overviewOpts{Emails: "not-an-email"},
			wantErr: "not a valid email address",
		},
		{
			name: "device walk failure",
			client: &overviewFakeClient{
				fakeClient: &fakeClient{},
				streamErr:  iru.ErrRateLimited,
			},
			opts:   overviewOpts{},
			wantIs: iru.ErrRateLimited,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runOverview(context.Background(), tc.client, &stdout, io.Discard, tc.opts)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err: got %v, want substring %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("err: got %v, want errors.Is %v", err, tc.wantIs)
			}
			if stdout.Len() != 0 {
				t.Errorf("nothing should render on error; got %q", stdout.String())
			}
		})
	}
}

func TestRenderOverviewEmailStdoutErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	cases := []struct {
		name    string
		flags   emailFlagValues
		wantErr string
	}{
		{"no from address", emailFlagValues{To: "ops@example.com"}, "no email from address"},
		{"unreadable message file", emailFlagValues{From: "noreply@example.com", MessageFile: missing}, "read --message-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			opts := overviewOpts{Output: "email", EmailFlags: tc.flags, gitEmail: fixedGitEmail("")}
			err := runOverview(context.Background(), usercovOverviewClient(), &stdout, io.Discard, opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
			if stdout.Len() != 0 {
				t.Errorf("no .eml should be written on error; got %q", stdout.String())
			}
		})
	}
}

// Every admin-send failure before the loop must stop the run without
// touching Gmail.
func TestRunOverviewAdminSendErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	cases := []struct {
		name    string
		mutate  func(o *overviewOpts)
		wantErr string
		wantIs  error
	}{
		{
			name:    "no from address",
			mutate:  func(o *overviewOpts) { o.EmailFlags.From = "" },
			wantErr: "no email from address",
		},
		{
			name:    "malformed --email-to list",
			mutate:  func(o *overviewOpts) { o.EmailFlags.To = "ops@example.com,nope" },
			wantErr: `not a valid email address: "nope"`,
		},
		{
			name:    "confirm prompt read failure",
			mutate:  func(o *overviewOpts) { o.Yes = false; o.ConfirmReader = usercovErrReader{} },
			wantIs:  usercovReadErr{},
			wantErr: "read failed",
		},
		{
			name:    "unreadable message file",
			mutate:  func(o *overviewOpts) { o.EmailFlags.MessageFile = missing },
			wantErr: "read --message-file",
		},
		{
			name:    "gmail not configured",
			mutate:  func(o *overviewOpts) { o.Profile.Email.GmailConfigured = false },
			wantIs:  errBulkGmailNotConfigured,
			wantErr: "--dry-run",
		},
		{
			name: "keychain read failure",
			mutate: func(o *overviewOpts) {
				o.KeychainGet = func() ([]byte, error) { return nil, errors.New("locked") }
			},
			wantErr: "read Gmail credentials from Keychain: locked",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeGmailSender{}
			opts := usercovAdminSendOpts(sender)
			tc.mutate(&opts)
			var stderr bytes.Buffer
			err := runOverview(context.Background(), usercovOverviewClient(), io.Discard, &stderr, opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("err: got %v, want errors.Is %v", err, tc.wantIs)
			}
			if code := classifyError(err); code != 1 {
				t.Errorf("exit code: got %d, want 1", code)
			}
			if sender.sent != nil {
				t.Error("no mail should have been sent")
			}
			if strings.Contains(stderr.String(), "summary:") {
				t.Errorf("no summary expected on a pre-send error; got:\n%s", stderr.String())
			}
		})
	}
}

func TestRunOverviewAdminAbortsOnPromptNo(t *testing.T) {
	sender := &fakeGmailSender{}
	opts := usercovAdminSendOpts(sender)
	opts.Yes = false
	opts.ConfirmReader = strings.NewReader("n\n")
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), usercovOverviewClient(), io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	if sender.sent != nil {
		t.Fatal("no mail should have been sent")
	}
	out := stderr.String()
	if !strings.Contains(out, "About to send the overview to 1 recipient. Continue? [y/N] ") {
		t.Errorf("stderr missing singular confirm prompt; got:\n%s", out)
	}
	if !strings.Contains(out, "aborted: no mail sent") {
		t.Errorf("stderr missing abort line; got:\n%s", out)
	}
}

// A render failure on one item is logged and counted as ErrRender (exit 1);
// skips and later items still go through.
func TestSendOverviewsRenderErrorIsCounted(t *testing.T) {
	sender := &fakeGmailSender{}
	items := []overviewSendItem{
		{skipUserID: "u-none"},
		{view: email.OverviewView{}, recipient: "ops@example.com", tag: "to=ops@example.com"},
	}
	var stderr bytes.Buffer
	var counters bulkCounters
	// No From: the renderer refuses to build the message.
	sendOverviews(context.Background(), &stderr, email.Options{}, items, sender, false, &counters)
	if counters.errs != 1 || counters.skipped != 1 || counters.sent != 0 {
		t.Fatalf("counters: %+v", counters)
	}
	err := counters.exitError()
	if !errors.Is(err, email.ErrRender) || classifyError(err) != 1 {
		t.Errorf("exit error: got %v (code %d), want ErrRender / 1", err, classifyError(err))
	}
	for _, want := range []string{"skip user=u-none reason=no-email", "error to=ops@example.com render:"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q; got:\n%s", want, stderr.String())
		}
	}
	if sender.sent != nil {
		t.Error("sender must not be called after a render failure")
	}
}

func TestOverviewCmdMissingConfigErrors(t *testing.T) {
	isolateCacheDir(t)
	failIfKeychainRead(t)
	cfg := filepath.Join(t.TempDir(), "nope.yml")
	_, _, err := execRootForTest(t, "overview", "--config", cfg)
	if err == nil || !strings.Contains(err.Error(), "no credentials found") {
		t.Fatalf("err: got %v, want no-credentials error", err)
	}
}

// One run has one timestamp: the view's generated_at is the same instant the
// email options are stamped with, not a second time.Now() read.
func TestOverviewGeneratedAtUsesRunTimestamp(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	var stdout bytes.Buffer
	err := runOverview(context.Background(), usercovOverviewClient(), &stdout, io.Discard,
		overviewOpts{Output: "json", NoCache: true, EmailNow: now})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var got struct {
		GeneratedAt time.Time `json:"generated_at"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if !got.GeneratedAt.Equal(now) {
		t.Errorf("generated_at: got %v want %v", got.GeneratedAt, now)
	}
}
