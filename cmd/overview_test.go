package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
)

// overviewFakeClient is a fakeClient subset that lets each user own a
// distinct device set. The base fakeClient's single devices slice can't
// express "alice has d1, bob has d2".
type overviewFakeClient struct {
	*fakeClient
	devicesByUser map[string][]iru.Device // key = user.ID
	streamErr     error                   // if set, ListDevicesStream returns this error
}

func (f *overviewFakeClient) ListDevicesStream(_ context.Context, _ iru.DeviceFilters, cb func(page []iru.Device) error) error {
	if f.streamErr != nil {
		return f.streamErr
	}
	usersByID := make(map[string]iru.User, len(f.users))
	for _, u := range f.users {
		usersByID[u.ID] = u
	}
	var all []iru.Device
	for userID, devs := range f.devicesByUser {
		for _, d := range devs {
			d.User = usersByID[userID]
			all = append(all, d)
		}
	}
	if len(all) == 0 {
		return nil
	}
	return cb(all)
}

func TestAssembleOverviewSumsAndSorts(t *testing.T) {
	base := &fakeClient{
		users: []iru.User{
			{ID: "u-alice", Name: "Alice", Email: "alice@x"},
			{ID: "u-bob", Name: "Bob", Email: "bob@x"},
			{ID: "u-carol", Name: "Carol", Email: "carol@x"}, // no devices -> excluded
		},
		detections: []iru.Detection{
			{DeviceID: "d-a1", CVEID: "CVE-1", CVSSScore: 9.8, Severity: "Critical"},
			{DeviceID: "d-a1", CVEID: "CVE-2", CVSSScore: 7.5, Severity: "High"},
			{DeviceID: "d-a2", CVEID: "CVE-3", CVSSScore: 5.0, Severity: "Medium"},
			{DeviceID: "d-b1", CVEID: "CVE-4", CVSSScore: 2.5, Severity: "Low"},
			{DeviceID: "d-other", CVEID: "CVE-X", CVSSScore: 9.0, Severity: "Critical"}, // belongs to no listed device
		},
	}
	c := &overviewFakeClient{
		fakeClient: base,
		devicesByUser: map[string][]iru.Device{
			"u-alice": {{DeviceID: "d-a1"}, {DeviceID: "d-a2"}},
			"u-bob":   {{DeviceID: "d-b1"}},
			"u-carol": nil,
		},
	}

	view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}

	// Carol has no devices -> excluded.
	if len(view.Users) != 2 {
		t.Fatalf("Users len: got %d, want 2 (carol excluded)", len(view.Users))
	}

	// Alice: 9.8 + 7.5 + 5.0 = 22.3, 3 issues, C=1 H=1 M=1 L=0, 2 devices.
	// Bob:   2.5,                    1 issue,  C=0 H=0 M=0 L=1, 1 device.
	// Sort: SecScore desc -> Alice rank 1, Bob rank 2.
	want := []email.UserStats{
		{UserID: "u-alice", Name: "Alice", Email: "alice@x", DeviceCount: 2,
			SecScore: 22.3, TotalIssues: 3, Critical: 1, High: 1, Medium: 1, Low: 0, Rank: 1},
		{UserID: "u-bob", Name: "Bob", Email: "bob@x", DeviceCount: 1,
			SecScore: 2.5, TotalIssues: 1, Critical: 0, High: 0, Medium: 0, Low: 1, Rank: 2},
	}
	for i := range want {
		// float compare with one-decimal tolerance to dodge FP noise.
		if diff := view.Users[i].SecScore - want[i].SecScore; diff > 0.05 || diff < -0.05 {
			t.Errorf("user[%d] SecScore: got %v want %v", i, view.Users[i].SecScore, want[i].SecScore)
		}
		// zero the float for the rest of the comparison so DeepEqual matches.
		view.Users[i].SecScore = want[i].SecScore
	}
	if !reflect.DeepEqual(view.Users, want) {
		t.Errorf("Users mismatch:\n got: %#v\nwant: %#v", view.Users, want)
	}

	if view.Totals.UserCount != 2 || view.Totals.DeviceCount != 3 || view.Totals.TotalIssues != 4 {
		t.Errorf("Totals counts wrong: %+v", view.Totals)
	}
	if view.Totals.Critical != 1 || view.Totals.High != 1 || view.Totals.Medium != 1 || view.Totals.Low != 1 {
		t.Errorf("Totals severity wrong: %+v", view.Totals)
	}
	// (22.3 + 2.5) / 2 = 12.4
	if diff := view.Averages.SecScorePerUser - 12.4; diff > 0.05 || diff < -0.05 {
		t.Errorf("Averages.SecScorePerUser: got %v want 12.4", view.Averages.SecScorePerUser)
	}

	if len(view.MostDangerousFive) != 2 || view.MostDangerousFive[0].UserID != "u-alice" {
		t.Errorf("MostDangerousFive wrong: %+v", view.MostDangerousFive)
	}
	if len(view.BestFive) != 2 || view.BestFive[0].UserID != "u-bob" {
		t.Errorf("BestFive wrong: %+v", view.BestFive)
	}
}

func TestAssembleOverviewEmptyRosterErrors(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient:    &fakeClient{users: []iru.User{{ID: "u1", Name: "x"}}},
		devicesByUser: map[string][]iru.Device{"u1": nil},
	}
	_, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil)
	if err == nil || err.Error() == "" {
		t.Fatalf("expected an empty-roster error, got nil")
	}
}

func TestAssembleOverviewTieBreakerByName(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users: []iru.User{
				{ID: "u-b", Name: "Beta", Email: "b@x"},
				{ID: "u-a", Name: "Alpha", Email: "a@x"},
			},
			// both score 0 (no detections), so name asc decides
			detections: nil,
		},
		devicesByUser: map[string][]iru.Device{
			"u-a": {{DeviceID: "d-a"}},
			"u-b": {{DeviceID: "d-b"}},
		},
	}
	view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}
	if view.Users[0].Name != "Alpha" || view.Users[1].Name != "Beta" {
		t.Fatalf("name-asc tiebreaker broken: %+v", view.Users)
	}
}

func TestRenderOverviewTable(t *testing.T) {
	v := email.OverviewView{
		Tenant: "acme",
		Totals: email.OverviewTotals{
			UserCount: 2, DeviceCount: 3, TotalIssues: 4, Critical: 1, High: 1, Medium: 1, Low: 1, SecScore: 24.8,
		},
		Averages: email.OverviewAverages{
			DevicesPerUser: 1.5, IssuesPerUser: 2.0, SecScorePerUser: 12.4,
			CriticalPerUser: 0.5, HighPerUser: 0.5, MediumPerUser: 0.5, LowPerUser: 0.5,
		},
		BestFive: []email.UserStats{
			{Rank: 2, Name: "Bob", SecScore: 2.5, Critical: 0, High: 0, Medium: 0, Low: 1},
		},
		MostDangerousFive: []email.UserStats{
			{Rank: 1, Name: "Alice", SecScore: 22.3, Critical: 1, High: 1, Medium: 1, Low: 0},
		},
		Users: []email.UserStats{
			{Rank: 1, Name: "Alice", SecScore: 22.3, Critical: 1, High: 1, Medium: 1, Low: 0},
			{Rank: 2, Name: "Bob", SecScore: 2.5, Critical: 0, High: 0, Medium: 0, Low: 1},
		},
	}
	var buf bytes.Buffer
	if err := renderOverviewTable(&buf, v); err != nil {
		t.Fatalf("renderOverviewTable: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"TOTALS", "BEST 5", "MOST DANGEROUS 5", "ALL USERS (2)",
		"Alice", "Bob",
		"22.3", "2.5", "12.4",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestSecScoreTier(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "good"},
		{4.9, "good"},
		{5.0, "medium"},
		{29.9, "medium"},
		{30.0, "high"},
		{99.9, "high"},
		{100.0, "critical"},
		{500.0, "critical"},
	}
	for _, c := range cases {
		if got := secScoreTier(c.score); got != c.want {
			t.Errorf("secScoreTier(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestRenderOverviewCSV(t *testing.T) {
	v := email.OverviewView{
		Users: []email.UserStats{
			{Rank: 1, Name: "Alice", Email: "alice@x", DeviceCount: 2,
				SecScore: 22.3, TotalIssues: 3, Critical: 1, High: 1, Medium: 1, Low: 0},
			{Rank: 2, Name: "Bob", Email: "bob@x", DeviceCount: 1,
				SecScore: 2.5, TotalIssues: 1, Critical: 0, High: 0, Medium: 0, Low: 1},
		},
	}
	var buf bytes.Buffer
	if err := renderOverviewCSV(&buf, v); err != nil {
		t.Fatalf("renderOverviewCSV: %v", err)
	}
	want := "name,email,devices_count,sec_score,total_issues,critical_issues,high_issues,medium_issues,low_issues\n" +
		"Alice,alice@x,2,22.3,3,1,1,1,0\n" +
		"Bob,bob@x,1,2.5,1,0,0,0,1\n"
	if buf.String() != want {
		t.Errorf("CSV mismatch:\n got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestRenderOverviewJSON(t *testing.T) {
	v := email.OverviewView{
		Tenant: "acme",
		Totals: email.OverviewTotals{UserCount: 1, SecScore: 22.3},
		Users:  []email.UserStats{{Rank: 1, Name: "Alice", SecScore: 22.3}},
	}
	var buf bytes.Buffer
	if err := renderOverviewStructured(&buf, "json", v); err != nil {
		t.Fatalf("renderOverviewStructured json: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		`"tenant": "acme"`,
		`"user_count": 1`,
		`"sec_score": 22.3`,
		`"best_five"`,
		`"most_dangerous_five"`,
		`"users"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"me"`) {
		t.Errorf("JSON should omit me when nil:\n%s", got)
	}
}

func TestRenderOverviewYAML(t *testing.T) {
	v := email.OverviewView{
		Tenant: "acme",
		Users:  []email.UserStats{{Rank: 1, Name: "Alice"}},
	}
	var buf bytes.Buffer
	if err := renderOverviewStructured(&buf, "yaml", v); err != nil {
		t.Fatalf("renderOverviewStructured yaml: %v", err)
	}
	if !strings.Contains(buf.String(), "tenant: acme") {
		t.Errorf("YAML missing tenant key:\n%s", buf.String())
	}
}

func TestRunOverviewAdminSend(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d1", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	fake := &fakeGmailSender{returnID: "msg-1"}
	opts := overviewOpts{
		Output:        "email",
		Yes:           true,
		EmailFlags:    emailFlagValues{To: "ops@example.com", From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		KeychainGet:   stubKeychain("{}"),
		NewSender:     newFakeSenderFactory(fake),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	if !strings.Contains(stderr.String(), "sent to=ops@example.com gmail-id=msg-1") {
		t.Errorf("stderr missing sent line:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "summary: sent=1 errors=0") {
		t.Errorf("stderr missing summary:\n%s", stderr.String())
	}
	if len(fake.sent) == 0 {
		t.Fatal("sender was not called")
	}
}

func TestRunOverviewAdminDryRun(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d1", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	opts := overviewOpts{
		Output:        "email",
		DryRun:        true,
		EmailFlags:    emailFlagValues{To: "ops@example.com,security@example.com", From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: false}}, // intentional: dry-run bypasses gmail check
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	for _, want := range []string{
		"DRY RUN", "would-send to=ops@example.com", "would-send to=security@example.com",
		"summary: would-send=2 errors=0",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr.String())
		}
	}
	// Confirm each would-send line carries a non-zero byte count.
	for _, line := range strings.Split(stderr.String(), "\n") {
		if !strings.HasPrefix(line, "would-send to=") {
			continue
		}
		if !strings.Contains(line, " bytes=") {
			t.Errorf("would-send line missing bytes=: %q", line)
		}
		// bytes=0 is a bug (something was rendered)
		if strings.Contains(line, "bytes=0\n") || strings.HasSuffix(line, "bytes=0") {
			t.Errorf("would-send line has zero bytes: %q", line)
		}
	}
}

func TestOverviewCmdRegistered(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"overview", "--help"})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr=%q", err, errBuf.String())
	}
	help := out.String()
	if !strings.Contains(help, "overview") {
		t.Fatalf("help missing command name; got:\n%s", help)
	}
	for _, flag := range []string{
		"--per-user", "--csv", "--emails", "--csv-email-column",
		"--email-to", "--email-from", "--email-subject",
		"--email-header-bg", "--email-logo",
		"--message", "--message-file",
		"--dry-run", "--yes", "--no-cache",
	} {
		if !strings.Contains(help, flag) {
			t.Errorf("help missing flag %s; got:\n%s", flag, help)
		}
	}
}

func TestRunOverviewPerUser(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users: []iru.User{
				{ID: "u1", Name: "Alice", Email: "alice@x"},
				{ID: "u2", Name: "Bob", Email: "bob@x"},
				{ID: "u3", Name: "Eve", Email: ""}, // no email -> skipped
			},
			detections: []iru.Detection{
				{DeviceID: "d-a", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5},
			},
		},
		devicesByUser: map[string][]iru.Device{
			"u1": {{DeviceID: "d-a"}},
			"u2": {{DeviceID: "d-b"}},
			"u3": {{DeviceID: "d-c"}},
		},
	}
	fake := &fakeGmailSender{returnID: "msg-1"}
	opts := overviewOpts{
		Output:        "email",
		PerUser:       true,
		Yes:           true,
		EmailFlags:    emailFlagValues{From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		KeychainGet:   stubKeychain("{}"),
		NewSender:     newFakeSenderFactory(fake),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	out := stderr.String()
	for _, want := range []string{
		"sent user=u1 to=alice@x",
		"sent user=u2 to=bob@x",
		"skip user=u3 reason=no-email",
		"summary: sent=2 skipped=1 errors=0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
}

func TestRunOverviewPerUserDryRun(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: nil,
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d-a"}}},
	}
	opts := overviewOpts{
		Output:        "email",
		PerUser:       true,
		DryRun:        true,
		EmailFlags:    emailFlagValues{From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: false}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "would-send user=u1 to=alice@x") {
		t.Errorf("stderr missing would-send line:\n%s", out)
	}
	// Real byte count, not "approx" placeholder.
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "would-send user=") {
			continue
		}
		if !strings.Contains(line, " bytes=") {
			t.Errorf("would-send line missing bytes=: %q", line)
		}
		if strings.HasSuffix(line, "bytes=0") {
			t.Errorf("would-send line has zero bytes: %q", line)
		}
	}
}

func TestRunOverviewAdminGmailErrorPerRecipient(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d1", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	fake := &fakeGmailSender{err: gmail.ErrRateLimited}
	opts := overviewOpts{
		Output:        "email",
		Yes:           true,
		EmailFlags:    emailFlagValues{To: "ops@example.com,security@example.com", From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		KeychainGet:   stubKeychain("{}"),
		NewSender:     newFakeSenderFactory(fake),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	err := runOverview(context.Background(), c, io.Discard, &stderr, opts)

	// Both recipients should have been attempted (loop did not abort on first error).
	out := stderr.String()
	if !strings.Contains(out, "error to=ops@example.com gmail:") {
		t.Errorf("missing first error line:\n%s", out)
	}
	if !strings.Contains(out, "error to=security@example.com gmail:") {
		t.Errorf("missing second error line:\n%s", out)
	}
	if !strings.Contains(out, "summary: sent=0 errors=2") {
		t.Errorf("summary wrong:\n%s", out)
	}
	// runOverview wraps the worst-class sentinel; rate-limit -> exit code 4 via classifyError.
	if err == nil {
		t.Fatal("expected wrapped error from counters.exitError, got nil")
	}
	if !errors.Is(err, gmail.ErrRateLimited) {
		t.Errorf("error should wrap gmail.ErrRateLimited, got %v", err)
	}
}

func TestAssembleOverviewDeviceWalkErrorPropagates(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: nil,
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d-a"}}},
		streamErr:     errors.New("iru down"),
	}
	_, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "iru down") {
		t.Fatalf("expected iru down error, got %v", err)
	}
}

func TestRunOverviewPerUserWarnsOnEmailToConflict(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d-a", Severity: "Low", CVSSScore: 2.0}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d-a"}}},
	}
	opts := overviewOpts{
		Output:        "email",
		PerUser:       true,
		DryRun:        true, // skip Gmail; the warn line is what we care about
		EmailFlags:    emailFlagValues{From: "noreply@example.com", To: "ops@example.com"}, // --email-to set: should be warned-and-ignored
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: false}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	if !strings.Contains(stderr.String(), "warn: --email-to ignored with --per-user") {
		t.Errorf("stderr missing warn line:\n%s", stderr.String())
	}
	// Confirm the per-user fanout still went ahead (recipient = u1's email, not the ignored --email-to).
	if !strings.Contains(stderr.String(), "would-send user=u1 to=alice@x") {
		t.Errorf("stderr missing per-user line:\n%s", stderr.String())
	}
}

func TestRunOverviewValidationErrors(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient:    &fakeClient{users: []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}}},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	cases := []struct {
		name string
		opts overviewOpts
		want string
	}{
		{
			name: "per-user with table output",
			opts: overviewOpts{Output: "table", PerUser: true},
			want: "--per-user requires --output=email",
		},
		{
			name: "email without email-to or per-user",
			opts: overviewOpts{Output: "email"},
			want: "--email-to",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runOverview(context.Background(), c, io.Discard, io.Discard, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err: got %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestAssembleOverviewFilterByEmails(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users: []iru.User{
				{ID: "u1", Name: "Alice", Email: "alice@x"},
				{ID: "u2", Name: "Bob", Email: "bob@x"},
				{ID: "u3", Name: "Carol", Email: "carol@x"},
			},
			detections: []iru.Detection{
				{DeviceID: "d-a", CVSSScore: 5.0, Severity: "Medium"},
				{DeviceID: "d-b", CVSSScore: 7.5, Severity: "High"},
				{DeviceID: "d-c", CVSSScore: 9.5, Severity: "Critical"},
			},
		},
		devicesByUser: map[string][]iru.Device{
			"u1": {{DeviceID: "d-a"}},
			"u2": {{DeviceID: "d-b"}},
			"u3": {{DeviceID: "d-c"}},
		},
	}
	filter := map[string]struct{}{
		"alice@x": {},
		"carol@x": {},
		"ghost@x": {}, // not in tenant -> should produce a warn line
	}
	var stderr bytes.Buffer
	view, err := assembleOverview(context.Background(), c, &stderr, false, filter)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}
	if len(view.Users) != 2 {
		t.Fatalf("expected 2 users in roster, got %d: %+v", len(view.Users), view.Users)
	}
	gotNames := []string{view.Users[0].Name, view.Users[1].Name}
	wantSet := map[string]bool{"Alice": true, "Carol": true}
	for _, n := range gotNames {
		if !wantSet[n] {
			t.Errorf("unexpected user in roster: %q", n)
		}
	}
	if !strings.Contains(stderr.String(), "warn: ghost@x not in tenant devices") {
		t.Errorf("stderr missing warn for ghost@x:\n%s", stderr.String())
	}
}

func TestBuildOverviewUserFilter(t *testing.T) {
	cases := []struct {
		name    string
		opts    overviewOpts
		wantNil bool
		wantSet map[string]struct{}
		wantErr string
	}{
		{
			name:    "no filter flags returns nil",
			opts:    overviewOpts{},
			wantNil: true,
		},
		{
			name: "emails parsed and lowercased",
			opts: overviewOpts{Emails: "Alice@x, BOB@x"},
			wantSet: map[string]struct{}{
				"alice@x": {},
				"bob@x":   {},
			},
		},
		{
			name:    "csv and emails together error",
			opts:    overviewOpts{CSVPath: "x", Emails: "a@x"},
			wantErr: "mutually exclusive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildOverviewUserFilter(tc.opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err: got %v want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.wantSet) {
				t.Errorf("got %v, want %v", got, tc.wantSet)
			}
		})
	}
}

func TestRunOverviewCsvAndEmailsConflict(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient:    &fakeClient{users: []iru.User{{ID: "u1", Email: "a@x"}}},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	opts := overviewOpts{CSVPath: "x", Emails: "a@x"}
	err := runOverview(context.Background(), c, io.Discard, io.Discard, opts)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got %v", err)
	}
}

func TestRunOverviewAdminMessageFileStdin(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d-a", Severity: "High", CVSSScore: 7.5}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d-a"}}},
	}
	fake := &fakeGmailSender{returnID: "msg-1"}
	opts := overviewOpts{
		Output:        "email",
		Yes:           true,
		EmailFlags:    emailFlagValues{To: "ops@example.com", From: "noreply@example.com", MessageFile: "-"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		KeychainGet:   stubKeychain("{}"),
		NewSender:     newFakeSenderFactory(fake),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
		MessageReader: strings.NewReader("Hello team, this is the security overview."),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	if !strings.Contains(stderr.String(), "sent to=ops@example.com gmail-id=msg-1") {
		t.Errorf("stderr missing sent line:\n%s", stderr.String())
	}
	// The Gmail sender captured the rendered email; the message body should appear in it.
	if !strings.Contains(string(fake.sent), "Hello team, this is the security overview") {
		t.Errorf("rendered email missing the injected message; .sent =\n%s", string(fake.sent))
	}
}
