package cmd

import (
	"bytes"
	"context"
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

// vulncovClient wraps fakeClient so a test can fail individual endpoints and
// see what the single-page path asked for.
type vulncovClient struct {
	*fakeClient
	pageErr   error
	streamErr error
	vulnErr   error
	pageLimit int
	pageCalls int
}

func (c *vulncovClient) ListDetectionsPage(ctx context.Context, f iru.DetectionFilters, limit int, cursor string) ([]iru.Detection, string, error) {
	c.pageCalls++
	c.pageLimit = limit
	if c.pageErr != nil {
		return nil, "", c.pageErr
	}
	return c.fakeClient.ListDetectionsPage(ctx, f, limit, cursor)
}

func (c *vulncovClient) ListDetectionsStream(ctx context.Context, f iru.DetectionFilters, cb func(page []iru.Detection) error) error {
	if c.streamErr != nil {
		return c.streamErr
	}
	return c.fakeClient.ListDetectionsStream(ctx, f, cb)
}

func (c *vulncovClient) ListVulnerabilitiesStream(ctx context.Context, f iru.VulnerabilityFilters, cb func(page []iru.Vulnerability) error) error {
	if c.vulnErr != nil {
		return c.vulnErr
	}
	return c.fakeClient.ListVulnerabilitiesStream(ctx, f, cb)
}

func vulncovDetections(n int) []iru.Detection {
	out := make([]iru.Detection, 0, n)
	for i := range n {
		out = append(out, iru.Detection{
			CVEID:     "CVE-" + string(rune('A'+i)),
			Severity:  "High",
			CVSSScore: float64(9 - i),
			DeviceID:  "d-1",
		})
	}
	return out
}

func vulncovCVEOrder(t *testing.T, csv string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(csv, "\n"), "\n")
	var ids []string
	for _, l := range lines[1:] {
		ids = append(ids, strings.SplitN(l, ",", 2)[0])
	}
	return ids
}

// vulncovTableRows reduces a boxed table render to one "a|b|c" string per
// header or data row, with cell padding trimmed and border lines dropped.
func vulncovTableRows(rendered string) []string {
	var rows []string
	for _, line := range strings.Split(rendered, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i, c := range cells {
			cells[i] = strings.TrimSpace(c)
		}
		rows = append(rows, strings.Join(cells, "|"))
	}
	return rows
}

// --limit takes the single-page path instead of the full walk, and the
// rendered rows are capped at the limit even when the page comes back
// larger.
func TestVulnsListLimitUsesSinglePage(t *testing.T) {
	client := &vulncovClient{
		fakeClient: &fakeClient{detections: vulncovDetections(5)},
		streamErr:  errors.New("full walk must not run under --limit"),
	}
	var out, stderr bytes.Buffer
	err := runVulnsList(context.Background(), client, &out, &stderr, vulnsListOpts{Output: "csv", Limit: 3, NoCache: true})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if client.pageCalls != 1 || client.pageLimit != 3 {
		t.Errorf("page calls %d limit %d; want 1 call with limit 3", client.pageCalls, client.pageLimit)
	}
	if got := vulncovCVEOrder(t, out.String()); strings.Join(got, " ") != "CVE-A CVE-B CVE-C" {
		t.Errorf("rows: got %v, want the first three", got)
	}
	if strings.Contains(stderr.String(), "clamped") {
		t.Errorf("no clamp warning expected under the server max, got %q", stderr.String())
	}
}

// A --limit above the server-side page max is clamped with a warning, and
// the request asks for the max rather than the raw value.
func TestVulnsListLimitClampedToServerMax(t *testing.T) {
	client := &vulncovClient{fakeClient: &fakeClient{detections: vulncovDetections(2)}}
	var stderr bytes.Buffer
	err := runVulnsList(context.Background(), client, io.Discard, &stderr, vulnsListOpts{Output: "json", Limit: iru.DefaultLimit + 1, NoCache: true})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if client.pageLimit != iru.DefaultLimit {
		t.Errorf("page limit: got %d want %d", client.pageLimit, iru.DefaultLimit)
	}
	want := "warning: limit clamped to 300 (Iru server-side max)\n"
	if stderr.String() != want {
		t.Errorf("stderr: got %q want %q", stderr.String(), want)
	}
}

func TestVulnsListPropagatesClientErrors(t *testing.T) {
	boom := errors.New("upstream boom")
	cases := []struct {
		name   string
		client *vulncovClient
		opts   vulnsListOpts
	}{
		{"single page", &vulncovClient{fakeClient: &fakeClient{}, pageErr: boom}, vulnsListOpts{Limit: 5}},
		{"full walk", &vulncovClient{fakeClient: &fakeClient{}, streamErr: boom}, vulnsListOpts{}},
		{"device walk", &vulncovClient{fakeClient: &fakeClient{}, streamErr: boom}, vulnsListOpts{DeviceID: "d-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.NoCache = true
			tc.opts.Output = "json"
			var out bytes.Buffer
			err := runVulnsList(context.Background(), tc.client, &out, io.Discard, tc.opts)
			if !errors.Is(err, boom) {
				t.Fatalf("got %v, want the client error", err)
			}
			if out.Len() != 0 {
				t.Errorf("nothing should render on error, got %q", out.String())
			}
		})
	}
}

// The device filter keeps only that device's rows, and --limit still caps
// them (the device path walks everything, so the cap is applied after).
func TestVulnsListDeviceIDFilterHonoursLimit(t *testing.T) {
	ds := vulncovDetections(3)
	ds = append(ds, iru.Detection{CVEID: "CVE-other", DeviceID: "d-2"})
	client := &fakeClient{detections: ds}
	var out bytes.Buffer
	err := runVulnsList(context.Background(), client, &out, io.Discard, vulnsListOpts{Output: "csv", DeviceID: "d-1", Limit: 2, NoCache: true})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := vulncovCVEOrder(t, out.String()); strings.Join(got, " ") != "CVE-A CVE-B" {
		t.Errorf("rows: got %v", got)
	}
}

func TestVulnsListTableAndCSVColumns(t *testing.T) {
	client := &fakeClient{detections: []iru.Detection{{
		CVEID: "CVE-2025-0001", Severity: "High", CVSSScore: 7.26,
		Name: "git", Version: "2.37.2", Path: "/usr/bin/git",
		DeviceID: "d-1", DeviceName: "Alice MBP", DeviceSerialNumber: "SN123",
	}}}

	t.Run("csv", func(t *testing.T) {
		var out bytes.Buffer
		if err := runVulnsList(context.Background(), client, &out, io.Discard, vulnsListOpts{Output: "csv", NoCache: true}); err != nil {
			t.Fatalf("run: %v", err)
		}
		want := "CVE,SEVERITY,CVSS,PACKAGE,VERSION,PATH,DEVICE,SERIAL\n" +
			"CVE-2025-0001,High,7.3,git,2.37.2,/usr/bin/git,Alice MBP,SN123\n"
		if out.String() != want {
			t.Errorf("csv:\n got %q\nwant %q", out.String(), want)
		}
	})

	for _, format := range []string{"table", ""} {
		t.Run("table "+format, func(t *testing.T) {
			var out bytes.Buffer
			if err := runVulnsList(context.Background(), client, &out, io.Discard, vulnsListOpts{Output: format, NoCache: true}); err != nil {
				t.Fatalf("run: %v", err)
			}
			got := vulncovTableRows(out.String())
			want := []string{
				"CVE|SEVERITY|CVSS|PACKAGE|VERSION|PATH|DEVICE|SERIAL",
				"CVE-2025-0001|High|7.3|git|2.37.2|/usr/bin/git|Alice MBP|SN123",
			}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("table rows:\n got %q\nwant %q\nraw:\n%s", got, want, out.String())
			}
		})
	}
}

func TestVulnsListUnknownOutputFormat(t *testing.T) {
	client := &fakeClient{detections: vulncovDetections(1)}
	var out bytes.Buffer
	err := runVulnsList(context.Background(), client, &out, io.Discard, vulnsListOpts{Output: "xml", NoCache: true})
	if err == nil || !strings.Contains(err.Error(), "xml") {
		t.Fatalf("expected an unknown-format error naming xml, got %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("nothing should render, got %q", out.String())
	}
}

// A config that cannot be loaded stops both vulns commands before any
// client is built or Keychain read.
func TestVulnsCommandsSurfaceConfigErrors(t *testing.T) {
	for _, sub := range []string{"list", "summary"} {
		t.Run(sub, func(t *testing.T) {
			failIfKeychainRead(t)
			path := writeRawConfig(t, malformedYAML)
			_, _, err := execRootForTest(t, "vulns", sub, "--config", path)
			if err == nil || !strings.Contains(err.Error(), "parse config") {
				t.Fatalf("got %v, want the config parse error", err)
			}
		})
	}
}

// Every --sort key orders the rollup descending on its metric, except cve
// which is ascending. Keys are case-insensitive.
func TestVulnsSummarySortKeys(t *testing.T) {
	vs := []iru.Vulnerability{
		{CVEID: "CVE-B", Severity: "Low", CVSSScore: 9.0, KEVScore: 1.0, DeviceCount: 2},
		{CVEID: "CVE-C", Severity: "Critical", CVSSScore: 5.0, KEVScore: 3.0, DeviceCount: 1},
		{CVEID: "CVE-A", Severity: "High", CVSSScore: 7.0, KEVScore: 2.0, DeviceCount: 3},
	}
	cases := []struct {
		sort string
		want string
	}{
		{"cvss", "CVE-B CVE-A CVE-C"},
		{"CVSS", "CVE-B CVE-A CVE-C"},
		{"kev", "CVE-C CVE-A CVE-B"},
		{"devices", "CVE-A CVE-B CVE-C"},
		{"cve", "CVE-A CVE-B CVE-C"},
		{"severity", "CVE-C CVE-A CVE-B"},
		{"", "CVE-C CVE-A CVE-B"},
	}
	for _, tc := range cases {
		t.Run("sort="+tc.sort, func(t *testing.T) {
			client := &fakeClient{vulnerabilities: append([]iru.Vulnerability(nil), vs...)}
			var out bytes.Buffer
			err := runVulnsSummary(context.Background(), client, &out, io.Discard, vulnsSummaryOpts{Output: "csv", Sort: tc.sort, NoCache: true})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := strings.Join(vulncovCVEOrder(t, out.String()), " "); got != tc.want {
				t.Errorf("order: got %q want %q", got, tc.want)
			}
		})
	}
}

// Rows that tie on the sort metric come out in CVE order, whatever order the
// walk returned them in, so repeated runs render identically.
func TestVulnsSummarySortBreaksTiesByCVE(t *testing.T) {
	vs := []iru.Vulnerability{
		{CVEID: "CVE-D", Severity: "High", CVSSScore: 7.0, KEVScore: 1.0, DeviceCount: 2},
		{CVEID: "CVE-C", Severity: "High", CVSSScore: 7.0, KEVScore: 1.0, DeviceCount: 2},
		{CVEID: "CVE-B", Severity: "High", CVSSScore: 7.0, KEVScore: 1.0, DeviceCount: 2},
		{CVEID: "CVE-A", Severity: "High", CVSSScore: 7.0, KEVScore: 1.0, DeviceCount: 2},
	}
	for _, key := range []string{"severity", "cvss", "kev", "devices", "cve"} {
		t.Run(key, func(t *testing.T) {
			client := &fakeClient{vulnerabilities: append([]iru.Vulnerability(nil), vs...)}
			var out bytes.Buffer
			err := runVulnsSummary(context.Background(), client, &out, io.Discard, vulnsSummaryOpts{Output: "csv", Sort: key, NoCache: true})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if got := strings.Join(vulncovCVEOrder(t, out.String()), " "); got != "CVE-A CVE-B CVE-C CVE-D" {
				t.Errorf("order: got %q, want CVE order on ties", got)
			}
		})
	}
}

// An unknown --sort key is a user error caught before any config, Keychain
// or API work, so a typo can't cost a full walk and then be ignored.
func TestVulnsSummaryRejectsUnknownSort(t *testing.T) {
	isolateCacheDir(t)
	stubNewIruClient(t, &fakeClient{})
	failIfKeychainRead(t)
	_, _, err := execRootForTest(t, "vulns", "summary", "--sort", "sevrity", "--config", validConfigPath(t))
	if err == nil {
		t.Fatal("expected an error for an unknown --sort key")
	}
	want := `invalid --sort "sevrity": want one of severity, cvss, kev, devices, cve`
	if err.Error() != want {
		t.Errorf("error: got %q want %q", err.Error(), want)
	}
	if code := classifyError(err); code != 1 {
		t.Errorf("exit: got %d want 1", code)
	}
}

func TestVulnsSummarySortCompletion(t *testing.T) {
	stdout, _, err := execRootForTest(t, "__complete", "vulns", "summary", "--sort", "")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	for _, key := range []string{"severity", "cvss", "kev", "devices", "cve"} {
		if !strings.Contains(stdout, key+"\n") {
			t.Errorf("completion missing %q in %q", key, stdout)
		}
	}
	if !strings.Contains(stdout, ":4") { // ShellCompDirectiveNoFileComp
		t.Errorf("completion should disable file completion: %q", stdout)
	}
}

func TestVulnsSummaryFiltersBySeverityCaseInsensitive(t *testing.T) {
	client := &fakeClient{vulnerabilities: []iru.Vulnerability{
		{CVEID: "CVE-A", Severity: "Critical", Status: "Active"},
		{CVEID: "CVE-B", Severity: "High", Status: "Active"},
		{CVEID: "CVE-C", Severity: "Critical", Status: "Remediated"},
	}}
	var out bytes.Buffer
	err := runVulnsSummary(context.Background(), client, &out, io.Discard, vulnsSummaryOpts{
		Output: "csv", Severity: "CRITICAL", Status: "Active", NoCache: true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.Join(vulncovCVEOrder(t, out.String()), " "); got != "CVE-A" {
		t.Errorf("rows: got %q, want only the active critical", got)
	}
}

func TestVulnsSummaryTableAndCSVColumns(t *testing.T) {
	client := &fakeClient{vulnerabilities: []iru.Vulnerability{{
		CVEID: "CVE-2025-0002", Severity: "Critical", CVSSScore: 9.84, KEVScore: 0.5,
		DeviceCount: 12, Status: "Active", Software: []string{"openssl", "curl"},
	}}}

	t.Run("csv", func(t *testing.T) {
		var out bytes.Buffer
		if err := runVulnsSummary(context.Background(), client, &out, io.Discard, vulnsSummaryOpts{Output: "csv", NoCache: true}); err != nil {
			t.Fatalf("run: %v", err)
		}
		want := "CVE,SEVERITY,CVSS,KEV,DEVICES,STATUS,SOFTWARE\n" +
			"CVE-2025-0002,Critical,9.8,0.5,12,Active,\"openssl,curl\"\n"
		if out.String() != want {
			t.Errorf("csv:\n got %q\nwant %q", out.String(), want)
		}
	})

	for _, format := range []string{"table", ""} {
		t.Run("table "+format, func(t *testing.T) {
			var out bytes.Buffer
			if err := runVulnsSummary(context.Background(), client, &out, io.Discard, vulnsSummaryOpts{Output: format, NoCache: true}); err != nil {
				t.Fatalf("run: %v", err)
			}
			got := vulncovTableRows(out.String())
			want := []string{
				"CVE|SEVERITY|CVSS|KEV|DEVICES|STATUS|SOFTWARE",
				"CVE-2025-0002|Critical|9.8|0.5|12|Active|openssl,curl",
			}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("table rows:\n got %q\nwant %q\nraw:\n%s", got, want, out.String())
			}
		})
	}
}

func TestVulnsSummaryUnknownOutputFormat(t *testing.T) {
	client := &fakeClient{vulnerabilities: []iru.Vulnerability{{CVEID: "CVE-A"}}}
	err := runVulnsSummary(context.Background(), client, &bytes.Buffer{}, io.Discard, vulnsSummaryOpts{Output: "xml", NoCache: true})
	if err == nil || !strings.Contains(err.Error(), "xml") {
		t.Fatalf("expected an unknown-format error naming xml, got %v", err)
	}
}

func TestVulnsSummaryPropagatesWalkError(t *testing.T) {
	boom := errors.New("upstream boom")
	client := &vulncovClient{fakeClient: &fakeClient{}, vulnErr: boom}
	err := runVulnsSummary(context.Background(), client, &bytes.Buffer{}, io.Discard, vulnsSummaryOpts{Output: "json", NoCache: true})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the walk error", err)
	}
}

// -o email with an unreadable --message-file fails before anything is
// written to stdout.
func TestVulnsSummaryEmailMessageFileError(t *testing.T) {
	client := &fakeClient{vulnerabilities: []iru.Vulnerability{{CVEID: "CVE-A", Severity: "Critical"}}}
	missing := filepath.Join(t.TempDir(), "nope.txt")
	var out bytes.Buffer
	err := runVulnsSummary(context.Background(), client, &out, io.Discard, vulnsSummaryOpts{
		Output:     "email",
		NoCache:    true,
		EmailFlags: emailFlagValues{From: "ops@example.com", MessageFile: missing},
		EmailNow:   time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "read --message-file") {
		t.Fatalf("got %v, want the message-file read error", err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty, got %q", out.String())
	}
}

// vulncovSendOpts is a --send-email setup that would succeed; each case in
// TestVulnsSummarySendEmailErrors breaks one piece of it.
func vulncovSendOpts(sender *fakeGmailSender) vulnsSummaryOpts {
	return vulnsSummaryOpts{
		EmailFlags:  emailFlagValues{Send: true, From: "ops@example.com", To: "secops@example.com"},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		NoCache:     true,
		gitEmail:    fixedGitEmail(""),
		KeychainGet: stubKeychain(`{"type":"service_account"}`),
		NewSender:   newFakeSenderFactory(sender),
	}
}

func TestVulnsSummarySendEmailErrors(t *testing.T) {
	sendErr := errors.New("gmail said no")
	cases := []struct {
		name       string
		mutate     func(o *vulnsSummaryOpts, s *fakeGmailSender)
		wantSent   bool
		check      func(t *testing.T, err error)
		wantSubstr string
	}{
		{
			name:       "no from address",
			mutate:     func(o *vulnsSummaryOpts, _ *fakeGmailSender) { o.EmailFlags.From = "" },
			wantSubstr: "no email from address",
		},
		{
			name: "message file unreadable",
			mutate: func(o *vulnsSummaryOpts, _ *fakeGmailSender) {
				o.EmailFlags.MessageFile = "/no/such/path/jellyfish-msg.txt"
			},
			wantSubstr: "read --message-file",
		},
		{
			name: "render fails on a bad CVE link template",
			mutate: func(o *vulnsSummaryOpts, _ *fakeGmailSender) {
				o.Profile.Email.CVELinkPrimary = "https://example.com/no-token"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, email.ErrRender) {
					t.Errorf("want email.ErrRender, got %v", err)
				}
			},
			wantSubstr: "{cve}",
		},
		{
			name:     "gmail send fails",
			mutate:   func(_ *vulnsSummaryOpts, s *fakeGmailSender) { s.err = sendErr },
			wantSent: true,
			check: func(t *testing.T, err error) {
				if !errors.Is(err, sendErr) {
					t.Errorf("want the send error, got %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeGmailSender{}
			opts := vulncovSendOpts(sender)
			tc.mutate(&opts, sender)
			client := &fakeClient{vulnerabilities: []iru.Vulnerability{{CVEID: "CVE-A", Severity: "Critical"}}}
			var stdout, stderr bytes.Buffer
			err := runVulnsSummary(context.Background(), client, &stdout, &stderr, opts)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q should contain %q", err, tc.wantSubstr)
			}
			if tc.check != nil {
				tc.check(t, err)
			}
			if got := sender.sent != nil; got != tc.wantSent {
				t.Errorf("sender called: got %v want %v", got, tc.wantSent)
			}
			if strings.Contains(stderr.String(), "sent:") {
				t.Errorf("no sent confirmation expected on failure, got %q", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout should stay empty under --send-email, got %q", stdout.String())
			}
		})
	}
}

// A failed cache save is best-effort: the walk's records are still returned
// and the user gets one warning naming the path.
func TestFetchAllCachedWarnsWhenSaveFails(t *testing.T) {
	saveErr := errors.New("disk full")
	var stderr bytes.Buffer
	got, err := fetchAllCached(&stderr, true, time.Minute, "widgets",
		func() (string, error) { return "/cache/widgets.json", nil },
		func(string, time.Duration) ([]int, bool, error) { return nil, false, nil },
		func(string, []int) error { return saveErr },
		func(cb func(page []int) error) error { return cb([]int{1, 2}) },
	)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err %v, want the live records", got, err)
	}
	want := "warning: could not write cache at /cache/widgets.json: disk full\n"
	if !strings.HasSuffix(stderr.String(), want) {
		t.Errorf("stderr: got %q, want suffix %q", stderr.String(), want)
	}
}
