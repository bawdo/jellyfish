package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
)

func TestUserShowByEmailJSON(t *testing.T) {
	client := &fakeClient{
		users: []iru.User{{ID: "u-1", Name: "Keith", Email: "keith@example.com"}},
		devices: []iru.Device{
			{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1", User: iru.User{ID: "u-1"}},
		},
		detections: []iru.Detection{
			{CVEID: "CVE-2025-0001", DeviceID: "d-1"},
			{CVEID: "CVE-unrelated", DeviceID: "d-stranger"},
		},
	}
	buf := &bytes.Buffer{}
	err := runUserShow(context.Background(), client, buf, io.Discard, userShowOpts{
		Identifier: "keith@example.com",
		Output:     "json",
		NoCache:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"keith@example.com", "d-1", "CVE-2025-0001"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "CVE-unrelated") {
		t.Fatalf("CVE-unrelated should have been bucketed out: %s", out)
	}
}

func TestUserShowByIDFallback(t *testing.T) {
	client := &fakeClient{
		users: []iru.User{{ID: "u-9", Name: "Test", Email: "t@x"}},
	}
	buf := &bytes.Buffer{}
	err := runUserShow(context.Background(), client, buf, io.Discard, userShowOpts{Identifier: "u-9", Output: "json", NoCache: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "u-9") {
		t.Fatalf("output %q", buf.String())
	}
}

func TestUserShowUserNotFound(t *testing.T) {
	client := &fakeClient{}
	err := runUserShow(context.Background(), client, &bytes.Buffer{}, io.Discard, userShowOpts{Identifier: "u-x", Output: "json", NoCache: true})
	if !errors.Is(err, iru.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUserShowCSVSortsBySeverity(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-low", Severity: "Low", CVSSScore: 3.0},
			{DeviceID: "d-1", CVEID: "CVE-crit", Severity: "Critical", CVSSScore: 9.5},
			{DeviceID: "d-1", CVEID: "CVE-med", Severity: "Medium", CVSSScore: 5.0},
			{DeviceID: "d-1", CVEID: "CVE-high", Severity: "High", CVSSScore: 8.0},
		},
	}
	buf := &bytes.Buffer{}
	err := runUserShow(context.Background(), client, buf, io.Discard, userShowOpts{
		Identifier: "u-1", Output: "csv", NoCache: true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	critIdx := strings.Index(out, "CVE-crit")
	highIdx := strings.Index(out, "CVE-high")
	medIdx := strings.Index(out, "CVE-med")
	lowIdx := strings.Index(out, "CVE-low")
	if critIdx < 0 || highIdx < 0 || medIdx < 0 || lowIdx < 0 {
		t.Fatalf("missing rows in CSV:\n%s", out)
	}
	if critIdx >= highIdx || highIdx >= medIdx || medIdx >= lowIdx {
		t.Fatalf("expected severity ordering Critical < High < Medium < Low in CSV, got:\n%s", out)
	}
}

func TestUserShowCSVColumnOrder(t *testing.T) {
	client := &fakeClient{
		users: []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{
			{DeviceID: "d-1", DeviceName: "Alice MBP", SerialNumber: "SN1"},
			{DeviceID: "d-2", DeviceName: "Alice iPad", SerialNumber: "SN2"},
		},
		detections: []iru.Detection{
			{
				DeviceID: "d-1", CVEID: "CVE-2024-3094", Severity: "Critical",
				CVSSScore: 10.0, Name: "xz-utils", Version: "5.6.1",
				DetectionDatetime: "2026-05-10T08:00:00Z",
			},
			{
				DeviceID: "d-1", CVEID: "CVE-2024-6387", Severity: "High",
				CVSSScore: 8.1, Name: "openssh-server", Version: "9.6",
				DetectionDatetime: "2026-05-11T09:30:00Z",
			},
		},
	}
	buf := &bytes.Buffer{}
	err := runUserShow(context.Background(), client, buf, io.Discard, userShowOpts{
		Identifier: "u-1", Output: "csv", NoCache: true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The fixture covers a device with detections (exercising the severity
	// sort) and a device with none (the empty-CVE-columns branch). The golden
	// pins the header set and column order documented in the README.
	goldenAssert(t, "user_show.csv", buf.Bytes())
}

func TestUserShowTextSortsDetectionsBySeverity(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-low", Severity: "Low", CVSSScore: 3.0},
			{DeviceID: "d-1", CVEID: "CVE-crit", Severity: "Critical", CVSSScore: 9.5},
			{DeviceID: "d-1", CVEID: "CVE-med", Severity: "Medium", CVSSScore: 5.0},
			{DeviceID: "d-1", CVEID: "CVE-high", Severity: "High", CVSSScore: 8.0},
		},
	}
	buf := &bytes.Buffer{}
	err := runUserShow(context.Background(), client, buf, io.Discard, userShowOpts{
		Identifier: "u-1", Output: "table", NoCache: true,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	critIdx := strings.Index(out, "CVE-crit")
	highIdx := strings.Index(out, "CVE-high")
	medIdx := strings.Index(out, "CVE-med")
	lowIdx := strings.Index(out, "CVE-low")
	if critIdx < 0 || highIdx < 0 || medIdx < 0 || lowIdx < 0 {
		t.Fatalf("missing rows in text table:\n%s", out)
	}
	if critIdx >= highIdx || highIdx >= medIdx || medIdx >= lowIdx {
		t.Fatalf("expected severity ordering Critical < High < Medium < Low in detection table, got:\n%s", out)
	}
}

func TestUserShowEmailWritesEml(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "Alice MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5, Name: "x", Version: "1.0"},
		},
	}
	buf := &bytes.Buffer{}
	opts := userShowOpts{
		Identifier: "u-1",
		Output:     "email",
		NoCache:    true,
		EmailFlags: emailFlagValues{From: "alice@example.com", To: "alice@example.com", Subject: "test"},
		EmailNow:   time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
	}
	if err := runUserShow(context.Background(), client, buf, io.Discard, opts); err != nil {
		t.Fatalf("run: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse: %v\nraw:\n%s", err, buf.String())
	}
	if got := msg.Header.Get("Subject"); got != "test" {
		t.Errorf("Subject: got %q", got)
	}
	if !strings.Contains(buf.String(), "CVE-A") {
		t.Errorf("expected CVE-A in body")
	}
}

func TestUserShowEmailErrorsWithoutFrom(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "Alice MBP", SerialNumber: "SN1"}},
	}
	err := runUserShow(context.Background(), client, &bytes.Buffer{}, io.Discard, userShowOpts{
		Identifier: "u-1",
		Output:     "email",
		NoCache:    true,
		gitEmail:   fixedGitEmail(""),
	})
	if err == nil {
		t.Fatal("expected error when no From address available")
	}
}

func TestUserShowSendEmailDefaultsToUserEmail(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5, Name: "x", Version: "1.0"},
		},
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	sender := &fakeGmailSender{returnID: "msg-xyz"}
	opts := userShowOpts{
		Identifier:  "u-1",
		NoCache:     true,
		EmailFlags:  emailFlagValues{Send: true, From: "ops@example.com"},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		KeychainGet: func() ([]byte, error) { return []byte(`{"type":"service_account"}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return sender, nil },
	}
	if err := runUserShow(context.Background(), client, stdout, stderr, opts); err != nil {
		t.Fatalf("run: %v", err)
	}
	if stdout.Len() > 0 {
		t.Errorf("stdout should be empty when --send-email; got %q", stdout.String())
	}
	want := "sent: to=alice@example.com from=ops@example.com gmail-id=msg-xyz"
	if !strings.Contains(stderr.String(), want) {
		t.Errorf("stderr confirmation:\n got %q\nwant substring %q", stderr.String(), want)
	}
	if sender.sent == nil {
		t.Fatal("sender was not called")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(sender.sent))
	if err != nil {
		t.Fatalf("parse sent eml: %v\nraw:\n%s", err, sender.sent)
	}
	if got := msg.Header.Get("To"); got != "alice@example.com" {
		t.Errorf("To: got %q", got)
	}
}

func TestUserShowSendEmailExplicitToOverridesUser(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5, Name: "x", Version: "1.0"},
		},
	}
	stderr := &bytes.Buffer{}
	sender := &fakeGmailSender{}
	opts := userShowOpts{
		Identifier:  "u-1",
		NoCache:     true,
		EmailFlags:  emailFlagValues{Send: true, From: "ops@example.com", To: "other@example.com"},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		KeychainGet: func() ([]byte, error) { return []byte(`{"type":"service_account"}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return sender, nil },
	}
	if err := runUserShow(context.Background(), client, &bytes.Buffer{}, stderr, opts); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stderr.String(), "to=other@example.com") {
		t.Errorf("expected explicit To to win; stderr=%q", stderr.String())
	}
}

func TestUserShowSendEmailPropagatesSenderError(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1"}},
	}
	sender := &fakeGmailSender{err: gmail.ErrUnauthorized}
	opts := userShowOpts{
		Identifier:  "u-1",
		NoCache:     true,
		EmailFlags:  emailFlagValues{Send: true, From: "ops@example.com"},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		KeychainGet: func() ([]byte, error) { return []byte(`{"type":"service_account"}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return sender, nil },
	}
	err := runUserShow(context.Background(), client, &bytes.Buffer{}, &bytes.Buffer{}, opts)
	if !errors.Is(err, gmail.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized propagated; got %v", err)
	}
}

func TestUserShowFlagsIncludeHeaderBGAndLogo(t *testing.T) {
	c := newUserCmd()
	show := findUserSubcommand(t, c, "show")
	if f := show.Flags().Lookup("email-header-bg"); f == nil {
		t.Fatal("--email-header-bg flag is missing")
	}
	if f := show.Flags().Lookup("email-logo"); f == nil {
		t.Fatal("--email-logo flag is missing")
	}
	if f := show.Flags().Lookup("message"); f == nil {
		t.Fatal("--message flag is missing")
	}
	if f := show.Flags().Lookup("message-file"); f == nil {
		t.Fatal("--message-file flag is missing")
	}
}

func findUserSubcommand(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, sub := range parent.Commands() {
		if sub.Name() == name {
			return sub
		}
	}
	t.Fatalf("subcommand %q not found under %s", name, parent.Name())
	return nil
}

func TestUserShowEmailIncludesMessageFromFile(t *testing.T) {
	dir := t.TempDir()
	msgPath := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(msgPath, []byte("plumbing check body\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "Alice MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5, Name: "x", Version: "1.0"},
		},
	}
	buf := &bytes.Buffer{}
	opts := userShowOpts{
		Identifier: "u-1",
		Output:     "email",
		NoCache:    true,
		EmailFlags: emailFlagValues{
			From:        "alice@example.com",
			To:          "alice@example.com",
			Subject:     "test",
			MessageFile: msgPath,
		},
		EmailNow: time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
	}
	if err := runUserShow(context.Background(), client, buf, io.Discard, opts); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "plumbing check body") {
		t.Fatalf("rendered email does not contain message body; got:\n%s", out)
	}
}

func TestUserShowMessageRejectsNonEmailOutput(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"user", "show", "alice@example.com", "--message", "-o", "csv"})
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetOut(&bytes.Buffer{})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}

func TestUserShowSendEmailSetsReportHeader(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5, Name: "x", Version: "1.0"},
		},
	}
	sender := &fakeGmailSender{returnID: "msg-xyz"}
	opts := userShowOpts{
		Identifier:  "u-1",
		NoCache:     true,
		EmailFlags:  emailFlagValues{Send: true, From: "ops@example.com"},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		KeychainGet: func() ([]byte, error) { return []byte(`{"type":"service_account"}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return sender, nil },
	}
	if err := runUserShow(context.Background(), client, &bytes.Buffer{}, &bytes.Buffer{}, opts); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !bytes.Contains(sender.sent, []byte("X-Jellyfish-Report: user-show\r\n")) {
		t.Fatalf("expected X-Jellyfish-Report: user-show; got:\n%s", sender.sent)
	}
}
