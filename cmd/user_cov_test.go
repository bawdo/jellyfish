package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/iru"
)

// usercovSendOpts is a user show --send-email setup that would succeed
// against usercovAliceClient; tests break one piece of it.
func usercovSendOpts(sender *fakeGmailSender) userShowOpts {
	return userShowOpts{
		Identifier:  "u-1",
		NoCache:     true,
		EmailFlags:  emailFlagValues{Send: true, From: "ops@example.com"},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		KeychainGet: stubKeychain(`{}`),
		NewSender:   newFakeSenderFactory(sender),
		gitEmail:    fixedGitEmail(""),
	}
}

func TestUserOneLine(t *testing.T) {
	cases := []struct {
		name string
		u    iru.User
		want string
	}{
		{"active with name", iru.User{ID: "u-1", Name: "Alice", Active: true}, "u-1 - Alice (active)"},
		{"falls back to email", iru.User{ID: "u-2", Email: "bob@x", Active: true}, "u-2 - bob@x (active)"},
		{"inactive", iru.User{ID: "u-3", Name: "Carol"}, "u-3 - Carol (inactive)"},
		{"archived beats inactive", iru.User{ID: "u-4", Name: "Dan", Archived: true}, "u-4 - Dan (archived)"},
		{"department suffix", iru.User{ID: "u-5", Name: "Eve", Active: true, Department: "Eng"}, "u-5 - Eve (active, dept: Eng)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := userOneLine(tc.u); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPromptForUserReadErrorPropagates(t *testing.T) {
	matches := []iru.User{{ID: "u-1", Name: "A"}, {ID: "u-2", Name: "B"}}
	var stderr bytes.Buffer
	_, ok, err := promptForUser(&stderr, usercovErrReader{}, "k@x", matches)
	if !errors.Is(err, usercovReadErr{}) {
		t.Fatalf("err: got %v, want usercovReadErr", err)
	}
	if ok {
		t.Error("ok must be false on a read error")
	}
	if !strings.Contains(stderr.String(), "[2] u-2 - B (inactive)") {
		t.Errorf("menu not written before reading; got:\n%s", stderr.String())
	}
}

// An invalid answer with no trailing newline is the last thing on stdin, so
// there is no point re-prompting: it is a clean abort, not an error.
func TestPromptForUserInvalidAtEOFAborts(t *testing.T) {
	matches := []iru.User{{ID: "u-1", Name: "A"}, {ID: "u-2", Name: "B"}}
	var stderr bytes.Buffer
	u, ok, err := promptForUser(&stderr, strings.NewReader("7"), "k@x", matches)
	if err != nil || ok || u.ID != "" {
		t.Fatalf("got (%+v, %v, %v), want clean abort", u, ok, err)
	}
	if strings.Contains(stderr.String(), "invalid selection") {
		t.Errorf("EOF abort must not report an invalid selection; got:\n%s", stderr.String())
	}
}

// With no stdinIsTTY override, the multi-match path must consult the real
// stdin: off a terminal it refuses to prompt, on one it reads the answer.
func TestRunUserShowDefaultTTYCheckUsesStdin(t *testing.T) {
	client := &fakeClient{
		usersByEmail: map[string][]iru.User{
			"k@x": {{ID: "u-1", Email: "k@x"}, {ID: "u-2", Email: "k@x"}},
		},
	}
	var stdout bytes.Buffer
	err := runUserShow(context.Background(), client, &stdout, io.Discard, userShowOpts{
		Identifier:   "k@x",
		Output:       "json",
		NoCache:      true,
		PromptReader: strings.NewReader("1\n"),
	})
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if err != nil || !strings.Contains(stdout.String(), `"u-1"`) {
			t.Fatalf("on a TTY the prompt should pick u-1; err=%v out=%s", err, stdout.String())
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "multiple users match k@x") {
		t.Fatalf("off a TTY expected the multi-match error, got %v", err)
	}
}

func TestRunUserShowIruErrorsPropagate(t *testing.T) {
	cases := []struct {
		name     string
		client   *usercovErrClient
		wantIs   error
		wantCode int
	}{
		{"detection walk", &usercovErrClient{fakeClient: usercovAliceClient(), detectionsErr: iru.ErrRateLimited}, iru.ErrRateLimited, 4},
		{"device list", &usercovErrClient{fakeClient: usercovAliceClient(), devicesErr: iru.ErrForbidden}, iru.ErrForbidden, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := runUserShow(context.Background(), tc.client, &stdout, io.Discard, userShowOpts{Identifier: "u-1", Output: "json", NoCache: true})
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("err: got %v, want %v", err, tc.wantIs)
			}
			if code := classifyError(err); code != tc.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tc.wantCode)
			}
			if stdout.Len() != 0 {
				t.Errorf("nothing should render on error; got %q", stdout.String())
			}
		})
	}
}

func TestRenderUserBundleErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	cases := []struct {
		name    string
		opts    userShowOpts
		wantErr string
	}{
		{
			name:    "unsupported format",
			opts:    userShowOpts{Output: "xml"},
			wantErr: `unsupported output format "xml"`,
		},
		{
			name: "email with unreadable message file",
			opts: userShowOpts{
				Output:     "email",
				EmailFlags: emailFlagValues{From: "ops@example.com", MessageFile: missing},
			},
			wantErr: "read --message-file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w bytes.Buffer
			b := UserBundle{User: iru.User{ID: "u-1", Email: "alice@example.com"}}
			err := renderUserBundle(&w, io.Discard, tc.opts, b)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
			if w.Len() != 0 {
				t.Errorf("nothing should be written on error; got %q", w.String())
			}
		})
	}
}

// Each send-path failure must surface before Gmail is called.
func TestRunUserShowSendEmailErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	cases := []struct {
		name    string
		mutate  func(o *userShowOpts)
		wantErr string
	}{
		{
			name:    "no from address",
			mutate:  func(o *userShowOpts) { o.EmailFlags.From = "" },
			wantErr: "no email from address",
		},
		{
			name:    "gmail not configured",
			mutate:  func(o *userShowOpts) { o.Profile.Email.GmailConfigured = false },
			wantErr: "--send-email requires Gmail credentials",
		},
		{
			name:    "unreadable message file",
			mutate:  func(o *userShowOpts) { o.EmailFlags.MessageFile = missing },
			wantErr: "read --message-file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := &fakeGmailSender{}
			opts := usercovSendOpts(sender)
			tc.mutate(&opts)
			var stderr bytes.Buffer
			err := runUserShow(context.Background(), usercovAliceClient(), &bytes.Buffer{}, &stderr, opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
			if sender.sent != nil {
				t.Error("no mail should have been sent")
			}
			if strings.Contains(stderr.String(), "sent:") {
				t.Errorf("stderr must not claim a send; got:\n%s", stderr.String())
			}
		})
	}
}

// A render failure is reported as ErrRender (exit 1) and Gmail is never
// handed a half-built message.
func TestSendUserBundleRenderErrorSkipsSend(t *testing.T) {
	sender := &fakeGmailSender{}
	b := UserBundle{User: iru.User{ID: "u-1", Email: "alice@example.com"}}
	id, err := sendUserBundle(context.Background(), sender, email.Options{To: "alice@example.com"}, io.Discard, b)
	if !errors.Is(err, email.ErrRender) {
		t.Fatalf("err: got %v, want email.ErrRender", err)
	}
	if code := classifyError(err); code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
	if id != "" || sender.sent != nil {
		t.Errorf("sender must not be called; id=%q sent=%d bytes", id, len(sender.sent))
	}
}
