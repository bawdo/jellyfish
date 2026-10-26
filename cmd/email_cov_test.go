package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
)

func TestBuildGmailSenderErrors(t *testing.T) {
	kcErr := errors.New("item not found")
	newSenderCalled := false
	factory := func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) {
		newSenderCalled = true
		return &fakeGmailSender{}, nil
	}
	cases := []struct {
		name      string
		keychain  func() ([]byte, error)
		newSender gmailNewSender
		want      string
	}{
		{"keychain seam unwired", nil, factory, "internal: KeychainGet not wired"},
		{"sender seam unwired", stubKeychain(`{}`), nil, "internal: NewSender not wired"},
		{"keychain read fails", func() ([]byte, error) { return nil, kcErr }, factory, "read Gmail credentials from Keychain: item not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newSenderCalled = false
			s, err := buildGmailSender(context.Background(), tc.keychain, tc.newSender, "ops@example.com")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if s != nil {
				t.Error("no sender expected on error")
			}
			if newSenderCalled {
				t.Error("sender factory must not run when the credentials are unavailable")
			}
		})
	}
	// The Keychain failure stays matchable for callers.
	_, err := buildGmailSender(context.Background(), func() ([]byte, error) { return nil, kcErr }, factory, "x@example.com")
	if !errors.Is(err, kcErr) {
		t.Errorf("keychain error should be wrapped, got %v", err)
	}
}

// A broken stdin is an error, distinct from EOF (which means "no").
func TestConfirmSendReadError(t *testing.T) {
	boom := errors.New("tty gone")
	var stderr bytes.Buffer
	ok, err := confirmSend(&stderr, iotest.ErrReader(boom), "Send? [y/N] ", false, false)
	if ok || !errors.Is(err, boom) {
		t.Fatalf("got ok=%v err=%v, want false and the read error", ok, err)
	}
	if stderr.String() != "Send? [y/N] " {
		t.Errorf("prompt should still be written, got %q", stderr.String())
	}
}

func TestRenderSubjectTemplateErrors(t *testing.T) {
	now := time.Date(2026, 5, 16, 10, 42, 0, 0, time.UTC)
	for _, tmpl := range []string{"Report {{.Date", "Report {{.Nope}}"} {
		t.Run(tmpl, func(t *testing.T) {
			if got, err := renderSubjectTemplate(tmpl, now); err == nil {
				t.Fatalf("expected an error, got %q", got)
			}
			// The config path names the setting so the admin knows what to fix.
			prof := config.Profile{Email: config.EmailConfig{SubjectTemplate: tmpl}}
			_, err := resolveEmailOptions(emailFlagValues{From: "ops@example.com"}, prof, nil, now)
			if err == nil || !strings.Contains(err.Error(), "render email subject_template") {
				t.Fatalf("got %v, want the subject_template error", err)
			}
		})
	}
	// A --email-subject flag wins, so a broken template in config is never
	// rendered.
	prof := config.Profile{Email: config.EmailConfig{SubjectTemplate: "{{.Date"}}
	got, err := resolveEmailOptions(emailFlagValues{From: "ops@example.com", Subject: "flag subject"}, prof, nil, now)
	if err != nil || got.Subject != "flag subject" {
		t.Fatalf("got subject %q err %v, want the flag to bypass the template", got.Subject, err)
	}
}

func TestGitUserEmailFailureModes(t *testing.T) {
	t.Run("git fails", func(t *testing.T) {
		dir := t.TempDir()
		// #nosec G306 - the stub has to be executable
		if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)
		got, err := gitUserEmail()
		if err != nil || got != "" {
			t.Fatalf("got %q err %v; an unset user.email is not an error", got, err)
		}
	})
	t.Run("git missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		got, err := gitUserEmail()
		if err == nil || !strings.Contains(err.Error(), "git not found on PATH") {
			t.Fatalf("got %q err %v, want the PATH error", got, err)
		}
	})
}

func TestAttachMessageErrorLeavesOptionsAlone(t *testing.T) {
	eo := email.Options{To: "ops@example.com", Message: "untouched"}
	err := attachMessage(&eo, emailFlagValues{MessageFile: filepath.Join(t.TempDir(), "missing.txt")}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "read --message-file") {
		t.Fatalf("got %v, want the message-file error", err)
	}
	if eo.Message != "untouched" {
		t.Errorf("Message changed on error: %q", eo.Message)
	}
}
