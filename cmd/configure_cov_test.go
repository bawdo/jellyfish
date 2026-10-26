package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/iru"
)

// cfgcovErr is a comparable error type, so a constant of it works as a
// sentinel with errors.Is.
type cfgcovErr string

func (e cfgcovErr) Error() string { return string(e) }

// cfgcovErrRead is the read failure the error-reader tests inject. Prompts
// must pass it straight through rather than treating it as EOF.
const cfgcovErrRead = cfgcovErr("cfgcov: stdin read failed")

// cfgcovReaderThenFail returns a reader that yields prefix and then fails
// with cfgcovErrRead, so a test can make a specific prompt's read fail.
func cfgcovReaderThenFail(prefix string) io.Reader {
	return io.MultiReader(strings.NewReader(prefix), iotest.ErrReader(cfgcovErrRead))
}

// cfgcovReadOnlyConfig seeds a config file and drops its write bit, so Load
// succeeds but the following Save fails with a permission error.
func cfgcovReadOnlyConfig(t *testing.T, f config.File) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions, so the save cannot be made to fail")
	}
	path := seedConfigFile(t, t.TempDir(), f)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	return path
}

// cfgcovReadFile returns path's bytes, failing the test if it can't be read.
func cfgcovReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 - test temp path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// cfgcovExecRoot runs the real root command with stdin wired up, so the
// configure subcommands' RunE closures are exercised end to end.
func cfgcovExecRoot(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// cfgcovPipeStdin replaces os.Stdin with a pipe holding content, so
// readMaskedToken always sees a non-terminal stdin (and never blocks on a
// masked read) whatever the test runner's own stdin is.
func cfgcovPipeStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatalf("write pipe: %v", err)
	}
	_ = w.Close()
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})
}

func TestConfigureVerifyIruTokenAgainstServer(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"accepted", http.StatusOK, nil},
		{"unauthorised", http.StatusUnauthorized, iru.ErrUnauthorized},
		{"forbidden", http.StatusForbidden, iru.ErrForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotQuery, gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotQuery, gotAuth = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("[]"))
			}))
			defer srv.Close()

			err := verifyIruToken(context.Background(), srv.URL+"/api/v1", "tkn-verify")
			if tc.want == nil && err != nil {
				t.Fatalf("verifyIruToken: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// One cheap page of devices, authenticated with the token under test.
			if gotPath != "/api/v1/devices" || gotQuery != "limit=1&offset=0" {
				t.Errorf("request %s?%s, want /api/v1/devices?limit=1&offset=0", gotPath, gotQuery)
			}
			if gotAuth != "Bearer tkn-verify" {
				t.Errorf("Authorization %q", gotAuth)
			}
		})
	}
}

func TestConfigureVerifyIruTokenHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled context fails before any dial, so no port or network is needed.
	err := verifyIruToken(ctx, "https://acme.api.kandji.io/api/v1", "tkn")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// Every early failure in runConfigure must return before the token is read,
// verified or stored, and must not write a config file.
func TestConfigureEarlyFailuresTouchNothing(t *testing.T) {
	cases := []struct {
		name      string
		stdin     io.Reader
		tokenErr  error
		wantIs    error
		wantInErr string
	}{
		{name: "subdomain read fails", stdin: cfgcovReaderThenFail(""), wantIs: cfgcovErrRead},
		{name: "region read fails", stdin: cfgcovReaderThenFail("acme\n"), wantIs: cfgcovErrRead},
		{name: "invalid subdomain", stdin: strings.NewReader("Acme_Co\nus\n"), wantInErr: "subdomain must match"},
		{name: "invalid region", stdin: strings.NewReader("acme\nmars\n"), wantInErr: `unsupported region "mars"`},
		{name: "token read fails", stdin: strings.NewReader("acme\nus\n"), tokenErr: cfgcovErrRead, wantIs: cfgcovErrRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "config.yml")
			var tokenRead, verified, stored bool
			err := runConfigure(context.Background(), configureOpts{
				ConfigPath: cfgPath,
				Stdin:      tc.stdin,
				Stdout:     &bytes.Buffer{},
				Stderr:     &bytes.Buffer{},
				StoreToken: func(_, _ string) error { stored = true; return nil },
				ReadTokenLine: func(_ *bufio.Reader) (string, error) {
					tokenRead = true
					return "tkn", tc.tokenErr
				},
				Verify: func(context.Context, string, string) error { verified = true; return nil },
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("err = %v, want wrapping %v", err, tc.wantIs)
			}
			if tc.wantInErr != "" && !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("err = %q, want it to contain %q", err, tc.wantInErr)
			}
			if tc.tokenErr == nil && tokenRead {
				t.Error("token was read despite an earlier failure")
			}
			if verified || stored {
				t.Errorf("verified=%v stored=%v, want neither", verified, stored)
			}
			if _, statErr := os.Stat(cfgPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("config was written (stat err %v)", statErr)
			}
		})
	}
}

func TestConfigureMalformedConfigIsReported(t *testing.T) {
	cfgPath := writeRawConfig(t, malformedYAML)
	before := cfgcovReadFile(t, cfgPath)
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath: cfgPath,
		Stdin:      strings.NewReader("acme\nus\n"),
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
		StoreToken: func(_, _ string) error { t.Fatal("store must not run"); return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) {
			t.Fatal("token must not be read")
			return "", nil
		},
	})
	// A broken file must surface, not be treated as a first run and overwritten.
	if err == nil || !strings.Contains(err.Error(), "read config") || !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("err = %v, want a read/parse config error", err)
	}
	if !bytes.Equal(cfgcovReadFile(t, cfgPath), before) {
		t.Error("malformed config was modified")
	}
}

func TestConfigureKeepTokenSaveFailureIsReturned(t *testing.T) {
	cfgPath := cfgcovReadOnlyConfig(t, config.File{"default": config.Profile{Subdomain: "acme", Region: "us"}})
	out := &bytes.Buffer{}
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("\n\n"),
		Stdout:        out,
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, _ string) error { t.Fatal("store must not run"); return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
		Verify:        func(context.Context, string, string) error { t.Fatal("verify must not run"); return nil },
	})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("err = %v, want a permission error from saving", err)
	}
	if strings.Contains(out.String(), "Configured.") {
		t.Errorf("success message printed despite the failed save: %q", out.String())
	}
}

func TestConfigureNewTokenSaveFailureReportsStoredToken(t *testing.T) {
	cfgPath := cfgcovReadOnlyConfig(t, config.File{"default": config.Profile{Subdomain: "acme", Region: "us"}})
	var stored string
	out := &bytes.Buffer{}
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("\n\n"),
		Stdout:        out,
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, tok string) error { stored = tok; return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "tkn-new", nil },
		Verify:        func(context.Context, string, string) error { return nil },
	})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("err = %v, want a permission error from saving", err)
	}
	// The admin must be told the Keychain already holds the new token.
	if !strings.Contains(err.Error(), "token verified and stored in Keychain, but saving config failed") {
		t.Errorf("error wording: %q", err)
	}
	if stored != "tkn-new" {
		t.Errorf("stored token %q, want tkn-new", stored)
	}
	if strings.Contains(out.String(), "Configured.") {
		t.Errorf("success message printed despite the failed save: %q", out.String())
	}
}

func TestConfigureReadMaskedTokenNonTerminal(t *testing.T) {
	t.Run("nil reader falls back to os.Stdin", func(t *testing.T) {
		cfgcovPipeStdin(t, "  tkn-from-stdin  \n")
		got, err := readMaskedToken(nil)
		if err != nil || got != "tkn-from-stdin" {
			t.Fatalf("got %q, %v; want tkn-from-stdin, nil", got, err)
		}
	})
	t.Run("supplied reader is read unmasked and EOF is fine", func(t *testing.T) {
		cfgcovPipeStdin(t, "")
		got, err := readMaskedToken(bufio.NewReader(strings.NewReader(" tkn-piped")))
		if err != nil || got != "tkn-piped" {
			t.Fatalf("got %q, %v; want tkn-piped, nil", got, err)
		}
	})
	t.Run("read error is returned", func(t *testing.T) {
		cfgcovPipeStdin(t, "")
		got, err := readMaskedToken(bufio.NewReader(iotest.ErrReader(cfgcovErrRead)))
		if !errors.Is(err, cfgcovErrRead) || got != "" {
			t.Fatalf("got %q, %v; want empty, %v", got, err, cfgcovErrRead)
		}
	})
}

func TestConfigureCmdWiresConfigFlagAndStdio(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	// An invalid subdomain fails before the token prompt, so the real
	// Keychain and masked reader wired into RunE are never reached.
	stdout, _, err := cfgcovExecRoot(t, "Bad_Sub\nus\n", "configure", "--config", cfgPath)
	if err == nil || !strings.Contains(err.Error(), "subdomain must match") {
		t.Fatalf("err = %v, want subdomain validation error", err)
	}
	if !strings.Contains(stdout, "Tenant subdomain") || !strings.Contains(stdout, "Region (us or eu)") {
		t.Errorf("prompts not written to the command's stdout: %q", stdout)
	}
	if _, statErr := os.Stat(cfgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("config was written (stat err %v)", statErr)
	}
}

func TestConfigureEmailCmdWiresConfigFlagAndStdio(t *testing.T) {
	t.Run("missing config names the --config path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.yml")
		_, _, err := cfgcovExecRoot(t, "", "configure", "email", "--config", missing)
		if err == nil || !strings.Contains(err.Error(), "no config found at "+missing) {
			t.Fatalf("err = %v, want missing-config error naming %s", err, missing)
		}
	})
	t.Run("saves to the --config path", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := seedConfigFile(t, dir, config.File{"default": config.Profile{Subdomain: "acme", Region: "us"}})
		// From set; everything else kept. Gmail is not configured and no
		// JSON path is given, so the Keychain is never touched.
		stdout, _, err := cfgcovExecRoot(t, "ops@example.com\n\n\n\n\n\n", "configure", "email", "--config", cfgPath)
		if err != nil {
			t.Fatalf("configure email: %v", err)
		}
		if !strings.Contains(stdout, "Email config saved to "+cfgPath) {
			t.Errorf("stdout %q", stdout)
		}
		loaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if got := loaded["default"].Email.From; got != "ops@example.com" {
			t.Errorf("Email.From %q", got)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "logos")); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("logos dir created without a logo being chosen (stat err %v)", statErr)
		}
	})
}

// Without the persistent --config flag (a subcommand run outside root),
// resolving the path must fail rather than silently fall back to the default.
func TestConfigureSubcommandsWithoutConfigFlagError(t *testing.T) {
	cases := map[string]func() *cobra.Command{
		"configure":       func() *cobra.Command { return newConfigureCmd() },
		"configure email": func() *cobra.Command { return newConfigureEmailCmd() },
		"configure cache": func() *cobra.Command { return newConfigureCacheCmd() },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			c := mk()
			c.SetArgs([]string{})
			c.SetIn(strings.NewReader("acme\nus\n"))
			c.SetOut(&bytes.Buffer{})
			c.SetErr(&bytes.Buffer{})
			err := c.Execute()
			if err == nil || !strings.Contains(err.Error(), "config") {
				t.Fatalf("err = %v, want a missing config flag error", err)
			}
		})
	}
}

func TestConfigureEmailMalformedConfigIsReported(t *testing.T) {
	cfgPath := writeRawConfig(t, malformedYAML)
	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "read config") || strings.Contains(err.Error(), "no config found") {
		t.Fatalf("err = %v, want a read config error (not missing-config)", err)
	}
}

// A read failure at any prompt aborts the run with that error and leaves the
// config file exactly as it was.
func TestConfigureEmailPromptReadFailuresLeaveConfig(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{"From", ""},
		{"DefaultTo", "\n"},
		{"Gmail JSON", "\n\n"},
		{"header colour", "\n\n\n"},
		{"logo", "\n\n\n\n"},
		{"List-Id domain", "\n\n\n\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := seedConfigFile(t, t.TempDir(), config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
				Email: config.EmailConfig{From: "a@example.com"},
			}})
			before := cfgcovReadFile(t, cfgPath)
			err := runConfigureEmail(context.Background(), configureEmailOpts{
				ConfigPath: cfgPath, Stdin: cfgcovReaderThenFail(tc.prefix),
				Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
			})
			if !errors.Is(err, cfgcovErrRead) {
				t.Fatalf("err = %v, want %v", err, cfgcovErrRead)
			}
			if !bytes.Equal(cfgcovReadFile(t, cfgPath), before) {
				t.Error("config changed despite the aborted run")
			}
		})
	}
}

func TestConfigureEmailGmailKeychainFailuresLeaveConfig(t *testing.T) {
	kcErr := errors.New("cfgcov: keychain locked")
	cases := []struct {
		name           string
		gmailBefore    bool
		gmailLine      func(dir string) string
		stubs          *gmailKeychainStubs
		wantInErr      string
		wantGmailAfter bool
	}{
		{
			name:        "delete fails on clear",
			gmailBefore: true,
			gmailLine:   func(string) string { return "-" },
			stubs:       &gmailKeychainStubs{delErr: kcErr},
			wantInErr:   "delete Gmail credentials from Keychain",
			// Still configured: the Keychain entry was not removed.
			wantGmailAfter: true,
		},
		{
			name:        "store fails on new JSON",
			gmailBefore: false,
			gmailLine:   func(dir string) string { return writeGmailJSON(t, dir) },
			stubs:       &gmailKeychainStubs{storeErr: kcErr},
			wantInErr:   "store Gmail JSON in Keychain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := seedConfigFile(t, dir, config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
				Email: config.EmailConfig{From: "a@example.com", GmailConfigured: tc.gmailBefore},
			}})
			in := strings.NewReader("\n\n" + tc.gmailLine(dir) + "\n\n\n\n")
			err := runConfigureEmail(context.Background(), configureEmailOpts{
				ConfigPath: cfgPath, Stdin: in, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
				StoreGmailJSON: tc.stubs.store, DeleteGmailJSON: tc.stubs.delete,
			})
			if !errors.Is(err, kcErr) || !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("err = %v, want %q wrapping %v", err, tc.wantInErr, kcErr)
			}
			loaded, err := config.Load(cfgPath)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if got := loaded["default"].Email.GmailConfigured; got != tc.wantGmailAfter {
				t.Errorf("GmailConfigured = %v, want %v", got, tc.wantGmailAfter)
			}
		})
	}
}

func TestConfigureEmailHeaderBGDashClearsSavedColour(t *testing.T) {
	cfgPath := seedConfigFile(t, t.TempDir(), config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com", HeaderBG: "#112233"},
	}})
	in := strings.NewReader("\n\n\n-\n\n\n")
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"].Email.HeaderBG; got != "" {
		t.Errorf("HeaderBG = %q, want cleared", got)
	}
}

// Three bad answers to a validated prompt give up with an error, report each
// rejection on stderr and leave the config untouched.
func TestConfigureEmailGivesUpAfterMaxAttempts(t *testing.T) {
	dir := t.TempDir()
	notPNG := filepath.Join(dir, "not-a-logo.png")
	if err := os.WriteFile(notPNG, []byte("plain text"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	missing := filepath.Join(dir, "missing.png")
	cases := []struct {
		name      string
		stdin     string
		wantInErr string
	}{
		{"header colour", "\n\n\nred\n#12\nzzzzzz\n", "invalid header background colour after 3 attempts"},
		{"logo", "\n\n\n\n" + missing + "\n" + notPNG + "\n" + missing + "\n", "invalid logo after 3 attempts"},
		{"List-Id domain", "\n\n\n\n\na b\nx@y\nbad domain\n", "invalid List-Id domain after 3 attempts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := seedConfigFile(t, t.TempDir(), config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
				Email: config.EmailConfig{From: "a@example.com"},
			}})
			before := cfgcovReadFile(t, cfgPath)
			var errBuf bytes.Buffer
			err := runConfigureEmail(context.Background(), configureEmailOpts{
				ConfigPath: cfgPath, LogosDir: filepath.Join(t.TempDir(), "logos"),
				Stdin: strings.NewReader(tc.stdin), Stdout: &bytes.Buffer{}, Stderr: &errBuf,
			})
			if err == nil || err.Error() != tc.wantInErr {
				t.Fatalf("err = %v, want %q", err, tc.wantInErr)
			}
			if n := strings.Count(strings.TrimSpace(errBuf.String()), "\n") + 1; n != configureEmailMaxAttempts {
				t.Errorf("stderr has %d lines, want one per attempt:\n%s", n, errBuf.String())
			}
			if !bytes.Equal(cfgcovReadFile(t, cfgPath), before) {
				t.Error("config changed despite giving up")
			}
		})
	}
}

func TestConfigureEmailLogoRetryAfterBadPath(t *testing.T) {
	dir := t.TempDir()
	srcBytes, err := os.ReadFile("../internal/email/testdata/logo_small.png")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	good := filepath.Join(dir, "good.png")
	if err := os.WriteFile(good, srcBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	logosDir := filepath.Join(dir, "logos")
	var errBuf bytes.Buffer
	got, err := promptLogo(&bytes.Buffer{}, &errBuf,
		bufio.NewReader(strings.NewReader(filepath.Join(dir, "missing.png")+"\n"+good+"\n")), "", logosDir)
	if err != nil {
		t.Fatalf("promptLogo: %v", err)
	}
	if want := filepath.Join(logosDir, "good.png"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !strings.Contains(errBuf.String(), "missing.png") {
		t.Errorf("first failure not reported on stderr: %q", errBuf.String())
	}
}

func TestConfigureCopyLogoToManagedDirFailures(t *testing.T) {
	srcBytes, err := os.ReadFile("../internal/email/testdata/logo_small.png")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	cases := []struct {
		name      string
		setup     func(t *testing.T, dir string) (src, logosDir string)
		wantInErr string
	}{
		{
			name: "logos dir blocked by a file",
			setup: func(t *testing.T, dir string) (string, string) {
				blocker := filepath.Join(dir, "blocker")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(dir, "logo.png"), filepath.Join(blocker, "logos")
			},
			wantInErr: "create logos dir",
		},
		{
			name: "destination is a directory",
			setup: func(t *testing.T, dir string) (string, string) {
				logosDir := filepath.Join(dir, "logos")
				if err := os.MkdirAll(filepath.Join(logosDir, "logo.png"), 0o700); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(dir, "logo.png"), logosDir
			},
			wantInErr: "write ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src, logosDir := tc.setup(t, dir)
			if err := os.WriteFile(src, srcBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := copyLogoToManagedDir(src, logosDir)
			if err == nil || !strings.Contains(err.Error(), tc.wantInErr) || got != "" {
				t.Fatalf("got %q, %v; want empty and an error containing %q", got, err, tc.wantInErr)
			}
		})
	}
}

func TestConfigureEmailLogoRemoveFailureWarnsAndSaves(t *testing.T) {
	dir := t.TempDir()
	logosDir := filepath.Join(dir, "logos")
	// A non-empty directory at the old logo path makes os.Remove fail with
	// something other than "not exist".
	old := filepath.Join(logosDir, "old.png")
	if err := os.MkdirAll(filepath.Join(old, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := seedConfigFile(t, dir, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com", LogoPath: old},
	}})
	var errBuf bytes.Buffer
	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, LogosDir: logosDir,
		Stdin: strings.NewReader("\n\n\n\n-\n\n"), Stdout: &bytes.Buffer{}, Stderr: &errBuf,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}
	if !strings.Contains(errBuf.String(), "warn: failed to remove previous logo "+old) {
		t.Errorf("stderr %q, want a removal warning", errBuf.String())
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"].Email.LogoPath; got != "" {
		t.Errorf("LogoPath = %q, want cleared", got)
	}
}

func TestConfigureEmailSaveFailureIsReturned(t *testing.T) {
	cfgPath := cfgcovReadOnlyConfig(t, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com"},
	}})
	out := &bytes.Buffer{}
	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: strings.NewReader("\n\n\n\n\n\n"), Stdout: out, Stderr: &bytes.Buffer{},
	})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("err = %v, want a permission error from saving", err)
	}
	if strings.Contains(out.String(), "Email config saved") {
		t.Errorf("success message printed despite the failed save: %q", out.String())
	}
}

func TestConfigureValidateListIDDomainCases(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"", ""},
		{"jellyfish.example.com", ""},
		{"a b", "whitespace"},
		{"a\tb", "whitespace"},
		{"ops@example.com", "'@'"},
	}
	for _, tc := range cases {
		err := validateListIDDomain(tc.in)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("validateListIDDomain(%q) = %v, want nil", tc.in, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("validateListIDDomain(%q) = %v, want error containing %q", tc.in, err, tc.wantErr)
		}
	}
}

func TestConfigureRemoveManagedLogoCases(t *testing.T) {
	dir := t.TempDir()
	logosDir := filepath.Join(dir, "logos")
	if err := os.MkdirAll(filepath.Join(logosDir, "busy.png", "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.png")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		path, dir   string
		wantRemoved bool
		wantErr     bool
	}{
		{"empty path", "", logosDir, false, false},
		{"empty logos dir", outside, "", false, false},
		{"outside managed dir", outside, logosDir, false, false},
		{"the managed dir itself", logosDir, logosDir, false, false},
		{"inside but already gone", filepath.Join(logosDir, "gone.png"), logosDir, true, false},
		{"inside but cannot be removed", filepath.Join(logosDir, "busy.png"), logosDir, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			removed, err := removeManagedLogo(tc.path, tc.dir)
			if removed != tc.wantRemoved || (err != nil) != tc.wantErr {
				t.Fatalf("got removed=%v err=%v, want removed=%v err=%v", removed, err, tc.wantRemoved, tc.wantErr)
			}
		})
	}
	// Files outside the managed dir are never deleted.
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("outside file touched: %v", err)
	}
}
