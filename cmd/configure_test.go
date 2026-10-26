package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/keychain"
)

func TestConfigureWritesConfigAndCallsKeychain(t *testing.T) {
	var verifiedURL, verifiedToken string
	verify := func(_ context.Context, baseURL, token string) error {
		verifiedURL, verifiedToken = baseURL, token
		return nil
	}

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yml")

	var keychainCalls []string
	store := func(_, token string) error {
		keychainCalls = append(keychainCalls, token)
		return nil
	}

	in := strings.NewReader("acme\nus\n")
	out := &bytes.Buffer{}

	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         in,
		Stdout:        out,
		Stderr:        out,
		StoreToken:    store,
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "tkn-123", nil },
		Verify:        verify,
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	if verifiedToken != "tkn-123" {
		t.Errorf("verify token %q", verifiedToken)
	}
	if verifiedURL != "https://acme.api.kandji.io/api/v1" {
		t.Errorf("verify URL %q", verifiedURL)
	}

	if len(keychainCalls) != 1 || keychainCalls[0] != "tkn-123" {
		t.Fatalf("keychain calls: %v", keychainCalls)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	got := loaded["default"]
	if got.Subdomain != "acme" || got.Region != "us" {
		t.Fatalf("saved profile %+v", got)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
}

func TestConfigureRerunKeepsSubdomainAndRegionOnEnter(t *testing.T) {
	var hits int
	verify := func(context.Context, string, string) error { hits++; return nil }

	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	var stored []string
	store := func(_, token string) error {
		stored = append(stored, token)
		return nil
	}

	in := strings.NewReader("\n\n") // Enter for subdomain, Enter for region
	out := &bytes.Buffer{}

	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         in,
		Stdout:        out,
		Stderr:        out,
		StoreToken:    store,
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "newtkn", nil },
		Verify:        verify,
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}

	loaded, _ := config.Load(cfgPath)
	got := loaded["default"]
	if got.Subdomain != "acme" || got.Region != "us" {
		t.Fatalf("subdomain/region should be preserved; got %+v", got)
	}
	if len(stored) != 1 || stored[0] != "newtkn" {
		t.Errorf("StoreToken calls: %v", stored)
	}
	if hits != 1 {
		t.Errorf("expected 1 verify hit; got %d", hits)
	}
}

func TestConfigureRerunEnterKeepsTokenSkipsKeychainAndVerify(t *testing.T) {
	var hits int
	verify := func(context.Context, string, string) error { hits++; return nil }

	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	var storeCalled bool
	store := func(_, _ string) error {
		storeCalled = true
		return nil
	}

	in := strings.NewReader("\n\n")
	out := &bytes.Buffer{}

	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         in,
		Stdout:        out,
		Stderr:        out,
		StoreToken:    store,
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
		ReadToken:     func(string) (string, error) { t.Error("ReadToken called for unchanged tenant"); return "", nil },
		Verify:        verify,
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	if storeCalled {
		t.Error("StoreToken should not be called when user keeps existing token")
	}
	if hits != 0 {
		t.Errorf("verification should be skipped when token kept; got %d hits", hits)
	}
}

func TestConfigureRerunPreservesEmailAndCacheTTL(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		CacheTTLMinutes: 30,
		Email: config.EmailConfig{
			From:            "alice@example.com",
			DefaultTo:       "secops@example.com",
			HeaderBG:        "#C6B8FE",
			GmailConfigured: true,
			SubjectTemplate: "Custom - {{.Date}}",
		},
	}})

	in := strings.NewReader("\n\n")
	out := &bytes.Buffer{}

	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         in,
		Stdout:        out,
		Stderr:        out,
		StoreToken:    func(_, _ string) error { return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "newtkn", nil },
		Verify:        func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	got := func() config.Profile {
		f, _ := config.Load(cfgPath)
		return f["default"]
	}()
	if got.CacheTTLMinutes != 30 {
		t.Errorf("CacheTTLMinutes lost; got %d", got.CacheTTLMinutes)
	}
	if got.Email.From != "alice@example.com" {
		t.Errorf("Email.From lost; got %q", got.Email.From)
	}
	if got.Email.DefaultTo != "secops@example.com" {
		t.Errorf("Email.DefaultTo lost; got %q", got.Email.DefaultTo)
	}
	if got.Email.HeaderBG != "#C6B8FE" {
		t.Errorf("Email.HeaderBG lost; got %q", got.Email.HeaderBG)
	}
	if !got.Email.GmailConfigured {
		t.Error("Email.GmailConfigured lost")
	}
	if got.Email.SubjectTemplate != "Custom - {{.Date}}" {
		t.Errorf("Email.SubjectTemplate lost; got %q", got.Email.SubjectTemplate)
	}
}

func TestConfigureRerunChangedSubdomainUpdatesProfile(t *testing.T) {
	var verifiedURL, verifiedToken string
	verify := func(_ context.Context, baseURL, token string) error {
		verifiedURL, verifiedToken = baseURL, token
		return nil
	}

	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	in := strings.NewReader("newco\n\n") // change subdomain, keep region
	out := &bytes.Buffer{}

	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         in,
		Stdout:        out,
		Stderr:        out,
		StoreToken:    func(_, _ string) error { return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "tkn", nil },
		ReadToken:     func(string) (string, error) { t.Error("ReadToken called when a new token was entered"); return "", nil },
		Verify:        verify,
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	loaded, _ := config.Load(cfgPath)
	got := loaded["default"]
	if got.Subdomain != "newco" {
		t.Errorf("subdomain: got %q", got.Subdomain)
	}
	// A new token was entered, so it (not the stored one) is checked against
	// the new tenant. The keep-token variant is covered by
	// TestConfigureKeepTokenTenantChangeVerifiesExistingToken.
	if verifiedToken != "tkn" || verifiedURL != "https://newco.api.kandji.io/api/v1" {
		t.Errorf("verify got (%q, %q); want new token against new tenant", verifiedURL, verifiedToken)
	}
}

func TestConfigureRerunPromptShowsExistingDefaults(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	in := strings.NewReader("\n\n")
	out := &bytes.Buffer{}

	_ = runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         in,
		Stdout:        out,
		Stderr:        out,
		StoreToken:    func(_, _ string) error { return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
	})

	text := out.String()
	if !strings.Contains(text, "[acme]") {
		t.Errorf("subdomain prompt should show existing default [acme]; got %q", text)
	}
	if !strings.Contains(text, "[us]") {
		t.Errorf("region prompt should show existing default [us]; got %q", text)
	}
	if !strings.Contains(text, "keep existing") {
		t.Errorf("token prompt should mention keeping existing token; got %q", text)
	}
}

func TestConfigureFirstRunStillRejectsEmptyToken(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yml")

	in := strings.NewReader("acme\nus\n")
	out := &bytes.Buffer{}

	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         in,
		Stdout:        out,
		Stderr:        out,
		StoreToken:    func(_, _ string) error { return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
	})
	if err == nil {
		t.Fatal("expected error for empty token on first run")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token; got %v", err)
	}
}

func TestPromptWithDefaultKeepsCurrentOnEnter(t *testing.T) {
	out := &bytes.Buffer{}
	r := bufio.NewReader(strings.NewReader("\n"))
	got, err := promptWithDefault(out, r, "Email From", "old@x")
	if err != nil {
		t.Fatalf("promptWithDefault: %v", err)
	}
	if got != "old@x" {
		t.Errorf("value: got %q want %q", got, "old@x")
	}
	if !strings.Contains(out.String(), "Email From [old@x]: ") {
		t.Errorf("prompt text: got %q", out.String())
	}
}

func TestPromptWithDefaultReplacesOnTypedValue(t *testing.T) {
	out := &bytes.Buffer{}
	r := bufio.NewReader(strings.NewReader("new@y\n"))
	got, err := promptWithDefault(out, r, "Email From", "old@x")
	if err != nil {
		t.Fatalf("promptWithDefault: %v", err)
	}
	if got != "new@y" {
		t.Errorf("value: got %q want %q", got, "new@y")
	}
}

func TestPromptWithDefaultDashClears(t *testing.T) {
	out := &bytes.Buffer{}
	r := bufio.NewReader(strings.NewReader("-\n"))
	got, err := promptWithDefault(out, r, "Email From", "old@x")
	if err != nil {
		t.Fatalf("promptWithDefault: %v", err)
	}
	if got != "" {
		t.Errorf("value: got %q want empty", got)
	}
}

func TestPromptWithDefaultOmitsBracketsWhenNoCurrent(t *testing.T) {
	out := &bytes.Buffer{}
	r := bufio.NewReader(strings.NewReader("new@y\n"))
	got, err := promptWithDefault(out, r, "Email From", "")
	if err != nil {
		t.Fatalf("promptWithDefault: %v", err)
	}
	if got != "new@y" {
		t.Errorf("value: got %q", got)
	}
	if strings.Contains(out.String(), "[") {
		t.Errorf("prompt should not show brackets when current is empty; got %q", out.String())
	}
	if !strings.Contains(out.String(), "Email From: ") {
		t.Errorf("prompt text: got %q", out.String())
	}
}

func TestPromptWithDefaultTrimsWhitespace(t *testing.T) {
	out := &bytes.Buffer{}
	r := bufio.NewReader(strings.NewReader("  alice@x  \n"))
	got, err := promptWithDefault(out, r, "Email From", "")
	if err != nil {
		t.Fatalf("promptWithDefault: %v", err)
	}
	if got != "alice@x" {
		t.Errorf("value: got %q", got)
	}
}

func TestValidateEmailishAcceptsWithAt(t *testing.T) {
	if err := validateEmailish("alice@example.com", false, "From"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateEmailishAcceptsEmptyWhenAllowed(t *testing.T) {
	if err := validateEmailish("", true, "DefaultTo"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateEmailishRejectsEmptyWhenNotAllowed(t *testing.T) {
	err := validateEmailish("", false, "From")
	if err == nil {
		t.Fatal("expected error for empty value")
	}
	if !strings.Contains(err.Error(), "From") {
		t.Errorf("error should mention field label; got %v", err)
	}
}

func TestValidateEmailishRejectsMissingAt(t *testing.T) {
	err := validateEmailish("no-at-sign", false, "From")
	if err == nil {
		t.Fatal("expected error for value without @")
	}
	if !strings.Contains(err.Error(), "@") {
		t.Errorf("error should mention @; got %v", err)
	}
}

func TestValidateEmailishAllowEmptyStillRejectsMalformed(t *testing.T) {
	err := validateEmailish("no-at-sign", true, "DefaultTo")
	if err == nil {
		t.Fatal("expected error for non-empty value missing @")
	}
}

func seedConfigFile(t *testing.T, dir string, f config.File) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	if err := config.Save(path, f); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return path
}

func TestConfigureEmailPromptsAndSaves(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	in := strings.NewReader("alice@example.com\nsecops@example.com\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	got := loaded["default"]
	if got.Email.From != "alice@example.com" {
		t.Errorf("Email.From: got %q", got.Email.From)
	}
	if got.Email.DefaultTo != "secops@example.com" {
		t.Errorf("Email.DefaultTo: got %q", got.Email.DefaultTo)
	}
	if got.Subdomain != "acme" || got.Region != "us" {
		t.Errorf("non-email fields lost: %+v", got)
	}
	if !strings.Contains(out.String(), "Email config saved to") {
		t.Errorf("expected confirmation in stdout; got %q", out.String())
	}
}

func TestConfigureEmailPreservesOtherEmailFields(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{
			SubjectTemplate: "Custom - {{.Date}}",
			CVELinkPrimary:  "https://mirror.example/{cve}",
		},
	}})

	in := strings.NewReader("alice@example.com\nsecops@example.com\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}

	loaded, _ := config.Load(cfgPath)
	got := loaded["default"].Email
	if got.From != "alice@example.com" || got.DefaultTo != "secops@example.com" {
		t.Errorf("updated fields wrong: %+v", got)
	}
	if got.SubjectTemplate != "Custom - {{.Date}}" {
		t.Errorf("SubjectTemplate lost: %q", got.SubjectTemplate)
	}
	if got.CVELinkPrimary != "https://mirror.example/{cve}" {
		t.Errorf("CVELinkPrimary lost: %q", got.CVELinkPrimary)
	}
}

func TestConfigureEmailEnterKeepsExisting(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "old@x", DefaultTo: "def@x"},
	}})

	in := strings.NewReader("\n\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}

	loaded, _ := config.Load(cfgPath)
	got := loaded["default"].Email
	if got.From != "old@x" {
		t.Errorf("From: got %q want %q", got.From, "old@x")
	}
	if got.DefaultTo != "def@x" {
		t.Errorf("DefaultTo: got %q want %q", got.DefaultTo, "def@x")
	}
}

func TestConfigureEmailDashClearsField(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "old@x", DefaultTo: "def@x"},
	}})

	in := strings.NewReader("-\n\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}

	loaded, _ := config.Load(cfgPath)
	got := loaded["default"].Email
	if got.From != "" {
		t.Errorf("From should have been cleared; got %q", got.From)
	}
	if got.DefaultTo != "def@x" {
		t.Errorf("DefaultTo: got %q want %q", got.DefaultTo, "def@x")
	}
}

func TestConfigureEmailRejectsInvalidFrom(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	in := strings.NewReader("no-at\nstill-no-at\nnope\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
	})
	if err == nil {
		t.Fatal("expected error after 3 invalid From attempts")
	}
	if !strings.Contains(err.Error(), "From") || !strings.Contains(err.Error(), "3 attempts") {
		t.Errorf("error wording: got %v", err)
	}
}

func TestConfigureEmailRejectsInvalidDefaultTo(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	in := strings.NewReader("alice@example.com\nbad\nbad\nbad\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
	})
	if err == nil {
		t.Fatal("expected error after 3 invalid DefaultTo attempts")
	}
	if !strings.Contains(err.Error(), "DefaultTo") {
		t.Errorf("error wording: got %v", err)
	}
}

func TestConfigureEmailAllowsEmptyDefaultTo(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	in := strings.NewReader("alice@example.com\n\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}

	loaded, _ := config.Load(cfgPath)
	got := loaded["default"].Email
	if got.From != "alice@example.com" {
		t.Errorf("From: got %q", got.From)
	}
	if got.DefaultTo != "" {
		t.Errorf("DefaultTo should be empty; got %q", got.DefaultTo)
	}
}

func TestConfigureEmailErrorsWhenConfigMissing(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "does-not-exist.yml")

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	if !strings.Contains(err.Error(), "no config found") {
		t.Errorf("error wording: got %v", err)
	}
}

func TestConfigureEmailErrorsWhenNoDefaultProfile(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"other": config.Profile{Subdomain: "x", Region: "us"}})

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error for missing default profile")
	}
	if !strings.Contains(err.Error(), `"default" profile`) {
		t.Errorf("error wording: got %v", err)
	}
}

// gmailKeychainStubs captures Set/Delete calls so tests can assert what
// runConfigureEmail did to the Keychain.
type gmailKeychainStubs struct {
	stored   []byte
	deleted  bool
	storeErr error
	delErr   error
}

func (g *gmailKeychainStubs) store(b []byte) error {
	if g.storeErr != nil {
		return g.storeErr
	}
	g.stored = append([]byte(nil), b...)
	return nil
}

func (g *gmailKeychainStubs) delete() error {
	if g.delErr != nil {
		return g.delErr
	}
	g.deleted = true
	return nil
}

// writeGmailJSON writes a syntactically valid service-account JSON to a temp
// file and returns the path. Used by tests that exercise the path-reading
// branch of the Gmail prompt.
func writeGmailJSON(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sa.json")
	contents := `{"type":"service_account","client_email":"x@y.iam.gserviceaccount.com","private_key":"k"}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write sa.json: %v", err)
	}
	return path
}

func TestConfigureEmailGmailPromptStoresJSON(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	jsonPath := writeGmailJSON(t, tmp)
	kc := &gmailKeychainStubs{}

	in := strings.NewReader("alice@example.com\nsecops@example.com\n" + jsonPath + "\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
		StoreGmailJSON:  kc.store,
		DeleteGmailJSON: kc.delete,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}
	if string(kc.stored) == "" {
		t.Fatal("expected StoreGmailJSON to be called")
	}
	loaded, _ := config.Load(cfgPath)
	if !loaded["default"].Email.GmailConfigured {
		t.Errorf("GmailConfigured should be true after storing JSON")
	}
}

func TestConfigureEmailGmailPromptDashClears(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "alice@example.com", DefaultTo: "secops@example.com", GmailConfigured: true},
	}})
	kc := &gmailKeychainStubs{}

	in := strings.NewReader("\n\n-\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
		StoreGmailJSON:  kc.store,
		DeleteGmailJSON: kc.delete,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}
	if !kc.deleted {
		t.Error("expected DeleteGmailJSON to be called")
	}
	loaded, _ := config.Load(cfgPath)
	if loaded["default"].Email.GmailConfigured {
		t.Errorf("GmailConfigured should be false after clearing")
	}
}

func TestConfigureEmailGmailPromptEnterKeepsExisting(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "alice@example.com", DefaultTo: "secops@example.com", GmailConfigured: true},
	}})
	kc := &gmailKeychainStubs{}

	in := strings.NewReader("\n\n\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
		StoreGmailJSON:  kc.store,
		DeleteGmailJSON: kc.delete,
	})
	if err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}
	if kc.stored != nil || kc.deleted {
		t.Errorf("Enter on Gmail prompt should not touch Keychain (stored=%v deleted=%v)", kc.stored, kc.deleted)
	}
	loaded, _ := config.Load(cfgPath)
	if !loaded["default"].Email.GmailConfigured {
		t.Errorf("GmailConfigured should remain true")
	}
}

func TestConfigureEmailGmailPromptRejectsMissingFile(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	missing := filepath.Join(tmp, "does-not-exist.json")
	kc := &gmailKeychainStubs{}

	in := strings.NewReader("alice@example.com\nsecops@example.com\n" + missing + "\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
		StoreGmailJSON:  kc.store,
		DeleteGmailJSON: kc.delete,
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if kc.stored != nil {
		t.Error("StoreGmailJSON should not have been called")
	}
	loaded, _ := config.Load(cfgPath)
	if loaded["default"].Email.GmailConfigured {
		t.Errorf("GmailConfigured should remain false on validation failure")
	}
}

func TestConfigureEmailGmailPromptRejectsWrongType(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	badPath := filepath.Join(tmp, "user.json")
	if err := os.WriteFile(badPath, []byte(`{"type":"authorized_user","client_email":"x@y"}`), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	kc := &gmailKeychainStubs{}

	in := strings.NewReader("alice@example.com\nsecops@example.com\n" + badPath + "\n")
	out := &bytes.Buffer{}

	err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: out, Stderr: out,
		StoreGmailJSON:  kc.store,
		DeleteGmailJSON: kc.delete,
	})
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
	if kc.stored != nil {
		t.Error("StoreGmailJSON should not have been called")
	}
}

func TestConfigureEmailPromptHeaderBGValidAndClear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	// Seed: requires existing default profile (configure email refuses otherwise).
	if err := config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com"},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Inputs (one per prompt, in order): from kept, defaultTo kept, gmail kept (none),
	// header_bg = #C6B8FE.
	in := strings.NewReader("\n\n\n#C6B8FE\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: path, Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	file, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if file["default"].Email.HeaderBG != "#C6B8FE" {
		t.Errorf("HeaderBG: got %q want #C6B8FE", file["default"].Email.HeaderBG)
	}
}

func TestConfigureEmailPromptHeaderBGEnterWritesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com"},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Inputs: from kept, defaultTo kept, gmail kept, header_bg Enter (keep default), logo Enter.
	in := strings.NewReader("\n\n\n\n\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: path, Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	file, _ := config.Load(path)
	if got := file["default"].Email.HeaderBG; got != "#2b3a55" {
		t.Errorf("HeaderBG: got %q want #2b3a55 (default written on Enter)", got)
	}
}

func TestConfigureEmailPromptHeaderBGRejectsInvalidThenAccepts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	_ = config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com"},
	}})
	// Inputs: from kept, defaultTo kept, gmail kept, bad colour twice, then valid.
	// Fifth prompt is logo - Enter keeps (empty current).
	in := strings.NewReader("\n\n\npurple\nnotahex\n#2b3a55\n\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: path, Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}
	if !strings.Contains(errBuf.String(), "invalid hex colour") {
		t.Errorf("expected stderr to mention invalid hex; got:\n%s", errBuf.String())
	}
	file, _ := config.Load(path)
	if file["default"].Email.HeaderBG != "#2b3a55" {
		t.Errorf("HeaderBG: got %q", file["default"].Email.HeaderBG)
	}
}

func TestConfigureEmailLogoCopiesIntoLogosDir(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	logosDir := filepath.Join(dir, "logos")
	srcLogo := filepath.Join(dir, "src", "header-logo.png")
	if err := os.MkdirAll(filepath.Dir(srcLogo), 0o700); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	// Reuse the fixture from internal/email/testdata as a real PNG.
	srcBytes, err := os.ReadFile("../internal/email/testdata/logo_small.png")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// #nosec G304 G703 - test fixture path under t.TempDir()
	if err := os.WriteFile(srcLogo, srcBytes, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	_ = config.Save(cfgPath, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com"},
	}})
	// Inputs (in order): from kept, defaultTo kept, gmail kept, header_bg blank kept, logo path supplied.
	in := strings.NewReader("\n\n\n\n" + srcLogo + "\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, LogosDir: logosDir,
		Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	dst := filepath.Join(logosDir, "header-logo.png")
	gotBytes, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("expected logo at %s: %v", dst, err)
	}
	if !bytes.Equal(gotBytes, srcBytes) {
		t.Errorf("copied bytes differ from src")
	}
	file, _ := config.Load(cfgPath)
	if file["default"].Email.LogoPath != dst {
		t.Errorf("LogoPath: got %q want %q", file["default"].Email.LogoPath, dst)
	}
}

func TestConfigureEmailLogoClearDeletesManagedFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	logosDir := filepath.Join(dir, "logos")
	if err := os.MkdirAll(logosDir, 0o700); err != nil {
		t.Fatalf("mkdir logos: %v", err)
	}
	managed := filepath.Join(logosDir, "old.png")
	if err := os.WriteFile(managed, []byte("png-bytes"), 0o600); err != nil {
		t.Fatalf("seed managed file: %v", err)
	}
	_ = config.Save(cfgPath, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com", LogoPath: managed},
	}})
	in := strings.NewReader("\n\n\n\n-\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, LogosDir: logosDir,
		Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	if _, err := os.Stat(managed); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected managed file deleted, stat err: %v", err)
	}
	if !strings.Contains(errBuf.String(), "removed: "+managed) {
		t.Errorf("expected stderr 'removed: %s', got:\n%s", managed, errBuf.String())
	}
	file, _ := config.Load(cfgPath)
	if file["default"].Email.LogoPath != "" {
		t.Errorf("LogoPath: got %q want empty", file["default"].Email.LogoPath)
	}
}

func TestConfigureEmailPromptListIDDomainSavesValue(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := config.Save(cfgPath, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "ops@example.com"},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Six prompts: from, defaultTo, gmail, header_bg, logo (all kept), then list_id_domain.
	in := strings.NewReader("\n\n\n\n\njellyfish.example.com\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"].Email.ListIDDomain; got != "jellyfish.example.com" {
		t.Errorf("ListIDDomain: got %q want %q", got, "jellyfish.example.com")
	}
	if !strings.Contains(out.String(), "List-Id domain") {
		t.Errorf("expected prompt to mention List-Id domain; got %q", out.String())
	}
}

func TestConfigureEmailPromptListIDDomainEnterKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := config.Save(cfgPath, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "ops@example.com", ListIDDomain: "jellyfish.example.com"},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	in := strings.NewReader("\n\n\n\n\n\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"].Email.ListIDDomain; got != "jellyfish.example.com" {
		t.Errorf("ListIDDomain should be preserved; got %q", got)
	}
}

func TestConfigureEmailPromptListIDDomainDashClears(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := config.Save(cfgPath, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "ops@example.com", ListIDDomain: "jellyfish.example.com"},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	in := strings.NewReader("\n\n\n\n\n-\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"].Email.ListIDDomain; got != "" {
		t.Errorf("ListIDDomain should be cleared; got %q", got)
	}
}

func TestConfigureEmailPromptListIDDomainRejectsInvalidThenAccepts(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := config.Save(cfgPath, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "ops@example.com"},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// First attempt has '@', second has whitespace, third is valid.
	in := strings.NewReader("\n\n\n\n\nbad@thing\nbad thing\njellyfish.example.com\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v\nstderr:\n%s", err, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "List-Id domain") {
		t.Errorf("expected stderr to mention List-Id domain validation; got:\n%s", errBuf.String())
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"].Email.ListIDDomain; got != "jellyfish.example.com" {
		t.Errorf("ListIDDomain after retry: got %q want %q", got, "jellyfish.example.com")
	}
}

func TestConfigureEmailLogoClearLeavesUnmanagedFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	logosDir := filepath.Join(dir, "logos")
	unmanaged := filepath.Join(dir, "elsewhere.png")
	if err := os.WriteFile(unmanaged, []byte("png"), 0o600); err != nil {
		t.Fatalf("seed unmanaged: %v", err)
	}
	_ = config.Save(cfgPath, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		Email: config.EmailConfig{From: "a@example.com", LogoPath: unmanaged},
	}})
	in := strings.NewReader("\n\n\n\n-\n")
	var out, errBuf bytes.Buffer
	if err := runConfigureEmail(context.Background(), configureEmailOpts{
		ConfigPath: cfgPath, LogosDir: logosDir,
		Stdin: in, Stdout: &out, Stderr: &errBuf,
	}); err != nil {
		t.Fatalf("runConfigureEmail: %v", err)
	}
	if _, err := os.Stat(unmanaged); err != nil {
		t.Errorf("unmanaged file should still exist: %v", err)
	}
}

// Token verification tests. Every runConfigure test injects the Verify seam
// (and ReadToken where the tenant changes) rather than starting an httptest
// server, so they run where binding a local port is not allowed and never
// touch the real Keychain.

func TestConfigureBadTokenLeavesKeychainAndConfigUnchanged(t *testing.T) {
	for _, sentinel := range []error{iru.ErrUnauthorized, iru.ErrForbidden} {
		t.Run(sentinel.Error(), func(t *testing.T) {
			tmp := t.TempDir()
			cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
			}})

			var storeCalled bool
			var verifiedToken, verifiedURL string
			out := &bytes.Buffer{}

			err := runConfigure(context.Background(), configureOpts{
				ConfigPath:    cfgPath,
				Stdin:         strings.NewReader("newco\neu\n"),
				Stdout:        out,
				Stderr:        &bytes.Buffer{},
				StoreToken:    func(_, _ string) error { storeCalled = true; return nil },
				ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "typo-tkn", nil },
				Verify: func(_ context.Context, baseURL, token string) error {
					verifiedURL, verifiedToken = baseURL, token
					return sentinel
				},
			})
			if err == nil {
				t.Fatal("expected error for a token that fails verification")
			}
			if !errors.Is(err, sentinel) {
				t.Errorf("error should wrap %v; got %v", sentinel, err)
			}
			if code := classifyError(err); code != 2 {
				t.Errorf("exit code: got %d want 2", code)
			}
			if !strings.Contains(err.Error(), "unchanged") {
				t.Errorf("error should say the existing token was left unchanged; got %v", err)
			}
			if storeCalled {
				t.Error("StoreToken must not be called when verification fails")
			}
			if verifiedToken != "typo-tkn" {
				t.Errorf("verify token: got %q", verifiedToken)
			}
			if verifiedURL != "https://newco.api.eu.kandji.io/api/v1" {
				t.Errorf("verify URL should be derived from the new subdomain/region; got %q", verifiedURL)
			}
			loaded, _ := config.Load(cfgPath)
			if got := loaded["default"]; got.Subdomain != "acme" || got.Region != "us" {
				t.Errorf("config must not change on failed verify; got %+v", got)
			}
			if strings.Contains(out.String(), "Configured") {
				t.Errorf("must not report success; stdout %q", out.String())
			}
		})
	}
}

func TestConfigureFirstRunBadTokenDoesNotWriteConfig(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yml")

	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("acme\nus\n"),
		Stdout:        &bytes.Buffer{},
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, _ string) error { t.Error("StoreToken called"); return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "bad", nil },
		Verify:        func(context.Context, string, string) error { return iru.ErrUnauthorized },
	})
	if code := classifyError(err); code != 2 {
		t.Fatalf("exit code: got %d (err %v)", code, err)
	}
	if _, statErr := os.Stat(cfgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("config file should not be created on failed verify; stat err %v", statErr)
	}
}

func TestConfigureVerifyUpstreamErrorDoesNotStore(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
	}{
		{"5xx", &iru.APIError{Status: 503, Message: "unavailable"}, 4},
		{"rate limited", iru.ErrRateLimited, 4},
		{"network", errors.New("dial tcp: connection refused"), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
			}})
			var storeCalled bool
			err := runConfigure(context.Background(), configureOpts{
				ConfigPath:    cfgPath,
				Stdin:         strings.NewReader("newco\n\n"),
				Stdout:        &bytes.Buffer{},
				Stderr:        &bytes.Buffer{},
				StoreToken:    func(_, _ string) error { storeCalled = true; return nil },
				ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "tkn", nil },
				Verify:        func(context.Context, string, string) error { return c.err },
			})
			if err == nil {
				t.Fatal("expected error when verification cannot complete")
			}
			if !errors.Is(err, c.err) {
				t.Errorf("error should wrap the verify error; got %v", err)
			}
			if code := classifyError(err); code != c.code {
				t.Errorf("exit code: got %d want %d", code, c.code)
			}
			if !strings.Contains(err.Error(), "unchanged") {
				t.Errorf("error should say the existing token was left unchanged; got %v", err)
			}
			if storeCalled {
				t.Error("StoreToken must not be called when verification fails")
			}
			loaded, _ := config.Load(cfgPath)
			if got := loaded["default"]; got.Subdomain != "acme" {
				t.Errorf("config must not change on failed verify; got %+v", got)
			}
		})
	}
}

func TestConfigureGoodTokenVerifiesThenStoresThenSaves(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})

	var order []string
	out := &bytes.Buffer{}
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath: cfgPath,
		Stdin:      strings.NewReader("newco\n\n"),
		Stdout:     out,
		Stderr:     out,
		StoreToken: func(account, token string) error {
			if account != "default" || token != "good-tkn" {
				t.Errorf("StoreToken(%q, %q)", account, token)
			}
			order = append(order, "store")
			return nil
		},
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "good-tkn", nil },
		Verify: func(_ context.Context, _, token string) error {
			if token != "good-tkn" {
				t.Errorf("verify token %q", token)
			}
			order = append(order, "verify")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	if strings.Join(order, ",") != "verify,store" {
		t.Errorf("call order: got %v want [verify store]", order)
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"]; got.Subdomain != "newco" || got.Region != "us" {
		t.Errorf("saved profile %+v", got)
	}
	if !strings.Contains(out.String(), "Token verified") {
		t.Errorf("stdout %q", out.String())
	}
}

func TestConfigureStoreFailureDoesNotSaveConfig(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("newco\n\n"),
		Stdout:        &bytes.Buffer{},
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, _ string) error { return errors.New("keychain locked") },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "good", nil },
		Verify:        func(context.Context, string, string) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "Keychain") {
		t.Fatalf("expected Keychain store error; got %v", err)
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"]; got.Subdomain != "acme" {
		t.Errorf("config must not change when the token cannot be stored; got %+v", got)
	}
}

func TestConfigureKeepTokenSameTenantSavesWithoutVerify(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us", CacheTTLMinutes: 30,
	}})
	out := &bytes.Buffer{}
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("\n\n"),
		Stdout:        out,
		Stderr:        out,
		StoreToken:    func(_, _ string) error { t.Error("StoreToken called"); return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
		ReadToken:     func(string) (string, error) { t.Error("ReadToken called"); return "", nil },
		Verify:        func(context.Context, string, string) error { t.Error("Verify called"); return nil },
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"]; got.Subdomain != "acme" || got.Region != "us" || got.CacheTTLMinutes != 30 {
		t.Errorf("saved profile %+v", got)
	}
	if !strings.Contains(out.String(), "Existing token unchanged") {
		t.Errorf("stdout %q", out.String())
	}
}

func TestConfigureKeepTokenTenantChangeVerifiesExistingToken(t *testing.T) {
	cases := []struct {
		name, stdin, wantURL, wantSub, wantRegion string
	}{
		{"subdomain changed", "newco\n\n", "https://newco.api.kandji.io/api/v1", "newco", "us"},
		{"region changed", "\neu\n", "https://acme.api.eu.kandji.io/api/v1", "acme", "eu"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
			}})
			var readAccount, verifiedURL, verifiedToken string
			out := &bytes.Buffer{}
			err := runConfigure(context.Background(), configureOpts{
				ConfigPath:    cfgPath,
				Stdin:         strings.NewReader(c.stdin),
				Stdout:        out,
				Stderr:        out,
				StoreToken:    func(_, _ string) error { t.Error("StoreToken called"); return nil },
				ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
				ReadToken: func(account string) (string, error) {
					readAccount = account
					return "kept-tkn", nil
				},
				Verify: func(_ context.Context, baseURL, token string) error {
					verifiedURL, verifiedToken = baseURL, token
					return nil
				},
			})
			if err != nil {
				t.Fatalf("runConfigure: %v", err)
			}
			if readAccount != "default" {
				t.Errorf("ReadToken account: got %q", readAccount)
			}
			if verifiedToken != "kept-tkn" {
				t.Errorf("verify token: got %q", verifiedToken)
			}
			if verifiedURL != c.wantURL {
				t.Errorf("verify URL: got %q want %q", verifiedURL, c.wantURL)
			}
			loaded, _ := config.Load(cfgPath)
			if got := loaded["default"]; got.Subdomain != c.wantSub || got.Region != c.wantRegion {
				t.Errorf("saved profile %+v", got)
			}
			if !strings.Contains(out.String(), "Existing token unchanged") {
				t.Errorf("stdout %q", out.String())
			}
		})
	}
}

func TestConfigureKeepTokenTenantChangeVerifyFailureLeavesConfig(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code int
	}{
		{"unauthorised", iru.ErrUnauthorized, 2},
		{"forbidden", iru.ErrForbidden, 2},
		{"5xx", &iru.APIError{Status: 503, Message: "unavailable"}, 4},
		{"rate limited", iru.ErrRateLimited, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
			}})
			out := &bytes.Buffer{}
			err := runConfigure(context.Background(), configureOpts{
				ConfigPath:    cfgPath,
				Stdin:         strings.NewReader("newco\neu\n"),
				Stdout:        out,
				Stderr:        out,
				StoreToken:    func(_, _ string) error { t.Error("StoreToken called"); return nil },
				ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
				ReadToken:     func(string) (string, error) { return "old-tenant-tkn", nil },
				Verify:        func(context.Context, string, string) error { return c.err },
			})
			if err == nil {
				t.Fatal("expected error when the kept token fails against the new tenant")
			}
			if !errors.Is(err, c.err) {
				t.Errorf("error should wrap %v; got %v", c.err, err)
			}
			if code := classifyError(err); code != c.code {
				t.Errorf("exit code: got %d want %d", code, c.code)
			}
			if !strings.Contains(err.Error(), "unchanged") || !strings.Contains(err.Error(), "new tenant") {
				t.Errorf("error should say config was left unchanged and ask for the new tenant's token; got %v", err)
			}
			loaded, _ := config.Load(cfgPath)
			if got := loaded["default"]; got.Subdomain != "acme" || got.Region != "us" {
				t.Errorf("config must not change on failed verify; got %+v", got)
			}
			if strings.Contains(out.String(), "Configured") {
				t.Errorf("must not report success; stdout %q", out.String())
			}
		})
	}
}

func TestConfigureKeepTokenTenantChangeMissingTokenErrors(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("newco\n\n"),
		Stdout:        &bytes.Buffer{},
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, _ string) error { t.Error("StoreToken called"); return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
		ReadToken:     func(string) (string, error) { return "", keychain.ErrNotFound },
		Verify:        func(context.Context, string, string) error { t.Error("Verify called"); return nil },
	})
	if err == nil {
		t.Fatal("expected error when no token is stored and the tenant changed")
	}
	if !strings.Contains(err.Error(), "token is required") {
		t.Errorf("error should say a token is required; got %v", err)
	}
	if code := classifyError(err); code != 1 {
		t.Errorf("exit code: got %d want 1", code)
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"]; got.Subdomain != "acme" {
		t.Errorf("config must not change; got %+v", got)
	}
}

func TestConfigureKeepTokenTenantChangeReadErrorLeavesConfig(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := seedConfigFile(t, tmp, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	readErr := errors.New("keychain locked")
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("newco\n\n"),
		Stdout:        &bytes.Buffer{},
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, _ string) error { t.Error("StoreToken called"); return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
		ReadToken:     func(string) (string, error) { return "", readErr },
		Verify:        func(context.Context, string, string) error { t.Error("Verify called"); return nil },
	})
	if !errors.Is(err, readErr) {
		t.Fatalf("expected wrapped read error; got %v", err)
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"]; got.Subdomain != "acme" {
		t.Errorf("config must not change; got %+v", got)
	}
}
