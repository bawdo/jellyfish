package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/keychain"
)

// fakeTokens is an in-memory Keychain keyed by account. reads records every
// account asked for, in order.
type fakeTokens struct {
	byAccount map[string]string
	reads     []string
}

func (f *fakeTokens) get(account string) (string, error) {
	f.reads = append(f.reads, account)
	tok, ok := f.byAccount[account]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return tok, nil
}

func TestTokenAccountIsPerTenant(t *testing.T) {
	got := tokenAccount(config.Profile{Subdomain: "acme", Region: "us"})
	if got != "iru:acme-us" {
		t.Fatalf("tokenAccount = %q, want iru:acme-us", got)
	}
	if a, b := tokenAccount(config.Profile{Subdomain: "acme", Region: "us"}),
		tokenAccount(config.Profile{Subdomain: "acme", Region: "eu"}); a == b {
		t.Fatalf("two tenants share account %q", a)
	}
}

// Each tenant's token lives in its own Keychain item, so a config for one
// tenant never picks up a token stored for another.
func TestBuildClientReadsTenantToken(t *testing.T) {
	kc := &fakeTokens{byAccount: map[string]string{
		"iru:acme-us": "acme-tok",
		"default":     "other-tok",
	}}
	stubKeychainGet(t, kc.get)
	_, tok := stubNewIruClient(t, &fakeClient{})
	if _, err := buildClient(newCmdWithConfigFlag(t, validConfigPath(t))); err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	if *tok != "acme-tok" {
		t.Fatalf("token = %q, want acme-tok", *tok)
	}
	if strings.Join(kc.reads, ",") != "iru:acme-us" {
		t.Errorf("Keychain reads = %v, want only iru:acme-us", kc.reads)
	}
}

// Installs configured before tokens were per tenant keep working from the
// legacy account until the next configure.
func TestBuildClientFallsBackToLegacyAccount(t *testing.T) {
	kc := &fakeTokens{byAccount: map[string]string{"default": "legacy-tok"}}
	stubKeychainGet(t, kc.get)
	_, tok := stubNewIruClient(t, &fakeClient{})
	if _, err := buildClient(newCmdWithConfigFlag(t, validConfigPath(t))); err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	if *tok != "legacy-tok" {
		t.Fatalf("token = %q, want legacy-tok", *tok)
	}
	if strings.Join(kc.reads, ",") != "iru:acme-us,default" {
		t.Errorf("Keychain reads = %v, want [iru:acme-us default]", kc.reads)
	}
}

// A Keychain failure on the tenant account (locked, access denied) must not
// quietly fall through to another tenant's legacy token.
func TestBuildClientDoesNotFallBackOnKeychainError(t *testing.T) {
	cause := errors.New("user interaction is not allowed")
	var reads []string
	stubKeychainGet(t, func(account string) (string, error) {
		reads = append(reads, account)
		return "", cause
	})
	_, err := buildClient(newCmdWithConfigFlag(t, validConfigPath(t)))
	if !errors.Is(err, cause) {
		t.Fatalf("expected the Keychain error, got %v", err)
	}
	if len(reads) != 1 {
		t.Errorf("Keychain reads = %v, want one", reads)
	}
}

func TestConfigureStoresNewTokenUnderTenantAccount(t *testing.T) {
	cfgPath := seedConfigFile(t, t.TempDir(), config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	var stored []string
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath: cfgPath,
		Stdin:      strings.NewReader("newco\n\n"),
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
		StoreToken: func(account, token string) error {
			stored = append(stored, account+"="+token)
			return nil
		},
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "new-tok", nil },
		Verify:        func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	if strings.Join(stored, ",") != "iru:newco-us=new-tok" {
		t.Fatalf("stored %v, want [iru:newco-us=new-tok]", stored)
	}
}

// Keeping the token across a tenant change checks it against the new tenant,
// then stores it under the new tenant's account. The legacy item is left
// alone: it may still be what another config file relies on.
func TestConfigureKeptTokenMovesToNewTenantAccount(t *testing.T) {
	cases := []struct {
		name     string
		accounts map[string]string
		wantRead string
	}{
		{"from old tenant account", map[string]string{"iru:acme-us": "kept-tok"}, "iru:newco-us,iru:acme-us"},
		{"from legacy account", map[string]string{"default": "kept-tok"}, "iru:newco-us,iru:acme-us,default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfgPath := seedConfigFile(t, t.TempDir(), config.File{"default": config.Profile{
				Subdomain: "acme", Region: "us",
			}})
			kc := &fakeTokens{byAccount: c.accounts}
			var stored, verified []string
			err := runConfigure(context.Background(), configureOpts{
				ConfigPath: cfgPath,
				Stdin:      strings.NewReader("newco\n\n"),
				Stdout:     &bytes.Buffer{},
				Stderr:     &bytes.Buffer{},
				StoreToken: func(account, token string) error {
					stored = append(stored, account+"="+token)
					return nil
				},
				ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
				ReadToken:     kc.get,
				Verify: func(_ context.Context, baseURL, token string) error {
					verified = append(verified, baseURL+" "+token)
					return nil
				},
			})
			if err != nil {
				t.Fatalf("runConfigure: %v", err)
			}
			if got := strings.Join(kc.reads, ","); got != c.wantRead {
				t.Errorf("reads = %s, want %s", got, c.wantRead)
			}
			if strings.Join(verified, ",") != "https://newco.api.kandji.io/api/v1 kept-tok" {
				t.Errorf("verified %v", verified)
			}
			if strings.Join(stored, ",") != "iru:newco-us=kept-tok" {
				t.Errorf("stored %v, want [iru:newco-us=kept-tok]", stored)
			}
		})
	}
}

// If the new tenant already has its own token, that is the one kept, and it
// is already in the right place.
func TestConfigureKeptTokenPrefersNewTenantsOwnToken(t *testing.T) {
	cfgPath := seedConfigFile(t, t.TempDir(), config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	kc := &fakeTokens{byAccount: map[string]string{
		"iru:newco-us": "newco-tok",
		"iru:acme-us":  "acme-tok",
	}}
	var verified string
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("newco\n\n"),
		Stdout:        &bytes.Buffer{},
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, _ string) error { t.Error("StoreToken called"); return nil },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
		ReadToken:     kc.get,
		Verify: func(_ context.Context, _, token string) error {
			verified = token
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runConfigure: %v", err)
	}
	if verified != "newco-tok" {
		t.Errorf("verified %q, want newco-tok", verified)
	}
}

// A kept token that cannot be stored under the new tenant leaves the config
// on the old tenant.
func TestConfigureKeptTokenStoreFailureDoesNotSaveConfig(t *testing.T) {
	cfgPath := seedConfigFile(t, t.TempDir(), config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}})
	kc := &fakeTokens{byAccount: map[string]string{"default": "kept-tok"}}
	err := runConfigure(context.Background(), configureOpts{
		ConfigPath:    cfgPath,
		Stdin:         strings.NewReader("newco\n\n"),
		Stdout:        &bytes.Buffer{},
		Stderr:        &bytes.Buffer{},
		StoreToken:    func(_, _ string) error { return errors.New("keychain locked") },
		ReadTokenLine: func(_ *bufio.Reader) (string, error) { return "", nil },
		ReadToken:     kc.get,
		Verify:        func(context.Context, string, string) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "Keychain") {
		t.Fatalf("expected a Keychain store error, got %v", err)
	}
	loaded, _ := config.Load(cfgPath)
	if got := loaded["default"]; got.Subdomain != "acme" {
		t.Errorf("config must not change when the token cannot be stored; got %+v", got)
	}
}

// An incomplete tenant has no account of its own; it must not be looked up
// as "iru:" or "", only skipped.
func TestReadIruTokenSkipsEmptyAccount(t *testing.T) {
	if got := tokenAccount(config.Profile{Subdomain: "acme"}); got != "" {
		t.Fatalf("tokenAccount for incomplete tenant = %q, want empty", got)
	}
	kc := &fakeTokens{byAccount: map[string]string{"default": "legacy-tok"}}
	tok, from, err := readIruToken(kc.get, "", legacyTokenAccount)
	if err != nil || tok != "legacy-tok" || from != legacyTokenAccount {
		t.Fatalf("got %q from %q, %v", tok, from, err)
	}
	if strings.Join(kc.reads, ",") != "default" {
		t.Errorf("Keychain reads = %v, want only default", kc.reads)
	}
}
