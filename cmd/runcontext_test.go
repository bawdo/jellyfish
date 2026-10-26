package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bawdo/jellyfish/internal/cache"
	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/iru"
)

// stubNewIruClient swaps the client constructor seam for the duration of a
// test, recording the base URL and token buildClient hands it.
func stubNewIruClient(t *testing.T, c iruClient) (gotBaseURL, gotToken *string) {
	t.Helper()
	var base, tok string
	orig := newIruClient
	newIruClient = func(baseURL, token string) iruClient {
		base, tok = baseURL, token
		return c
	}
	t.Cleanup(func() { newIruClient = orig })
	return &base, &tok
}

// isolateCacheDir points HOME and XDG_CACHE_HOME at a fresh temp dir and
// returns the jellyfish cache dir os.UserCacheDir resolves to under it.
func isolateCacheDir(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	dir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("UserCacheDir: %v", err)
	}
	return filepath.Join(dir, "jellyfish")
}

func writeProfileConfig(t *testing.T, prof config.Profile) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := config.Save(path, config.File{"default": prof}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return path
}

func execRootForTest(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// Each cache-using command must thread the active profile's tenant through to
// the cache, so a real run lands in the per-tenant file rather than running
// live (or worse, sharing a file across tenants).
func TestCommandsWritePerTenantCache(t *testing.T) {
	user := iru.User{ID: "u1", Name: "U One", Email: "u1@example.com", Active: true}
	cases := []struct {
		name string
		args []string
		file string
	}{
		{"vulns list", []string{"vulns", "list", "-o", "json"}, "detections-acme-eu.json"},
		{"vulns summary", []string{"vulns", "summary", "-o", "json"}, "vulnerabilities-acme-eu.json"},
		{"user show", []string{"user", "show", "u1", "-o", "json"}, "detections-acme-eu.json"},
		{"overview", []string{"overview", "-o", "json"}, "detections-acme-eu.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := isolateCacheDir(t)
			cfg := writeProfileConfig(t, config.Profile{Subdomain: "acme", Region: "eu"})
			stubKeychainGet(t, func(string) (string, error) { return "tok", nil })
			fake := &fakeClient{
				users:           []iru.User{user},
				devices:         []iru.Device{{DeviceID: "d1", User: user}},
				detections:      []iru.Detection{{CVEID: "CVE-1", DeviceID: "d1"}},
				vulnerabilities: []iru.Vulnerability{{CVEID: "CVE-1"}},
			}
			base, tok := stubNewIruClient(t, fake)

			_, stderr, err := execRootForTest(t, append(tc.args, "--config", cfg)...)
			if err != nil {
				t.Fatalf("execute: %v\nstderr:\n%s", err, stderr)
			}
			if *base != "https://acme.api.eu.kandji.io/api/v1" || *tok != "tok" {
				t.Errorf("client built with base %q token %q", *base, *tok)
			}
			if strings.Contains(stderr, "cache disabled") {
				t.Errorf("cache unexpectedly disabled:\n%s", stderr)
			}
			if _, err := os.Stat(filepath.Join(cacheDir, tc.file)); err != nil {
				t.Errorf("per-tenant cache file not written: %v", err)
			}
		})
	}
}

// ageCacheFile rewrites the fetched_at stamp of a cache file written by
// cache.Save, so tests can exercise TTL boundaries without knowing the
// on-disk version number.
func ageCacheFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	stamp, err := json.Marshal(time.Now().UTC().Add(-age))
	if err != nil {
		t.Fatal(err)
	}
	raw["fetched_at"] = stamp
	data, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The configured cache_ttl_minutes reaches the cache read: a 20 minute old
// cache is fresh under a 30 minute TTL and stale under the 15 minute default.
func TestVulnsListHonoursConfiguredTTL(t *testing.T) {
	cases := []struct {
		name    string
		ttlMins int
		wantCVE string
	}{
		{"configured 30m serves the cache", 30, "CVE-CACHED"},
		{"default 15m walks live", 0, "CVE-LIVE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := isolateCacheDir(t)
			cachePath := filepath.Join(cacheDir, "detections-acme-us.json")
			if err := cache.Save(cachePath, []iru.Detection{{CVEID: "CVE-CACHED"}}); err != nil {
				t.Fatal(err)
			}
			ageCacheFile(t, cachePath, 20*time.Minute)
			cfg := writeProfileConfig(t, config.Profile{Subdomain: "acme", Region: "us", CacheTTLMinutes: tc.ttlMins})
			stubKeychainGet(t, func(string) (string, error) { return "tok", nil })
			stubNewIruClient(t, &fakeClient{detections: []iru.Detection{{CVEID: "CVE-LIVE"}}})

			stdout, stderr, err := execRootForTest(t, "vulns", "list", "-o", "json", "--config", cfg)
			if err != nil {
				t.Fatalf("execute: %v\nstderr:\n%s", err, stderr)
			}
			if !strings.Contains(stdout, tc.wantCVE) {
				t.Errorf("want %s in output, got:\n%s", tc.wantCVE, stdout)
			}
		})
	}
}

// loadRunContext reads the config once and derives every per-run value from
// that single profile.
func TestLoadRunContextDerivesAllFieldsFromOneProfile(t *testing.T) {
	cfg := writeProfileConfig(t, config.Profile{Subdomain: "acme", Region: "us", CacheTTLMinutes: 42})
	stubKeychainGet(t, func(string) (string, error) { return "tok", nil })
	fake := &fakeClient{}
	stubNewIruClient(t, fake)

	rc, err := loadRunContext(newCmdWithConfigFlag(t, cfg))
	if err != nil {
		t.Fatalf("loadRunContext: %v", err)
	}
	if rc.Client != iruClient(fake) {
		t.Errorf("client not from the constructor seam")
	}
	if rc.Profile.Subdomain != "acme" || rc.Profile.Region != "us" {
		t.Errorf("profile: %+v", rc.Profile)
	}
	if rc.CacheTTL != 42*time.Minute {
		t.Errorf("ttl: got %v want 42m", rc.CacheTTL)
	}
	if rc.CacheTenant != "acme-us" {
		t.Errorf("tenant: got %q want acme-us", rc.CacheTenant)
	}
}

func TestLoadRunContextMissingConfigKeepsFriendlyMessage(t *testing.T) {
	failIfKeychainRead(t)
	path := filepath.Join(t.TempDir(), "does-not-exist.yml")
	_, err := loadRunContext(newCmdWithConfigFlag(t, path))
	want := `no credentials found at ` + path + `. Run "jellyfish configure" to set up`
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want %q", err, want)
	}
}
