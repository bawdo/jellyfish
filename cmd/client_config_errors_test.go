package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/cache"
	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/keychain"
)

// writeRawConfig writes body verbatim to a config file in a temp dir, so
// tests can exercise YAML that config.Save would never produce.
func writeRawConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const (
	malformedYAML = "default:\n  subdomain: [unterminated\n"
	outOfRangeTTL = "default:\n  subdomain: acme\n  region: us\n  cache_ttl_minutes: 5000\n"
)

// stubKeychainGet swaps the package-level keychain seam for the duration of
// a test so nothing touches the real macOS Keychain.
func stubKeychainGet(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	orig := keychainGet
	keychainGet = fn
	t.Cleanup(func() { keychainGet = orig })
}

func failIfKeychainRead(t *testing.T) {
	t.Helper()
	stubKeychainGet(t, func(string) (string, error) {
		t.Fatal("keychain must not be read when config load fails")
		return "", nil
	})
}

func TestBuildClientMalformedYAMLSurfacesParseError(t *testing.T) {
	failIfKeychainRead(t)
	path := writeRawConfig(t, malformedYAML)
	_, err := buildClient(newCmdWithConfigFlag(t, path))
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	msg := err.Error()
	if strings.Contains(msg, "no credentials found") {
		t.Errorf("parse error masked as missing credentials: %q", msg)
	}
	if !strings.Contains(msg, "parse config") || !strings.Contains(msg, path) {
		t.Errorf("error should name the parse failure and path, got %q", msg)
	}
}

func TestBuildClientOutOfRangeTTLSurfacesValidationError(t *testing.T) {
	failIfKeychainRead(t)
	path := writeRawConfig(t, outOfRangeTTL)
	_, err := buildClient(newCmdWithConfigFlag(t, path))
	if err == nil {
		t.Fatal("expected error for out-of-range TTL")
	}
	msg := err.Error()
	if strings.Contains(msg, "no credentials found") {
		t.Errorf("validation error masked as missing credentials: %q", msg)
	}
	if !strings.Contains(msg, "cache_ttl_minutes") || !strings.Contains(msg, path) {
		t.Errorf("error should name the TTL problem and path, got %q", msg)
	}
}

func TestBuildClientMissingConfigKeepsFriendlyMessage(t *testing.T) {
	failIfKeychainRead(t)
	path := filepath.Join(t.TempDir(), "does-not-exist.yml")
	_, err := buildClient(newCmdWithConfigFlag(t, path))
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	want := `no credentials found at ` + path + `. Run "jellyfish configure" to set up`
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func validConfigPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return path
}

func TestBuildClientKeychainNotFoundKeepsFriendlyMessage(t *testing.T) {
	stubKeychainGet(t, func(string) (string, error) { return "", keychain.ErrNotFound })
	_, err := buildClient(newCmdWithConfigFlag(t, validConfigPath(t)))
	if err == nil {
		t.Fatal("expected error when token is missing")
	}
	want := `no token found in Keychain. Run "jellyfish configure" to set up`
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestBuildClientKeychainOtherErrorIsWrapped(t *testing.T) {
	cause := errors.New("user interaction is not allowed")
	stubKeychainGet(t, func(string) (string, error) { return "", cause })
	_, err := buildClient(newCmdWithConfigFlag(t, validConfigPath(t)))
	if err == nil {
		t.Fatal("expected error when keychain read fails")
	}
	if !errors.Is(err, cause) {
		t.Errorf("error does not wrap the keychain cause: %v", err)
	}
	if strings.Contains(err.Error(), "no token found") {
		t.Errorf("keychain failure masked as missing token: %q", err.Error())
	}
}

func TestBuildClientKeychainSuccess(t *testing.T) {
	stubKeychainGet(t, func(string) (string, error) { return "tok", nil })
	c, err := buildClient(newCmdWithConfigFlag(t, validConfigPath(t)))
	if err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}

func TestActiveProfileMalformedYAMLReturnsError(t *testing.T) {
	path := writeRawConfig(t, malformedYAML)
	_, err := activeProfile(newCmdWithConfigFlag(t, path))
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error should name the config path, got %q", err.Error())
	}
}

func TestActiveProfileOutOfRangeTTLReturnsError(t *testing.T) {
	path := writeRawConfig(t, outOfRangeTTL)
	_, err := activeProfile(newCmdWithConfigFlag(t, path))
	if err == nil {
		t.Fatal("expected error for out-of-range TTL, got nil")
	}
	if !strings.Contains(err.Error(), "cache_ttl_minutes") || !strings.Contains(err.Error(), path) {
		t.Errorf("error should name the TTL problem and path, got %q", err.Error())
	}
}

func TestActiveProfileMissingConfigReturnsEmptyProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yml")
	prof, err := activeProfile(newCmdWithConfigFlag(t, path))
	if err != nil {
		t.Fatalf("activeProfile: %v", err)
	}
	if prof != (config.Profile{}) {
		t.Errorf("want empty profile, got %+v", prof)
	}
}

func TestResolveCacheTTLMalformedConfigReturnsError(t *testing.T) {
	path := writeRawConfig(t, malformedYAML)
	got, err := resolveCacheTTL(newCmdWithConfigFlag(t, path))
	if err == nil {
		t.Fatalf("expected error, got TTL %v", got)
	}
	if got == cache.DefaultTTL {
		t.Errorf("broken config should not silently fall back to DefaultTTL")
	}
}
