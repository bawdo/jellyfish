package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/config"
)

func writeBasicConfig(t *testing.T, dir string, ttl int) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	prof := config.Profile{
		Subdomain: "acme", Region: "us",
	}
	if ttl > 0 {
		prof.CacheTTLMinutes = ttl
	}
	if err := config.Save(path, config.File{"default": prof}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return path
}

func TestConfigureCacheSetsValue(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 0)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("30\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := loaded["default"].CacheTTLMinutes; got != 30 {
		t.Errorf("CacheTTLMinutes: got %d want 30", got)
	}
}

func TestConfigureCacheKeepsExistingOnEnter(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 45)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, _ := config.Load(path)
	if got := loaded["default"].CacheTTLMinutes; got != 45 {
		t.Errorf("CacheTTLMinutes: got %d want 45 (Enter should keep)", got)
	}
}

func TestConfigureCacheDashClears(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 45)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("-\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, _ := config.Load(path)
	if got := loaded["default"].CacheTTLMinutes; got != 0 {
		t.Errorf("CacheTTLMinutes: got %d want 0 (dash should clear)", got)
	}
}

func TestConfigureCacheRetriesOnInvalid(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 0)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("0\nabc\n15\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, _ := config.Load(path)
	if got := loaded["default"].CacheTTLMinutes; got != 15 {
		t.Errorf("CacheTTLMinutes: got %d want 15", got)
	}
	if !strings.Contains(out.String(), "out of range") && !strings.Contains(out.String(), "invalid") {
		t.Errorf("expected validation message on stderr; got: %s", out.String())
	}
}

func TestConfigureCacheGivesUpAfterMaxAttempts(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 0)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("0\n-1\n9999\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err == nil {
		t.Fatal("expected error after three invalid attempts")
	}
}

func TestConfigureCacheRequiresDefaultProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := config.Save(path, config.File{"other": config.Profile{
		Subdomain: "acme", Region: "us",
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("15\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err == nil {
		t.Fatal("expected error for missing default profile")
	}
	if !strings.Contains(err.Error(), `"jellyfish configure"`) {
		t.Errorf("error %q: want guidance to run jellyfish configure", err)
	}
}

func TestConfigureCacheMissingConfigFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yml")
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: missing,
		Stdin:      strings.NewReader("15\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}
