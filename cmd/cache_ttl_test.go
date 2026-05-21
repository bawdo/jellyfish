package cmd

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/cache"
	"github.com/bawdo/jellyfish/internal/config"
)

// newCmdWithConfigFlag returns a bare *cobra.Command with the --config flag
// registered, used to drive resolveCacheTTL in tests without standing up the
// full root command tree.
//
// We register --config as a local flag (not persistent) because cobra only
// merges persistent flags from parents into a command's Flags() during
// Execute(); in unit tests we bypass Execute(), so a local flag is the
// simplest way to expose --config to the function under test.
func newCmdWithConfigFlag(t *testing.T, cfgPath string) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "x"}
	c.Flags().String("config", "", "")
	if cfgPath != "" {
		if err := c.Flags().Set("config", cfgPath); err != nil {
			t.Fatalf("set --config: %v", err)
		}
	}
	return c
}

func TestResolveCacheTTLMissingConfigReturnsDefault(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yml")
	c := newCmdWithConfigFlag(t, missing)
	got, err := resolveCacheTTL(c)
	if err != nil {
		t.Fatalf("resolveCacheTTL: %v", err)
	}
	if got != cache.DefaultTTL {
		t.Errorf("got %v, want %v (DefaultTTL)", got, cache.DefaultTTL)
	}
}

func TestResolveCacheTTLZeroFieldReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := newCmdWithConfigFlag(t, path)
	got, err := resolveCacheTTL(c)
	if err != nil {
		t.Fatalf("resolveCacheTTL: %v", err)
	}
	if got != cache.DefaultTTL {
		t.Errorf("got %v, want %v", got, cache.DefaultTTL)
	}
}

func TestResolveCacheTTLHonoursProfileValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us",
		CacheTTLMinutes: 30,
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := newCmdWithConfigFlag(t, path)
	got, err := resolveCacheTTL(c)
	if err != nil {
		t.Fatalf("resolveCacheTTL: %v", err)
	}
	if got != 30*time.Minute {
		t.Errorf("got %v, want %v", got, 30*time.Minute)
	}
}
