package cmd

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/config"
)

func TestConfigureCacheCmdWiresConfigFlagAndStdio(t *testing.T) {
	cfgPath := writeBasicConfig(t, t.TempDir(), 15)
	stdout, _, err := cfgcovExecRoot(t, "30\n", "configure", "cache", "--config", cfgPath)
	if err != nil {
		t.Fatalf("configure cache: %v", err)
	}
	if !strings.Contains(stdout, "Cache TTL in minutes [15]") {
		t.Errorf("prompt missing from stdout: %q", stdout)
	}
	if !strings.Contains(stdout, "Cache TTL set to 30 minutes (saved to "+cfgPath+")") {
		t.Errorf("confirmation missing from stdout: %q", stdout)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := loaded["default"].CacheTTLMinutes; got != 30 {
		t.Errorf("CacheTTLMinutes = %d, want 30", got)
	}
}

func TestConfigureCacheMalformedConfigIsReported(t *testing.T) {
	cfgPath := writeRawConfig(t, malformedYAML)
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: cfgPath, Stdin: strings.NewReader("30\n"), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "read config") || strings.Contains(err.Error(), "no config found") {
		t.Fatalf("err = %v, want a read config error (not missing-config)", err)
	}
}

// With no TTL set, both Enter and "-" keep the built-in default and leave
// the file byte-for-byte unchanged.
func TestConfigureCacheUnsetTTLKeepsBuiltInDefault(t *testing.T) {
	for name, line := range map[string]string{"enter": "\n", "dash": "-\n"} {
		t.Run(name, func(t *testing.T) {
			cfgPath := writeBasicConfig(t, t.TempDir(), 0)
			before := cfgcovReadFile(t, cfgPath)
			out := &bytes.Buffer{}
			if err := runConfigureCache(configureCacheOpts{
				ConfigPath: cfgPath, Stdin: strings.NewReader(line), Stdout: out, Stderr: &bytes.Buffer{},
			}); err != nil {
				t.Fatalf("runConfigureCache: %v", err)
			}
			if !strings.Contains(out.String(), "Cache TTL unchanged (using built-in default)") {
				t.Errorf("stdout %q", out.String())
			}
			if !bytes.Equal(cfgcovReadFile(t, cfgPath), before) {
				t.Error("config rewritten on keep")
			}
		})
	}
}

func TestConfigureCacheReadFailureIsReturned(t *testing.T) {
	cfgPath := writeBasicConfig(t, t.TempDir(), 15)
	before := cfgcovReadFile(t, cfgPath)
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: cfgPath, Stdin: cfgcovReaderThenFail(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
	})
	if !errors.Is(err, cfgcovErrRead) {
		t.Fatalf("err = %v, want %v", err, cfgcovErrRead)
	}
	if !bytes.Equal(cfgcovReadFile(t, cfgPath), before) {
		t.Error("config changed despite the read failure")
	}
}

func TestConfigureCacheSaveFailureIsReturned(t *testing.T) {
	cfgPath := cfgcovReadOnlyConfig(t, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us", CacheTTLMinutes: 15,
	}})
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: cfgPath, Stdin: strings.NewReader("30\n"), Stdout: out, Stderr: &bytes.Buffer{},
	})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("err = %v, want a permission error from saving", err)
	}
	if strings.Contains(out.String(), "Cache TTL set") {
		t.Errorf("success message printed despite the failed save: %q", out.String())
	}
}
