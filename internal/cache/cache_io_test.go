package cache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bawdo/jellyfish/internal/iru"
)

// Save creates any missing parent directories 0700: the cache holds tenant
// vulnerability data and must not be listable by other local users.
func TestSaveCreatesPrivateParentDirs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "a", "b", "detections-acme-us.json")
	if err := Save(path, []iru.Detection{{CVEID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("%s: expected 0700, got %o", dir, info.Mode().Perm())
		}
	}
}

// An I/O error other than "not found" is a real error, not a silent miss.
func TestLoadReturnsReadErrors(t *testing.T) {
	dir := t.TempDir() // reading a directory fails with EISDIR
	for name, load := range map[string]func() (bool, error){
		"Load": func() (bool, error) {
			out, hit, err := Load(dir, time.Hour)
			return hit || out != nil, err
		},
		"LoadVulnerabilities": func() (bool, error) {
			out, hit, err := LoadVulnerabilities(dir, time.Hour)
			return hit || out != nil, err
		},
	} {
		gotData, err := load()
		if err == nil {
			t.Errorf("%s: expected a read error", name)
		}
		if errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: unexpected NotExist error %v", name, err)
		}
		if gotData {
			t.Errorf("%s: expected no data alongside the error", name)
		}
	}
}

// A parent path that is a regular file makes the cache dir impossible to
// create; both savers must report that rather than claim success.
func TestSaveFailsWhenCacheDirCannotBeCreated(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Save(filepath.Join(blocker, "detections-acme-us.json"), []iru.Detection{{CVEID: "CVE-1"}})
	if err == nil || !strings.Contains(err.Error(), "create cache dir") {
		t.Errorf("Save: expected a create cache dir error, got %v", err)
	}
	err = SaveVulnerabilities(filepath.Join(blocker, "vulnerabilities-acme-us.json"), []iru.Vulnerability{{CVEID: "CVE-1"}})
	if err == nil || !strings.Contains(err.Error(), "create cache dir") {
		t.Errorf("SaveVulnerabilities: expected a create cache dir error, got %v", err)
	}
}

// With no resolvable user cache dir the default paths are an error (so cmd
// disables the cache) and an explicit-path save still works, skipping the
// legacy clean-up it cannot locate.
func TestNoUserCacheDir(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	if _, err := os.UserCacheDir(); err == nil {
		t.Skip("os.UserCacheDir resolves without HOME on this platform")
	}
	if p, err := DefaultPath("acme-us"); err == nil {
		t.Errorf("DefaultPath: expected an error, got %q", p)
	}
	if p, err := DefaultVulnPath("acme-us"); err == nil {
		t.Errorf("DefaultVulnPath: expected an error, got %q", p)
	}
	path := filepath.Join(t.TempDir(), "detections-acme-us.json")
	if err := Save(path, []iru.Detection{{CVEID: "CVE-1"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, hit, _ := Load(path, time.Hour); !hit {
		t.Error("explicit-path cache should still be written")
	}
}
