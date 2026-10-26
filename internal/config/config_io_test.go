package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Directories Save creates are 0700, so other local users cannot list the
// config dir (it also holds the copied email logo).
func TestSaveCreatesPrivateParentDirs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "child", "config.yml")
	if err := Save(path, File{"default": Profile{Subdomain: "x", Region: "us"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	for _, dir := range []string{filepath.Join(root, "nested"), filepath.Join(root, "nested", "child")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("%s: expected mode 0700, got %o", dir, info.Mode().Perm())
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config file: expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestSaveFailsWhenParentIsAFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Save(filepath.Join(blocker, "config.yml"), File{"default": Profile{Subdomain: "x", Region: "us"}})
	if err == nil || !strings.Contains(err.Error(), "create config dir") {
		t.Fatalf("expected a create config dir error, got %v", err)
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("default: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("expected a parse config error, got %v", err)
	}
	if f != nil {
		t.Fatalf("expected no config alongside the error, got %+v", f)
	}
}

func TestDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if want := filepath.Join(home, ".config", "jellyfish", "config.yml"); got != want {
		t.Fatalf("DefaultPath = %q, want %q", got, want)
	}
}

func TestDefaultPathWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir resolves without HOME on this platform")
	}
	if p, err := DefaultPath(); err == nil {
		t.Fatalf("expected an error without HOME, got %q", p)
	}
}
