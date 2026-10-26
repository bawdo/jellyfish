package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func readMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// assertNoTempFiles fails if a write left anything but want behind in dir.
func assertNoTempFiles(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	keep := map[string]bool{}
	for _, w := range want {
		keep[w] = true
	}
	for _, e := range entries {
		if !keep[e.Name()] {
			t.Errorf("unexpected leftover file %q", e.Name())
		}
	}
}

func TestWriteFileCreatesWithMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")
	if err := WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("content: got %q", got)
	}
	if m := readMode(t, path); m != 0o600 {
		t.Errorf("mode: got %o want 600", m)
	}
	assertNoTempFiles(t, dir, "out.yml")
}

// The regression this package exists for: os.WriteFile only applies perm
// when it creates the file, so an existing 0644 file stayed world-readable.
func TestWriteFileTightensExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")
	if err := os.WriteFile(path, []byte("old contents that are longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // defeat the umask
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("content: got %q", got)
	}
	if m := readMode(t, path); m != 0o600 {
		t.Errorf("mode: got %o want 600", m)
	}
	assertNoTempFiles(t, dir, "out.yml")
}

// A symlinked target (say, a dotfiles-managed config) keeps its link: the
// write lands on the file the link points at, which ends up 0600.
func TestWriteFileFollowsSymlink(t *testing.T) {
	realDir := t.TempDir()
	linkDir := t.TempDir()
	linkTarget := filepath.Join(realDir, "config.yml")
	if err := os.WriteFile(linkTarget, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "config.yml")
	if err := os.Symlink(linkTarget, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(link, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	got, err := os.ReadFile(linkTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("content via link target: got %q", got)
	}
	if m := readMode(t, linkTarget); m != 0o600 {
		t.Errorf("link target mode: got %o want 600", m)
	}
	assertNoTempFiles(t, realDir, "config.yml")
}

// A failed rename (target is a directory) leaves the target alone and cleans
// up the temp file.
func TestWriteFileFailureLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(target, []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error writing over a non-empty directory")
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("target directory disturbed: %v", err)
	}
	assertNoTempFiles(t, dir, "target")
}

func TestWriteFileMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "out.yml")
	if err := WriteFile(path, []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error when the parent directory does not exist")
	}
}
