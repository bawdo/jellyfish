package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzDefaultPath checks that a tenant key can never move a cache file out
// of the jellyfish cache directory: an accepted key always lands as
// detections-<tenant>.json directly inside it, with no separator or ".." in
// the name. The key comes from config.yml, which may be tampered. These
// invariants are checked on the path itself rather than by mirroring
// tenantRe, so loosening the regex can't loosen the test with it.
func FuzzDefaultPath(f *testing.F) {
	f.Setenv("HOME", f.TempDir())
	f.Setenv("XDG_CACHE_HOME", f.TempDir())
	base, err := os.UserCacheDir()
	if err != nil {
		f.Fatalf("UserCacheDir: %v", err)
	}
	dir := filepath.Join(base, "jellyfish")
	for _, s := range []string{
		"acme-us", "other-eu", "a", "a1-b2-c3",
		"", "-", "..", "../evil", "a/b", `a\b`, "acme.us", "Acme-US", "acme us",
		"acme-us\n", "acme-us/../../x", "acme\x00us",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, tenant string) {
		got, err := DefaultPath(tenant)
		if err != nil {
			// Lowercase letters and digits alone are always a safe key.
			if tenant != "" && !strings.ContainsFunc(tenant, func(r rune) bool {
				return (r < 'a' || r > 'z') && (r < '0' || r > '9')
			}) {
				t.Fatalf("DefaultPath(%q) rejected a plain alphanumeric key: %v", tenant, err)
			}
			return
		}
		name := filepath.Base(got)
		if filepath.Dir(got) != dir {
			t.Fatalf("DefaultPath(%q) = %q: not directly inside %q", tenant, got, dir)
		}
		if strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, filepath.Separator) {
			t.Fatalf("DefaultPath(%q) = %q: name %q contains a path separator", tenant, got, name)
		}
		if strings.Contains(name, "..") {
			t.Fatalf("DefaultPath(%q) = %q: name %q contains \"..\"", tenant, got, name)
		}
		if strings.ContainsRune(name, 0) {
			t.Fatalf("DefaultPath(%q) = %q: name %q contains NUL", tenant, got, name)
		}
		if name != "detections-"+tenant+".json" {
			t.Fatalf("DefaultPath(%q) = %q: name %q, want %q", tenant, got, name, "detections-"+tenant+".json")
		}
	})
}
