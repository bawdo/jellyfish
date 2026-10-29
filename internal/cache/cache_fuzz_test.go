package cache

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzDefaultPath checks that a tenant key can never move a cache file out
// of the jellyfish cache directory: an accepted key always lands as
// detections-<tenant>.json directly inside it, and a key that fails tenantRe
// is always refused. The key comes from config.yml, which may be tampered.
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
			if tenantRe.MatchString(tenant) {
				t.Fatalf("DefaultPath(%q) rejected a valid key: %v", tenant, err)
			}
			return
		}
		if !tenantRe.MatchString(tenant) {
			t.Fatalf("DefaultPath(%q) = %q, want an error", tenant, got)
		}
		if want := filepath.Join(dir, "detections-"+tenant+".json"); got != want || filepath.Dir(got) != dir {
			t.Fatalf("DefaultPath(%q) = %q, want %q inside %q", tenant, got, want, dir)
		}
	})
}
