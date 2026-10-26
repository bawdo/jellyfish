package version

import (
	"testing"
)

func TestResolveUsesLdflagsValues(t *testing.T) {
	t.Cleanup(saveAndReset())
	Version = "v9.9.9"
	Commit = "abcdef0123456789"
	Tag = "v9.9.9"
	Dirty = "true"

	got := Resolve()
	if got.Version != "v9.9.9" {
		t.Errorf("Version: got %q", got.Version)
	}
	if got.Commit != "abcdef0123456789" {
		t.Errorf("Commit: got %q", got.Commit)
	}
	if got.Tag != "v9.9.9" {
		t.Errorf("Tag: got %q", got.Tag)
	}
	if !got.Dirty {
		t.Errorf("Dirty: want true")
	}
}

func TestResolveDirtyDefaults(t *testing.T) {
	t.Cleanup(saveAndReset())
	Dirty = "" // unset

	got := Resolve()
	// Cannot assert a concrete value here because go test populates vcs.*
	// settings only when run from a git tree. Just confirm it doesn't
	// panic and returns a struct.
	_ = got
}

// With only some ldflags set, Resolve consults build info for the rest but
// must never overwrite a value the build did set.
func TestResolvePartialLdflagsKeepsSetValues(t *testing.T) {
	cases := []struct {
		name, commit, dirty string
		wantDirty           bool
	}{
		{"commit set, dirty unset", "abcdef0123456789", "", false},
		{"commit unset, dirty false", "", "false", false},
		{"commit unset, dirty true", "", "true", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Cleanup(saveAndReset())
			Version, Commit, Tag, Dirty = "v1.0.0", c.commit, "", c.dirty

			got := Resolve()
			if got.Version != "v1.0.0" || got.Tag != "" {
				t.Errorf("Version/Tag changed: %+v", got)
			}
			if c.commit != "" && got.Commit != c.commit {
				t.Errorf("Commit: got %q, want the ldflags value %q", got.Commit, c.commit)
			}
			// Dirty set by ldflags is authoritative; a go test binary has no
			// vcs.modified setting, so an unset Dirty resolves to false here.
			if got.Dirty != c.wantDirty {
				t.Errorf("Dirty: got %v, want %v", got.Dirty, c.wantDirty)
			}
		})
	}
}

// saveAndReset returns a cleanup func that restores the package-level vars
// to their default ("dev"/empty) state so tests can't leak state into each
// other or into the cmd-layer tests that also touch Version.
func saveAndReset() func() {
	origV, origC, origT, origD := Version, Commit, Tag, Dirty
	return func() {
		Version, Commit, Tag, Dirty = origV, origC, origT, origD
	}
}
