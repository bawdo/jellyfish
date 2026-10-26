package version

import (
	"runtime/debug"
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

// stubBuildInfo replaces debug.ReadBuildInfo for one test. settings nil with
// ok false models a binary built without module support. calls counts reads.
func stubBuildInfo(t *testing.T, ok bool, settings ...debug.BuildSetting) *int {
	t.Helper()
	calls := 0
	orig := readBuildInfo
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		calls++
		if !ok {
			return nil, false
		}
		return &debug.BuildInfo{Settings: settings}, true
	}
	t.Cleanup(func() { readBuildInfo = orig })
	return &calls
}

// Without ldflags, Commit and Dirty come from the toolchain's vcs.* build
// settings; ldflags values, when present, always win.
func TestResolveFallsBackToBuildInfo(t *testing.T) {
	vcs := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "fedcba9876543210"},
		{Key: "vcs.modified", Value: "true"},
		{Key: "vcs.time", Value: "2026-01-01T00:00:00Z"},
	}
	cases := []struct {
		name, commit, dirty string
		ok                  bool
		settings            []debug.BuildSetting
		wantCommit          string
		wantDirty           bool
	}{
		{name: "nothing set", ok: true, settings: vcs, wantCommit: "fedcba9876543210", wantDirty: true},
		{name: "commit set keeps it, dirty from build info", commit: "abc", ok: true, settings: vcs, wantCommit: "abc", wantDirty: true},
		{name: "dirty false from ldflags is authoritative", dirty: "false", ok: true, settings: vcs, wantCommit: "fedcba9876543210", wantDirty: false},
		{name: "clean tree", ok: true, settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "fedcba9876543210"}, {Key: "vcs.modified", Value: "false"},
		}, wantCommit: "fedcba9876543210", wantDirty: false},
		{name: "no vcs settings", ok: true, wantCommit: "", wantDirty: false},
		{name: "no build info", ok: false, wantCommit: "", wantDirty: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Cleanup(saveAndReset())
			stubBuildInfo(t, c.ok, c.settings...)
			Version, Commit, Tag, Dirty = "dev", c.commit, "", c.dirty

			got := Resolve()
			if got.Commit != c.wantCommit {
				t.Errorf("Commit: got %q want %q", got.Commit, c.wantCommit)
			}
			if got.Dirty != c.wantDirty {
				t.Errorf("Dirty: got %v want %v", got.Dirty, c.wantDirty)
			}
			if got.Version != "dev" || got.Tag != "" {
				t.Errorf("Version/Tag changed: %+v", got)
			}
		})
	}
}

// With Commit and Dirty both set by ldflags there is nothing to fill, so
// build info is never read.
func TestResolveSkipsBuildInfoWhenLdflagsComplete(t *testing.T) {
	t.Cleanup(saveAndReset())
	calls := stubBuildInfo(t, true, debug.BuildSetting{Key: "vcs.revision", Value: "other"})
	Commit, Dirty = "abc", "false"
	if got := Resolve(); got.Commit != "abc" || got.Dirty {
		t.Errorf("got %+v", got)
	}
	if *calls != 0 {
		t.Errorf("build info read %d times, want 0", *calls)
	}
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
			stubBuildInfo(t, true)
			Version, Commit, Tag, Dirty = "v1.0.0", c.commit, "", c.dirty

			got := Resolve()
			if got.Version != "v1.0.0" || got.Tag != "" {
				t.Errorf("Version/Tag changed: %+v", got)
			}
			if c.commit != "" && got.Commit != c.commit {
				t.Errorf("Commit: got %q, want the ldflags value %q", got.Commit, c.commit)
			}
			// Dirty set by ldflags is authoritative; with no vcs.modified
			// setting an unset Dirty resolves to false.
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
