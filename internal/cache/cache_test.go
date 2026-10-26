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

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detections.json")
	dets := []iru.Detection{
		{CVEID: "CVE-1", DeviceID: "d-1"},
		{CVEID: "CVE-2", DeviceID: "d-2"},
	}
	if err := Save(path, dets); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %o", info.Mode().Perm())
	}
	out, hit, err := Load(path, 1*time.Minute)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !hit {
		t.Fatal("expected hit")
	}
	if len(out) != 2 || out[0].CVEID != "CVE-1" {
		t.Fatalf("bad payload: %+v", out)
	}
}

func TestLoadMissingFile(t *testing.T) {
	out, hit, err := Load(filepath.Join(t.TempDir(), "missing.json"), 1*time.Minute)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if hit {
		t.Fatal("expected miss")
	}
	if out != nil {
		t.Fatalf("expected nil, got %+v", out)
	}
}

func TestLoadExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detections.json")
	if err := Save(path, []iru.Detection{{CVEID: "CVE-old"}}); err != nil {
		t.Fatal(err)
	}
	// Re-write with an old timestamp by editing the file directly.
	data, _ := os.ReadFile(path) //nolint:gosec // path is a test temp dir file
	// Use a small TTL so the current entry is expired immediately by sleeping briefly.
	time.Sleep(20 * time.Millisecond)
	_, hit, err := Load(path, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Fatal("expected miss because cache is expired")
	}
	_ = data
}

func TestLoadCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detections.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, hit, err := Load(path, 1*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if hit || out != nil {
		t.Fatal("expected silent miss on corrupt cache")
	}
}

func TestLoadRejectsSupersededFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detections.json")
	// A file written by a previous cache schema (version 1, "detections" key).
	// A schema bump must treat it as a miss, not silently decode it as empty.
	old := `{"version":1,"fetched_at":"` + time.Now().UTC().Format(time.RFC3339) +
		`","detections":[{"cve_id":"CVE-OLD","device_id":"d-old"}]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	out, hit, err := Load(path, 1*time.Minute)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if hit || out != nil {
		t.Fatalf("expected a miss for a superseded cache format, got hit=%v out=%+v", hit, out)
	}
}

func TestSaveAndLoadVulnerabilitiesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerabilities.json")
	vulns := []iru.Vulnerability{
		{CVEID: "CVE-2025-0001", Severity: "High", CVSSScore: 8.5, Status: "Active", Software: []string{"git"}},
		{CVEID: "CVE-2025-0002", Severity: "Medium", CVSSScore: 5.0, Status: "Remediated", Software: []string{"curl"}},
	}
	if err := SaveVulnerabilities(path, vulns); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %o", info.Mode().Perm())
	}
	out, hit, err := LoadVulnerabilities(path, 1*time.Minute)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !hit {
		t.Fatal("expected hit")
	}
	if len(out) != 2 || out[0].CVEID != "CVE-2025-0001" {
		t.Fatalf("bad payload: %+v", out)
	}
}

func TestLoadVulnerabilitiesMissingFile(t *testing.T) {
	out, hit, err := LoadVulnerabilities(filepath.Join(t.TempDir(), "missing.json"), 1*time.Minute)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if hit {
		t.Fatal("expected miss")
	}
	if out != nil {
		t.Fatalf("expected nil, got %+v", out)
	}
}

func TestDefaultPathsAreTenantSpecific(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	for name, fn := range map[string]func(string) (string, error){
		"DefaultPath":     DefaultPath,
		"DefaultVulnPath": DefaultVulnPath,
	} {
		a, err := fn("acme-us")
		if err != nil {
			t.Fatalf("%s(acme-us): %v", name, err)
		}
		b, err := fn("other-eu")
		if err != nil {
			t.Fatalf("%s(other-eu): %v", name, err)
		}
		if a == b {
			t.Errorf("%s: tenants share a cache path %q", name, a)
		}
		if !strings.Contains(filepath.Base(a), "acme-us") {
			t.Errorf("%s: path %q does not name the tenant", name, a)
		}
	}
	d, _ := DefaultPath("acme-us")
	v, _ := DefaultVulnPath("acme-us")
	if d == v {
		t.Errorf("detections and vulnerabilities share a path %q", d)
	}
}

func TestDefaultPathsRejectUnsafeTenant(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	for _, tenant := range []string{"", "..", "../evil", "a/b", `a\b`, "acme.us", "Acme-US", "acme us", "-"} {
		if p, err := DefaultPath(tenant); err == nil {
			t.Errorf("DefaultPath(%q): expected error, got %q", tenant, p)
		}
		if p, err := DefaultVulnPath(tenant); err == nil {
			t.Errorf("DefaultVulnPath(%q): expected error, got %q", tenant, p)
		}
	}
}

func TestCacheForOneTenantMissesForAnother(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	pathA, err := DefaultPath("acme-us")
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(pathA, []iru.Detection{{CVEID: "CVE-A", DeviceID: "d-a"}}); err != nil {
		t.Fatal(err)
	}
	pathB, err := DefaultPath("other-eu")
	if err != nil {
		t.Fatal(err)
	}
	out, hit, err := Load(pathB, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if hit || out != nil {
		t.Fatalf("tenant B read tenant A's cache: hit=%v out=%+v", hit, out)
	}
	if _, hit, _ := Load(pathA, time.Hour); !hit {
		t.Fatal("tenant A's own cache should still hit")
	}
}

func TestLoadVulnerabilitiesCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerabilities.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, hit, err := LoadVulnerabilities(path, 1*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if hit || out != nil {
		t.Fatal("expected silent miss on corrupt cache")
	}
}

// writeLegacy drops a pre-tenant cache file (as older binaries wrote it) in dir.
func writeLegacy(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(`{"version":1,"items":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSaveRemovesLegacyDetectionsFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	path, err := DefaultPath("acme-us")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyDet := writeLegacy(t, dir, "detections.json")
	legacyVuln := writeLegacy(t, dir, "vulnerabilities.json")

	if err := Save(path, []iru.Detection{{CVEID: "CVE-1"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(legacyDet); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy detections.json should be removed, stat err = %v", err)
	}
	if _, err := os.Stat(legacyVuln); err != nil {
		t.Errorf("a detections save must not touch vulnerabilities.json: %v", err)
	}
	if _, hit, _ := Load(path, time.Hour); !hit {
		t.Error("per-tenant cache should still be written")
	}
}

func TestSaveVulnerabilitiesRemovesLegacyVulnerabilitiesFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	path, err := DefaultVulnPath("acme-us")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyDet := writeLegacy(t, dir, "detections.json")
	legacyVuln := writeLegacy(t, dir, "vulnerabilities.json")

	if err := SaveVulnerabilities(path, []iru.Vulnerability{{CVEID: "CVE-1"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(legacyVuln); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy vulnerabilities.json should be removed, stat err = %v", err)
	}
	if _, err := os.Stat(legacyDet); err != nil {
		t.Errorf("a vulnerabilities save must not touch detections.json: %v", err)
	}
}

// No legacy file is the common case and must not be an error.
func TestSaveWithoutLegacyFileSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jellyfish", "detections-acme-us.json")
	if err := Save(path, []iru.Detection{{CVEID: "CVE-1"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
}

// isolateCacheDir points os.UserCacheDir at a fresh tempdir and returns the
// default jellyfish cache directory inside it, created.
func isolateCacheDir(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	path, err := DefaultPath("acme-us")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A failure to remove the legacy file (here: it is a non-empty directory) is
// best-effort and must not fail the save.
func TestSaveIgnoresLegacyRemovalFailure(t *testing.T) {
	dir := isolateCacheDir(t)
	blocker := filepath.Join(dir, "detections.json")
	if err := os.MkdirAll(filepath.Join(blocker, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "detections-acme-us.json")
	if err := Save(path, []iru.Detection{{CVEID: "CVE-1"}}); err != nil {
		t.Fatalf("save should ignore legacy removal failure: %v", err)
	}
	if _, hit, _ := Load(path, time.Hour); !hit {
		t.Error("per-tenant cache should still be written")
	}
}

// Saving to a path whose name is the legacy name itself must not delete the
// file just written.
func TestSaveToLegacyNamedPathKeepsFile(t *testing.T) {
	path := filepath.Join(isolateCacheDir(t), "detections.json")
	if err := Save(path, []iru.Detection{{CVEID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	if _, hit, _ := Load(path, time.Hour); !hit {
		t.Fatal("file written to the legacy name must survive its own save")
	}
}

// Save accepts any path; a file that only shares the legacy name in some
// other directory is not ours and must survive a save next to it.
func TestSaveOutsideDefaultDirLeavesLegacyNamedFiles(t *testing.T) {
	defaultDir := isolateCacheDir(t)
	other := t.TempDir()
	otherDet := writeLegacy(t, other, "detections.json")
	otherVuln := writeLegacy(t, other, "vulnerabilities.json")
	// A real legacy file in the default directory must also be left alone
	// by a save elsewhere.
	defaultDet := writeLegacy(t, defaultDir, "detections.json")

	if err := Save(filepath.Join(other, "detections-acme-us.json"), []iru.Detection{{CVEID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := SaveVulnerabilities(filepath.Join(other, "vulnerabilities-acme-us.json"), []iru.Vulnerability{{CVEID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{otherDet, otherVuln, defaultDet} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s must survive a save outside the default dir: %v", p, err)
		}
	}
}
