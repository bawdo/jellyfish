// Package cache stores the latest detection walk on disk so subsequent
// invocations within a TTL can skip the (slow) walk.
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/bawdo/jellyfish/internal/atomicfile"
	"github.com/bawdo/jellyfish/internal/iru"
)

const fileMode = 0o600
const dirMode = 0o700

// cacheVersion is the on-disk schema version. Bump it whenever the file layout
// changes so files written by an older jellyfish are treated as a miss — a
// stale cache just triggers a fresh walk, never a wrong result.
const cacheVersion = 2

// DefaultTTL is the maximum age for a cached detection list to be considered fresh.
const DefaultTTL = 15 * time.Minute

// cacheFile is the on-disk representation of any cached walk.
type cacheFile[T any] struct {
	Version   int       `json:"version"`
	FetchedAt time.Time `json:"fetched_at"`
	Items     []T       `json:"items"`
}

// load reads a cache file. Returns (items, true, nil) for a fresh entry;
// (nil, false, nil) for a miss — file absent, corrupt, wrong version, or
// expired; (nil, false, err) for I/O errors other than NotExist.
func load[T any](path string, ttl time.Duration) ([]T, bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is the OS cache dir + a filename from a tenantRe-validated key
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var f cacheFile[T]
	if err := json.Unmarshal(data, &f); err != nil {
		// Treat parse errors as a miss — corrupt cache shouldn't fail the command.
		return nil, false, nil
	}
	if f.Version != cacheVersion {
		return nil, false, nil
	}
	if time.Since(f.FetchedAt) > ttl {
		return nil, false, nil
	}
	return f.Items, true, nil
}

// Pre-tenant filenames written by older jellyfish binaries. They sit next to
// the per-tenant files in the default cache directory, may hold another
// tenant's data, and are never read any more, so a save to the default
// directory removes the one matching the cache it writes.
const (
	legacyDetectionsName      = "detections.json"
	legacyVulnerabilitiesName = "vulnerabilities.json"
)

// removeLegacy best-effort deletes the pre-tenant file legacyName from the
// default cache directory, but only when path itself lives there: Save and
// SaveVulnerabilities accept any path, and a file that merely shares the
// legacy name in some other directory is not ours to delete. It is skipped
// when path is itself the legacy file, and any failure (including NotExist)
// is ignored: a leftover file is harmless to correctness and must never fail
// a save.
func removeLegacy(path, legacyName string) {
	legacy, err := cachePath(legacyName)
	if err != nil {
		return
	}
	clean := filepath.Clean(path)
	if filepath.Dir(clean) != filepath.Dir(legacy) || clean == legacy {
		return
	}
	_ = os.Remove(legacy)
}

// save writes a cache file with mode 0600 (enforced on an existing file too,
// and replaced atomically), creating the parent dir with 0700.
func save[T any](path string, items []T) error {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	data, err := json.Marshal(cacheFile[T]{
		Version:   cacheVersion,
		FetchedAt: time.Now().UTC(),
		Items:     items,
	})
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, data, fileMode)
}

// cachePath returns ~/.cache/jellyfish/<name> or the OS-appropriate
// equivalent (os.UserCacheDir).
func cachePath(name string) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "jellyfish", name), nil
}

// tenantRe bounds a tenant key to characters that are safe in a filename:
// lowercase alphanumerics and hyphens, starting and ending alphanumeric. This
// rules out empty keys, path separators and "..".
var tenantRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// tenantCachePath returns the per-tenant cache path "<base>-<tenant>.json".
// Each tenant gets its own file so a walk cached for one tenant can never be
// served to another.
func tenantCachePath(base, tenant string) (string, error) {
	if !tenantRe.MatchString(tenant) {
		return "", fmt.Errorf("invalid cache tenant key %q", tenant)
	}
	return cachePath(base + "-" + tenant + ".json")
}

// DefaultPath returns the cache file path for the detections walk of the
// given tenant (e.g. "acme-us"). An empty or path-unsafe tenant is an error.
func DefaultPath(tenant string) (string, error) {
	return tenantCachePath("detections", tenant)
}

// DefaultVulnPath returns the cache file path for vulnerability rollups of
// the given tenant, distinct from the detections cache.
func DefaultVulnPath(tenant string) (string, error) {
	return tenantCachePath("vulnerabilities", tenant)
}

// Load reads the detections cache. See load for hit/miss/error semantics.
func Load(path string, ttl time.Duration) ([]iru.Detection, bool, error) {
	return load[iru.Detection](path, ttl)
}

// Save writes the detections cache and, when path is in the default cache
// directory, removes any legacy detections.json there.
func Save(path string, dets []iru.Detection) error {
	if err := save(path, dets); err != nil {
		return err
	}
	removeLegacy(path, legacyDetectionsName)
	return nil
}

// LoadVulnerabilities reads the vulnerability cache. See load for semantics.
func LoadVulnerabilities(path string, ttl time.Duration) ([]iru.Vulnerability, bool, error) {
	return load[iru.Vulnerability](path, ttl)
}

// SaveVulnerabilities writes the vulnerability cache and, when path is in the
// default cache directory, removes any legacy vulnerabilities.json there.
func SaveVulnerabilities(path string, vulns []iru.Vulnerability) error {
	if err := save(path, vulns); err != nil {
		return err
	}
	removeLegacy(path, legacyVulnerabilitiesName)
	return nil
}
