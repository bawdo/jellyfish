// Package cache stores the latest detection walk on disk so subsequent
// invocations within a TTL can skip the (slow) walk.
package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	data, err := os.ReadFile(path) //nolint:gosec // path is the OS cache dir + fixed filename
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

// save writes a cache file with mode 0600, creating the parent dir with 0700.
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
	return os.WriteFile(path, data, fileMode)
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

// DefaultPath returns the cache file path for the detections walk.
func DefaultPath() (string, error) {
	return cachePath("detections.json")
}

// DefaultVulnPath returns the cache file path for vulnerability rollups —
// distinct from the detections cache.
func DefaultVulnPath() (string, error) {
	return cachePath("vulnerabilities.json")
}

// Load reads the detections cache. See load for hit/miss/error semantics.
func Load(path string, ttl time.Duration) ([]iru.Detection, bool, error) {
	return load[iru.Detection](path, ttl)
}

// Save writes the detections cache.
func Save(path string, dets []iru.Detection) error {
	return save(path, dets)
}

// LoadVulnerabilities reads the vulnerability cache. See load for semantics.
func LoadVulnerabilities(path string, ttl time.Duration) ([]iru.Vulnerability, bool, error) {
	return load[iru.Vulnerability](path, ttl)
}

// SaveVulnerabilities writes the vulnerability cache.
func SaveVulnerabilities(path string, vulns []iru.Vulnerability) error {
	return save(path, vulns)
}
