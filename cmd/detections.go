package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/bawdo/jellyfish/internal/cache"
	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/iru"
)

// fetchAllCached returns every record of a resource: from the on-disk cache
// when fresh (and useCache is set), otherwise by walking the API with a
// per-page progress line on stderr. The cache funcs are best-effort: a path
// or save failure degrades to a live walk rather than failing the command,
// with a one-line warning on stderr so the slow walk is not a mystery.
func fetchAllCached[T any](
	stderr io.Writer,
	useCache bool,
	ttl time.Duration,
	noun string,
	cachePathFn func() (string, error),
	loadFn func(string, time.Duration) ([]T, bool, error),
	saveFn func(string, []T) error,
	stream func(cb func(page []T) error) error,
) ([]T, error) {
	if ttl <= 0 {
		ttl = cache.DefaultTTL
	}
	cachePath, err := cachePathFn()
	if err != nil {
		// Non-fatal: proceed without cache, but say so when the cache was
		// wanted (under --no-cache the path is irrelevant).
		cachePath = ""
		if useCache {
			_, _ = fmt.Fprintf(stderr, "warning: cache disabled (%v); fetching live\n", err)
		}
	}

	if useCache && cachePath != "" {
		if cached, hit, err := loadFn(cachePath, ttl); err == nil && hit {
			_, _ = fmt.Fprintf(stderr, "using cached %s (%d records); pass --no-cache for fresh data\n", noun, len(cached))
			return cached, nil
		}
	}

	var all []T
	pages := 0
	err = stream(func(page []T) error {
		all = append(all, page...)
		pages++
		_, _ = fmt.Fprintf(stderr, "\rfetching %s: %d pages, %d records...", noun, pages, len(all))
		return nil
	})
	// Clear the progress line with a newline so subsequent output is on its own line.
	if pages > 0 {
		_, _ = fmt.Fprintln(stderr)
	}
	if err != nil {
		return nil, err
	}

	if useCache && cachePath != "" {
		// Cache save is best-effort; warn but don't fail the command.
		if saveErr := saveFn(cachePath, all); saveErr != nil {
			_, _ = fmt.Fprintf(stderr, "warning: could not write cache at %s: %v\n", cachePath, saveErr)
		}
	}
	return all, nil
}

// cacheTenantKey returns the on-disk cache key for the profile's tenant,
// "<subdomain>-<region>", or "" when either part is unset. An empty key makes
// the cache path lookup fail, so the walk runs live rather than sharing a
// file between tenants.
func cacheTenantKey(prof config.Profile) string {
	if prof.Subdomain == "" || prof.Region == "" {
		return ""
	}
	return prof.Subdomain + "-" + prof.Region
}

// fetchAllDetections returns every detection in the tenant, from cache when
// fresh or by walking the API. The progress indicator on stderr lets the user
// see the walk advancing. tenant is the cacheTenantKey for the active profile
// and keeps each tenant's cache in its own file.
func fetchAllDetections(ctx context.Context, client iruClient, stderr io.Writer, useCache bool, ttl time.Duration, tenant string) ([]iru.Detection, error) {
	return fetchAllCached(stderr, useCache, ttl, "detections",
		func() (string, error) { return cache.DefaultPath(tenant) }, cache.Load, cache.Save,
		func(cb func(page []iru.Detection) error) error {
			return client.ListDetectionsStream(ctx, iru.DetectionFilters{}, cb)
		})
}

// fetchAllVulnerabilities returns every vulnerability rollup in the tenant,
// from cache when fresh or by walking the API. tenant is as for
// fetchAllDetections.
func fetchAllVulnerabilities(ctx context.Context, client iruClient, stderr io.Writer, useCache bool, ttl time.Duration, tenant string) ([]iru.Vulnerability, error) {
	return fetchAllCached(stderr, useCache, ttl, "vulnerabilities",
		func() (string, error) { return cache.DefaultVulnPath(tenant) }, cache.LoadVulnerabilities, cache.SaveVulnerabilities,
		func(cb func(page []iru.Vulnerability) error) error {
			return client.ListVulnerabilitiesStream(ctx, iru.VulnerabilityFilters{}, cb)
		})
}
