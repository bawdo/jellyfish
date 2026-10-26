package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/cache"
)

// resolveCacheTTL returns the cache TTL for the active profile. Falls back
// to cache.DefaultTTL when the config file is missing (activeProfile returns
// an empty profile in that case), or the active profile has CacheTTLMinutes
// unset (zero). Other profile-load errors propagate to the caller.
//
// Called from every cache-using command's RunE, so a re-read of the YAML
// happens on every CLI invocation (no in-process config cache).
func resolveCacheTTL(cmd *cobra.Command) (time.Duration, error) {
	prof, err := activeProfile(cmd)
	if err != nil {
		return 0, err
	}
	if prof.CacheTTLMinutes <= 0 {
		return cache.DefaultTTL, nil
	}
	return time.Duration(prof.CacheTTLMinutes) * time.Minute, nil
}
