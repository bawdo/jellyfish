package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
)

// Standalone forms of the per-run config resolution. Commands use
// loadRunContext, which shares one config read; these let tests exercise
// each policy (client, profile, TTL) on its own.

// buildClient loads config and builds the Iru client.
func buildClient(cmd *cobra.Command) (iruClient, error) {
	lc, err := loadConfig(cmd)
	if err != nil {
		return nil, err
	}
	return lc.client()
}

// activeProfile returns the active profile from config; see
// loadedConfig.profile for the missing-file and error semantics.
func activeProfile(cmd *cobra.Command) (config.Profile, error) {
	lc, err := loadConfig(cmd)
	if err != nil {
		return config.Profile{}, err
	}
	return lc.profile()
}

// resolveCacheTTL returns the cache TTL for the active profile. Falls back
// to cache.DefaultTTL when the config file is missing (activeProfile returns
// an empty profile in that case), or the active profile has CacheTTLMinutes
// unset (zero). Other profile-load errors propagate to the caller.
func resolveCacheTTL(cmd *cobra.Command) (time.Duration, error) {
	prof, err := activeProfile(cmd)
	if err != nil {
		return 0, err
	}
	return cacheTTLForProfile(prof), nil
}
