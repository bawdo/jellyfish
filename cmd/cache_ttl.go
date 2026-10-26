package cmd

import (
	"time"

	"github.com/bawdo/jellyfish/internal/cache"
	"github.com/bawdo/jellyfish/internal/config"
)

// cacheTTLForProfile returns the profile's configured cache TTL, or
// cache.DefaultTTL when CacheTTLMinutes is unset (zero or negative).
func cacheTTLForProfile(prof config.Profile) time.Duration {
	if prof.CacheTTLMinutes <= 0 {
		return cache.DefaultTTL
	}
	return time.Duration(prof.CacheTTLMinutes) * time.Minute
}
