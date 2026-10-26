package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/keychain"
	"github.com/bawdo/jellyfish/internal/version"
)

// resolveConfigPath returns the config file path to use: the --config flag
// value, or config.DefaultPath() when the flag is unset.
func resolveConfigPath(cmd *cobra.Command) (string, error) {
	cfgPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return "", err
	}
	if cfgPath != "" {
		return cfgPath, nil
	}
	return config.DefaultPath()
}

// keychainGet is the Keychain read used by loadedConfig.client. It is a
// variable so tests can stub it without touching the real macOS Keychain.
var keychainGet = keychain.Get

// newIruClient constructs the concrete Iru client from an already validated
// base URL and token. It is a variable so tests can inject a fake iruClient
// while still exercising the real config and Keychain resolution.
var newIruClient = func(baseURL, token string) iruClient {
	return iru.NewClient(baseURL, token, iru.WithUserAgent("jellyfish/"+version.Version))
}

// loadedConfig is a single read of the config file, shared by every value a
// command derives from it so config.yml is parsed once per run.
type loadedConfig struct {
	path string
	file config.File
	err  error // raw config.Load error, possibly wrapping os.ErrNotExist
}

// loadConfig resolves the config path and reads it once. Only a failure to
// resolve the path is returned here; load errors are kept on the result so
// each consumer can apply its own policy (loadedConfig.client needs the
// file, loadedConfig.profile tolerates its absence).
func loadConfig(cmd *cobra.Command) (loadedConfig, error) {
	cfgPath, err := resolveConfigPath(cmd)
	if err != nil {
		return loadedConfig{}, err
	}
	f, err := config.Load(cfgPath)
	return loadedConfig{path: cfgPath, file: f, err: err}, nil
}

// client builds the Iru client from the loaded config and the Keychain token.
func (lc loadedConfig) client() (iruClient, error) {
	if errors.Is(lc.err, os.ErrNotExist) {
		return nil, fmt.Errorf(`no credentials found at %s. Run "jellyfish configure" to set up`, lc.path)
	}
	if lc.err != nil {
		return nil, fmt.Errorf("read config: %w", lc.err)
	}
	prof, ok := lc.file["default"]
	if !ok {
		return nil, errors.New(`no "default" profile in config. Run "jellyfish configure" to set up`)
	}
	// Derive the base URL from subdomain + region rather than trusting any
	// stored value: this guarantees the API token is only ever sent to a
	// real Iru host, never to an attacker-controlled URL from a tampered
	// or malicious --config file.
	baseURL, err := config.BuildBaseURL(prof.Subdomain, prof.Region)
	if err != nil {
		return nil, fmt.Errorf(`invalid tenant config in %s (%w). Re-run "jellyfish configure"`, lc.path, err)
	}
	tok, err := keychainGet("default")
	if errors.Is(err, keychain.ErrNotFound) {
		return nil, errors.New(`no token found in Keychain. Run "jellyfish configure" to set up`)
	}
	if err != nil {
		return nil, fmt.Errorf("read token from Keychain: %w", err)
	}
	return newIruClient(baseURL, tok), nil
}

// profile returns the "default" profile (the only one honoured today). A
// missing config file is treated as "no profile" rather than an error so the
// email command can still rely purely on flags + git fallback. Any other load
// error (bad YAML, out-of-range values, permissions) is returned, so a broken
// config never silently drops settings like email.from.
func (lc loadedConfig) profile() (config.Profile, error) {
	if errors.Is(lc.err, os.ErrNotExist) {
		return config.Profile{}, nil
	}
	if lc.err != nil {
		return config.Profile{}, fmt.Errorf("read config: %w", lc.err)
	}
	return lc.file["default"], nil
}

// runContext is everything a cache-using command derives from config: the
// Iru client, the active profile, the cache TTL and the per-tenant cache key.
type runContext struct {
	Client      iruClient
	Profile     config.Profile
	CacheTTL    time.Duration
	CacheTenant string
}

// loadRunContext reads config.yml once and builds the full runContext from
// that single read. Errors are those of loadedConfig.client, since the client
// is the first thing resolved and needs a valid config.
func loadRunContext(cmd *cobra.Command) (runContext, error) {
	lc, err := loadConfig(cmd)
	if err != nil {
		return runContext{}, err
	}
	client, err := lc.client()
	if err != nil {
		return runContext{}, err
	}
	prof, err := lc.profile()
	if err != nil {
		return runContext{}, err
	}
	return runContext{
		Client:      client,
		Profile:     prof,
		CacheTTL:    cacheTTLForProfile(prof),
		CacheTenant: cacheTenantKey(prof),
	}, nil
}
