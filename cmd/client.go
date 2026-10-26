package cmd

import (
	"errors"
	"fmt"
	"os"

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

// keychainGet is the Keychain read used by buildClient. It is a variable so
// tests can stub it without touching the real macOS Keychain.
var keychainGet = keychain.Get

func buildClient(cmd *cobra.Command) (iruClient, error) {
	cfgPath, err := resolveConfigPath(cmd)
	if err != nil {
		return nil, err
	}
	f, err := config.Load(cfgPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf(`no credentials found at %s. Run "jellyfish configure" to set up`, cfgPath)
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	prof, ok := f["default"]
	if !ok {
		return nil, errors.New(`no "default" profile in config. Run "jellyfish configure" to set up`)
	}
	// Derive the base URL from subdomain + region rather than trusting any
	// stored value: this guarantees the API token is only ever sent to a
	// real Iru host, never to an attacker-controlled URL from a tampered
	// or malicious --config file.
	baseURL, err := config.BuildBaseURL(prof.Subdomain, prof.Region)
	if err != nil {
		return nil, fmt.Errorf(`invalid tenant config in %s (%w). Re-run "jellyfish configure"`, cfgPath, err)
	}
	tok, err := keychainGet("default")
	if errors.Is(err, keychain.ErrNotFound) {
		return nil, errors.New(`no token found in Keychain. Run "jellyfish configure" to set up`)
	}
	if err != nil {
		return nil, fmt.Errorf("read token from Keychain: %w", err)
	}
	return iru.NewClient(baseURL, tok, iru.WithUserAgent("jellyfish/"+version.Version)), nil
}

// activeProfile returns the named profile from config (only "default" honoured
// today). A missing config file is treated as "no profile" rather than an
// error so the email command can still rely purely on flags + git fallback.
// Any other load error (bad YAML, out-of-range values, permissions) is
// returned, so a broken config never silently drops settings like email.from.
func activeProfile(cmd *cobra.Command) (config.Profile, error) {
	cfgPath, err := resolveConfigPath(cmd)
	if err != nil {
		return config.Profile{}, err
	}
	f, err := config.Load(cfgPath)
	if errors.Is(err, os.ErrNotExist) {
		return config.Profile{}, nil
	}
	if err != nil {
		return config.Profile{}, fmt.Errorf("read config: %w", err)
	}
	if prof, ok := f["default"]; ok {
		return prof, nil
	}
	return config.Profile{}, nil
}
