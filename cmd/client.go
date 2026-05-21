package cmd

import (
	"errors"
	"fmt"

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

func buildClient(cmd *cobra.Command) (iruClient, error) {
	cfgPath, err := resolveConfigPath(cmd)
	if err != nil {
		return nil, err
	}
	f, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf(`no credentials found at %s. Run "jellyfish configure" to set up`, cfgPath)
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
	tok, err := keychain.Get("default")
	if err != nil {
		return nil, fmt.Errorf(`no token found in Keychain. Run "jellyfish configure" to set up`)
	}
	return iru.NewClient(baseURL, tok, iru.WithUserAgent("jellyfish/"+version.Version)), nil
}

// activeProfile returns the named profile from config (only "default" honoured
// today). A missing config file is treated as "no profile" rather than an
// error so the email command can still rely purely on flags + git fallback.
func activeProfile(cmd *cobra.Command) (config.Profile, error) {
	cfgPath, err := resolveConfigPath(cmd)
	if err != nil {
		return config.Profile{}, err
	}
	f, err := config.Load(cfgPath)
	if err != nil {
		return config.Profile{}, nil
	}
	if prof, ok := f["default"]; ok {
		return prof, nil
	}
	return config.Profile{}, nil
}
