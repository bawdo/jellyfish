package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// EmailConfig holds optional defaults for the -o email output. Every field
// is optional. Flags override these values; if both are empty the renderer
// falls back to built-in defaults (or, for "from", git user.email).
type EmailConfig struct {
	From             string `yaml:"from,omitempty"`
	DefaultTo        string `yaml:"default_to,omitempty"`
	SubjectTemplate  string `yaml:"subject_template,omitempty"`
	CVELinkPrimary   string `yaml:"cve_link_primary,omitempty"`
	CVELinkSecondary string `yaml:"cve_link_secondary,omitempty"`
	HeaderBG         string `yaml:"header_bg,omitempty"`
	LogoPath         string `yaml:"logo_path,omitempty"`
	GmailConfigured  bool   `yaml:"gmail_configured,omitempty"`
	ListIDDomain     string `yaml:"list_id_domain,omitempty"`
}

// CacheTTLMinMinutes / CacheTTLMaxMinutes bound the configurable cache TTL.
// 0 (or unset) means "use the built-in default"; 1440 minutes = 24h is the
// upper limit to discourage acting on dangerously stale data.
const (
	CacheTTLMinMinutes = 1
	CacheTTLMaxMinutes = 1440
)

// ValidateCacheTTLMinutes returns nil iff n is in [CacheTTLMinMinutes, CacheTTLMaxMinutes].
func ValidateCacheTTLMinutes(n int) error {
	if n < CacheTTLMinMinutes || n > CacheTTLMaxMinutes {
		return fmt.Errorf("cache_ttl_minutes %d out of range [%d, %d]",
			n, CacheTTLMinMinutes, CacheTTLMaxMinutes)
	}
	return nil
}

// Profile holds one tenant's settings. The Iru API base URL is never stored:
// it is always derived from Subdomain + Region via BuildBaseURL, so a tampered
// config file cannot redirect the API token to an attacker-controlled host.
type Profile struct {
	Subdomain       string      `yaml:"subdomain"`
	Region          string      `yaml:"region"`
	CacheTTLMinutes int         `yaml:"cache_ttl_minutes,omitempty"`
	Email           EmailConfig `yaml:"email,omitempty"`
}

// File maps profile name to its configuration. v1 only honours "default".
type File map[string]Profile

var subdomainRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// DefaultPath returns ~/.config/jellyfish/config.yml.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "jellyfish", "config.yml"), nil
}

// Load reads and parses the YAML file at path.
func Load(path string) (File, error) {
	// #nosec G304 - path is controlled by user via --config flag or default location
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	for name, prof := range f {
		if prof.CacheTTLMinutes != 0 {
			if err := ValidateCacheTTLMinutes(prof.CacheTTLMinutes); err != nil {
				return nil, fmt.Errorf("profile %q: %w", name, err)
			}
		}
	}
	return f, nil
}

// Save writes the file with mode 0600, creating parent directories with 0700 if needed.
func Save(path string, f File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

// BuildBaseURL derives the Iru API base URL from subdomain + region.
func BuildBaseURL(subdomain, region string) (string, error) {
	if !subdomainRe.MatchString(subdomain) {
		return "", errors.New("subdomain must match [a-z0-9-]+")
	}
	switch region {
	case "us":
		return fmt.Sprintf("https://%s.api.kandji.io/api/v1", subdomain), nil
	case "eu":
		return fmt.Sprintf("https://%s.api.eu.kandji.io/api/v1", subdomain), nil
	default:
		return "", fmt.Errorf("unsupported region %q (want us or eu)", region)
	}
}
