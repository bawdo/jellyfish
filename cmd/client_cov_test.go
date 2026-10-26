package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// A command without a --config flag can't resolve its config path; every
// entry point must surface that rather than reading the default config.
func TestClientMissingConfigFlagErrors(t *testing.T) {
	failIfKeychainRead(t)
	entry := map[string]func(*cobra.Command) error{
		"loadConfig":     func(c *cobra.Command) error { _, err := loadConfig(c); return err },
		"buildClient":    func(c *cobra.Command) error { _, err := buildClient(c); return err },
		"loadRunContext": func(c *cobra.Command) error { _, err := loadRunContext(c); return err },
	}
	for name, fn := range entry {
		t.Run(name, func(t *testing.T) {
			err := fn(&cobra.Command{Use: "x"})
			if err == nil || !strings.Contains(err.Error(), "config") {
				t.Fatalf("err = %v, want a missing config flag error", err)
			}
		})
	}
}

// A config that loads but can't yield a safe tenant must fail before the
// Keychain is read or a client is built.
func TestClientRejectsUnusableProfileBeforeKeychain(t *testing.T) {
	cases := []struct {
		name string
		body string
		want func(path string) []string
	}{
		{
			name: "no default profile",
			body: "other:\n  subdomain: acme\n  region: us\n",
			want: func(string) []string {
				return []string{`no "default" profile in config. Run "jellyfish configure" to set up`}
			},
		},
		{
			name: "subdomain that is not a bare label",
			body: "default:\n  subdomain: evil.example.com/\n  region: us\n",
			want: func(p string) []string {
				return []string{"invalid tenant config in " + p, "subdomain must match", `Re-run "jellyfish configure"`}
			},
		},
		{
			name: "unknown region",
			body: "default:\n  subdomain: acme\n  region: mars\n",
			want: func(p string) []string {
				return []string{"invalid tenant config in " + p, `unsupported region "mars"`}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failIfKeychainRead(t)
			gotBase, _ := stubNewIruClient(t, nil)
			path := writeRawConfig(t, tc.body)
			_, err := loadRunContext(newCmdWithConfigFlag(t, path))
			if err == nil {
				t.Fatal("expected error")
			}
			for _, w := range tc.want(path) {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %q, want it to contain %q", err, w)
				}
			}
			if *gotBase != "" {
				t.Errorf("client built for %q despite the bad profile", *gotBase)
			}
		})
	}
}
