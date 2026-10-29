package config

import (
	"net/url"
	"testing"
)

// FuzzBuildBaseURL checks the invariant that keeps the bearer token at home:
// whatever subdomain and region a (possibly tampered) config file holds, a
// URL that BuildBaseURL accepts is always https on the expected kandji.io API
// host, with no userinfo, port, query or fragment an attacker could use to
// steer the request elsewhere.
func FuzzBuildBaseURL(f *testing.F) {
	for _, c := range [][2]string{
		{"acme", "us"},
		{"acme", "eu"},
		{"acme-corp-2", "us"},
		{"", "us"},
		{"acme", ""},
		{"acme", "au"},
		{"ACME", "us"},
		{"evil.test/", "us"},
		{"evil.test#", "us"},
		{"user@evil.test", "us"},
		{"acme:8443", "eu"},
		{"acme\n", "us"},
		{"../acme", "us"},
		{"acme", "us\n"},
	} {
		f.Add(c[0], c[1])
	}
	f.Fuzz(func(t *testing.T, subdomain, region string) {
		got, err := BuildBaseURL(subdomain, region)
		validRegion := region == "us" || region == "eu"
		if err != nil {
			if subdomainRe.MatchString(subdomain) && validRegion {
				t.Fatalf("BuildBaseURL(%q, %q) rejected a valid pair: %v", subdomain, region, err)
			}
			return
		}
		if !subdomainRe.MatchString(subdomain) || !validRegion {
			t.Fatalf("BuildBaseURL(%q, %q) = %q, want an error", subdomain, region, got)
		}
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("BuildBaseURL(%q, %q) = %q: unparseable: %v", subdomain, region, got, err)
		}
		wantHost := subdomain + ".api.kandji.io"
		if region == "eu" {
			wantHost = subdomain + ".api.eu.kandji.io"
		}
		if u.Scheme != "https" || u.Host != wantHost || u.User != nil ||
			u.Path != "/api/v1" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			t.Fatalf("BuildBaseURL(%q, %q) = %q: want https://%s/api/v1 and nothing else",
				subdomain, region, got, wantHost)
		}
	})
}
