package cmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/iru"
)

func TestCacheTenantKey(t *testing.T) {
	cases := []struct {
		prof config.Profile
		want string
	}{
		{config.Profile{Subdomain: "acme", Region: "us"}, "acme-us"},
		{config.Profile{Subdomain: "acme", Region: "eu"}, "acme-eu"},
		{config.Profile{Subdomain: "", Region: "us"}, ""},
		{config.Profile{Subdomain: "acme", Region: ""}, ""},
		{config.Profile{}, ""},
	}
	for _, tc := range cases {
		if got := cacheTenantKey(tc.prof); got != tc.want {
			t.Errorf("cacheTenantKey(%+v): got %q want %q", tc.prof, got, tc.want)
		}
	}
}

// A cache written for one tenant must never satisfy a read for another
// tenant, otherwise detections from tenant A get joined against tenant B's
// devices.
func TestFetchAllDetectionsIsolatedByTenant(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := context.Background()
	clientA := &fakeClient{detections: []iru.Detection{{CVEID: "CVE-A", DeviceID: "d-a"}}}
	clientB := &fakeClient{detections: []iru.Detection{{CVEID: "CVE-B", DeviceID: "d-b"}}}

	got, err := fetchAllDetections(ctx, clientA, io.Discard, true, time.Hour, "acme-us")
	if err != nil || len(got) != 1 || got[0].CVEID != "CVE-A" {
		t.Fatalf("tenant A walk: got %+v err %v", got, err)
	}
	got, err = fetchAllDetections(ctx, clientB, io.Discard, true, time.Hour, "other-eu")
	if err != nil || len(got) != 1 || got[0].CVEID != "CVE-B" {
		t.Fatalf("tenant B got %+v err %v; want its own live data, not tenant A's cache", got, err)
	}
	// Tenant A's cache is still intact and served from disk.
	got, err = fetchAllDetections(ctx, clientB, io.Discard, true, time.Hour, "acme-us")
	if err != nil || len(got) != 1 || got[0].CVEID != "CVE-A" {
		t.Fatalf("tenant A cache: got %+v err %v", got, err)
	}
}

func TestFetchAllVulnerabilitiesIsolatedByTenant(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := context.Background()
	clientA := &fakeClient{vulnerabilities: []iru.Vulnerability{{CVEID: "CVE-A"}}}
	clientB := &fakeClient{vulnerabilities: []iru.Vulnerability{{CVEID: "CVE-B"}}}

	if _, err := fetchAllVulnerabilities(ctx, clientA, io.Discard, true, time.Hour, "acme-us"); err != nil {
		t.Fatal(err)
	}
	got, err := fetchAllVulnerabilities(ctx, clientB, io.Discard, true, time.Hour, "other-eu")
	if err != nil || len(got) != 1 || got[0].CVEID != "CVE-B" {
		t.Fatalf("tenant B got %+v err %v; want its own live data", got, err)
	}
}

// An unknown tenant (empty key) must not read or write a shared cache file.
func TestFetchAllDetectionsEmptyTenantSkipsCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := context.Background()
	clientA := &fakeClient{detections: []iru.Detection{{CVEID: "CVE-A"}}}
	clientB := &fakeClient{detections: []iru.Detection{{CVEID: "CVE-B"}}}
	if _, err := fetchAllDetections(ctx, clientA, io.Discard, true, time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	got, err := fetchAllDetections(ctx, clientB, io.Discard, true, time.Hour, "")
	if err != nil || len(got) != 1 || got[0].CVEID != "CVE-B" {
		t.Fatalf("empty tenant got %+v err %v; want a live walk every time", got, err)
	}
}

// When the cache is wanted but its path can't be resolved, the user gets one
// warning line instead of a silent 30-90 s live walk on every run.
func TestFetchAllDetectionsWarnsWhenCachePathUnresolvable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	client := &fakeClient{detections: []iru.Detection{{CVEID: "CVE-A"}}}
	var stderr bytes.Buffer
	got, err := fetchAllDetections(context.Background(), client, &stderr, true, time.Hour, "")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v err %v; want the live walk to still succeed", got, err)
	}
	out := stderr.String()
	if n := strings.Count(out, "warning: cache disabled"); n != 1 {
		t.Fatalf("want exactly one cache-disabled warning, got %d in:\n%s", n, out)
	}
	if !strings.Contains(out, "fetching live") || !strings.Contains(out, "invalid cache tenant key") {
		t.Errorf("warning should name the reason and say it is fetching live, got:\n%s", out)
	}
}

func TestFetchAllVulnerabilitiesWarnsWhenCachePathUnresolvable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	client := &fakeClient{vulnerabilities: []iru.Vulnerability{{CVEID: "CVE-A"}}}
	var stderr bytes.Buffer
	if _, err := fetchAllVulnerabilities(context.Background(), client, &stderr, true, time.Hour, "-bad-"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "warning: cache disabled") {
		t.Errorf("missing cache-disabled warning, got:\n%s", stderr.String())
	}
}

// --no-cache is an explicit opt-out, so an unresolvable path is not news.
func TestFetchAllDetectionsNoWarningWhenCacheNotWanted(t *testing.T) {
	client := &fakeClient{detections: []iru.Detection{{CVEID: "CVE-A"}}}
	var stderr bytes.Buffer
	if _, err := fetchAllDetections(context.Background(), client, &stderr, false, time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "warning") {
		t.Errorf("no warning expected under --no-cache, got:\n%s", stderr.String())
	}
}
