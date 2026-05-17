# Cache TTL Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the detection/vulnerability cache TTL configurable per-profile via `~/.config/jellyfish/config.yml` and a new `jellyfish configure cache` subcommand. The hardcoded 15-minute default stays as a fallback.

**Architecture:** Add `CacheTTLMinutes int` to `config.Profile`. Add `resolveCacheTTL(cmd)` in `cmd/` that reads the active profile on every invocation and returns a `time.Duration` (or the existing `cache.DefaultTTL`). Thread that duration into the existing `fetchAllDetections` / `fetchAllVulnerabilities` helpers via each command's opts struct. Add a `configure cache` subcommand that mirrors `configure email`. `internal/cache` is not modified.

**Tech Stack:** Go 1.x, cobra (CLI), gopkg.in/yaml.v3 (config), standard library `testing`.

**Spec:** `docs/superpowers/specs/2026-05-17-cache-ttl-config-design.md`

**Target version:** v1.2.0 (tag on merge to master).

---

## File Structure

**New files:**
- `cmd/cache_ttl.go` — `resolveCacheTTL(cmd *cobra.Command) (time.Duration, error)` helper.
- `cmd/cache_ttl_test.go` — unit tests for the resolver.
- `cmd/configure_cache.go` — `jellyfish configure cache` subcommand + `runConfigureCache`.
- `cmd/configure_cache_test.go` — unit tests for the subcommand.

**Modified files:**
- `internal/config/config.go` — add `CacheTTLMinutes` field, `CacheTTLMinMinutes`/`CacheTTLMaxMinutes` constants, `ValidateCacheTTLMinutes` func, and call validation from `Load`.
- `internal/config/config_test.go` — add tests for the new field + validator.
- `cmd/detections.go` — `fetchAllDetections` / `fetchAllVulnerabilities` gain a `ttl time.Duration` parameter with a defensive `ttl <= 0` → `cache.DefaultTTL` guard.
- `cmd/overview.go` — `overviewOpts.CacheTTL`, `assembleOverview` gains `ttl` param, `RunE` calls `resolveCacheTTL`.
- `cmd/user.go` — `userShowOpts.CacheTTL`, `RunE` calls `resolveCacheTTL`, pass through to `fetchAllDetections`.
- `cmd/users.go` — `usersSendEmailOpts.CacheTTL`, `RunE` calls `resolveCacheTTL`, pass through.
- `cmd/vulns.go` — `vulnsListOpts.CacheTTL` and `vulnsSummaryOpts.CacheTTL`, `RunE` populates each, pass through.
- `cmd/configure.go` — `newConfigureCmd()` calls `c.AddCommand(newConfigureCacheCmd())`.
- `cmd/overview_test.go` — update existing `assembleOverview(...)` calls to pass a zero `time.Duration` (which the fetcher defaults). Add one new test that a non-zero TTL is honoured.
- `README.md` — remove stale `--cache-ttl` bullet at line 796; add a sentence under "Detection cache" pointing to `configure cache`.

---

## Task 1: Add `CacheTTLMinutes` field and validator to `internal/config`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write failing tests for `ValidateCacheTTLMinutes`**

Append to `internal/config/config_test.go`:

```go
func TestValidateCacheTTLMinutes(t *testing.T) {
	good := []int{1, 15, 60, 1440}
	for _, n := range good {
		if err := ValidateCacheTTLMinutes(n); err != nil {
			t.Errorf("ValidateCacheTTLMinutes(%d): unexpected err: %v", n, err)
		}
	}
	bad := []int{0, -1, -100, 1441, 100000}
	for _, n := range bad {
		if err := ValidateCacheTTLMinutes(n); err == nil {
			t.Errorf("ValidateCacheTTLMinutes(%d): expected error, got nil", n)
		}
	}
}
```

- [ ] **Step 2: Run test, confirm it fails**

Run: `go test ./internal/config/ -run TestValidateCacheTTLMinutes -v`

Expected: FAIL with `undefined: ValidateCacheTTLMinutes`.

- [ ] **Step 3: Add field, constants, validator to `internal/config/config.go`**

Add the constants and function near the top of the file (below the existing `EmailConfig` block):

```go
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
```

Add the field to `Profile`:

```go
type Profile struct {
	Subdomain       string      `yaml:"subdomain"`
	Region          string      `yaml:"region"`
	BaseURL         string      `yaml:"base_url"`
	CacheTTLMinutes int         `yaml:"cache_ttl_minutes,omitempty"`
	Email           EmailConfig `yaml:"email,omitempty"`
}
```

- [ ] **Step 4: Run test, confirm it passes**

Run: `go test ./internal/config/ -run TestValidateCacheTTLMinutes -v`

Expected: PASS.

- [ ] **Step 5: Write failing test for `Load` rejecting an invalid YAML value**

Append to `internal/config/config_test.go`:

```go
func TestLoadRejectsInvalidCacheTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	content := []byte("default:\n  subdomain: acme\n  region: us\n  cache_ttl_minutes: -5\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: expected error for cache_ttl_minutes=-5, got nil")
	}
	if !strings.Contains(err.Error(), "cache_ttl_minutes") {
		t.Errorf("Load error %q: want substring %q", err, "cache_ttl_minutes")
	}
}
```

Add `"strings"` to the test file's imports if it's not already there.

- [ ] **Step 6: Run test, confirm it fails**

Run: `go test ./internal/config/ -run TestLoadRejectsInvalidCacheTTL -v`

Expected: FAIL — `Load` currently doesn't validate.

- [ ] **Step 7: Add validation inside `Load`**

In `internal/config/config.go`, modify `Load` so that after `yaml.Unmarshal` succeeds, it validates any non-zero `CacheTTLMinutes` across all profiles:

```go
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
```

- [ ] **Step 8: Run test, confirm it passes**

Run: `go test ./internal/config/ -run TestLoadRejectsInvalidCacheTTL -v`

Expected: PASS.

- [ ] **Step 9: Write failing tests for round-trip and omitempty**

Append to `internal/config/config_test.go`:

```go
func TestSaveLoadPreservesCacheTTLMinutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	in := File{"default": Profile{
		Subdomain: "acme", Region: "us", BaseURL: "https://acme.api.kandji.io/api/v1",
		CacheTTLMinutes: 30,
	}}
	if err := Save(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := out["default"].CacheTTLMinutes; got != 30 {
		t.Errorf("CacheTTLMinutes: got %d want 30", got)
	}
}

func TestSaveOmitsZeroCacheTTLMinutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	in := File{"default": Profile{
		Subdomain: "acme", Region: "us", BaseURL: "https://acme.api.kandji.io/api/v1",
		// CacheTTLMinutes is 0 - should be omitted from YAML
	}}
	if err := Save(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), "cache_ttl_minutes") {
		t.Errorf("zero CacheTTLMinutes was written to YAML:\n%s", raw)
	}
}
```

- [ ] **Step 10: Run tests, confirm they pass**

Run: `go test ./internal/config/ -v`

Expected: all PASS, including the two new round-trip tests (omitempty handles zero correctly already).

- [ ] **Step 11: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): added cache_ttl_minutes profile field"
```

---

## Task 2: Add `resolveCacheTTL` helper in `cmd/`

**Files:**
- Create: `cmd/cache_ttl.go`
- Create: `cmd/cache_ttl_test.go`

- [ ] **Step 1: Write failing tests**

Create `cmd/cache_ttl_test.go`:

```go
package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/cache"
	"github.com/bawdo/jellyfish/internal/config"
)

// newCmdWithConfigFlag returns a bare *cobra.Command with the --config flag
// registered, used to drive resolveCacheTTL in tests without standing up the
// full root command tree.
func newCmdWithConfigFlag(t *testing.T, cfgPath string) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "x"}
	c.PersistentFlags().String("config", "", "")
	if cfgPath != "" {
		if err := c.PersistentFlags().Set("config", cfgPath); err != nil {
			t.Fatalf("set --config: %v", err)
		}
	}
	return c
}

func TestResolveCacheTTLMissingConfigReturnsDefault(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yml")
	c := newCmdWithConfigFlag(t, missing)
	got, err := resolveCacheTTL(c)
	if err != nil {
		t.Fatalf("resolveCacheTTL: %v", err)
	}
	if got != cache.DefaultTTL {
		t.Errorf("got %v, want %v (DefaultTTL)", got, cache.DefaultTTL)
	}
}

func TestResolveCacheTTLZeroFieldReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us", BaseURL: "https://acme/api/v1",
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := newCmdWithConfigFlag(t, path)
	got, err := resolveCacheTTL(c)
	if err != nil {
		t.Fatalf("resolveCacheTTL: %v", err)
	}
	if got != cache.DefaultTTL {
		t.Errorf("got %v, want %v", got, cache.DefaultTTL)
	}
}

func TestResolveCacheTTLHonoursProfileValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := config.Save(path, config.File{"default": config.Profile{
		Subdomain: "acme", Region: "us", BaseURL: "https://acme/api/v1",
		CacheTTLMinutes: 30,
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := newCmdWithConfigFlag(t, path)
	got, err := resolveCacheTTL(c)
	if err != nil {
		t.Fatalf("resolveCacheTTL: %v", err)
	}
	if got != 30*time.Minute {
		t.Errorf("got %v, want %v", got, 30*time.Minute)
	}
}

// Guards against silent regression if activeProfile ever starts returning
// non-NotExist errors that resolveCacheTTL should propagate.
var _ = errors.New
var _ = os.ErrNotExist
```

- [ ] **Step 2: Run tests, confirm they fail**

Run: `go test ./cmd/ -run TestResolveCacheTTL -v`

Expected: FAIL with `undefined: resolveCacheTTL`.

- [ ] **Step 3: Create the resolver**

Create `cmd/cache_ttl.go`:

```go
package cmd

import (
	"errors"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/cache"
)

// resolveCacheTTL returns the cache TTL for the active profile. Falls back
// to cache.DefaultTTL when the config file is missing, or the active
// profile has CacheTTLMinutes unset (zero). Other profile-load errors
// propagate to the caller.
//
// Called from every cache-using command's RunE, so a re-read of the YAML
// happens on every CLI invocation (no in-process config cache).
func resolveCacheTTL(cmd *cobra.Command) (time.Duration, error) {
	prof, err := activeProfile(cmd)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache.DefaultTTL, nil
		}
		return 0, err
	}
	if prof.CacheTTLMinutes <= 0 {
		return cache.DefaultTTL, nil
	}
	return time.Duration(prof.CacheTTLMinutes) * time.Minute, nil
}
```

- [ ] **Step 4: Run tests, confirm they pass**

Run: `go test ./cmd/ -run TestResolveCacheTTL -v`

Expected: all three PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/cache_ttl.go cmd/cache_ttl_test.go
git commit -m "feat(cmd): added resolveCacheTTL helper"
```

---

## Task 3: Plumb `ttl` through the fetchers in `cmd/detections.go`

**Files:**
- Modify: `cmd/detections.go`

This task adds a `ttl time.Duration` parameter to both fetchers. Callers are updated in later tasks (one task per command file). To keep the build green between tasks, this task also updates **every** call site to pass `cache.DefaultTTL` for now, which preserves current behaviour. Tasks 4-7 then replace those literal `cache.DefaultTTL` calls with `opts.CacheTTL` resolved per-invocation.

- [ ] **Step 1: Modify `fetchAllDetections` signature and add defensive guard**

In `cmd/detections.go`, change the function signature to add `ttl time.Duration`, replace `cache.DefaultTTL` with the argument, and add the guard:

```go
func fetchAllDetections(ctx context.Context, client iruClient, stderr io.Writer, useCache bool, ttl time.Duration) ([]iru.Detection, error) {
	if ttl <= 0 {
		ttl = cache.DefaultTTL
	}
	cachePath, err := cache.DefaultPath()
	if err != nil {
		cachePath = ""
	}

	if useCache && cachePath != "" {
		if cached, hit, err := cache.Load(cachePath, ttl); err == nil && hit {
			_, _ = fmt.Fprintf(stderr, "using cached detections (%d records); pass --no-cache for fresh data\n", len(cached))
			return cached, nil
		}
	}
	// (rest unchanged)
```

Add `"time"` to the imports.

- [ ] **Step 2: Modify `fetchAllVulnerabilities` the same way**

```go
func fetchAllVulnerabilities(ctx context.Context, client iruClient, stderr io.Writer, useCache bool, ttl time.Duration) ([]iru.Vulnerability, error) {
	if ttl <= 0 {
		ttl = cache.DefaultTTL
	}
	cachePath, err := cache.DefaultVulnPath()
	if err != nil {
		cachePath = ""
	}

	if useCache && cachePath != "" {
		if cached, hit, err := cache.LoadVulnerabilities(cachePath, ttl); err == nil && hit {
			_, _ = fmt.Fprintf(stderr, "using cached vulnerabilities (%d records); pass --no-cache for fresh data\n", len(cached))
			return cached, nil
		}
	}
	// (rest unchanged)
```

- [ ] **Step 3: Update every call site to pass `cache.DefaultTTL`**

Edit the following call sites to add the new arg. The change is purely mechanical — no behaviour change because `DefaultTTL` is what the fetcher used internally before this task.

- `cmd/overview.go:40`:
  ```go
  allDetections, err := fetchAllDetections(ctx, client, stderr, !noCache, cache.DefaultTTL)
  ```
- `cmd/user.go:109`:
  ```go
  all, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, cache.DefaultTTL)
  ```
- `cmd/users.go:184`:
  ```go
  allDetections, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, cache.DefaultTTL)
  ```
- `cmd/vulns.go:85`:
  ```go
  all, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, cache.DefaultTTL)
  ```
- `cmd/vulns.go:106`:
  ```go
  ds, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, cache.DefaultTTL)
  ```
- `cmd/vulns.go:241`:
  ```go
  all, err := fetchAllVulnerabilities(ctx, client, stderr, !opts.NoCache, cache.DefaultTTL)
  ```

For each file you edit, add `"github.com/bawdo/jellyfish/internal/cache"` to imports if it's not already there. (At a minimum `cmd/overview.go` already imports it indirectly via the fetcher call; verify with `goimports` or by running `go build ./...`.)

- [ ] **Step 4: Build everything**

Run: `go build ./...`

Expected: succeeds, no "wrong number of args" errors.

- [ ] **Step 5: Run the full test suite**

Run: `go test ./...`

Expected: all tests PASS. Behaviour is unchanged — callers still pass `DefaultTTL`.

- [ ] **Step 6: Commit**

```bash
git add cmd/detections.go cmd/overview.go cmd/user.go cmd/users.go cmd/vulns.go
git commit -m "feat(cache): plumbed ttl parameter through fetchers"
```

---

## Task 4: Wire `CacheTTL` into `overview` command

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/overview_test.go`

- [ ] **Step 1: Update existing `assembleOverview` test calls (5 sites)**

In `cmd/overview_test.go`, add a `time.Duration` argument (zero value, which the fetcher's guard turns into `DefaultTTL`) to each `assembleOverview` call. The existing imports already include `"time"`.

Change `cmd/overview_test.go:73`:
```go
view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil, time.Duration(0))
```

Change `cmd/overview_test.go:128`:
```go
_, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil, time.Duration(0))
```

Change `cmd/overview_test.go:149`:
```go
view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil, time.Duration(0))
```

Change `cmd/overview_test.go:529`:
```go
_, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false, nil, time.Duration(0))
```

Change `cmd/overview_test.go:721`:
```go
view, err := assembleOverview(context.Background(), c, &stderr, false, filter, time.Duration(0))
```

(These tests will currently fail to compile because `assembleOverview` doesn't yet take a `ttl` param. That's intentional — TDD: red first.)

- [ ] **Step 2: Run overview tests, confirm they fail to compile**

Run: `go test ./cmd/ -run TestAssembleOverview -v`

Expected: build failure — `too many arguments in call to assembleOverview`.

- [ ] **Step 3: Update `assembleOverview` signature**

In `cmd/overview.go`, change line 39:

```go
func assembleOverview(ctx context.Context, client iruClient, stderr io.Writer, noCache bool, userFilter map[string]struct{}, ttl time.Duration) (email.OverviewView, error) {
	allDetections, err := fetchAllDetections(ctx, client, stderr, !noCache, ttl)
	// (rest unchanged)
```

Then remove the `cache` import-only reference from `cmd/overview.go` if Task 3 added it (it's no longer needed here because the resolver lives elsewhere and `ttl` is passed in directly — `goimports` will tidy this for you).

- [ ] **Step 4: Add `CacheTTL` to `overviewOpts`**

In `cmd/overview.go` around line 308, add the field:

```go
type overviewOpts struct {
	Output         string
	ExplicitOutput string
	PerUser        bool
	CSVPath        string
	Emails         string
	CSVEmailColumn string
	EmailFlags     emailFlagValues
	DryRun         bool
	Yes            bool
	NoCache        bool
	CacheTTL       time.Duration
	Profile        config.Profile
	EmailNow       time.Time
	// (rest unchanged)
}
```

- [ ] **Step 5: Populate `CacheTTL` in `RunE`**

In `cmd/overview.go` `newOverviewCmd`, inside `RunE`, after the `buildClient` call, add:

```go
ttl, err := resolveCacheTTL(cmd)
if err != nil {
	return err
}
opts.CacheTTL = ttl
```

- [ ] **Step 6: Pass `opts.CacheTTL` into `assembleOverview` in `runOverview`**

In `cmd/overview.go` around line 398, change:

```go
view, err := assembleOverview(ctx, client, stderr, opts.NoCache, filter, opts.CacheTTL)
```

- [ ] **Step 7: Write a test that proves a non-zero TTL is plumbed through**

Append to `cmd/overview_test.go`:

```go
func TestAssembleOverviewAcceptsCustomTTL(t *testing.T) {
	// We only assert the call compiles and runs with a non-zero ttl
	// argument; cache behaviour is exercised in the cache package tests.
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users: []iru.User{{ID: "u1", Name: "U1", Email: "u1@x"}},
			detections: []iru.Detection{
				{DeviceID: "d1", CVEID: "CVE-A", CVSSScore: 5.0, Severity: "Medium"},
			},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, true /* noCache so we skip disk */, nil, 30*time.Minute)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}
	if len(view.Users) != 1 {
		t.Fatalf("Users len: got %d want 1", len(view.Users))
	}
}
```

- [ ] **Step 8: Run overview tests**

Run: `go test ./cmd/ -run TestAssembleOverview -v`

Expected: all PASS (including the new one).

- [ ] **Step 9: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(overview): wired cache_ttl_minutes through opts"
```

---

## Task 5: Wire `CacheTTL` into `user show` command

**Files:**
- Modify: `cmd/user.go`

- [ ] **Step 1: Add field to `userShowOpts`**

Locate the `userShowOpts` struct in `cmd/user.go` (search for `type userShowOpts struct`). Add a `CacheTTL time.Duration` field next to the existing `NoCache bool` field. Add `"time"` to imports if not already present.

- [ ] **Step 2: Populate `CacheTTL` in `RunE`**

In `cmd/user.go` `newUserCmd`, inside `RunE`, after `buildClient(cmd)` succeeds, add:

```go
ttl, err := resolveCacheTTL(cmd)
if err != nil {
	return err
}
opts.CacheTTL = ttl
```

- [ ] **Step 3: Pass `opts.CacheTTL` to the fetcher**

In `cmd/user.go` line 109, change:

```go
all, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, opts.CacheTTL)
```

Then remove any stale `"github.com/bawdo/jellyfish/internal/cache"` import added by Task 3 if it's no longer referenced — `goimports` / `go vet` will flag this.

- [ ] **Step 4: Build + run user tests**

Run: `go test ./cmd/ -run TestUser -v`

Expected: PASS. Existing tests construct `userShowOpts{...}` without `CacheTTL`, which defaults to zero, which the fetcher's guard turns into `DefaultTTL` — identical to prior behaviour.

- [ ] **Step 5: Commit**

```bash
git add cmd/user.go
git commit -m "feat(user): wired cache_ttl_minutes through opts"
```

---

## Task 6: Wire `CacheTTL` into `users send-email` command

**Files:**
- Modify: `cmd/users.go`

- [ ] **Step 1: Add field to `usersSendEmailOpts`**

Locate `type usersSendEmailOpts struct` in `cmd/users.go`. Add `CacheTTL time.Duration` next to `NoCache bool`. Add `"time"` import if missing.

- [ ] **Step 2: Populate `CacheTTL` in `RunE`**

In `cmd/users.go` `newUsersSendEmailCmd`, inside `RunE`, after `buildClient(cmd)` succeeds:

```go
ttl, err := resolveCacheTTL(cmd)
if err != nil {
	return err
}
opts.CacheTTL = ttl
```

- [ ] **Step 3: Pass `opts.CacheTTL` to the fetcher**

In `cmd/users.go` line 184, change:

```go
allDetections, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, opts.CacheTTL)
```

Remove the temporary `cache` import if `goimports` flags it.

- [ ] **Step 4: Build + run users tests**

Run: `go test ./cmd/ -run TestUsers -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/users.go
git commit -m "feat(users): wired cache_ttl_minutes through opts"
```

---

## Task 7: Wire `CacheTTL` into `vulns list` and `vulns summary` commands

**Files:**
- Modify: `cmd/vulns.go`

- [ ] **Step 1: Add fields to both opts structs**

Locate `type vulnsListOpts struct` and `type vulnsSummaryOpts struct` in `cmd/vulns.go`. Add `CacheTTL time.Duration` next to `NoCache bool` in each. Add `"time"` import if missing (it's likely already there for `vulnsSummaryOpts.EmailNow`).

- [ ] **Step 2: Populate `CacheTTL` in `newVulnsListCmd.RunE`**

In `newVulnsListCmd`, inside `RunE`, after the client is built:

```go
ttl, err := resolveCacheTTL(cmd)
if err != nil {
	return err
}
opts.CacheTTL = ttl
```

- [ ] **Step 3: Populate `CacheTTL` in `newVulnsSummaryCmd.RunE`**

Same change in `newVulnsSummaryCmd`'s `RunE`, after `buildClient(cmd)` succeeds.

- [ ] **Step 4: Pass `opts.CacheTTL` to the three fetcher call sites in `runVulnsList`**

`cmd/vulns.go:85`:
```go
all, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, opts.CacheTTL)
```

`cmd/vulns.go:106`:
```go
ds, err := fetchAllDetections(ctx, client, stderr, !opts.NoCache, opts.CacheTTL)
```

- [ ] **Step 5: Pass `opts.CacheTTL` to the fetcher in `runVulnsSummary`**

`cmd/vulns.go:241`:
```go
all, err := fetchAllVulnerabilities(ctx, client, stderr, !opts.NoCache, opts.CacheTTL)
```

Remove the temporary `cache` import if `goimports` flags it.

- [ ] **Step 6: Build + run vulns tests**

Run: `go test ./cmd/ -run TestVulns -v`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/vulns.go
git commit -m "feat(vulns): wired cache_ttl_minutes through opts"
```

---

## Task 8: Add `jellyfish configure cache` subcommand

**Files:**
- Create: `cmd/configure_cache.go`
- Create: `cmd/configure_cache_test.go`
- Modify: `cmd/configure.go`

- [ ] **Step 1: Write failing tests**

Create `cmd/configure_cache_test.go`:

```go
package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/config"
)

func writeBasicConfig(t *testing.T, dir string, ttl int) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	prof := config.Profile{
		Subdomain: "acme", Region: "us", BaseURL: "https://acme.api.kandji.io/api/v1",
	}
	if ttl > 0 {
		prof.CacheTTLMinutes = ttl
	}
	if err := config.Save(path, config.File{"default": prof}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return path
}

func TestConfigureCacheSetsValue(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 0)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("30\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := loaded["default"].CacheTTLMinutes; got != 30 {
		t.Errorf("CacheTTLMinutes: got %d want 30", got)
	}
}

func TestConfigureCacheKeepsExistingOnEnter(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 45)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, _ := config.Load(path)
	if got := loaded["default"].CacheTTLMinutes; got != 45 {
		t.Errorf("CacheTTLMinutes: got %d want 45 (Enter should keep)", got)
	}
}

func TestConfigureCacheDashClears(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 45)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("-\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, _ := config.Load(path)
	if got := loaded["default"].CacheTTLMinutes; got != 0 {
		t.Errorf("CacheTTLMinutes: got %d want 0 (dash should clear)", got)
	}
}

func TestConfigureCacheRetriesOnInvalid(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 0)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("0\nabc\n15\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatalf("runConfigureCache: %v", err)
	}
	loaded, _ := config.Load(path)
	if got := loaded["default"].CacheTTLMinutes; got != 15 {
		t.Errorf("CacheTTLMinutes: got %d want 15", got)
	}
	if !strings.Contains(out.String(), "out of range") && !strings.Contains(out.String(), "invalid") {
		t.Errorf("expected validation message on stderr; got: %s", out.String())
	}
}

func TestConfigureCacheGivesUpAfterMaxAttempts(t *testing.T) {
	dir := t.TempDir()
	path := writeBasicConfig(t, dir, 0)
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("0\n-1\n9999\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err == nil {
		t.Fatal("expected error after three invalid attempts")
	}
}

func TestConfigureCacheRequiresDefaultProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	// Save a config with no "default" profile.
	if err := config.Save(path, config.File{"other": config.Profile{
		Subdomain: "acme", Region: "us", BaseURL: "https://x/api/v1",
	}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: path,
		Stdin:      strings.NewReader("15\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err == nil {
		t.Fatal("expected error for missing default profile")
	}
	if !strings.Contains(err.Error(), `"jellyfish configure"`) {
		t.Errorf("error %q: want guidance to run jellyfish configure", err)
	}
}

func TestConfigureCacheMissingConfigFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yml")
	out := &bytes.Buffer{}
	err := runConfigureCache(configureCacheOpts{
		ConfigPath: missing,
		Stdin:      strings.NewReader("15\n"),
		Stdout:     out,
		Stderr:     out,
	})
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}
```

- [ ] **Step 2: Run tests, confirm they fail to compile**

Run: `go test ./cmd/ -run TestConfigureCache -v`

Expected: FAIL with `undefined: runConfigureCache` and friends.

- [ ] **Step 3: Create `cmd/configure_cache.go`**

```go
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
)

type configureCacheOpts struct {
	ConfigPath string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

func newConfigureCacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cache",
		Short: "Interactively configure the detection/vulnerability cache TTL",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			if cfgPath == "" {
				cfgPath, err = config.DefaultPath()
				if err != nil {
					return err
				}
			}
			return runConfigureCache(configureCacheOpts{
				ConfigPath: cfgPath,
				Stdin:      cmd.InOrStdin(),
				Stdout:     cmd.OutOrStdout(),
				Stderr:     cmd.ErrOrStderr(),
			})
		},
	}
}

func runConfigureCache(o configureCacheOpts) error {
	file, err := config.Load(o.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf(`no config found at %s - run "jellyfish configure" first to set up tenant + token`, o.ConfigPath)
		}
		return fmt.Errorf("read config: %w", err)
	}
	prof, ok := file["default"]
	if !ok {
		return errors.New(`no "default" profile yet - run "jellyfish configure" first to set up tenant + token`)
	}

	r := bufio.NewReader(o.Stdin)

	current := ""
	if prof.CacheTTLMinutes > 0 {
		current = strconv.Itoa(prof.CacheTTLMinutes)
	}

	var chosen int
	var setExplicitly bool
	cleared := false

	for attempt := 1; attempt <= configureEmailMaxAttempts; attempt++ {
		line, err := promptWithDefault(o.Stdout, r, "Cache TTL in minutes", current)
		if err != nil {
			return err
		}
		// promptWithDefault collapses "-" to "" and leaves current alone
		// when the user presses Enter. We need to distinguish those two
		// cases. Re-read the raw input? Too brittle. Instead: ask
		// promptWithDefault separately by inspecting line vs current.
		switch {
		case line == current:
			// User pressed Enter; keep whatever we had (which may be "").
			if prof.CacheTTLMinutes == 0 {
				_, _ = fmt.Fprintln(o.Stdout, "Cache TTL unchanged (using built-in default)")
				return nil
			}
			_, _ = fmt.Fprintf(o.Stdout, "Cache TTL unchanged (%d minutes)\n", prof.CacheTTLMinutes)
			return nil
		case line == "":
			// User typed "-" (collapsed to empty). Clear the field.
			cleared = true
		default:
			n, perr := strconv.Atoi(line)
			if perr != nil {
				_, _ = fmt.Fprintf(o.Stderr, "invalid number: %v\n", perr)
				continue
			}
			if vErr := config.ValidateCacheTTLMinutes(n); vErr != nil {
				_, _ = fmt.Fprintln(o.Stderr, vErr)
				continue
			}
			chosen = n
			setExplicitly = true
		}
		break
	}

	if !cleared && !setExplicitly {
		return fmt.Errorf("invalid cache TTL after %d attempts", configureEmailMaxAttempts)
	}

	if cleared {
		prof.CacheTTLMinutes = 0
	} else {
		prof.CacheTTLMinutes = chosen
	}
	file["default"] = prof

	if err := config.Save(o.ConfigPath, file); err != nil {
		return err
	}

	if cleared {
		_, _ = fmt.Fprintf(o.Stdout, "Cache TTL cleared (using built-in default; saved to %s)\n", o.ConfigPath)
	} else {
		_, _ = fmt.Fprintf(o.Stdout, "Cache TTL set to %d minutes (saved to %s)\n", chosen, o.ConfigPath)
	}
	return nil
}
```

- [ ] **Step 4: Wire the subcommand into `configure`**

In `cmd/configure.go`, locate `newConfigureCmd()` (around line 45). Add `c.AddCommand(newConfigureCacheCmd())` right next to the existing `c.AddCommand(newConfigureEmailCmd())`:

```go
c.AddCommand(newConfigureEmailCmd())
c.AddCommand(newConfigureCacheCmd())
return c
```

- [ ] **Step 5: Run tests, confirm they pass**

Run: `go test ./cmd/ -run TestConfigureCache -v`

Expected: all PASS.

- [ ] **Step 6: Smoke-test the full suite**

Run: `go test ./...`

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/configure_cache.go cmd/configure_cache_test.go cmd/configure.go
git commit -m "feat(configure): added 'configure cache' subcommand"
```

---

## Task 9: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Remove the stale `--cache-ttl` bullet**

In `README.md`, delete line 796 entirely. The bullet currently reads:

```
- A configurable `--cache-ttl` flag (currently the 15-minute TTL is hardcoded).
```

- [ ] **Step 2: Add a configure-cache note under "Detection cache"**

In `README.md`, the "Detection cache" section starts around line 165 with text about the 15-minute default. After the paragraph that describes the TTL and `--no-cache`, add:

```markdown
The 15-minute default is per-profile configurable. Set
`cache_ttl_minutes: <1-1440>` under the profile in `~/.config/jellyfish/config.yml`,
or run `jellyfish configure cache` for an interactive prompt. Use
`--no-cache` to bypass for a single invocation.
```

Place this paragraph so it reads as a natural continuation. Adjust line breaks to match the surrounding 80-column style if the existing section uses it.

- [ ] **Step 3: Verify links / formatting**

Run: `grep -n "cache-ttl\|cache_ttl_minutes\|configure cache" README.md`

Expected: no `--cache-ttl` matches; one or two `cache_ttl_minutes` / `configure cache` matches in the new paragraph; existing `--no-cache` mentions intact.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): documented configure cache; dropped --cache-ttl note"
```

---

## Task 10: Pre-CI verification

**Files:** (none — verification only)

- [ ] **Step 1: Run the pre-CI script**

Run: `./scripts/pre-ci.sh` (or `make pre-ci` if that's the wrapper — check the recent commit `cdb8b34 chore: added local pre-CI script and made it pass 9/9`)

Expected: all 9 checks pass.

- [ ] **Step 2: Manual smoke test (optional, requires real config)**

Only meaningful in an interactive shell with a valid `~/.config/jellyfish/config.yml`:

```bash
go run . configure cache             # set to 30, observe write
yq '.default.cache_ttl_minutes' ~/.config/jellyfish/config.yml  # should print 30
go run . overview                    # observe cache hit reuses 30m TTL
go run . configure cache             # type "-" to clear, observe omitempty
yq '.default | has("cache_ttl_minutes")' ~/.config/jellyfish/config.yml  # should print false
```

- [ ] **Step 3: Verify the version-bump memory is still applicable**

After this branch merges to master, the `[[project-v1-2-0-cache-ttl]]` memory entry directs us to tag `v1.2.0`. Do not bump in this branch — bump on the merge commit.

---

## Self-Review

**Spec coverage check:**
- §1 Config schema → Task 1 ✓
- §2 Validation → Task 1 ✓
- §3 TTL resolver → Task 2 ✓
- §4 `configure cache` subcommand → Task 8 ✓
- §5 Wiring into 5 commands → Tasks 3-7 ✓
- §6 README updates → Task 9 ✓
- Tests for all new code → covered inline in each task ✓
- Rollout / commit ordering → Tasks 1-9 each produce a clean commit ✓
- v1.2.0 tag note → Task 10 step 3 ✓

**Placeholder scan:** no TBDs, no "add error handling", no "similar to Task N" without code.

**Type consistency:**
- `CacheTTLMinutes int` consistent across config.go, resolver, configure_cache.go.
- `resolveCacheTTL(cmd *cobra.Command) (time.Duration, error)` signature consistent in resolver definition and all call sites.
- `configureEmailMaxAttempts` (existing const, value 3) reused in configure_cache.go — no rename, no shadow.
- Fetcher new signature `(ctx, client, stderr, useCache, ttl)` consistent across detections.go and all 6 call sites (1 in overview, 1 in user, 1 in users, 3 in vulns).

No issues found.
