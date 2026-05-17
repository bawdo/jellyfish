# Configurable cache TTL via global config

Status: design approved (sections 1-5), pending implementation plan.
Date: 2026-05-17
Target version: v1.2.0 (on merge to master)

## Problem

The detection and vulnerability caches use a hardcoded 15-minute TTL
(`cache.DefaultTTL` in `internal/cache/cache.go:20`). Operators with
different freshness needs (e.g. wanting an 8-hour cache for a slow daily
report) have no way to change it without recompiling. The fleet runs
small enough commands frequently enough that one TTL does not fit all
use cases.

## Goals

- Per-profile `cache_ttl_minutes` field in `~/.config/jellyfish/config.yml`.
- New `jellyfish configure cache` subcommand to set, change, or clear it
  interactively.
- Existing 15-minute behaviour preserved when the field is absent or zero.
- `--no-cache` flag unchanged; remains the only kill switch.

## Non-goals

- **No `--cache-ttl` CLI flag.** Explicitly dropped from scope.
- No environment-variable override.
- No per-cache-type TTL (detections and vulnerabilities share one value).
- No prompt added to the main `jellyfish configure` flow — the new
  `configure cache` subcommand is the only interactive entry point.

## Design

### 1. Config schema

Add one optional field to `config.Profile` in `internal/config/config.go`:

```go
type Profile struct {
    Subdomain       string      `yaml:"subdomain"`
    Region          string      `yaml:"region"`
    BaseURL         string      `yaml:"base_url"`
    CacheTTLMinutes int         `yaml:"cache_ttl_minutes,omitempty"`
    Email           EmailConfig `yaml:"email,omitempty"`
}
```

YAML on disk:

```yaml
default:
  subdomain: example
  region: us
  base_url: https://example.api.kandji.io/api/v1
  cache_ttl_minutes: 15
  email:
    from: ...
```

Backwards compatibility: existing configs without the field load
unchanged. `omitempty` keeps freshly-written YAML clean for profiles
that have not opted in.

### 2. Validation

New constants and helper, exported from `internal/config`:

```go
const CacheTTLMinMinutes = 1
const CacheTTLMaxMinutes = 1440 // 24h

// ValidateCacheTTLMinutes returns nil if n is in [1, 1440], else an
// error mentioning the field name and bounds.
func ValidateCacheTTLMinutes(n int) error
```

Called from two sites:

1. **`config.Load`** — when YAML carries a non-zero `cache_ttl_minutes`,
   validate it. Invalid values fail the load loudly (rather than being
   silently treated as "use default") so misconfiguration surfaces.
2. **`configure cache` prompt** — reject invalid input at type-in time
   and reprompt.

Zero / missing is always valid and means "use built-in default".

### 3. TTL resolver

New helper in `cmd/cache_ttl.go`:

```go
// resolveCacheTTL returns the cache TTL for the active profile. Falls
// back to cache.DefaultTTL when:
//   - the config file is missing (os.ErrNotExist)
//   - the active profile has no cache_ttl_minutes set (zero)
// Other profile-load errors propagate to the caller.
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

The resolver runs **on every CLI invocation** because each `RunE`
closure freshly calls `activeProfile`, which calls `config.Load` from
disk. There is no in-process config cache: a `jellyfish configure cache`
that changes the YAML takes effect on the very next `jellyfish ...` run.

The TTL is fixed for the lifetime of a single CLI invocation (which
runs in seconds).

### 4. `jellyfish configure cache` subcommand

New file `cmd/configure_cache.go`. Mirrors the existing `configure
email` pattern.

```go
type configureCacheOpts struct {
    ConfigPath string
    Stdin      io.Reader
    Stdout     io.Writer
    Stderr     io.Writer
}

func newConfigureCacheCmd() *cobra.Command
func runConfigureCache(o configureCacheOpts) error
```

Wired into `newConfigureCmd()` alongside `newConfigureEmailCmd()`.

Behaviour:

- Requires an existing `default` profile. Errors with the same
  `run "jellyfish configure" first` message used by `configure email`
  if the config is missing or the profile is absent.
- Single prompt: `Cache TTL in minutes [15]: ` (or the existing value,
  if set).
- Re-uses `promptWithDefault`'s keep/clear/replace rules:
  - **Enter** with current value → keep.
  - **Enter** with no current value → keep built-in default (writes nothing).
  - **`-`** → clear the field; YAML omits it via `omitempty`.
  - **`<n>`** → parse int, call `config.ValidateCacheTTLMinutes`,
    retry up to `configureEmailMaxAttempts` (3) on invalid input.
- On success: `config.Save` and print
  `Cache TTL set to <n> minutes (saved to <path>)`.

### 5. Wiring the resolver into commands

Five commands consume the cache today. Each calls `resolveCacheTTL(cmd)`
once in `RunE` and stores the result on its opts struct. The fetchers in
`cmd/detections.go` grow one `time.Duration` parameter:

| File                | Function (and its signature change)                                          |
|---------------------|------------------------------------------------------------------------------|
| `cmd/detections.go` | `fetchAllDetections(ctx, client, stderr, useCache, ttl)`                     |
| `cmd/detections.go` | `fetchAllVulnerabilities(ctx, client, stderr, useCache, ttl)`                |
| `cmd/overview.go`   | `assembleOverview(ctx, client, stderr, noCache, userFilter, ttl)`            |
| `cmd/user.go`       | `runUserShow` reads `opts.CacheTTL`                                          |
| `cmd/users.go`      | `runUsersSendEmail` reads `opts.CacheTTL`                                    |
| `cmd/vulns.go`      | `runVulnsList` / `runVulnsSummary` read `opts.CacheTTL`                      |

Add a `CacheTTL time.Duration` field to each existing opts struct
(`overviewOpts`, `userShowOpts`, `usersSendEmailOpts`, `vulnsListOpts`,
`vulnsSummaryOpts`).

The fetchers in `cmd/detections.go` pass `ttl` through to
`cache.Load(cachePath, ttl)` and `cache.LoadVulnerabilities(cachePath, ttl)`
in place of `cache.DefaultTTL`. **`internal/cache` is not modified.**

Defensive guard inside the fetchers:

```go
if ttl <= 0 {
    ttl = cache.DefaultTTL
}
```

This keeps existing test signatures untouched: tests that construct
opts with a zero `CacheTTL` continue to get the default behaviour.

The stderr hint `pass --no-cache for fresh data` is unchanged. The
TTL value itself is not surfaced in command output — it lives in
`config.yml` and is set via `configure cache`.

### 6. README updates

- Remove the stale bullet at `README.md:796`:
  `A configurable --cache-ttl flag (currently the 15-minute TTL is hardcoded).`
- Under the existing "Detection cache" section (around `README.md:165`),
  add a short note that the 15-minute default is per-profile configurable
  via `cache_ttl_minutes` in `config.yml` or interactively via
  `jellyfish configure cache`.

## Tests

### `internal/config/config_test.go`

- `ValidateCacheTTLMinutes`: accepts 1, 15, 1440; rejects 0, -1, 1441,
  large positive overflow.
- `Load`: YAML with `cache_ttl_minutes: 30` round-trips correctly; YAML
  with `cache_ttl_minutes: -5` returns a load error mentioning the field.
- `Save`: Profile with `CacheTTLMinutes: 0` writes YAML *without* the
  field (omitempty); with `15` writes the field.

### `cmd/cache_ttl_test.go` (new)

- Missing config file → returns `cache.DefaultTTL`, no error.
- Profile with `CacheTTLMinutes: 0` → returns `cache.DefaultTTL`.
- Profile with `CacheTTLMinutes: 30` → returns `30 * time.Minute`.
- Profile load returns a non-NotExist error → resolver propagates it.

### `cmd/configure_cache_test.go` (new)

- Happy path: existing profile, type `30`, YAML reflects `cache_ttl_minutes: 30`.
- Keep: existing value 30, press Enter, YAML unchanged.
- Clear: existing value 30, type `-`, YAML omits the field.
- Invalid retry: type `0` then `abc` then `15`; first two reprompt on
  stderr, third saves.
- Missing profile: errors with the existing
  `run "jellyfish configure" first` message.
- Max attempts: three invalid entries → error after the third.

### Existing command tests

- `overview_test.go`, `user_test.go`, `users_test.go`, `vulns_test.go`:
  one new test each verifying a custom `opts.CacheTTL` is honoured
  (cache hit when fresh under custom TTL, miss when older).

## Rollout

Single branch, multiple logical commits:

1. `feat(config): added cache_ttl_minutes per-profile field + validation`
2. `feat(cache): plumbed configurable ttl through fetchers`
3. `feat(configure): added 'configure cache' subcommand`
4. `docs(readme): documented configure cache; removed stale --cache-ttl note`

`scripts/pre-ci.sh` must pass before merge.

**Version bump:** on merge to master, tag `v1.2.0`. The new subcommand
+ user-visible config field warrants a minor version increment.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Operator sets TTL too long and acts on stale data | 24h cap; `--no-cache` still works as escape hatch |
| Malformed YAML field silently ignored | `Load` validates and errors loudly |
| Existing tests break from signature changes | Defensive `ttl <= 0 → DefaultTTL` guard in fetchers; new opts field defaults to zero |
| Config loaded from disk on every invocation | Acceptable: CLI commands run in seconds; YAML parse is microseconds |

## Out-of-scope follow-ups

- A `--cache-ttl` CLI flag (deferred indefinitely).
- Separate TTLs for detections vs vulnerabilities caches.
- An env-var override (e.g. `JELLYFISH_CACHE_TTL`).
- Prompting for the TTL during the main `jellyfish configure` flow.
