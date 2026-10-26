# Changelog

All notable changes to jellyfish are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Releases are cut automatically. A merge to `main` whose newest
  `CHANGELOG.md` heading names an untagged version tags that commit, builds
  the darwin arm64 and amd64 binaries, attests the checksums with build
  provenance and publishes the release with the changelog section as its
  notes. CI fails if the newest changelog version is behind the latest tag,
  has a malformed date or no link reference.
- `SECURITY.md`, `CONTRIBUTING.md`, a pull request template and Dependabot
  version updates for Go modules and GitHub Actions.

## [0.3.0] - 2026-10-27

### Security

- `config.yml`, the detection and vulnerability caches, and the managed
  email logo are now always left at mode 0600. Before, the mode was only set
  when the file was first created, so a file that already existed with wider
  permissions kept them. Each write now goes to a temp file and is renamed
  into place, so an interrupted save can't leave a partial file either.
  A symlinked `config.yml` keeps its link. Parent directories that already
  exist keep their mode.

### Changed

- `vulns summary --sort` rejects an unknown key with exit 1 before fetching
  anything. It used to ignore the key and return rows unsorted. Shell
  completion now offers the valid keys.
- `vulns summary` puts rows that tie on the sort key in CVE ID order, so the
  output is the same on every run.
- `--message` accepts an editor with arguments or quoting in `$VISUAL` or
  `$EDITOR` (for example `code -w`), using the same rules as git. A plain
  command name or path is still run directly.
- Test coverage rose from about 81% to 97%. The coverage check in CI now
  fails below 90%, or when a change drops coverage by more than 1%.
- The gated real-Keychain tests can no longer read, overwrite or delete the
  configured Iru token or Gmail credential.

## [0.2.0] - 2026-10-27

### Security

- The API token is scoped to the Iru origin (scheme and host). Redirects to
  another host, or from https down to http, are refused.
- Terminal output is sanitised everywhere: errors, table cells, headings and
  all command stderr. Control characters are stripped, including a lone 0x9b
  byte in invalid UTF-8.
- Logo files must be regular files. They are opened non-blocking and checked
  on the open handle, at most 512 KB is read, and images are capped at
  2048x2048 pixels.
- Error response bodies are read up to 64 KiB.
- Detection and vulnerability caches are kept per tenant.
- `jellyfish configure` checks a new token against Iru before writing anything.
  It does the same for a kept token when the subdomain or region changes.
- CI actions are pinned by commit SHA, and govulncheck is pinned to a fixed
  version.
- golang.org/x/net is bumped to v0.55.0 (GO-2026-5026), then to v0.60.0.

### Added

- `user show` and `users send-email` handle several Iru users sharing one
  email address. `user show` asks which one to display on a terminal, and
  exits non-zero with a re-run hint otherwise. `users send-email` sends to
  each match.
- The detection file path appears in `user show` output and the user email.
- `make help`.

### Changed

- Network failures (DNS, connection refused, timeout, server hang-up) now
  exit 4 instead of 1. A cancelled run, a refused redirect and a malformed URL
  still exit 1.
- A server that sends a cursor it has already sent now stops cursor
  pagination with exit 4 instead of looping forever.
- Retry-After waits are capped at 10 s. A wait that would leave less than 1 s
  before the request deadline returns the 429/5xx straight away (exit 4)
  instead of timing out.
- Cache files are now `detections-<subdomain>-<region>.json` and
  `vulnerabilities-<subdomain>-<region>.json`. The old shared files are
  removed from the default cache directory on the next save.
- A configured logo over the pixel limit is dropped with a warning.
- Config and Keychain errors now show the real cause instead of a generic
  "no credentials found" message.
- cve.org is now the primary CVE link in emails.
- Mail clients no longer auto-link file paths and package names in emails.
- Go 1.26 is now the minimum version.
- Config is read once per command run, and the duplicated email, logo and
  user-page code is consolidated.

### Removed

- The Go Report Card badge (that service has been retired).

## [0.1.1] - 2026-05-21

### Security

- The Iru API base URL is always derived from the subdomain and region, never
  read from config, so a tampered config can't redirect the token.
- CSV output neutralises spreadsheet formula injection.

### Added

- GitHub Actions CI workflow, and README status badges.
- MIT License.

### Changed

- The upstream error body is kept across retries, so the final error shows
  Iru's message.
- Client option ordering is deterministic.
- The README is rewritten, with Gmail send setup and `-o email` documented.
- The renderers, the overview send loop, cached fetches and output row
  iteration are consolidated (no behaviour change).

### Removed

- The reserved `--profile` flag.

## [0.1.0] - 2026-05-20

First release.

### Added

- `jellyfish vulns list`: one row per device and CVE, filterable by status,
  device ID or serial.
- `jellyfish vulns summary`: a per-CVE rollup with status, severity, CVSS, KEV
  score, affected software and device count.
- `jellyfish user show <id-or-email>`: a user, their devices and the active
  detections on each.
- `jellyfish overview`: `sec_score` per user, Best-5 and Most-Dangerous-5
  leaderboards, and a ranked roster. Filter with `--csv` / `--emails`, and use
  `--send-email` for an admin report or per-user copies.
- `jellyfish users send-email`: bulk per-user vulnerability reports from a CSV
  or an email list, with `--dry-run` and a confirm prompt.
- `jellyfish configure`: tenant, region and API token. The token is stored in
  the macOS Keychain and checked against Iru.
- `jellyfish configure email`: From/To, Gmail service-account JSON, header
  colour, logo and `List-Id` domain.
- `jellyfish configure cache`: the cache TTL.
- Output formats `table`, `json`, `yaml`, `csv` and `email` (multipart
  `.eml`, with HTML and plain text).
- Gmail sending through a Workspace service account with domain-wide
  delegation.
- `List-Id` and `X-Jellyfish-*` headers for mail filtering.
- An on-disk cache of detection and vulnerability walks. The TTL defaults to
  15 minutes and can be set with `cache_ttl_minutes`.
- Retries with backoff on 429 and 5xx, honouring `Retry-After`.
- Stable exit codes: 0 success, 1 user error, 2 auth, 3 not found, 4 upstream.
- A `help` bareword alias for `--help`, and `jellyfish version` with commit
  and tag.

[Unreleased]: https://github.com/bawdo/jellyfish/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/bawdo/jellyfish/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bawdo/jellyfish/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/bawdo/jellyfish/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bawdo/jellyfish/releases/tag/v0.1.0
