# jellyfish

A macOS-only Go CLI for the Iru (formerly Kandji) Endpoint Management API.

## Features

- `jellyfish vulns list` - vulnerability detections across the fleet, one row per device-CVE pair; filter by device ID or serial.
- `jellyfish vulns summary` - per-CVE rollup: status, severity, CVSS, KEV score, affected software, device count.
- `jellyfish user show <id-or-email>` - a user, their devices, and the active detections on each.
- `jellyfish overview` - org-wide `sec_score` per user with Best-5 / Most-Dangerous-5 leaderboards and a ranked roster.
- `jellyfish users send-email` - bulk per-user vulnerability reports from a CSV or email list.
- `jellyfish configure` - store tenant, region, API token and Gmail credentials (secrets go in the macOS Keychain).

## Install

Requires Go 1.25+ on macOS.

```bash
go install github.com/bawdo/jellyfish@latest
```

This installs to `$GOBIN` (or `$GOPATH/bin`, default `~/go/bin`). Add it to your `PATH`:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

For a local build without installing, `make build` produces `./bin/jellyfish`. Confirm the install with `jellyfish version`.

### Shell completion

`jellyfish` ships Cobra's completion script. For Zsh (the macOS default):

```bash
mkdir -p ~/.zsh/completions
jellyfish completion zsh > ~/.zsh/completions/_jellyfish
exec zsh
```

If `~/.zsh/completions` is not on `fpath`, add it in `~/.zshrc`. Re-run the command after an upgrade to pick up new flags. Other shells: `jellyfish completion {bash,fish,powershell} --help`.

### Getting help

Every command accepts `--help`, `-h`, or the bareword `help` - `jellyfish overview help` and `jellyfish overview --help` are equivalent.

## Configure

```bash
jellyfish configure
```

Prompts for the tenant subdomain (the bit before `.api.kandji.io` - the hostname is still `kandji.io` even though the product was renamed Iru), region (`us` or `eu`), and API token. Re-running is safe: each prompt shows the current value, and Enter keeps it.

Subdomain and region are written to `~/.config/jellyfish/config.yml` (mode `0600`); the token goes to the macOS Keychain under service `jellyfish.secrets`, account `default`:

```bash
security find-generic-password -s jellyfish.secrets -a default
security delete-generic-password -s jellyfish.secrets -a default
```

### Configure email defaults

```bash
jellyfish configure email
```

Prompts for `From`, default `To`, a Gmail service-account JSON path, header background colour, a logo PNG, and an optional `List-Id` domain. Non-secret values go to the `email:` block of `config.yml`; the Gmail JSON goes to the Keychain; the logo PNG (validated, under 512 KB) is copied into `~/.config/jellyfish/logos/`. Enter keeps a value; a literal `-` clears it.

`list_id_domain` sets the `List-Id` header on sent mail. Left unset, it falls back to `jellyfish.` plus the domain of `email.from` - so a `from` of `ops@example.com` yields `List-Id: <jellyfish.example.com>`. You can also edit `config.yml` directly.

## Usage

### Vulnerability detections

```bash
jellyfish vulns list                       # everything
jellyfish vulns list --device-id d-123     # one device by ID
jellyfish vulns list --serial C02XL0RKDV4  # one device by serial
jellyfish vulns list --limit 50            # single page
jellyfish vulns list -o json               # JSON for jq
jellyfish vulns list --no-cache            # always fetch fresh
```

Every detection returned is active by definition - Iru drops a detection once the CVE is patched, so there is no "active only" filter. `--limit` is clamped to Iru's server-side maximum (300).

### Detection cache

`vulns list` and `user show` walk Iru's detections endpoint in full, because Iru has no per-device server filter. The first call takes 30-90 seconds on a large tenant; results are cached for 15 minutes under `~/Library/Caches/jellyfish/`. Pass `--no-cache` to force a fresh fetch. Change the TTL with `cache_ttl_minutes` in `config.yml` or via `jellyfish configure cache`.

### Vulnerability summary

A per-CVE rollup across the fleet - one row per CVE with status, severity, CVSS, KEV score, affected software, and device count.

```bash
jellyfish vulns summary                            # severity-sorted
jellyfish vulns summary --status active            # currently-affecting only
jellyfish vulns summary --severity critical        # critical only
jellyfish vulns summary --sort devices --limit 20  # top 20 by exposure
jellyfish vulns summary --sort kev                 # sort by KEV
```

Sort keys: `severity` (default), `cvss`, `kev`, `devices`, `cve`. The `kev_score` field reflects whether a CVE is in CISA's Known Exploited Vulnerabilities Catalog - bugs seen exploited in the wild, often a stronger patch-priority signal than CVSS alone.

### Per-user view

```bash
jellyfish user show keith@example.com   # by email
jellyfish user show 1f5b...e4           # by user ID
jellyfish user show keith@example.com -o json
```

Email lookup is a single request; bucketing detections per device triggers the detection walk (see Detection cache).

### Output formats

`-o` accepts `table` (default), `json`, `yaml`, `csv`, `email`. `user show -o csv` flattens to one row per detection, with these columns:

```
user_id, user_email, user_name, device_id, device_name, serial_number,
cve_id, package_name, package_version, severity, cvss_score,
detection_datetime
```

### Email output

`-o email` writes an RFC 5322 `.eml` to stdout - styled HTML plus a plain-text alternative, with clickable NVD/MITRE CVE links. Open it in Mail, pipe it onward, or use `--send-email` to send it via Gmail.

```bash
jellyfish vulns summary --severity critical -o email > critical.eml
jellyfish vulns summary -o email | open -f -a Mail
```

Filter large reports with `--severity`, `--status`, or `--limit` first - Gmail clips long messages.

Recipient, sender, and subject default from the `email:` block of `config.yml`; flags override:

| Flag | Config key | Default |
|---|---|---|
| `--email-to` | `email.default_to` | empty |
| `--email-from` | `email.from` | `git config user.email` |
| `--email-subject` | `email.subject_template` | per-command default |
| `--email-header-bg` | `email.header_bg` | `#2b3a55` (slate blue) |
| `--email-logo` | `email.logo_path` | empty (no logo) |
| `--message` / `--message-file` | - | unset |

The logo renders at 56px height (width scales to its aspect ratio); supply a PNG under 512 KB, ideally at 2x height for retina displays. `email.subject_template` is a Go template with `{{.Date}}` and `{{.Time}}`. CVE link targets (`cve_link_primary`, `cve_link_secondary`) are config-overridable; the `{cve}` token is substituted literally.

#### Message section (`--message`, `--message-file`)

Adds a short note to the top of an email. Supported by `vulns summary` and `user show` when producing email output.

- `--message` opens `$VISUAL` / `$EDITOR` / `vi` on a scratch file; `#` lines are dropped on save, and an empty result aborts.
- `--message-file <path>` reads the note verbatim (use `-` for stdin; `#` lines are kept).
- The two are mutually exclusive and require email output. URLs in the note become clickable links.

```bash
jellyfish vulns summary --severity critical --send-email --message
jellyfish user show alice@example.com --send-email --message-file note.txt
echo "Patching window moved to Saturday." | jellyfish user show alice@example.com --send-email --message-file -
```

#### Sending via Gmail (`--send-email`)

`--send-email` renders the `.eml` and sends it via the Gmail API instead of writing it to stdout.

```bash
jellyfish vulns summary --severity critical --send-email --email-to secops@example.com
jellyfish user show keith@example.com --send-email
```

For `user show`, the recipient is `--email-to`, else `email.default_to`, else the user's own address. `vulns summary` has no user fallback - pass `--email-to` or set `email.default_to`. On success, stderr prints `sent: to=<addr> from=<addr> gmail-id=<id>`.

The Gmail path uses a Workspace service account with domain-wide delegation; the service-account JSON lives in the Keychain under service `jellyfish.secrets`, account `gmail_default` (set it via `jellyfish configure email`).

#### Filtering Jellyfish mail in Gmail

Every sent message carries a `List-Id` header. Create a Gmail filter with `Has the words: list:<your-domain>` to label all Jellyfish mail in one rule. The `X-Jellyfish-Report` header (`vulns-summary`, `user-show`, `users-send`, `overview`) distinguishes commands; `X-Jellyfish-Tenant` and `X-Jellyfish-Version` are also set for audit.

### Bulk send via `users send-email`

Mails per-user vulnerability reports to a list of addresses in one run. Each recipient gets a report for their own devices; users with no devices or no vulnerabilities are skipped.

```bash
jellyfish users send-email --csv fleet.csv                           # auto-detects email column
jellyfish users send-email --emails alice@example.com,bob@example.com
jellyfish users send-email --csv fleet.csv --dry-run                 # preview, no mail sent
jellyfish users send-email --csv fleet.csv --email-to me@example.com # redirect all (test mode)
```

`--csv` and `--emails` are mutually exclusive. The detection walk runs once and is reused, so a 50-user run costs about one `user show` plus the per-user sends. The command prompts before sending; `--yes` skips the prompt. `--csv-email-column` overrides CSV header auto-detection (`email`, `user_email`, `e-mail`).

Stderr emits one line per recipient and a final summary:

```
sent input=alice@example.com to=alice@example.com gmail-id=msg-abc
skip input=bob@example.com reason=no-devices
error input=dave@example.com reason=user-not-found
summary: sent=1 skipped=1 errors=1
```

`reason=` values: `no-devices`, `no-vulnerabilities`, `user-not-found`, `no-recipient`. Dry-run lines use `would-send`. Unlike `user show`, this command ignores `email.default_to` - set `--email-to` explicitly to redirect.

### Org-wide overview via `overview`

Computes a `sec_score` per user (the sum of CVSS scores across their active detections) and rolls those into org totals, averages, a Best-5 and Most-Dangerous-5 leaderboard, and a ranked roster. The roster is sorted by `sec_score` ascending, so rank 1 is the most secure user. Users with no devices are excluded.

```bash
jellyfish overview                                              # table to stdout
jellyfish overview -o csv > scores.csv
jellyfish overview --send-email --email-to security@example.com # admin report
jellyfish overview --send-email --per-user                      # personalised fanout
jellyfish overview --emails alice@example.com,bob@example.com   # roster subset
```

`--per-user` requires `--send-email` and sends each user a copy with a "Your standing" callout and a highlighted roster row. `--send-email` without `--per-user` requires `--email-to`. `--csv` / `--emails` narrow the roster - and the totals, leaderboards, and fanout - to a named subset.

Roster rows are coloured by tier:

| Tier | SecScore | Colour |
|---|---|---|
| critical | >= 100 | red |
| high | 30 - 99.9 | orange |
| medium | 5 - 29.9 | yellow |
| good | < 5 | green |

#### Flags

| Flag | Purpose |
|---|---|
| `--csv <path>` | User emails to include, from a CSV. Mutually exclusive with `--emails`. |
| `--emails <list>` | Comma-separated user emails. Mutually exclusive with `--csv`. |
| `--csv-email-column <name>` | Override CSV header auto-detection. |
| `--send-email` | Send via Gmail: admin report, or per-user fanout with `--per-user`. |
| `--per-user` | One personalised copy per user (requires `--send-email`). |
| `--email-to <addr>` | Admin recipients; with `--per-user`, redirects every copy here (test mode). |
| `--email-from` / `--email-subject` | Override the From and Subject headers. |
| `--email-header-bg` / `--email-logo` | Override the header colour and logo. |
| `--message` / `--message-file` | Add a shared message above the body. |
| `--dry-run` | Render but do not send. |
| `--yes` | Skip the confirmation prompt. |
| `--no-cache` | Bypass the detection cache. |

Stderr emits one line per recipient (`sent` / `would-send` / `skip` / `error`) and a trailing `summary:` line. With `--per-user --email-to`, lines gain a `for=<user-email>` field for traceability.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | User error (bad flags, missing config) |
| 2 | Authentication or permissions failure |
| 3 | User, device or detection not found |
| 4 | Upstream error (5xx, network) |

## Development

```bash
make test     # go test ./...
make lint     # golangci-lint run
make pre-ci   # nine-check local build validator
make build    # ./bin/jellyfish with version ldflags
```

`make pre-ci` (`scripts/pre-ci-check.sh`) runs the Go version check, `go mod download`, `gofmt -s`, `go test -race`, `golangci-lint`, coverage tracking, a versioned build, `govulncheck`, and a CLI smoke test; logs land in `coverage/`. `make pre-ci-fix` auto-fixes gofmt issues first.

Real-Keychain integration tests:

```bash
JELLYFISH_KEYCHAIN_TESTS=1 go test ./internal/keychain/... -count=1
```

The first run pops a macOS dialog asking to allow the test binary to read your Keychain; approve it and re-run.

## Known follow-ups

These items were noted during development but are not blocking. Captured
here so they do not get lost.

### Iru response shape probing (resolved)

`internal/iru/types.go` was originally authored without a live tenant. A
series of v1.1 commits realigned the code against the real Iru API after
live probing:

- `/users` paginates with `?cursor=<value>` and returns `{next, previous,
  results}` where `next` is a full URL.
- `/detections` paginates with `?after=<value>` and returns the same
  wrapper but with `next` as a raw cursor string. `nextCursor()` handles
  both shapes.
- `/devices` returns a top-level JSON array; no wrapper.
- Iru ignores per-device filters on `/detections` entirely. Detection
  filtering happens client-side after a full walk; results are cached
  for 15 minutes.
- User lookup by email uses `/users?email=<address>` directly (single
  request, no walk).
- `Detection` records have no `status` field. `User` and `Device` structs
  expanded with the rich fields Iru returns.

### Retry transport drops the upstream error message body

When `internal/iru/retry.go` exhausts all three attempts on a 429 or 5xx, it
drains and closes each response body in the retry loop, then returns the last
response. By the time `client.do` calls `decodeAPIError(resp)`, the body is
already closed and reads as empty - so `APIError.Message` ends up blank.

Status codes are preserved correctly (so `classifyError` still maps 429 to
exit 4 and 5xx to exit 4), and exit-code behaviour is unaffected. The only
loss is the human-readable error text from Iru.

Fix path: in the retry loop, read the body into a `[]byte` before closing,
then restore it via `io.NopCloser(bytes.NewReader(buf))` on the response
returned to the caller. Small change; needs a test that asserts the message
survives after retries.

### `WithHTTPClient` plus `WithTimeout` option ordering is fragile

If a caller passes both `iru.WithTimeout(d)` and `iru.WithHTTPClient(custom)`
in that order, `WithHTTPClient` replaces the whole `*http.Client` and the
timeout from the previous option is lost. This is not triggered anywhere in
v1 because `WithHTTPClient` is never called by production code (only the
constructor's default `*http.Client` is used). Worth fixing before exposing
the option more broadly. Either make `WithHTTPClient` preserve any timeout
already set, or document the ordering contract on each option.

### CSV column order for `user show` is fixed without a test

The flattened CSV columns for `jellyfish user show -o csv` are listed in the
README above and pinned in `cmd/user.go`'s `renderUserBundleCSV`. There is
currently no test asserting the order. If the order ever needs to change,
that change should land alongside a golden-file test that locks it down.

### Other future work

- Env-var fallback for the token (`JELLYFISH_API_TOKEN`) for CI environments
  with no Keychain.
- A `-vv` extra-verbose mode that logs response bodies with token + PII
  redaction.
