# jellyfish

A macOS-only Go CLI for the Iru (formerly Kandji) Endpoint Management API.

## Features

- `jellyfish vulns list` - list vulnerability detections across the fleet (one row per device-CVE intersection), filter by device ID or serial number.
- `jellyfish vulns summary` - per-CVE rollup view with status, severity, CVSS, KEV (CISA Known Exploited Vulnerabilities) score, affected software, and device count.
- `jellyfish user show <id-or-email>` - resolve a user, their devices, and the active detections per device.
- `jellyfish configure` - interactively store the tenant subdomain, region and API token (token in the macOS Keychain).

## Install

Requires Go 1.21+ on macOS. The module path `github.com/bawdo/jellyfish` is
private (no `go-import` meta tag is served), so install from a local checkout
rather than the network.

```bash
git clone <repo-url> jellyfish && cd jellyfish
make install
```

`make install` runs `go install .` with version metadata baked in via
`-ldflags`. It places `jellyfish` in `$GOBIN` if set, otherwise `$GOPATH/bin`
(default `~/go/bin`). Add that directory to your `PATH` once:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

For an in-tree build (no install) use:

```bash
make build       # produces ./bin/jellyfish
./bin/jellyfish version
```

After install, confirm the binary is wired up:

```bash
jellyfish version    # prints e.g. "jellyfish 7f579d3" (the current git ref)
```

### Shell completion

`jellyfish` ships Cobra's auto-generated completion script. To enable Zsh
completion (the macOS default shell), drop the script somewhere Zsh's `fpath`
already covers:

```bash
mkdir -p "$(brew --prefix)/share/zsh/site-functions"
jellyfish completion zsh > "$(brew --prefix)/share/zsh/site-functions/_jellyfish"
exec zsh    # reload
```

For other shells: `jellyfish completion {bash,fish,powershell} --help`.

## Configure

```bash
jellyfish configure
```

Interactive prompts:

1. Tenant subdomain (the bit before `.api.kandji.io`).
2. Region: `us` or `eu`.
3. API token (input is masked).

Subdomain and region are written to `~/.config/jellyfish/config.yml` with mode
`0600`. The token is stored in the macOS Keychain under the service
`jellyfish.secrets` and account `default`. You can inspect or remove
it via Keychain Access or:

```bash
security find-generic-password -s jellyfish.secrets -a default
security delete-generic-password -s jellyfish.secrets -a default
```

### Configure email defaults

```bash
jellyfish configure email
```

Prompts (in order): `From`, default `To`, path to a Gmail service-account
JSON file, header background colour, path to a logo PNG. The first two
values and `header_bg` are written to the `email:` block of
`~/.config/jellyfish/config.yml`. When a Gmail JSON path is provided, the
file is read, validated, then stored in the macOS Keychain (the source
path is not persisted). When a logo path is provided, the PNG is validated
(decodable PNG, no larger than 512 KB) and copied into
`~/.config/jellyfish/logos/<basename>`; the resulting managed path is
written to `email.logo_path`. The source file is left alone.

For each prompt: Enter keeps the current value; type a literal `-` to
clear a field. Clearing the logo also deletes the copy under `logos/`
(but never any file outside that directory).

The `email:` block also accepts an optional `list_id_domain` key. When
set, it becomes the value inside the `List-Id` header on every sent
message; when unset, the domain part of `email.from` is used. Use this
to give an org-wide audit identity that's distinct from the sending
mailbox, e.g.:

```yaml
email:
  from: jellyfish-noreply@example.com
  list_id_domain: jellyfish.example.com
```

`jellyfish configure email` does not prompt for this value - edit
`~/.config/jellyfish/config.yml` directly.

## Usage

### Vulnerability detections

```bash
jellyfish vulns list                              # everything
jellyfish vulns list --device-id d-123            # one device by ID
jellyfish vulns list --serial C02XL0RKDV4         # one device by serial
jellyfish vulns list --limit 50                   # single page of 50
jellyfish vulns list -o json                      # JSON for jq
jellyfish vulns list -o csv > vulns.csv           # CSV export
jellyfish vulns list --no-cache                   # skip cache, always fetch fresh
```

### Detection cache

Both `vulns list` and `user show` walk Iru's `/vulnerability-management/detections`
endpoint client-side. Iru exposes no per-device filter on that endpoint
(probed against a live tenant — `device_id=`, `device_serial_number=`, and
others are all silently ignored), so the only way to deliver a per-device
view is to fetch every detection and filter in memory.

That walk is the bulk of the wall time. On a tenant with thousands of CVE
detections, expect roughly **30-90 seconds** for the first call (a progress
indicator on stderr shows pages as they come in). To avoid repeating that
walk on every command, the result is cached for **15 minutes** at the OS
cache location:

- macOS: `~/Library/Caches/jellyfish/detections.json` (detections), `~/Library/Caches/jellyfish/vulnerabilities.json` (vulnerability rollups)
- Linux: `$XDG_CACHE_HOME/jellyfish/detections.json` or `~/.cache/jellyfish/detections.json` (detections), same directory for `vulnerabilities.json`

Subsequent commands within the TTL skip the walk and return in under a
second. Pass `--no-cache` (available on both `vulns list` and `user show`)
to force a fresh fetch. Delete the file by hand to invalidate manually.

### Iru detection semantics

Iru's `/detections` endpoint returns one record per (device, CVE, package
version) intersection. There is **no status field on detection records** —
a detection exists exactly while the underlying CVE is present on the
device's installed package. When the package gets patched, Iru re-scans
and the detection disappears.

The corollary: every detection `jellyfish vulns list` or `jellyfish user
show` returns is by definition active / non-remediated. There is no need
to (and no way to) filter to "active only".

For a per-CVE rollup with remediation status, use `jellyfish vulns summary`
(backed by Iru's `/vulnerability-management/vulnerabilities` endpoint).

### Vulnerability summary

Per-CVE rollup across the fleet, backed by Iru's
`/vulnerability-management/vulnerabilities` endpoint. Unlike `vulns list`
(per device, per CVE), this is one row per CVE with status, severity,
CVSS, KEV score, affected software, and how many devices are exposed.

```bash
jellyfish vulns summary                            # all CVEs, severity-sorted
jellyfish vulns summary --status active            # only currently-affecting CVEs
jellyfish vulns summary --severity critical        # critical only
jellyfish vulns summary --sort devices --limit 20  # top 20 by device exposure
jellyfish vulns summary --sort kev                 # sort by KEV (known-exploited)
jellyfish vulns summary -o json                    # JSON for jq
jellyfish vulns summary --no-cache                 # bypass the 15-minute cache
```

Sort keys: `severity` (default - Critical first, then CVSS desc within tier),
`cvss`, `kev`, `devices`, `cve`. Iru ignores status/severity query params on
this endpoint, so filtering is client-side after a full walk (~3000 records
on a typical tenant; a few seconds with the progress indicator). Results
are cached separately from detections at
`~/Library/Caches/jellyfish/vulnerabilities.json`.

**About KEV.** `kev_score` reflects whether the CVE appears in CISA's
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) -
a list of vulnerabilities observed being actively exploited in the wild, not
just theoretically dangerous. For triage, `--sort kev` is usually a stronger
patch-priority signal than CVSS alone: a Medium-CVSS bug that attackers are
actively using can be more urgent than a Critical-CVSS bug that nobody has
weaponised yet. Iru does not document the exact `kev_score` semantics; on
this tenant the field is numeric (0 for non-KEV entries). Inspect the
distribution with:

```bash
jellyfish vulns summary -o json | jq '[.[].kev_score] | unique'
```

### Per-user view

```bash
jellyfish user show keith@example.com        # by email
jellyfish user show 1f5b...e4                     # by user ID
jellyfish user show keith@example.com -o json
jellyfish user show keith@example.com --no-cache
```

Email lookup is a single direct `?email=` request against Iru. The
per-user-device detection bucketing is what triggers the detection walk
(see Detection cache, above).

### Output formats

`-o` accepts `table` (default), `json`, `yaml`, `csv`.

For `user show -o csv`, the output is flattened: one row per detection, with
user and device columns repeated. Column order:

```
user_id, user_email, user_name, device_id, device_name, serial_number,
cve_id, package_name, package_version, severity, cvss_score,
detection_datetime
```

### Email output

`-o email` writes an RFC 5322 multipart/alternative message (.eml) to stdout.
It carries a styled HTML body (executive summary + per-CVE table with
clickable NVD/MITRE CVE links) and a plain-text alternative. Open the .eml
file in Mail, pipe it to your mail tooling, or pass --send-email to send it via the Gmail API (see below).

```bash
jellyfish vulns summary --severity critical -o email > critical.eml
jellyfish vulns summary -o email | open -f -a Mail            # macOS
jellyfish user show keith@example.com -o email \
    --email-to keith@example.com > exposure.eml
```

On a real tenant `vulns summary` is ~3000 rows. Gmail will clip the message
if you send the unfiltered output - filter with `--severity`, `--status`, or
`--limit` first.

Recipient, sender, and subject default from the `email:` block in
`config.yml`; flags override:

| Flag | Config key | Default |
|---|---|---|
| `--email-to`         | `email.default_to`       | empty (header renders as `<unspecified>`) |
| `--email-from`       | `email.from`             | `git config user.email` |
| `--email-subject`    | `email.subject_template` | per-command default |
| `--email-header-bg`  | `email.header_bg`        | `#2b3a55` (default header colour) |
| `--email-logo`       | `email.logo_path`        | empty (no logo) |
| `--message`          | -                        | unset (no message section) |
| `--message-file`     | -                        | unset (no message section) |

The default `#2b3a55` is the default header colour. A logo whose recognisable
element is the same purple (the logo, for example) will blend into
that background - pair the default with a logo whose distinguishing element
is white or dark, or pick a contrasting header colour such as `#C6B8FE`
(light lavender) or `#6846D8` (deep purple).

**Logo dimensions.** The header renders the logo at a fixed 56px height; width
scales by the source PNG's aspect ratio (the renderer never crops or distorts).
Any pixel dimensions work; what matters for sharpness is supplying enough
source pixels for the mail client to downscale cleanly to that 56px row:

| Target rendering   | Minimum source height | Recommended source height |
|---|---|---|
| Standard display   | 56 px                 | 56-100 px                 |
| Retina / HiDPI     | 112 px (2x)           | 112-200 px                |

For square logos use a 1:1 source; for wordmark / landscape logos a 2:1 or
3:1 source is typical. Keep the entire PNG canvas under 512 KB (the renderer
rejects oversized files); a well-optimised 200x100 PNG is usually well under
10 KB.

**Don't resize logos to chase exact dimensions.** Brand assets are usually
already supplied at suitable sizes; downscaling a logo from, say, 200x100 to
exactly 112x56 with a generic resampling filter can subtly alter the visible
content aspect ratio (Lanczos and friends extend anti-aliased edges, which
skews the bounding box). Use whatever the design team ships and let the mail
client do the 56px downscale.

`email.subject_template` is a Go template; available variables: `{{.Date}}`
(YYYY-MM-DD) and `{{.Time}}` (HH:MM).

CVE link targets are also config-overridable; defaults are NVD and MITRE:

```yaml
email:
  from: alice@example.com
  default_to: secops@example.com
  subject_template: "Weekly brief - {{.Date}}"
  cve_link_primary: "https://nvd.nist.gov/vuln/detail/{cve}"
  cve_link_secondary: "https://www.cve.org/CVERecord?id={cve}"
```

The `{cve}` token in link templates is a literal substring replacement.

#### Optional message section (`--message`, `--message-file`)

Attach a short note to the top of a rendered email (between the branded header
and the stats tiles). Both `vulns summary` and `user show` support this when
producing email output (`-o email` or `--send-email`).

- `--message` opens `$VISUAL` (then `$EDITOR`, then `vi`) on a templated
  scratch file. Lines starting with `#` are ignored on save (matches
  `git commit` behaviour). An empty or whitespace-only result aborts the
  command with exit 1.
- `--message-file <path>` reads the message verbatim from the file. Use
  `--message-file -` to read from stdin. `#` lines are **not** stripped from
  files - whatever is in the file goes into the email.
- The two flags are mutually exclusive; setting either without `-o email` or
  `--send-email` errors out with exit 1.
- Messages over 4000 characters render fine but emit a stderr warning
  (`warn: --message is N chars; long messages may be clipped by mail clients`).
- Auto-linkification: any `http(s)://...` in the message renders as a
  clickable link in the HTML body. The plain-text alternative carries the
  message verbatim.

```bash
# Compose interactively, then send
jellyfish vulns summary --severity critical --send-email --message

# Take the body from a file (handy for templated weekly briefings)
jellyfish user show alice@example.com --send-email --message-file note.txt

# Pipe from stdin
echo "FYI - patching window moved to Saturday." \
    | jellyfish user show alice@example.com --send-email --message-file -
```

#### Sending via Gmail (`--send-email`)

`--send-email` on `vulns summary` or `user show` renders the .eml internally
and sends it via the Gmail API instead of writing it to stdout. Combine with
any of the existing email/filter flags:

```bash
jellyfish vulns summary --severity critical --send-email --email-to secops@example.com
jellyfish user show keith@example.com --send-email
```

Recipient resolution for `user show --send-email`:

1. `--email-to <addr>` if provided
2. `email.default_to` from config if non-empty
3. The resolved user's own email address

For `vulns summary --send-email` the user fallback does not apply — pass
`--email-to` or set `email.default_to`.

On success, stdout stays empty and stderr gets one line:
`sent: to=<addr> from=<addr> gmail-id=<id>`.

Combining `--send-email` with an explicit `-o` other than `email` errors out
(exit 1). Use one or the other.

The Gmail send path uses a Workspace service account with domain-wide
delegation. The service-account JSON is stored in the macOS Keychain under
service `jellyfish.secrets`, account `gmail_default` — install it
via `jellyfish configure email` (third prompt). Inspect or remove it via:

```bash
security find-generic-password -s jellyfish.secrets -a gmail_default
security delete-generic-password -s jellyfish.secrets -a gmail_default
```

Gmail-side failures surface via exit codes 2 (auth/permissions: bad JWT,
DWD scope not granted, mailbox forbidden) and 4 (rate-limited or 5xx
upstream).

#### Filtering Jellyfish mail in Gmail

Every Jellyfish-sent message carries a `List-Id` header derived from your
`email.from` domain (or from `email.list_id_domain`; see above). Gmail's
filter UI has a first-class `list:` operator for this - create a filter
with `Has the words: list:example.com` (substitute your own
domain) and label every Jellyfish mail in one rule.

Per-command discrimination lives in the `X-Jellyfish-Report` header
(values: `vulns-summary`, `user-show`, `users-send`). Gmail's filter UI
does not expose arbitrary header search, but you can view the value in
"Show original" or in any mail client that surfaces raw headers (sieve,
mutt, server-side rules). Two more headers are set for audit:
`X-Jellyfish-Tenant` (your Iru tenant subdomain) and `X-Jellyfish-Version`
(the jellyfish build that sent the message).

### Bulk send via `users send-email`

For mailing per-user vulnerability reports to a list of addresses in one
invocation. Each recipient gets a report for their own devices; users with
no devices or no active vulnerabilities are skipped (and logged to stderr).

```bash
# CSV with auto-detected `email` / `user_email` / `e-mail` column
jellyfish users send-email --csv fleet.csv

# CSV with a custom column
jellyfish users send-email --csv fleet.csv --csv-email-column primary_contact

# Comma-separated list
jellyfish users send-email --emails alice@example.com,bob@example.com

# Redirect every email to one address (test / audit mode)
jellyfish users send-email --csv fleet.csv --email-to me@example.com

# Dry-run: walk the list and print what would happen; no mail is sent
jellyfish users send-email --csv fleet.csv --dry-run

# Compose one message body, shared across every recipient
jellyfish users send-email --csv fleet.csv --message
```

`--csv` and `--emails` are mutually exclusive. Email addresses are
deduped case-insensitively (first-seen address wins for display). The
detection walk runs once at the start of the batch and is reused for
every recipient, so a 50-user run takes roughly the same wall time as
one `user show` plus the per-user Gmail sends.

By default the command prompts before sending:

```
About to send vulnerability reports to 47 users. Continue? [y/N]
```

Use `--yes` to skip the prompt in scripts.

Stderr emits one record per recipient and a final summary line:

```
sent: alice@example.com to=alice@example.com gmail-id=msg-abc
skip: bob@example.com no devices
skip: carol@example.com no vulnerabilities
error: dave@example.com user not found in Iru
summary: sent=1 skipped=2 errors=1
```

`<input-email>` (the first column of each line) is always the address as
supplied in the CSV / list, not the resolved recipient - useful for
tracing each line back to a row in the source file.

Unlike `user show --send-email`, the bulk command intentionally does not
honour `email.default_to` from config. If you want every email redirected
to one address, set `--email-to` explicitly so the redirect is visible
in the command line.

Exit codes follow the standard table below; the worst per-user outcome
wins (auth > upstream > not-found).

### Org-wide overview via `overview`

Computes a `sec_score` for every user in your Iru tenant - the sum of CVSS
scores across all active detections on all their devices - and rolls those up
into org-wide totals, averages, a Best-5 leaderboard, a Most-Dangerous-5
leaderboard, and a full ranked roster. Supports the standard output formats
(`table`, `json`, `yaml`, `csv`) plus `email`. With `-o email` you can send a
single admin report to one or more addresses, or use `--per-user` to fan out a
personalised copy to every user with devices.

#### How `sec_score` is computed

- Each user's `sec_score` is the sum of CVSS scores across every active
  detection on every device they own.
- Iru drops a detection when the issue is patched - there is no separate
  "active" filter needed on the jellyfish side.
- Detections with an empty or `"Undefined"` severity are still counted in
  `sec_score` and `total_issues`, but do not increment any of the four
  severity buckets (`critical_issues`, `high_issues`, `medium_issues`,
  `low_issues`). The four severity counts will therefore not always sum to
  `total_issues` for a given user.
- Users with no devices are excluded from totals, averages, leaderboards, and
  the roster entirely.

#### Tier thresholds

The roster row colour (and email border colour) is determined by the user's
`sec_score`. These are the initial values, locked at design time; they may be
retuned after the first real-data review.

| Tier | SecScore range | Colour |
|---|---|---|
| critical | >= 100 | red (`#dc2626`) |
| high | 30 - 99.9 | orange (`#ea580c`) |
| medium | 5 - 29.9 | yellow (`#ca8a04`) |
| good | < 5 | green (`#16a34a`) |

#### Usage

```bash
# Default table output to stdout
jellyfish overview

# CSV for spreadsheets
jellyfish overview -o csv > scores.csv

# Send an admin report by email
jellyfish overview -o email --email-to security@example.com

# Per-user fanout preview (no mail sent)
jellyfish overview -o email --per-user --dry-run

# Admin report with an editor-composed message
jellyfish overview -o email --email-to security@example.com --message

# Roster restricted to two users
jellyfish overview --emails alice@example.com,bob@example.com
```

#### Flags

| Flag | Purpose |
|---|---|
| `--csv <path>` | Read user emails to include from a CSV file. Mutually exclusive with `--emails`. Default: all users with devices. |
| `--emails <list>` | Comma-separated user emails to include. Mutually exclusive with `--csv`. Default: all users with devices. |
| `--csv-email-column <name>` | Override CSV header auto-detection. Default scans for `email`, `user_email`, `e-mail` (case-insensitive). |
| `--per-user` | Fan out personalised copies (only with `-o email`). Each recipient gets a copy personalised to them - see below. |
| `--email-to <addr>` | Comma-separated admin recipients. Required for `-o email` without `--per-user`. When combined with `--per-user`, every personalised copy is redirected to this address (test/audit mode); stderr lines include `for=<user-email>` for traceability. |
| `--email-from` | From: address (default: `email.from` from config, then git `user.email`). |
| `--email-subject` | Subject: header (default: per-command default or `email.subject_template`). |
| `--email-header-bg` | Email header background colour as `#RRGGBB` (default: `email.header_bg` or `#2b3a55`). |
| `--email-logo` | Path to a PNG to show in the email header (default: `email.logo_path`). |
| `--message` | Open `$VISUAL`/`$EDITOR` to compose a message rendered above the body (shared across all recipients). |
| `--message-file` | Read the message body from a file (use `-` for stdin). Mutually exclusive with `--message`. |
| `--dry-run` | Run the full pipeline including render, but skip the Gmail send. |
| `--yes` | Skip the interactive confirmation prompt. |
| `--no-cache` | Bypass the detection cache; always fetch fresh from Iru. |

#### Stderr line format

Admin path (one report to `--email-to` recipients):

```
sent to=alice@acme.com gmail-id=<id>
would-send to=alice@acme.com bytes=NNN         # dry-run only
error to=alice@acme.com gmail: <reason>
summary: sent=N errors=K                        # admin path totals
```

Per-user path (`--per-user`):

```
sent user=<id> to=alice@acme.com gmail-id=<id>
would-send user=<id> to=alice@acme.com bytes=NNN
skip user=<id> reason=no-email
error user=<id> gmail: <reason>
summary: sent=N skipped=M errors=K              # per-user path totals
```

When `--email-to` is also set, every personalised copy is redirected to that
address (test/audit mode) and lines gain a `for=<user-email>` field:

```
note: --email-to set; all N personalised overviews will be redirected to <addr>
sent user=<id> for=alice@acme.com to=<addr> gmail-id=<id>
would-send user=<id> for=alice@acme.com to=<addr> bytes=NNN
error user=<id> for=alice@acme.com gmail: <reason>
```

The trailing `summary:` line is always emitted, even at zero counts.

#### Filtering the roster

By default `overview` includes every user with at least one device. To
narrow the roster to a named subset, pass either `--csv` or `--emails`.
Both totals, averages, leaderboards, and the roster itself are then
computed over just that subset. The `--per-user` fanout (when used)
sends only to the filtered users.

```sh
# Compute the overview for the platform team only
jellyfish overview --emails alice@example.com,bob@example.com

# Subset from a CSV (auto-detects email / user_email / e-mail headers)
jellyfish overview --csv ./platform-team.csv -o email --per-user

# Override the column when the CSV uses a non-default header
jellyfish overview --csv ./contacts.csv --csv-email-column primary_email
```

Filter entries that don't match any device-owning user in the tenant
produce a `warn: <email> not in tenant devices` line on stderr - useful
for catching typos or stale CSVs without aborting the run.

#### Email headers

Every sent message sets `X-Jellyfish-Report: overview`. See
[Filtering Jellyfish mail in Gmail](#filtering-jellyfish-mail-in-gmail) for
how to use `List-Id` and `X-Jellyfish-Report` headers to route or label
Jellyfish mail.

#### How `--per-user` differs from the admin report

The admin report is identical for every address in `--email-to` - whole-org
summary, Best-5, Most-Dangerous-5, full roster, no user-specific callout.

With `--per-user` each copy contains the same whole-org summary and
leaderboards, plus two additions:

- A **"Your standing"** callout between Most Dangerous 5 and the full roster,
  showing the recipient's rank (e.g. "14th of 87"), device count, issue count,
  severity pills, and score.
- A highlighted **YOU** row in the full roster - blue left border, blue rank
  tile, blue background, and a `YOU` pill next to the recipient's name.

The shared content (totals, averages, leaderboards, roster) is identical
across all per-user copies; only the `Me` binding changes.

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
make test
make lint
```

Real-Keychain integration tests:

```bash
JELLYFISH_KEYCHAIN_TESTS=1 go test ./internal/keychain/... -count=1
```

The first run will pop a macOS dialog asking to allow the test binary to read
your Keychain; approve it and re-run.

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

### Linux / Windows support

The CLI is macOS-only because the credential store is the macOS Keychain.
Porting to Linux would mean swapping in libsecret (or similar); Windows would
need Credential Manager. Non-darwin builds currently fail at compile time on
the `keychain` package, which is the intended signal.

### Other future work

- Multi-profile support: the `--profile` flag is already declared but only
  `default` is honoured. The config file format already keys by profile name,
  so extending this is mainly a `--profile` plumbing change.
- Env-var fallback for the token (`JELLYFISH_API_TOKEN`) for CI environments
  with no Keychain.
- A configurable `--cache-ttl` flag (currently the 15-minute TTL is hardcoded).
- Write operations (acknowledge, suppress, kick off remediation).
- A `-vv` extra-verbose mode that logs response bodies with token + PII
  redaction.
- Promote `internal/iru` to a public package once a second consumer needs the
  client.
