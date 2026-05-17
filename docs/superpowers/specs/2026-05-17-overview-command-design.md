# Org-wide security overview — `jellyfish overview`

Status: design
Date: 2026-05-17

## Goal

Produce a single org-wide security overview that summarises every user
who has at least one device. For each user we compute a `sec_score` —
the sum of CVSS scores across every active issue on every one of their
devices — and roll those up into totals, averages, two leaderboards
("The best 5", "The most dangerous 5") and a full roster.

The command supports the same output formats as the rest of the CLI
(`table`, `json`, `yaml`, `csv`, `email`) and the same Gmail send
plumbing as `jellyfish users send-email`. With `--per-user` it fans the
email out to every user with devices, each copy personalised so the
recipient sees where they sit in the ranking.

## Non-goals

- No new severity scoring model. `sec_score` is the straight sum of
  CVSS scores Iru already returns on each detection. No weighting,
  normalisation, or trend computation.
- No historical comparison ("up 12% on last week"). Single point-in-time
  snapshot.
- No filtering flags (by department, by score band, etc.). The overview
  is whole-org; downstream filtering is a spreadsheet job on the CSV.
- No `--top N` flag. The leaderboards are fixed at five each; tweaking
  this is out of scope.
- No per-recipient template substitution in `--message`. The optional
  message is verbatim for every recipient (same as `users send-email`).
- No concurrency for the `--per-user` send loop. Strictly sequential.
- No "summary by department" or "summary by blueprint". One axis (user)
  for this command; other dimensions can be future siblings.
- ~~No `--csv` / `--emails` recipient list flags.~~ This non-goal was
  reversed: `--csv`, `--emails`, and `--csv-email-column` were added to
  let operators restrict the overview to a named subset of users. The
  original workaround (pipe `overview -o csv` into `users send-email`)
  still works but is no longer the only path.

## Command surface

```
jellyfish overview
    [-o table|json|yaml|csv|email]
    [--per-user]
    [--csv <path> | --emails <list>] [--csv-email-column <name>]
    [--email-to <addr>] [--email-from <addr>] [--email-subject <str>]
    [--email-header-bg <#RRGGBB>] [--email-logo <path>]
    [--message | --message-file <path>]
    [--dry-run] [--yes] [--no-cache]
```

### Flags

| Flag | Purpose |
|---|---|
| `-o, --output` | One of `table` (default), `json`, `yaml`, `csv`, `email`. |
| `--per-user` | With `--output=email` only: send one personalised copy to every user with devices instead of one admin report. |
| `--csv <path>` | Restrict the roster to users listed in this CSV file. Auto-detects `email`/`user_email`/`e-mail` header. Mutually exclusive with `--emails`. Default: all users with devices. |
| `--emails <list>` | Comma-separated list of user emails to include in the roster. Mutually exclusive with `--csv`. Default: all users with devices. |
| `--csv-email-column <name>` | Override CSV header auto-detection for `--csv`. |
| `--email-to <addr>` | Recipient(s) for the admin report. Comma-separated list accepted. Required when `--output=email` and `--per-user` is not set. When combined with `--per-user`, every personalised copy is redirected to this address (test/audit mode); stderr lines include `for=<user-email>` for traceability. |
| `--email-from`, `--email-subject`, `--email-header-bg`, `--email-logo` | Standard email options. Resolved by the existing `resolveEmailOptions()` (flag > config > git). |
| `--message`, `--message-file <path>` | Optional editor / file message inserted via `_message.html.tmpl`. Verbatim for every send (admin or per-user). Mutually exclusive. |
| `--dry-run` | Run the full pipeline including render, but skip the Gmail send. |
| `--yes` | Skip the interactive confirmation prompt. |
| `--no-cache` | Bypass the user / detection cache; force a fresh walk. |

### Validation (exit 1)

- `--output=email` with neither `--email-to` nor `--per-user`.
- `--per-user` set with `--output` not equal to `email`.
- `--email-to` set with an invalid address (`mail.ParseAddress`).
- Both `--message` and `--message-file` set.
- `--message-file` empty after trimming whitespace.
- `--output=email` and Gmail not configured
  (`profile.Email.GmailConfigured == false`) and `--dry-run` not set.
- Resolved user roster is empty after the "users with devices" filter
  (clean exit 1 with `error: no users with devices`; nothing useful to
  send or render).

## Recipient model

- **Admin report (default).** One email per address in `--email-to`,
  identical content, no `Your standing` callout, no `YOU` highlight on
  any roster row.
- **`--per-user` fanout.** Recipients are derived from the Iru user
  list. Every user with `DeviceCount > 0` and a non-empty `Email`
  receives one copy. The shared parts of the view (totals, averages,
  best 5, most dangerous 5, full roster) are identical across all
  copies — only `Me` differs, which lights up the `Your standing`
  callout and tints the recipient's row in the full roster.

~~`--per-user` and `--email-to` are intentionally not combined. If both
are set, `--email-to` is ignored with a stderr warning. The reason: the
admin redirect pattern (`--email-to me@example.com` for testing) doesn't
make sense for a fanout where the audit value is "the right person got
their copy".~~

When both `--per-user` and `--email-to` are set, every personalised copy
is redirected to the `--email-to` address (test/audit mode). Each user's
personalisation (`Me` callout, `YOU` row) is preserved - the content is
identical to what that user would receive in production. To make each
user's copy identifiable on stderr, lines gain a `for=<user-email>` field
when a redirect is in effect and the user has a non-empty email.

## Execution flow

```
1. parse + validate flags                                  (exit 1 on bad input)
2. compose message ONCE (if --message / --message-file)    (exit 1 if empty)
3. build Iru client; if --output=email and not --dry-run,
   build Gmail sender                                      (exit 2 on auth fail)
4. fetch users + devices + detections:
   a. ListUsersStream — walk every user                    (paginated)
   b. ListDetectionsStream — walk every detection once     (~30-90s first call;
                                                            progress to stderr)
   c. for each user, ListDevices (sequential; matches the strictly
      sequential pattern from users send-email) to get device IDs.
      Progress emitted to stderr as `users: 23/87 fetched` every ~5
      users so long walks don't look hung.
   d. bucket detections by DeviceID in memory
5. assemble per-user UserStats:
   - filter users where DeviceCount > 0
   - sum CVSS across detections-on-their-devices -> SecScore
   - tally Critical/High/Medium/Low counts (severity field)
6. sort by SecScore asc, name asc tiebreak; assign Rank (1 = lowest sec_score = most secure)
7. compute OverviewTotals + OverviewAverages
   (averages denominated by users-with-devices count)
8. dispatch on --output:
   - table       -> sectioned tables to stdout (TOTALS, BEST 5,
                   MOST DANGEROUS 5, ALL USERS)
   - json/yaml   -> single OverviewView object to stdout
   - csv         -> per-user rows only, named columns
   - email       -> render once (admin) or N times (per-user),
                   confirm, send (or would-send under --dry-run)
9. exit code per the existing classifyError matrix
   (0 / 1 / 2 / 3 / 4 with the same precedence as users send-email)
```

### Key decisions

- **Single detection walk.** Step 4b runs the same `ListDetectionsStream`
  the existing commands use. The per-user bucketing is in-memory; no
  per-user detection refetches.
- **Sort happens before render.** All output formats consume the same
  pre-sorted `UserStats` slice; the renderers don't re-sort. Rank is
  assigned once.
- **Averages exclude the no-devices user count.** Denominator is the
  filtered roster (users with devices). Mixing in users-with-no-devices
  would understate per-user numbers in a misleading way.
- **`sec_score` precision.** Stored as `float64`, formatted `%.1f`
  everywhere (matches CVSS convention). Averages also one decimal.
- **Tie-breakers.** Roster and Best 5 sort by `SecScore asc, name asc,
  user-id asc`. Most Dangerous 5 re-sorts a copy by `SecScore desc,
  name asc, user-id asc`. Output is deterministic across runs and
  renderers.

- **Rank semantics.** The `UserStats.Rank` field is the global rank
  (**1 = lowest SecScore = most secure**). The roster is sorted SecScore
  asc, so position-in-roster equals Rank. Leaderboard sections in the
  email display a *leaderboard position* (1-5) computed from the slice
  index, not the global rank, so position 1 in "Best 5" is the most
  secure user and position 1 in "Most Dangerous 5" is the most dangerous
  user. The global Rank is only displayed in (a) the full roster's rank
  tile, (b) the per-user `Your standing` callout copy ("14th of 87"
  where 1st is the safest user in the org), and (c) the `Rank` column
  in JSON / YAML output.

- **View types live in `internal/email`.** Following the existing
  `email.UserBundleInput` pattern, the `OverviewView`, `UserStats`,
  `OverviewTotals`, and `OverviewAverages` types are defined in
  `internal/email/overview_types.go`. The `cmd` package builds and
  populates them; all renderers (table / csv / json / yaml / email)
  consume the same types. This avoids a cyclic import (`email` cannot
  depend on `cmd`).
- **No `--top N`.** Five is the spec. If we change our mind later,
  add it then.

## Stderr line format

Admin path (single recipient list):

```
sent to=alice@acme.com gmail-id=<id>
would-send to=alice@acme.com bytes=NNN         # dry-run only
error to=alice@acme.com gmail: <reason>
summary: sent=N errors=K                        # admin path totals
```

Per-user path:

```
sent user=<id> to=alice@acme.com gmail-id=<id>
would-send user=<id> to=alice@acme.com bytes=NNN
skip user=<id> reason=no-email
error user=<id> gmail: <reason>
summary: sent=N skipped=M errors=K              # per-user path totals
```

The trailing `summary:` line is always emitted, even at zero counts.

## Code layout

### New file: `cmd/overview.go`

```go
type overviewOpts struct {
    Output       string              // table | json | yaml | csv | email
    PerUser      bool
    EmailFlags   emailFlagValues     // To/From/Subject/HeaderBG/Logo/Message/MessageFile
    DryRun       bool
    Yes          bool
    NoCache      bool
    Profile      config.Profile
    EmailNow     time.Time
    // injected for tests:
    gitEmail     gitEmailLookup
    KeychainGet  func() ([]byte, error)
    NewSender    gmailNewSender
    ConfirmReader io.Reader
}

func newOverviewCmd() *cobra.Command
func runOverview(ctx context.Context, client iruClient,
    stdout, stderr io.Writer, opts overviewOpts) error

// data assembly
func assembleOverview(ctx context.Context, client iruClient,
    stderr io.Writer, noCache bool) (email.OverviewView, error)

// per-output dispatch (all consume email.OverviewView)
func renderOverviewTable(w io.Writer, v email.OverviewView) error
func renderOverviewCSV(w io.Writer, v email.OverviewView) error
func renderOverviewJSON(w io.Writer, v email.OverviewView) error
func renderOverviewYAML(w io.Writer, v email.OverviewView) error

// email send paths
func sendOverviewAdmin(ctx context.Context, sender gmail.Sender,
    opts email.Options, stderr io.Writer, v email.OverviewView,
    recipients []string, dryRun bool) (sendCounters, error)
func sendOverviewPerUser(ctx context.Context, sender gmail.Sender,
    opts email.Options, stderr io.Writer, v email.OverviewView,
    dryRun bool) (sendCounters, error)
```

### New types: `internal/email/overview_types.go`

Defined in `internal/email` (not `cmd`) for the reasons in Key
decisions above. The `cmd` package imports them.

```go
type UserStats struct {
    UserID      string
    Name        string   // User.Name; falls back to User.Email when empty
    Email       string
    DeviceCount int
    SecScore    float64
    TotalIssues int
    Critical    int
    High        int
    Medium      int
    Low         int
    Rank        int      // 1 = lowest SecScore (most secure)
}

type OverviewTotals struct {
    UserCount   int      // users with devices
    DeviceCount int
    TotalIssues int
    Critical    int
    High        int
    Medium      int
    Low         int
    SecScore    float64
}

type OverviewAverages struct {
    DevicesPerUser   float64
    IssuesPerUser    float64
    SecScorePerUser  float64
    CriticalPerUser  float64
    HighPerUser      float64
    MediumPerUser    float64
    LowPerUser       float64
}

type OverviewView struct {
    Tenant          string
    GeneratedAt     time.Time
    Totals          OverviewTotals
    Averages        OverviewAverages
    BestFive        []UserStats   // SecScore asc, then name asc (lowest score first)
    MostDangerousFive []UserStats // SecScore desc, then name asc (highest score first)
    Users           []UserStats   // full roster, SecScore asc, then name asc (rank 1 = most secure)
    Me              *UserStats    // nil unless rendering a per-user copy
}
```

### Interface addition: `cmd/iru_iface.go`

```go
ListUsersStream(ctx context.Context, cb func(page []iru.User) error) error
```

Implemented in `internal/iru/users.go` as a thin loop over the existing
`ListUsersPage`. Mirrors the shape of `ListDetectionsStream`.

### New file: `internal/email/overview.go`

```go
type OverviewInput struct {
    View        OverviewView   // defined in overview_types.go (same package)
    Tenant      string
    GeneratedAt time.Time
}

func NewOverviewRenderer(opts Options) *OverviewRenderer
func (r *OverviewRenderer) Render(in OverviewInput) ([]byte, error)
```

`cmd/overview.go` builds an `OverviewView`, wraps it in `OverviewInput`,
and hands it to the renderer. Same shape as `UserBundleInput` today.

The renderer reuses:

- `Options.Report = "overview"` so the `X-Jellyfish-Report` header is
  set per the existing list-id / x-headers convention.
- `_header.html.tmpl`, `_message.html.tmpl`.
- `sevPillBG`, `sevPillFG`, `sevRowBG` helpers and the slate palette
  from `email.go`.
- `assembleMessage()` for RFC 5322 envelope assembly.

### New templates

- `internal/email/templates/overview.html.tmpl` — header (stat cards +
  inline averages), optional message, optional `Your standing` callout
  (rendered only when `.Me != nil`), Best 5, Most Dangerous 5, full
  roster. All sections use the row-card layout (coloured left border,
  rank tile, name, severity pills, score on the right). Column widths
  are identical across the three list sections.
- `internal/email/templates/overview.txt.tmpl` — plain text equivalent
  for the `text/plain` part. Simple ASCII sections, no styling, same
  data.

### Wiring

`cmd/root.go` registers `newOverviewCmd()` at the top level alongside
`user`, `users`, `vulns`, `configure`, `version`, `detections`,
`message`.

### Cache key

Reuse the existing detection cache; key on tenant + day. Users walk
uses the same TTL strategy as the detections walk (no separate user
cache layer — `ListUsersStream` is single-API; the cost is dominated
by the detections walk).

## Output structure

### Table

Sequential blocks, each its own `output.Table().WithColumns(...)`,
separated by a blank line and a single-line uppercase header label:

```
SECURITY OVERVIEW · <tenant> · <YYYY-MM-DD HH:MM>

TOTALS
metric              total      avg/user
users                  87             -
devices               142           1.6
issues              1,247          14.3
sec score          8,914.3         102.5
critical               23           0.3
high                  198           2.3
medium                512           5.9
low                   514           5.9

BEST 5
rank  name              sec_score   C   H   M   L
   1  Ada Lovelace            0.0   0   0   0   0
   2  Bruce Lee               3.7   0   0   1   0
   ...

MOST DANGEROUS 5
rank  name              sec_score   C   H   M   L
   1  Walter White          412.6   4  12  28  19
   ...

ALL USERS (87)
rank  name              sec_score   C   H   M   L
   1  Walter White          412.6   4  12  28  19
   ...
```

### JSON / YAML

Single `OverviewView` object, snake_case keys to match the rest of the
CLI:

```json
{
  "tenant": "acme",
  "generated_at": "2026-05-17T10:30:00Z",
  "totals": { "user_count": 87, "device_count": 142, ... },
  "averages": { "devices_per_user": 1.6, ... },
  "best_five": [{ "rank": 1, "name": "Ada Lovelace", ... }, ...],
  "most_dangerous_five": [{ "rank": 87, "name": "Walter White", ... }, ...],
  "users": [{ "rank": 1, ... }, ...]
}
```

`me` is omitted when nil (only present in per-user email rendering, not
stdout — JSON/YAML stdout never sets `Me`).

### CSV

One header row, one row per user, no totals, no sections:

```
name,email,devices_count,sec_score,total_issues,critical_issues,high_issues,medium_issues,low_issues
Walter White,walter@acme.com,2,412.6,63,4,12,28,19
Tony Stark,tony@acme.com,3,387.2,65,3,9,31,22
...
```

Sort order matches the email roster: `SecScore` desc, name asc.

### Email — admin

The full overview rendered in the order: header (stat cards +
averages), optional message, Best 5, Most Dangerous 5, full roster.
No `Your standing` callout. No row highlight on any roster row.

### Email — per-user

Identical to admin except `Me` is set, which inserts the `Your
standing` callout between Most Dangerous 5 and the full roster, and
tints the recipient's row in the full roster with a blue left border,
blue rank tile, blue background, and a `YOU` pill next to their name.

## Email visual design

All values from the locked-in mockups in the brainstorming session
(saved under `.superpowers/brainstorm/`):

- **Header totals** — slate-on-white card grid, two rows of four stat
  cards (counts on top, severities below), each cell stacks
  `<bignumber>` and `<UPPERCASE LABEL>` and a small `<NN / user>` line
  underneath. Severity colours: `#dc2626` critical, `#ea580c` high,
  `#ca8a04` medium, `#0369a1` low.
- **Best 5 / Most Dangerous 5** — row cards with a 3px left border
  (`#16a34a` green for best, `#dc2626` red for most dangerous), 28px
  rank tile in the section colour, name in bold slate, four severity
  pills, score in monospace on the right. Column widths fixed and
  identical across both sections.
- **Full roster** — same row-card layout. Border colour reflects the
  user's tier. **Initial thresholds** (to be reviewed after first
  real-data run; documented in the README, configurable as a follow-up):

  | Tier    | SecScore range | Border / rank colour |
  |---------|----------------|----------------------|
  | critical | >= 100        | `#dc2626` red        |
  | high     | 30 - 99.9     | `#ea580c` orange     |
  | medium   | 5 - 29.9      | `#ca8a04` yellow     |
  | good     | < 5           | `#16a34a` green      |
- **`Your standing` callout (per-user only)** — large blue rank
  (`14`<sup>`th`</sup> of 87), name, "N devices · N issues", severity
  pills, score. Tinted blue background, blue left border. Sits between
  Most Dangerous 5 and the full roster.
- **`YOU` row highlight (per-user only)** — recipient's row in the
  full roster gets the same blue tint, blue border, blue rank tile,
  and a small uppercase `YOU` pill next to the name.

## Error handling

| Error | Per-user? | Aborts batch? | Counts toward exit code |
|---|---|---|---|
| Bad flag combo | n/a | yes (before loop) | exit 1 |
| `--email-to` invalid address | n/a | yes | exit 1 |
| `--message-file` empty | n/a | yes | exit 1 |
| `--output=email` + Gmail not configured + not `--dry-run` | n/a | yes | exit 1 |
| Empty filtered roster (no users with devices) | n/a | yes | exit 1 |
| Iru down (users or detections walk fails) | n/a | yes | propagates existing exit code (4) |
| Gmail sender construction fails | n/a | yes (before loop) | exit 2 |
| User confirms `n` at prompt | n/a | yes (no sends) | exit 0; emits `aborted: no mail sent` |
| Admin: Gmail send 401/403 | yes (per recipient) | no | tracked → exit 2 |
| Admin: Gmail send 429/5xx | yes (per recipient) | no | tracked → exit 4 unless 2 also seen |
| Per-user: user has no email | yes | no | logged `skip`, does not affect exit |
| Per-user: Gmail send 401/403 | yes | no | tracked → exit 2 |
| Per-user: Gmail send 429/5xx | yes | no | tracked → exit 4 unless 2 also seen |

Reuses `classifyError` and the exit-code precedence (2 > 4 > 3) already
in place for `users send-email`.

## Edge cases

- **User with devices but zero detections.** SecScore = 0, severity
  counts all zero, appears at the bottom of the roster (Best 5 if in
  the lowest five). They're in scope — having devices is the filter,
  not having issues.
- **User with `User.Email` empty.** Excluded from `--per-user` send
  with a `skip user=<id> reason=no-email` line. Still appears in the
  rendered overview content (their row uses the User.ID or User.Name
  fallback).
- **Detection with empty `Severity` or `"Undefined"`.** Counted in
  `TotalIssues` and `SecScore`, but does not increment any of the four
  severity counts (the four-bucket pills will not sum to TotalIssues
  for that user — note this in the README).
- **CVSS score of 0.0.** Counted in `TotalIssues`, adds 0 to
  `SecScore`. Still a row in the roster.
- **Sole user with devices.** Best 5 and Most Dangerous 5 both
  contain only one row. Averages == that user's values.
- **Exactly five users with devices.** Both leaderboards contain all
  five, in opposite orders. Roster is the same five again. Acceptable;
  no special-casing.
- **Tied SecScores.** Resolved by name asc, then user-id asc. The user
  whose copy is rendered (in `--per-user`) is still the same user;
  rank assignment is stable across runs.
- **Cache hit in the middle of a per-user run.** The detection walk
  happens once at step 4b before the loop; per-user iteration reads
  from the in-memory bucket. Cache TTL behaviour is unchanged.
- **Confirm prompt EOF.** Treat as `n`; exit 0 with `aborted: no mail
  sent`. Same as `users send-email`.
- **Iru returns a user with a device count but ListDevices returns
  zero.** Honour `ListDevices` (it's the authoritative join). The
  user is filtered out.

## Testing strategy

| Layer | Tests |
|---|---|
| `assembleOverview` (fake iru client) | users-with-devices filter; sec_score sum across multiple devices; severity tally; rank assignment; sort stability; tie-breaker; empty roster error |
| `renderOverviewTable` | section ordering; column widths; thousand-separators; one-decimal precision; tier colouring N/A (table doesn't colour) |
| `renderOverviewCSV` | header row matches spec; row order; one row per user; no totals row; field formatting |
| `renderOverviewJSON / YAML` | snake_case keys; `me` omitted; `best_five` / `most_dangerous_five` cardinality and order |
| `OverviewRenderer` (golden tests) | admin variant; per-user variant; with message; without message; with logo; without logo; empty Best 5 if N < 5 (degenerate roster) |
| `sendOverviewAdmin` | multi-recipient loop; dry-run; gmail error per recipient does not abort; stderr line format; exit-code precedence |
| `sendOverviewPerUser` | skip no-email user; per-user `Me` is correct in each rendered copy; YOU row highlighted in goldens; dry-run; same exit-code precedence |
| `--per-user` flag combinations | error on `--output=table`; redirect to `--email-to` when set (test/audit mode); works with `--dry-run` |
| Confirm prompt | both paths' prompt copy differs (admin vs per-user); EOF; `--yes` short-circuit |

## Documentation

New README section under "Commands" titled **"Org-wide overview via
`overview`"**. Mirror the existing `users send-email` section:

- One example: `jellyfish overview` (default table output).
- One example: `jellyfish overview -o csv > scores.csv`.
- One example: `jellyfish overview -o email --email-to security@example.com`.
- One example: `jellyfish overview -o email --per-user --dry-run`.
- One example with `--message-file`.
- A short subsection **"How `sec_score` is computed"** explaining the
  CVSS-sum-per-user model, the tier thresholds used for the roster
  border colours, and the "user must have at least one device" filter.
- Note about the `X-Jellyfish-Report: overview` header and the
  `List-Id` value for this command (per the existing list-id spec).
- Cross-reference the existing "Exit codes" table.

## Out-of-scope follow-ups

These are deliberately deferred:

- `--top N` flag to override the leaderboard size.
- `--department`, `--blueprint`, `--platform` filters to restrict the
  overview to a slice of users.
- Trend / delta against a previous snapshot.
- Concurrency / `--parallel N` on the `--per-user` send loop.
- Per-recipient template substitution in the message body.
- Alternative score models (e.g. EPSS-weighted, KEV-boosted).
- A separate `overview devices` or `overview vulns` sibling for other
  aggregation axes.
- Reading from a Google Sheets URL instead of computing fresh.
