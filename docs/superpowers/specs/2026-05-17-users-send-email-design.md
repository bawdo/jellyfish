# Bulk user vulnerability mailout — `jellyfish users send-email`

Status: design
Date: 2026-05-17

## Goal

Send each user in a supplied list their own vulnerability report by email,
skipping any user who has no device or no active vulnerabilities. Input is
either a CSV file or a comma-separated list of email addresses. A single
optional message can be attached to every email in the batch.

This is the bulk analogue of `jellyfish user show <email> --send-email`.
The single-user command stays as-is; the bulk command reuses its render and
send pipeline via a small refactor.

## Non-goals

- No per-recipient template substitution (`{{.Name}}` etc). The message,
  if supplied, is verbatim for every recipient.
- No concurrency or bounded parallel sends. Strictly sequential.
- No CSV write of a per-row report. Stderr lines plus a summary line are
  the audit trail.
- No support for Iru user IDs in input; emails only.
- No `-o` flag. The subcommand name (`send-email`) implies the action; the
  command does not write `.eml` files to stdout.
- No hard cap on batch size. The interactive confirm prompt is the only
  pre-send brake (suppressible with `--yes`).

## Command surface

```
jellyfish users send-email
    (--csv <path> | --emails <list>)
    [--csv-email-column <name>]
    [--email-to <addr>]
    [--email-from <addr>] [--email-subject <str>]
    [--email-header-bg <#RRGGBB>] [--email-logo <path>]
    [--message | --message-file <path>]
    [--dry-run] [--yes] [--no-cache]
```

### Flags

| Flag | Purpose |
|---|---|
| `--csv <path>` | Read recipients from a CSV file. Mutually exclusive with `--emails`. |
| `--emails <list>` | Comma-separated list of email addresses. Mutually exclusive with `--csv`. |
| `--csv-email-column <name>` | Override CSV header auto-detection. Default scans for `email`, `user_email`, `e-mail` (case-insensitive). |
| `--email-to <addr>` | Redirect every recipient to one address (test/audit mode). When set, replaces the per-user recipient for every send. |
| `--email-from`, `--email-subject`, `--email-header-bg`, `--email-logo` | Same semantics as `user show --send-email`; carried via existing `emailFlagValues`. |
| `--message` | Open `$VISUAL` / `$EDITOR` / `vi` once to compose a body used verbatim for every recipient. |
| `--message-file <path>` | Read message body from file (or `-` for stdin). |
| `--dry-run` | Run the full pipeline (resolve, filter, would-render) but skip the Gmail send. |
| `--yes` | Skip the interactive confirmation prompt. |
| `--no-cache` | Force a fresh detection walk (otherwise reuse the 15-minute cache). |

### Recipient model

- **Default (no `--email-to`)**: each user receives their own report at
  their own email address (the address Iru holds for that user — usually,
  but not necessarily, the same as the input address).
- **With `--email-to <addr>`**: every email in the batch goes to that one
  address. Useful for test runs and audit. The per-user content is
  unchanged; only the `To:` header is rewritten.

This mirrors the precedence in `user show --send-email` today, minus the
`email.default_to` config fallback (the bulk command intentionally does
not consult `email.default_to` — if you want all mail redirected, set
`--email-to` explicitly).

### Validation (exit 1)

- both `--csv` and `--emails` set, or neither
- `--csv` path does not exist or is unreadable
- CSV has no header row or no email column (after auto-detect + override)
- `--emails` contains an entry without an `@` sign
- both `--message` and `--message-file` set
- `--email-to` set to an invalid address (via `mail.ParseAddress`)
- `--message-file` empty after stripping whitespace
- Gmail not configured (`profile.Email.GmailConfigured == false`) and
  `--dry-run` not set
- empty resolved recipient list (after dedupe)

## Execution flow

```
1. parse + validate flags                                   (exit 1 on bad input)
2. read identifiers
   - --csv  : open, parse header, find email column, collect addresses
              (dedupe case-insensitively, preserve first-seen order)
   - --emails: split on comma, trim, validate, dedupe
3. compose message ONCE (if --message / --message-file)     (exit 1 if empty)
4. build Iru client; if not --dry-run, build Gmail sender   (exit 2 on auth fail)
5. fetch ALL detections once (cache-aware, single walk)     (~30-90s first call;
                                                             progress to stderr)
6. interactive confirm:
   "About to send vulnerability reports to N users. Continue? [y/N]"
   (suppressed by --yes or --dry-run; --dry-run prints
    "DRY RUN — no mail will be sent" before listing actions)
7. for each email in input order:
     a. resolve user via FindUserByEmail
        - not-found  -> "error: <email> user not found in Iru"   (count error, continue)
     b. list user's devices
        - no devices -> "skip: <email> no devices"               (count skip, continue)
     c. bucket detections by device ID from the prefetched list
        - none across all devices -> "skip: <email> no vulnerabilities"
     d. resolve recipient: --email-to (if set) > user's own email from Iru
     e. render email (reuses email.NewUserShowRendererWithStderr)
     f. if --dry-run:   "would-send: <email> to=<recipient>"     (count would-send, continue)
        else:           send via Gmail, print
                        "sent: <email> to=<recipient> gmail-id=<id>"
                        - send failure -> "error: <email> gmail: <reason>" (count error, continue)
8. final summary line:
   "summary: sent=N skipped=M errors=K"
   (dry-run uses "would-send=N skipped=M errors=K")
9. exit code:
   - 0 if errors=0
   - 2 if any Gmail auth/permission errors
   - 3 if any user-not-found errors AND no auth/upstream errors
   - 4 if any Gmail rate-limit / 5xx errors
   - precedence (most-severe wins): 2 > 4 > 3
```

### Key decisions

- **Detection walk once.** Step 5 fetches every detection a single time
  before the loop. Each per-user iteration buckets in memory; no repeated
  30-90s walks. Cache TTL and `--no-cache` behaviour are unchanged.
- **Confirm uses resolved input count, not post-filter count.** We
  cannot filter without doing the per-user work. The confirm protects
  against bulk-sending against the wrong list (typo in path, stale CSV).
- **Errors never abort the batch.** A bad row mid-list does not strand
  the rest. The exit code reports the worst outcome at the end.
- **`<input-email>` is always the address from the input.** Every stderr
  line begins with the address the user typed / supplied, not the
  Iru-resolved recipient. Operators can trace each line to a row in the
  source CSV.

## Stderr line format

One record per line, grep-friendly, stable column order:

```
sent: <input-email> to=<recipient> gmail-id=<id>
would-send: <input-email> to=<recipient>           # dry-run only
skip: <input-email> no devices
skip: <input-email> no vulnerabilities
error: <input-email> user not found in Iru
error: <input-email> gmail: <reason>
summary: sent=N skipped=M errors=K                 # or would-send=N in dry-run
```

The trailing `summary:` line is always emitted, even when N+M+K = 0.

## Code layout

### New file: `cmd/users.go`

```go
type usersSendEmailOpts struct {
    CSVPath          string
    Emails           string
    CSVEmailColumn   string
    EmailTo          string              // when set, overrides per-user recipient
    EmailFlags       emailFlagValues     // carries Subject/From/HeaderBG/Logo/Message/MessageFile
    DryRun           bool
    Yes              bool
    NoCache          bool
    Profile          config.Profile
    EmailNow         time.Time
    // injected for tests:
    gitEmail         gitEmailLookup
    KeychainGet      func() ([]byte, error)
    NewSender        gmailNewSender
    ConfirmReader    io.Reader           // defaults to os.Stdin
}

func newUsersCmd() *cobra.Command           // parent, adds send-email subcommand
func newUsersSendEmailCmd() *cobra.Command  // flag wiring + RunE -> runUsersSendEmail

func runUsersSendEmail(ctx context.Context, client iruClient,
    stderr io.Writer, opts usersSendEmailOpts) error
    // orchestrates steps 1-9 above

func readRecipientList(opts usersSendEmailOpts) ([]string, error)
    // dispatches to readCSVRecipients or splitEmails

func readCSVRecipients(path, columnOverride string) ([]string, error)
    // header detect (case-insensitive), column resolve, row scan,
    // case-insensitive dedupe preserving first-seen order

func splitEmails(raw string) ([]string, error)
    // split-trim-validate-dedupe

func confirmSend(stderr io.Writer, in io.Reader,
    count int, dryRun, yes bool) (bool, error)

type bulkCounters struct {
    sent, wouldSend, skipped, errs int
    worstExitCode                  int  // 0, then bumped per the precedence rules
}
```

### Refactor in `cmd/user.go`

Extract two helpers so `users send-email` reuses the same render-and-send
path that `user show --send-email` already exercises:

```go
// resolveBundleForUser fetches a user + devices and buckets detections
// from a pre-fetched detection list. Used by the bulk loop; the single-user
// command keeps its existing fetch-then-bundle code path unchanged.
func resolveBundleForUser(ctx context.Context, client iruClient,
    email string, allDetections []iru.Detection) (UserBundle, error)

// sendUserBundle renders + sends a single user's email and returns the
// gmail id. Pre-conditions: emailOpts.To and emailOpts.Message already set,
// sender ready.
func sendUserBundle(ctx context.Context, sender gmail.Sender,
    emailOpts email.Options, stderr io.Writer, b UserBundle) (gmailID string, err error)
```

`runSendUserShow` collapses to: resolve user, fetch detections, bucket
via `resolveBundleForUser`, capture message, call `sendUserBundle`, print
its existing `sent: ...` line. Behaviour is preserved (existing tests in
`cmd/send_email_test.go` and `cmd/user_test.go` cover this).

### Wiring

`cmd/root.go` registers `newUsersCmd()` alongside the existing `user`,
`vulns`, and `configure` roots. The existing singular `user` (with the
`show` subcommand) and the new plural `users` (with `send-email`) coexist
intentionally — they map to different verbs (`show one`, `send to many`).
Cobra routes on the literal first token, so there is no conflict at parse
time. The README's "Usage" section will introduce them as siblings.

### Exit-code propagation

`classifyError` in `cmd/root.go` already maps Iru / Gmail sentinel errors
to exit codes 2, 3, and 4. The bulk runner uses the existing wiring: it
tracks the worst per-row failure category in `bulkCounters.worstExitCode`,
then on return wraps a sentinel error (`iru.ErrUnauthorized`,
`iru.ErrNotFound`, `iru.ErrRateLimited`) using `fmt.Errorf("%w: %d
errors", sentinel, n)`. `classifyError` picks up the wrapped sentinel and
returns the right code. No changes to `classifyError` itself.

### Editor template header in bulk

`captureMessage` includes a `# To: <recipient>` line in the editor
scratch template. In bulk mode there is no single recipient yet, so the
bulk runner passes a synthesised display string:

- `--email-to <addr>` set → `# To: <addr> (redirect)`
- otherwise → `# To: <N recipients>` (a literal count, not a list,
  to keep the scratch readable for large batches)

The body the user types is still used verbatim for every recipient.

### No new packages

The Iru client, detection fetch, email render, and Gmail send are reused
as-is from `internal/iru`, `internal/email`, and `internal/gmail`.

## Error handling

| Error | Per-user? | Aborts batch? | Counts toward exit code |
|---|---|---|---|
| Bad flag combo | n/a | yes (before loop) | exit 1 |
| `--csv` file missing / unreadable | n/a | yes | exit 1 |
| CSV has no email column | n/a | yes | exit 1 |
| `--emails` contains non-email | n/a | yes | exit 1 |
| Empty resolved recipient list | n/a | yes | exit 1 |
| Detection walk fails (Iru down) | n/a | yes | propagates existing exit code (4) |
| Gmail sender construction fails | n/a | yes (before loop) | exit 2 |
| User confirms `n` at prompt | n/a | yes (no sends) | exit 0; emits `aborted: no mail sent` |
| User-not-found (`FindUserByEmail` 404) | yes | no | tracked → exit 3 unless 2/4 also seen |
| ListDevices error | yes | no | tracked → exit 4 unless 2 also seen |
| Gmail send 401/403 | yes | no | tracked → exit 2 |
| Gmail send 429/5xx | yes | no | tracked → exit 4 unless 2 also seen |

## Edge cases

- **Empty CSV after header.** Treat as "no recipients" → exit 1 with a
  clear message naming the path.
- **Whitespace-only header cells.** Treated as untitled; skipped during
  auto-detect; `--csv-email-column` can still target a literal name.
- **Duplicate emails in input** (case-insensitive). Deduped at parse
  time. When at least one dupe was dropped, emit
  `note: deduped N entries` to stderr before step 6.
- **`--email-to` set with an invalid address.** Validated at flag parse
  time via `mail.ParseAddress`; exit 1.
- **`--message-file` empty after trim.** Exit 1 (matches existing
  single-user behaviour).
- **Confirm prompt EOF** (stdin closed before answer). Treat as `n`;
  exit 0 with `aborted: no mail sent`.
- **Detection cache miss + `--no-cache`.** The walk runs once at step 5;
  subsequent commands in the next 15 min benefit from the resulting
  cache write.
- **Mixed-case CSV header** (`Email`, `USER_EMAIL`). Matched
  case-insensitively.
- **CRLF line endings, BOM at start of file.** Handled transparently
  (Go's `encoding/csv` plus a BOM trim on first read).
- **Recipient that resolves to a user whose own email differs from the
  input address.** Recipient is the user's Iru email; the input address
  is still what shows in the stderr line for traceability.

## Testing strategy

| Layer | Tests |
|---|---|
| `readCSVRecipients` | header detect (3 default names), column override, missing header, missing column, dupes, empty rows, BOM, CRLF, mixed case |
| `splitEmails` | trim, dedupe, whitespace, invalid addresses, empty result |
| `confirmSend` | `y` / `Y` / `yes` / `n` / `N` / `<enter>` / EOF / `--yes` short-circuit / `--dry-run` short-circuit |
| `runUsersSendEmail` (end-to-end, fake iru client + fake gmail sender) | user not found, no devices, no vulns, has vulns; capture stderr; assert per-row lines, `summary:` line, and exit code |
| `--email-to` redirect | one fake user with own email; assert `To:` header in sent payload is the override, not the user's own |
| `--dry-run` | assert `NewSender` is never invoked, lines match `would-send:` format, summary uses `would-send=` |
| Exit-code precedence | mix of error categories in one run; assert the 2 > 4 > 3 ordering |
| Confirm-prompt abort | user answers `n`; assert zero sends, exit 0, `aborted: no mail sent` line |

No new golden fixtures needed; the existing `email.NewUserShowRenderer`
goldens already cover the rendered output.

## Documentation

New README section under "Usage" titled **"Bulk send via `users send-email`"**.
Mirror the style of the existing `--send-email` and `--message` sections:

- One example for `--csv` with header auto-detect.
- One example for `--csv --csv-email-column primary_contact`.
- One example for `--emails a@x,b@x`.
- One example for `--email-to me@example.com` (test/audit redirect).
- One example for `--dry-run` showing the would-send stderr.
- Note the deduplication, the single detection walk, the summary line
  format, and the exit-code precedence (cross-reference the existing
  "Exit codes" table).

## Out-of-scope follow-ups

These are deliberately deferred:

- Concurrency / `--parallel N` (sequential is fine for fleet sizes
  realistic for this tool).
- Per-recipient template substitution in the message body.
- Per-row CSV report output (`--report path.csv`).
- Reading from a Google Sheets URL instead of a CSV file.
- Pluggable input shapes beyond CSV / comma-list (e.g. JSON list).
