# Filter-friendly email headers: `List-Id` and `X-Jellyfish-*`

Status: design
Date: 2026-05-17

## Goal

Make Jellyfish-sent email easy to filter and audit by adding standard and
custom headers:

- A single `List-Id` header so Gmail's first-class `list:` filter operator
  matches every Jellyfish-sent message in one rule.
- Three `X-Jellyfish-*` headers (`Report`, `Tenant`, `Version`) for audit /
  raw-header inspection in any client.

Operators get one Gmail rule that labels everything; the X-* headers carry
provenance (which command, which tenant, which build) for `.eml` audit and
non-Gmail clients.

## Non-goals

- Per-command `List-Id` granularity. Single Jellyfish-wide ID. Per-command
  discrimination lives in `X-Jellyfish-Report` (filterable in clients that
  expose raw headers, not in Gmail's filter UI).
- `List-Unsubscribe` header. Not a mailing list; would invite "Unsubscribe"
  UI in Gmail for transactional reports.
- `Sender:` header. Single Workspace sender; no need.
- `X-Jellyfish-Input-Email` (the bulk-only "what CSV row produced this"
  header). Deliberately skipped to keep every command's header set
  symmetric.
- A CLI flag to override `List-Id` per invocation. Config is the right
  level for an org-wide identity.
- A prompt in `jellyfish configure email` for `list_id_domain`. Advanced
  knob, YAML-only, README-documented.

## Header surface

Every Jellyfish-sent email gains four new headers, written after
`MIME-Version` and before `Content-Type`:

```
From: ...
To: ...
Subject: ...
Date: ...
Message-ID: ...
MIME-Version: 1.0
List-Id: <jellyfish.example.com>
X-Jellyfish-Report: users-send
X-Jellyfish-Tenant: acme
X-Jellyfish-Version: v1.2.3
Content-Type: ...
```

### `List-Id`

- Bracketed-only, no human-readable name prefix. Matches RFC 2919 and
  Gmail's `list:` filter operator.
- Domain comes from new config key `email.list_id_domain`. When unset,
  defaults to the domain portion of `email.from` (i.e. the same domain
  used for `Message-ID`).
- If neither is available, the `List-Id` header is omitted entirely
  (defensive; should not happen because `From` is required).

### `X-Jellyfish-Report`

- Identifies the source command. Three values in v1:
  - `vulns-summary`
  - `user-show`
  - `users-send`
- Hardcoded per command (not user-configurable). This IS the command
  identity.
- Omitted entirely when empty (test fixtures may construct messages
  without it).

### `X-Jellyfish-Tenant`

- The Iru tenant subdomain, sourced from `config.Profile.Subdomain`
  (which already populates `email.Options.Tenant`).
- Omitted entirely when empty.

### `X-Jellyfish-Version`

- The Jellyfish build version, sourced from
  `github.com/bawdo/jellyfish/internal/version.Version`.
- Omitted entirely when empty.

## Sanitisation

All values flow through the existing `sanitiseHeaderValue` (strips CR/LF)
already used by `assembleMessage`. None of these values are operator-typed
free-form text in v1 (Report is hardcoded, Tenant comes from config,
Version is built in via `-ldflags`, ListIDDomain is config), so the risk
of header injection is theoretical. The sanitiser stays as
defence-in-depth.

## Config schema

New optional key under `email:` in `~/.config/jellyfish/config.yml`:

```yaml
email:
  from: jellyfish-noreply@example.com
  list_id_domain: jellyfish.example.com  # optional
```

Go struct addition in `internal/config`:

```go
type EmailConfig struct {
    // ... existing fields ...
    ListIDDomain string `yaml:"list_id_domain,omitempty"`
}
```

No validation in the config loader. If the operator types a malformed
value, the result is a malformed `List-Id` header — visible in any
`.eml` and easy to fix. No `jellyfish configure email` prompt; README
documents it.

## Code layout

### `internal/email/email.go`

`Options` grows three fields:

```go
type Options struct {
    // ... existing ...
    Report       string // command identity; "" → skip header
    Version      string // build version;    "" → skip header
    ListIDDomain string // explicit List-Id domain;
                        // "" → derive from domainFromAddress(From)
}
```

`messageHeaders` mirrors the three new fields:

```go
type messageHeaders struct {
    From         string
    To           string
    Subject      string
    Date         time.Time
    Report       string
    Tenant       string
    Version      string
    ListIDDomain string
}
```

`assembleMessage` writes the new headers in stable order between
`MIME-Version` and `Content-Type`. Header is skipped (not emitted with
empty value) when the source field is empty.

### Renderers (`internal/email/user_show.go`, `internal/email/vulns_summary.go`)

When building the `messageHeaders` from `Options`, populate the new
fields:

```go
hdr := messageHeaders{
    From:         r.opts.From,
    To:           r.opts.To,
    Subject:      subject,
    Date:         r.opts.GeneratedAt,
    Report:       r.opts.Report,
    Tenant:       r.opts.Tenant,
    Version:      r.opts.Version,
    ListIDDomain: r.opts.ListIDDomain,
}
```

### `cmd/email.go` (`resolveEmailOptions`)

Two new lines populate `Version` and `ListIDDomain` from config + the
build constant:

```go
opts.Version = version.Version
opts.ListIDDomain = prof.Email.ListIDDomain
```

`Report` is intentionally NOT set here — `resolveEmailOptions` is
shared across commands and shouldn't know command identity.

### Per-command Report wiring

Each command's send / email-render path sets the Report value after
calling `resolveEmailOptions`:

- `cmd/vulns.go`:
  - `runSendVulnsSummary` → `emailOpts.Report = "vulns-summary"`
  - `renderVulnsSummary` email branch (for `-o email`) → same
- `cmd/user.go`:
  - `runSendUserShow` → `emailOpts.Report = "user-show"`
  - `renderUserBundle` email branch → same
- `cmd/users.go`:
  - `runUsersSendEmail` → `baseEmailOpts.Report = "users-send"`

## Testing

| Test | File | Asserts |
|---|---|---|
| `TestAssembleMessageEmitsListIdFromDomain` | `internal/email/email_test.go` | `List-Id: <example.com>` when `ListIDDomain == ""` and `From = "ops@example.com"` |
| `TestAssembleMessageHonoursExplicitListIDDomain` | `internal/email/email_test.go` | `List-Id: <jellyfish.example.com>` overrides the From-derived default |
| `TestAssembleMessageEmitsAllXJellyfishHeaders` | `internal/email/email_test.go` | All three `X-Jellyfish-*` headers appear with the supplied values |
| `TestAssembleMessageSkipsEmptyXHeaders` | `internal/email/email_test.go` | When Report/Tenant/Version are empty, those header lines are absent (not present with empty value) |
| `TestAssembleMessageSkipsListIDWhenNoFromDomain` | `internal/email/email_test.go` | Defensive: empty `ListIDDomain` AND `From` without `@` → no `List-Id` header |
| `TestRunUsersSendEmailSetsReportHeader` | `cmd/users_test.go` | Bulk happy-path: parse the .eml from `fakeGmailSender.sent` and assert `X-Jellyfish-Report: users-send` |
| `TestUserShowSendEmailSetsReportHeader` | `cmd/user_test.go` | Single `user show --send-email`: assert `X-Jellyfish-Report: user-show` |
| `TestVulnsSummarySendEmailSetsReportHeader` | `cmd/vulns_test.go` | `vulns summary --send-email`: assert `X-Jellyfish-Report: vulns-summary` |

### Golden file regeneration

Six golden files pin the assembled message bytes:

- `internal/email/testdata/user_show.golden.eml`
- `internal/email/testdata/user_show_no_detections.golden.eml`
- `internal/email/testdata/user_show_with_message.golden.eml`
- `internal/email/testdata/vulns_summary.golden.eml`
- `internal/email/testdata/vulns_summary_empty.golden.eml`
- `internal/email/testdata/vulns_summary_with_message.golden.eml`

All six will need regeneration because four new header lines are inserted
between `MIME-Version` and `Content-Type`. The existing `-update-golden`
flag regenerates them. Review the diff to confirm only the four new
header lines appear; no other content changes.

## Documentation

### README

Two short additions:

1. **Under "Configure email":** one paragraph + YAML snippet documenting
   `email.list_id_domain`. Explain the default (derive from From domain)
   and when to override (org-wide audit identity distinct from sending
   mailbox).

2. **Under "Email output":** new "Filtering in Gmail" subsection. One
   sentence on `list:example.com` (matching whatever domain ships
   in `list_id_domain`); a one-line example filter that labels every
   Jellyfish mail; a mention that `X-Jellyfish-Report` is visible in
   "Show original" for splitting commands by hand.

## Edge cases

- **`From` address with no `@`:** invalid input that `resolveEmailOptions`
  already rejects upstream (the From validation errors before we get to
  the renderer). Belt-and-braces: if it ever does happen, `List-Id` is
  omitted rather than emitting `List-Id: <>` or `List-Id: <ops>`.
- **`list_id_domain` containing spaces or CR/LF:** `sanitiseHeaderValue`
  strips control characters; a value with a literal space produces a
  visibly malformed `List-Id: <foo bar.com>` line. Operator-visible bug,
  no security risk.
- **Empty `Version` string** (e.g., test fixtures that don't pin the
  build version): header is omitted. Tests assert this.
- **`Tenant` not set** (no config file or no subdomain): header is
  omitted. `email.Options.Tenant` already defaults to empty in this
  case.

## Out-of-scope follow-ups

- `X-Jellyfish-Input-Email` on bulk sends (deliberately omitted to keep
  command headers symmetric).
- `List-Unsubscribe` (intentionally avoided; would mis-signal these as
  marketing mail).
- Per-command `List-Id` (chose single Jellyfish-wide; granularity lives
  in `X-Jellyfish-Report`).
- A `jellyfish configure email` prompt for `list_id_domain` (advanced
  knob; YAML-only is the right ergonomic).
- Sieve / procmail recipe examples in the README.
