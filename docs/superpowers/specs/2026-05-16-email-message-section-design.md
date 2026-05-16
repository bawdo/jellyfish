# Optional message section in email output

**Status:** Design approved, ready for implementation plan.
**Date:** 2026-05-16

## Goal

Let the author of a `vulns summary` or `user show` email attach a short
personal note (a cover paragraph, a heads-up, context for the reader) that
renders inside the styled email between the branded header and the stats
tiles. The note is opt-in via a CLI flag; when opted in, an editor opens so
the user can compose freely, or the text can be supplied from a file / stdin
for scripted use.

This is the natural way to send a vuln report with "Hi team - heads-up on the
KEV spike before Friday's freeze" stapled to the top, rather than firing off
the raw stats and relying on a separate email to provide context.

## Out of scope

- Markdown / rich text. The body is plain text (paragraphs and URLs only).
- HTML passthrough from the user. The renderer always escapes user input.
- Persisting the message anywhere outside the rendered .eml (no cache, no
  config key, no last-message file).
- Adding email/`--send-email` support to `vulns list`. Still deferred.
- Templated greetings / signatures driven from config.

## UX surface

Two new flags, declared on both `vulns summary` and `user show` alongside the
existing email flags. Identical semantics on both commands.

| Flag | Type | Behaviour |
|---|---|---|
| `--message` | bool | Opens `$VISUAL` (else `$EDITOR`, else `vi`) on a templated scratch file. On editor exit, the saved buffer has `#`-prefixed lines stripped and surrounding whitespace trimmed. Empty → exit 1. |
| `--message-file <path>` | string | Reads the message verbatim from `<path>`. `--message-file -` reads stdin. No `#` stripping. Whitespace-only → exit 1. |

### Validation (all exit 1)

- `--message` AND `--message-file` together:
  `--message and --message-file are mutually exclusive`.
- Either set without `-o email` or `--send-email`:
  `--message requires email output (-o email or --send-email)`.
- `--message-file` path unreadable: `read --message-file <path>: <wrapped err>`.
- Editor exited non-zero: `editor exited with status N`.
- Resulting message empty: `--message produced an empty message; aborting`.

### Editor invocation

The scratch file is created at `os.TempDir()/jellyfish-message-<8 hex>.txt`
and unconditionally deleted (defer) regardless of success or failure. It is
pre-populated with:

```
# Jellyfish message for: <subject>
# To: <recipient>
# Lines starting with '#' will be ignored.
#

```

`<subject>` and `<recipient>` come from the already-resolved `email.Options`
(so they reflect any `--email-subject` / `--email-to` overrides). When the
recipient is empty (renderer would have rendered `<unspecified>`), the line
shows `# To: (none)`.

The editor process inherits the controlling terminal (`os.Stdin`,
`os.Stdout`, `os.Stderr`). Non-zero exit aborts the command before any
rendering / sending happens.

After read:

1. Split on `\n`.
2. Drop lines whose first non-whitespace byte is `#`.
3. Re-join with `\n`, run `strings.TrimSpace`.
4. If the result is empty → error, exit 1.
5. If `len(result) > 4000` → emit on stderr
   `warn: --message is N chars; long messages may be clipped by mail clients`
   and keep the full text. Soft cap, not hard.

### Editor choice

Lookup order: `$VISUAL` → `$EDITOR` → `vi`. Matches `git commit`,
`crontab -e`, and the general Unix convention. The chosen command is run as a
single token via `exec.LookPath`; the value is **not** word-split (so
`EDITOR="code -w"` would not work, which is a known and accepted limitation
matching, e.g., older versions of git). If we need that, we can revisit with
`shellwords`-style parsing later.

## Rendering

Placement: between the branded header and the stats tiles, in both HTML and
plain-text bodies.

### HTML

A new partial `_message.html.tmpl`:

```html
{{define "message"}}
{{- if .Message}}
<tr><td style="padding:18px 24px;border-bottom:1px solid #e2e8f0;background:#ffffff;">
  <div style="font:700 10px/1 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.1em;text-transform:uppercase;margin-bottom:10px;">Message</div>
  <div style="font:14px/1.55 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.MessageHTML}}</div>
</td></tr>
{{- end}}
{{end}}
```

The "MESSAGE" eyebrow matches the existing "TOP BY PRIORITY" eyebrow visually.
Guarded by `{{if .Message}}` so with no message the partial renders nothing
(not even whitespace differences in goldens).

Both `vulns_summary.html.tmpl` and `user_show.html.tmpl` insert
`{{template "message" .}}` immediately after `{{template "header" .}}`.

### Plain text

Both `vulns_summary.txt.tmpl` and `user_show.txt.tmpl` get a guarded block at
the very top:

```
{{if .Message -}}
{{.Message}}

---

{{end -}}
```

Raw text, no escaping, no linkification. The author wrote it; whatever
paragraph structure they used renders verbatim.

### Auto-linkification (HTML only)

Two small helpers in `internal/email/message.go`:

- `linkifyHTML(plain string) template.HTML` — `html.EscapeString` the input,
  then walk it with a conservative regex to wrap matches of
  `https?://[^\s<>"']+` in `<a href="X" style="color:#0f172a;text-decoration:underline;">X</a>`.
  Trailing punctuation (`.`, `,`, `)`, `;`, `:`) at the end of the match is
  excluded from the link (so "see https://example.com." links to
  `https://example.com`, with the period outside the anchor).
- `paragraphsHTML(plain string) template.HTML` — split on runs of blank
  lines into paragraphs, wrap each in `<p style="margin:0 0 10px;">…</p>`,
  call `linkifyHTML` per paragraph, and replace remaining single newlines
  inside a paragraph with `<br>`.

The renderer assigns `view.MessageHTML = paragraphsHTML(opts.Message)` only
when `opts.Message != ""`.

## Plumbing

### `email.Options`

Add one field:

```go
Message string // plain-text message body; empty disables the section
```

`withDefaults()` does not change. The existing `From == ""` guard stays.

### View structs

Both `vulnSummaryView` and `userShowView` gain:

```go
Message     string         // raw plain text, used by the text template and the {{if}} guard
MessageHTML template.HTML  // escaped + linkified + paragraph-wrapped
```

`build*View` populates them straight from `opts.Message`.

### Embed lists & ParseFS

`internal/email/vulns_summary.go` and `internal/email/user_show.go` both add
`templates/_message.html.tmpl` to their `//go:embed` directive and to the
`ParseFS` call in `renderXxxHTML`.

### cmd layer

- `cmd/email.go`: extend `emailFlagValues` with `Message bool` and
  `MessageFile string`; `readEmailFlags` reads them. **No change** to
  `resolveEmailOptions` — message capture happens after it.
- New `cmd/message.go` exposing
  `captureMessage(flags emailFlagValues, hasEmailOutput bool, recipient, subject string, stdin io.Reader, stderr io.Writer, runEditor func(path string) error) (string, error)`.
  Encapsulates mutual-exclusion, the output-mode gate, file/stdin read,
  editor launch, `#` stripping, whitespace trim, soft cap warning. The
  production `runEditor` resolves the `$VISUAL` → `$EDITOR` → `vi` chain via
  `exec.LookPath`, runs the resolved binary against the scratch path with
  inherited stdio, and returns a non-nil error if the child exits non-zero or
  cannot be launched. Tests pass a fake that writes a known body to the
  scratch path and returns nil.
- `cmd/vulns.go` and `cmd/user.go`: register the two new cobra flags
  alongside the existing email flags. In each command's run function, after
  `resolveEmailOptions` produces `eo`, call `captureMessage(...)` and assign
  the result to `eo.Message`. Doing this **before** the renderer is
  constructed (and before any Gmail send setup) means an editor abort costs
  nothing.

The `hasEmailOutput` argument is `flags.Send || explicitOutput == "email"`.
It is the gate for the "neither -o email nor --send-email" error.

## Error handling summary

| Condition | Exit | stderr |
|---|---|---|
| `--message` and `--message-file` both set | 1 | `--message and --message-file are mutually exclusive` |
| `--message`/`--message-file` set, no email output | 1 | `--message requires email output (-o email or --send-email)` |
| `--message-file` unreadable | 1 | `read --message-file <path>: <err>` |
| editor non-zero exit | 1 | `editor exited with status N` |
| editor exec failure (e.g. vi not on PATH and `$EDITOR` unset) | 1 | `launch editor: <err>` |
| result empty after stripping | 1 | `--message produced an empty message; aborting` |
| result > 4000 chars | 0 (renders) | `warn: --message is N chars; long messages may be clipped by mail clients` |

## Testing strategy

- `internal/email/message_test.go`: table tests for `linkifyHTML` (URL with
  trailing punctuation; URL inside parentheses; no URL; multiple URLs;
  characters needing escape inside and outside URLs) and `paragraphsHTML`
  (single paragraph; multiple paragraphs separated by blank lines; single
  newline within a paragraph → `<br>`; empty input → empty `template.HTML`).
- Golden files: new with-message variants for both renderers under
  `internal/email/testdata`. Existing without-message goldens must remain
  byte-for-byte identical — the `{{if}}` guard is responsible for this and is
  the regression-trip.
- `cmd/message_test.go`: cover mutual-exclusion error, output-mode gate
  error, file path read (including `-` reading from an injected `io.Reader`),
  comment-line stripping, whitespace-only abort, soft-cap warning emitted on
  stderr, editor-exit-non-zero error, success path with an injected fake
  `runEditor` that writes a known body to the scratch path.
- `cmd/vulns_test.go` and `cmd/user_test.go`: assert both flags exist on the
  cobra commands (matches the existing pattern for `--email-header-bg` /
  `--email-logo`).

The integration smoke (real Gmail send to `k@example.com`) is **not**
re-run for this change; the existing send tests cover the byte path. A new
test that asserts `opts.Message` propagates to the rendered .eml when set is
covered by the with-message golden.

## Open questions

None at design time.

## README updates

Add a "Message section" subheading under "Email output" with:

- The two flags and their interplay.
- The editor lookup order.
- The `#`-strip rule (and that it does not apply to `--message-file`).
- The soft cap behaviour.
- A one-line example each:
  - `jellyfish vulns summary --severity critical --send-email --message`
  - `jellyfish user show alice@example.com --send-email --message-file note.txt`
  - `echo "FYI" | jellyfish user show alice@example.com --send-email --message-file -`

Update the email-flags table to list `--message` and `--message-file`.
