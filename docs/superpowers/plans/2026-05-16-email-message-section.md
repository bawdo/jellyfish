# Optional message section in email output - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--message` and `--message-file` flags to `jellyfish vulns summary` and `jellyfish user show`. When set, capture a plain-text note (via `$EDITOR` or from file/stdin) and render it inside the styled email between the header and the stats tiles.

**Architecture:** A new `internal/email/message.go` owns the HTML rendering (escape + auto-linkify + paragraph-wrap). A new `_message.html.tmpl` partial renders the block; both existing HTML templates include it, both `.txt.tmpl` templates prepend the raw text. `email.Options` gains one `Message` field; both view structs gain `Message` + `MessageHTML`. The cmd layer adds a `captureMessage` helper in a new `cmd/message.go` that handles the editor launch (`$VISUAL` → `$EDITOR` → `vi`), file/stdin read, `#`-comment stripping, whitespace trim, and a soft-cap warning. The editor invocation is injected as a `runEditor func(path string) error` so tests fake it. Capture runs after `resolveEmailOptions` and before any renderer construction, so an editor abort costs nothing.

**Tech Stack:** Go 1.25, `html/template`, `text/template`, stdlib `os/exec`, `regexp`, `html`.

**Spec:** `docs/superpowers/specs/2026-05-16-email-message-section-design.md`

---

## File map

**Create:**
- `internal/email/message.go` — `linkifyHTML`, `paragraphsHTML`
- `internal/email/message_test.go` — unit tests for both helpers
- `internal/email/templates/_message.html.tmpl` — guarded HTML partial
- `internal/email/testdata/vulns_summary_with_message.golden.eml` — golden for vulns summary + message
- `internal/email/testdata/user_show_with_message.golden.eml` — golden for user show + message
- `cmd/message.go` — `captureMessage` helper + production `runEditor`
- `cmd/message_test.go` — table tests for `captureMessage`

**Modify:**
- `internal/email/email.go` — add `Message string` to `Options`
- `internal/email/vulns_summary.go` — embed `_message.html.tmpl`, ParseFS, view fields, populate
- `internal/email/user_show.go` — same
- `internal/email/templates/vulns_summary.html.tmpl` — insert `{{template "message" .}}` after header
- `internal/email/templates/user_show.html.tmpl` — same
- `internal/email/templates/vulns_summary.txt.tmpl` — prepend guarded raw-text block
- `internal/email/templates/user_show.txt.tmpl` — same
- `cmd/email.go` — `emailFlagValues.Message bool` + `MessageFile string`; extend `readEmailFlags`
- `cmd/user.go` — register flags; call `validateMessageFlags` early in RunE; call `captureMessage` in `renderUserBundle` (email branch) and in `runSendUserShow`
- `cmd/vulns.go` — register flags; call `validateMessageFlags` early in RunE; call `captureMessage` in `renderVulns` (email branch) and in `runSendVulnsSummary`
- `cmd/user_test.go` — assert both new flags exist; assert non-email output errors
- `cmd/vulns_test.go` — assert both new flags exist; assert non-email output errors
- `README.md` — Email output → new "Message section" subsection; extend the flags table

---

## Task 1: Add `Message` field to `email.Options`

**Files:**
- Modify: `internal/email/email.go:25-44`

- [ ] **Step 1: Add the field**

Edit `internal/email/email.go`. In the `Options` struct, after the `LogoPath` field and before the `BoundaryOverride` block, add:

```go
	Message string // optional plain-text message; empty disables the message section
```

The final struct field order:

```go
type Options struct {
	To      string
	From    string
	Subject string

	CVELinkPrimary   string
	CVELinkSecondary string

	GeneratedAt time.Time
	Tenant      string

	HeaderBG string
	LogoPath string

	Message string // optional plain-text message; empty disables the message section

	BoundaryOverride        string
	RelatedBoundaryOverride string
	MessageIDOverride       string
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/email/...`
Expected: exits 0, no output.

- [ ] **Step 3: Run the existing email tests**

Run: `go test ./internal/email/... -count=1`
Expected: all existing tests still pass (no behaviour change yet).

- [ ] **Step 4: Commit**

```bash
git add internal/email/email.go
git commit -m "feat(email): added optional Message field to Options"
```

---

## Task 2: Build `linkifyHTML` and `paragraphsHTML`

**Files:**
- Create: `internal/email/message.go`
- Create: `internal/email/message_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/email/message_test.go`:

```go
package email

import (
	"html/template"
	"testing"
)

func TestLinkifyHTMLEscapesPlainText(t *testing.T) {
	got := linkifyHTML(`a <b> & "c"`)
	want := template.HTML(`a &lt;b&gt; &amp; &#34;c&#34;`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLWrapsSimpleURL(t *testing.T) {
	got := linkifyHTML(`see https://example.com here`)
	want := template.HTML(`see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a> here`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLExcludesTrailingPunctuation(t *testing.T) {
	got := linkifyHTML(`see https://example.com.`)
	want := template.HTML(`see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a>.`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLExcludesTrailingClosingParen(t *testing.T) {
	got := linkifyHTML(`(see https://example.com)`)
	want := template.HTML(`(see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a>)`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLHandlesMultipleURLs(t *testing.T) {
	got := linkifyHTML(`a https://x.test b https://y.test c`)
	want := template.HTML(`a <a href="https://x.test" style="color:#0f172a;text-decoration:underline;">https://x.test</a> b <a href="https://y.test" style="color:#0f172a;text-decoration:underline;">https://y.test</a> c`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLHandlesHTTPScheme(t *testing.T) {
	got := linkifyHTML(`http://example.com`)
	want := template.HTML(`<a href="http://example.com" style="color:#0f172a;text-decoration:underline;">http://example.com</a>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLNoURL(t *testing.T) {
	got := linkifyHTML(`just plain text`)
	want := template.HTML(`just plain text`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLSingleParagraph(t *testing.T) {
	got := paragraphsHTML(`hi team`)
	want := template.HTML(`<p style="margin:0 0 10px;">hi team</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLMultipleParagraphs(t *testing.T) {
	got := paragraphsHTML("para one\n\npara two")
	want := template.HTML(`<p style="margin:0 0 10px;">para one</p><p style="margin:0 0 10px;">para two</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLLineBreakInsideParagraph(t *testing.T) {
	got := paragraphsHTML("line one\nline two")
	want := template.HTML(`<p style="margin:0 0 10px;">line one<br>line two</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLLinkifiesPerParagraph(t *testing.T) {
	got := paragraphsHTML("see https://example.com\n\nbye")
	want := template.HTML(`<p style="margin:0 0 10px;">see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a></p><p style="margin:0 0 10px;">bye</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLEmptyInput(t *testing.T) {
	got := paragraphsHTML(``)
	if got != template.HTML(``) {
		t.Fatalf("got %q want empty", got)
	}
}

func TestParagraphsHTMLCollapsesMultipleBlankLines(t *testing.T) {
	got := paragraphsHTML("a\n\n\n\nb")
	want := template.HTML(`<p style="margin:0 0 10px;">a</p><p style="margin:0 0 10px;">b</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
```

- [ ] **Step 2: Run tests, expect compile failure**

Run: `go test ./internal/email/... -run 'TestLinkifyHTML|TestParagraphsHTML' -count=1`
Expected: compile error — `linkifyHTML` / `paragraphsHTML` undefined.

- [ ] **Step 3: Implement `message.go`**

Create `internal/email/message.go`:

```go
package email

import (
	"html"
	"html/template"
	"regexp"
	"strings"
)

// urlPattern matches http:// or https:// followed by anything that is not
// whitespace or HTML-significant. Trailing punctuation is trimmed after the
// match (see linkifyHTML).
var urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

// linkifyHTML returns plain escaped for HTML, with http(s):// URLs wrapped in
// <a> anchors. Trailing . , ; : ) characters at the end of a URL match are
// excluded from the anchor so "see https://x.test." renders the period
// outside the link.
func linkifyHTML(plain string) template.HTML {
	if plain == "" {
		return ""
	}
	var sb strings.Builder
	idx := 0
	for _, loc := range urlPattern.FindAllStringIndex(plain, -1) {
		start, end := loc[0], loc[1]
		// Peel trailing punctuation back out of the URL.
		for end > start && strings.ContainsRune(".,;:)", rune(plain[end-1])) {
			end--
		}
		sb.WriteString(html.EscapeString(plain[idx:start]))
		raw := plain[start:end]
		escapedURL := html.EscapeString(raw)
		sb.WriteString(`<a href="`)
		sb.WriteString(escapedURL)
		sb.WriteString(`" style="color:#0f172a;text-decoration:underline;">`)
		sb.WriteString(escapedURL)
		sb.WriteString(`</a>`)
		idx = end
	}
	sb.WriteString(html.EscapeString(plain[idx:]))
	return template.HTML(sb.String())
}

// blankLineRun splits a string on runs of one or more blank lines (lines
// containing only whitespace).
var blankLineRun = regexp.MustCompile(`(?:\r?\n[ \t]*){2,}`)

// paragraphsHTML wraps each paragraph (separated by blank-line runs) in a
// styled <p>, calls linkifyHTML on the paragraph body, and replaces single
// newlines inside a paragraph with <br>. Empty input returns empty.
func paragraphsHTML(plain string) template.HTML {
	if plain == "" {
		return ""
	}
	paragraphs := blankLineRun.Split(plain, -1)
	var sb strings.Builder
	for _, p := range paragraphs {
		p = strings.TrimRight(p, "\r\n")
		if p == "" {
			continue
		}
		lines := strings.Split(p, "\n")
		for i, line := range lines {
			lines[i] = strings.TrimRight(line, "\r")
		}
		body := strings.Join(lines, "\x00") // placeholder we can swap to <br> after escaping
		linked := string(linkifyHTML(body))
		linked = strings.ReplaceAll(linked, "\x00", "<br>")
		sb.WriteString(`<p style="margin:0 0 10px;">`)
		sb.WriteString(linked)
		sb.WriteString(`</p>`)
	}
	return template.HTML(sb.String())
}
```

The `\x00` placeholder dance avoids re-escaping the body after `linkifyHTML` has already escaped it. `\x00` doesn't appear in any URL match (we exclude `<` and `>` already, but `\x00` is also not in the URL regex's character class), and it can't appear in user paragraph bodies in practice (it's a NUL byte). If it ever did, it would render as a `<br>`, which is acceptable.

- [ ] **Step 4: Run the tests, expect pass**

Run: `go test ./internal/email/... -run 'TestLinkifyHTML|TestParagraphsHTML' -v -count=1`
Expected: all listed tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/email/message.go internal/email/message_test.go
git commit -m "feat(email): added message linkification and paragraph rendering"
```

---

## Task 3: Add the `_message.html.tmpl` partial

**Files:**
- Create: `internal/email/templates/_message.html.tmpl`

- [ ] **Step 1: Create the partial**

Create `internal/email/templates/_message.html.tmpl` with this exact content (note the trailing newline):

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

The `{{- if .Message}}` / `{{- end}}` trim whitespace on the empty branch, so view data with empty `Message` produces zero output bytes from this partial.

- [ ] **Step 2: Verify the file exists**

Run: `ls internal/email/templates/_message.html.tmpl`
Expected: file listed.

- [ ] **Step 3: Commit**

```bash
git add internal/email/templates/_message.html.tmpl
git commit -m "feat(email): added _message.html.tmpl partial"
```

---

## Task 4: Wire the partial into the vulns summary renderer

**Files:**
- Modify: `internal/email/vulns_summary.go:17-18` (embed directive)
- Modify: `internal/email/vulns_summary.go:22-35` (view struct)
- Modify: `internal/email/vulns_summary.go:65-115` (`buildVulnSummaryView`)
- Modify: `internal/email/vulns_summary.go:136-154` (`renderVulnSummaryHTML`)
- Modify: `internal/email/templates/vulns_summary.html.tmpl:13` (insertion point)
- Modify: `internal/email/templates/vulns_summary.txt.tmpl` (prepend guarded block)

- [ ] **Step 1: Extend the embed directive**

In `internal/email/vulns_summary.go`, replace:

```go
//go:embed templates/vulns_summary.txt.tmpl templates/vulns_summary.html.tmpl templates/_header.html.tmpl
var vulnSummaryFS embed.FS
```

with:

```go
//go:embed templates/vulns_summary.txt.tmpl templates/vulns_summary.html.tmpl templates/_header.html.tmpl templates/_message.html.tmpl
var vulnSummaryFS embed.FS
```

- [ ] **Step 2: Add Message fields to the view struct**

Add `htmltmpl "html/template"` import only if it's not already present (it is — line 6). In `vulnSummaryView`, after the `Rows` field, add two new fields:

```go
type vulnSummaryView struct {
	Header         Header
	Tenant         string
	GeneratedAtStr string
	GeneratedDate  string
	TotalCVEs      int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	KEVCount       int
	DeviceCount    int
	Rows           []vulnSummaryRow
	Message        string
	MessageHTML    htmltmpl.HTML
}
```

- [ ] **Step 3: Populate the new fields in `buildVulnSummaryView`**

In `buildVulnSummaryView`, after the `view.DeviceCount = maxDevices` line, before the closing `return view`, add:

```go
	view.Message = opts.Message
	if opts.Message != "" {
		view.MessageHTML = paragraphsHTML(opts.Message)
	}
```

The final tail of the function:

```go
	view.DeviceCount = maxDevices
	view.Message = opts.Message
	if opts.Message != "" {
		view.MessageHTML = paragraphsHTML(opts.Message)
	}
	return view
}
```

- [ ] **Step 4: Include the partial in ParseFS**

In `renderVulnSummaryHTML`, change the `ParseFS` call from:

```go
	}).ParseFS(vulnSummaryFS,
		"templates/_header.html.tmpl",
		"templates/vulns_summary.html.tmpl",
	)
```

to:

```go
	}).ParseFS(vulnSummaryFS,
		"templates/_header.html.tmpl",
		"templates/_message.html.tmpl",
		"templates/vulns_summary.html.tmpl",
	)
```

- [ ] **Step 5: Insert the partial in the HTML template**

In `internal/email/templates/vulns_summary.html.tmpl`, change lines 13-14 from:

```html
{{template "header" .}}

<tr><td style="padding:0;">
```

to:

```html
{{template "header" .}}
{{template "message" .}}

<tr><td style="padding:0;">
```

- [ ] **Step 6: Prepend the guarded block in the text template**

In `internal/email/templates/vulns_summary.txt.tmpl`, prepend at the very top (before the existing first line `{{.CriticalCount}} Critical, ...`):

```
{{if .Message -}}
{{.Message}}

---

{{end -}}
```

The first lines of the file should now read:

```
{{if .Message -}}
{{.Message}}

---

{{end -}}
{{.CriticalCount}} Critical, {{.HighCount}} High, ...
```

- [ ] **Step 7: Run the full email test suite, expect goldens unchanged**

Run: `go test ./internal/email/... -count=1`
Expected: all existing tests still PASS (no message set in the test fixtures, so `{{if}}` is false and goldens stay byte-identical).

- [ ] **Step 8: Commit**

```bash
git add internal/email/vulns_summary.go internal/email/templates/vulns_summary.html.tmpl internal/email/templates/vulns_summary.txt.tmpl
git commit -m "feat(email): wired message partial into vulns summary renderer"
```

---

## Task 5: Add a golden test for vulns summary with a message

**Files:**
- Modify: `internal/email/vulns_summary_test.go` (add a test)
- Create: `internal/email/testdata/vulns_summary_with_message.golden.eml`

- [ ] **Step 1: Add the failing test**

Append to `internal/email/vulns_summary_test.go`:

```go
func TestNewVulnSummaryRendererGoldenWithMessage(t *testing.T) {
	var buf bytes.Buffer
	opts := newPinnedOpts()
	opts.Message = "Hi team -\n\nHeads-up on this week's KEV spike before Friday's freeze. See https://example.com/runbook for the rollback steps."
	r := NewVulnSummaryRenderer(opts)
	if err := r.Render(&buf, sampleVulns()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	goldenAssert(t, "vulns_summary_with_message.golden.eml", buf.Bytes())
}
```

- [ ] **Step 2: Run, expect golden-not-found**

Run: `go test ./internal/email/... -run TestNewVulnSummaryRendererGoldenWithMessage -count=1`
Expected: FAIL with `read golden testdata/vulns_summary_with_message.golden.eml: ... (run with -update-golden to regenerate)`.

- [ ] **Step 3: Generate the golden**

Run: `go test ./internal/email/... -run TestNewVulnSummaryRendererGoldenWithMessage -update-golden -count=1`
Expected: PASS, file `internal/email/testdata/vulns_summary_with_message.golden.eml` created.

- [ ] **Step 4: Inspect the golden, then re-run without `-update-golden`**

Open `internal/email/testdata/vulns_summary_with_message.golden.eml` in your editor. Confirm by eye:
- The HTML body contains a `<tr>` with `Message` as the eyebrow text, immediately after the header `<tr>` and before the stats `<tr>`.
- The text body starts with `Hi team -` followed by a blank line, `---`, blank line, then the existing summary content.
- The URL `https://example.com/runbook` appears wrapped in an `<a href="https://example.com/runbook"...>` element in the HTML body (the quoted-printable encoding may break the line; that is fine, search for the URL fragments).

Then run: `go test ./internal/email/... -run TestNewVulnSummaryRendererGoldenWithMessage -count=1`
Expected: PASS.

- [ ] **Step 5: Run all email tests, expect existing goldens unchanged**

Run: `go test ./internal/email/... -count=1`
Expected: every test PASSes.

- [ ] **Step 6: Commit**

```bash
git add internal/email/vulns_summary_test.go internal/email/testdata/vulns_summary_with_message.golden.eml
git commit -m "test(email): added golden for vulns summary with message"
```

---

## Task 6: Wire the partial into the user show renderer

**Files:**
- Modify: `internal/email/user_show.go:30-31` (embed directive)
- Modify: `internal/email/user_show.go:33-46` (view struct)
- Modify: `internal/email/user_show.go:63-111` (`buildUserShowView`)
- Modify: `internal/email/user_show.go:132-150` (`renderUserShowHTML`)
- Modify: `internal/email/templates/user_show.html.tmpl:13` (insertion point)
- Modify: `internal/email/templates/user_show.txt.tmpl` (prepend guarded block)

- [ ] **Step 1: Extend the embed directive**

In `internal/email/user_show.go`, replace:

```go
//go:embed templates/user_show.txt.tmpl templates/user_show.html.tmpl templates/_header.html.tmpl
var userShowFS embed.FS
```

with:

```go
//go:embed templates/user_show.txt.tmpl templates/user_show.html.tmpl templates/_header.html.tmpl templates/_message.html.tmpl
var userShowFS embed.FS
```

- [ ] **Step 2: Add Message fields to the view struct**

In `userShowView`, append two fields after `Devices`:

```go
type userShowView struct {
	Header         Header
	User           iru.User
	Tenant         string
	GeneratedAtStr string
	GeneratedDate  string
	TotalCVEs      int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	DeviceCount    int
	Devices        []userShowDeviceView
	Message        string
	MessageHTML    htmltmpl.HTML
}
```

- [ ] **Step 3: Populate the new fields in `buildUserShowView`**

In `buildUserShowView`, immediately before the closing `return view`, add:

```go
	view.Message = opts.Message
	if opts.Message != "" {
		view.MessageHTML = paragraphsHTML(opts.Message)
	}
```

The final tail of the function:

```go
		view.Devices[i] = userShowDeviceView{Device: dev.Device, Rows: rows}
	}
	view.Message = opts.Message
	if opts.Message != "" {
		view.MessageHTML = paragraphsHTML(opts.Message)
	}
	return view
}
```

- [ ] **Step 4: Include the partial in ParseFS**

In `renderUserShowHTML`, change the `ParseFS` call from:

```go
	}).ParseFS(userShowFS,
		"templates/_header.html.tmpl",
		"templates/user_show.html.tmpl",
	)
```

to:

```go
	}).ParseFS(userShowFS,
		"templates/_header.html.tmpl",
		"templates/_message.html.tmpl",
		"templates/user_show.html.tmpl",
	)
```

- [ ] **Step 5: Insert the partial in the HTML template**

In `internal/email/templates/user_show.html.tmpl`, change lines 13-14 from:

```html
{{template "header" .}}

<tr><td style="padding:0;">
```

to:

```html
{{template "header" .}}
{{template "message" .}}

<tr><td style="padding:0;">
```

- [ ] **Step 6: Prepend the guarded block in the text template**

In `internal/email/templates/user_show.txt.tmpl`, prepend at the very top (before the existing first line `Vulnerability exposure for {{.User.Name}}...`):

```
{{if .Message -}}
{{.Message}}

---

{{end -}}
```

- [ ] **Step 7: Run all email tests, expect existing goldens unchanged**

Run: `go test ./internal/email/... -count=1`
Expected: every test PASSes (the existing `user_show.golden.eml` and `user_show_no_detections.golden.eml` should match byte-for-byte; no test sets `Message`).

- [ ] **Step 8: Commit**

```bash
git add internal/email/user_show.go internal/email/templates/user_show.html.tmpl internal/email/templates/user_show.txt.tmpl
git commit -m "feat(email): wired message partial into user show renderer"
```

---

## Task 7: Add a golden test for user show with a message

**Files:**
- Modify: `internal/email/user_show_test.go` (add a test)
- Create: `internal/email/testdata/user_show_with_message.golden.eml`

- [ ] **Step 1: Inspect the existing pinned-opts helper**

Run: `grep -n "newUserShowPinnedOpts\|newPinnedOpts\|func Test.*GoldenWithMessage\|sampleUserBundle\|UserBundleInput{" internal/email/user_show_test.go | head -30`
Expected: lists the helper used by the existing user-show golden test (e.g. `newUserShowPinnedOpts` or similar) and the fixture builder for the bundle. Note the exact names — Step 2 reuses them verbatim.

- [ ] **Step 2: Add the failing test**

Using the helper names you just identified, append to `internal/email/user_show_test.go`. The template below uses the same names as `TestNewVulnSummaryRendererGoldenWithMessage`; substitute the names from Step 1 if the user-show file uses different ones:

```go
func TestNewUserShowRendererGoldenWithMessage(t *testing.T) {
	var buf bytes.Buffer
	opts := newUserShowPinnedOpts() // use the exact name from Step 1
	opts.Message = "Hi Alice -\n\nHere's your current exposure. Patch CVE-2025-12345 first - it's KEV-listed.\n\nSee https://example.com/runbook."
	r := NewUserShowRenderer(opts)
	if err := r.Render(&buf, sampleUserBundle()); err != nil { // use the exact bundle fixture from Step 1
		t.Fatalf("Render: %v", err)
	}
	goldenAssert(t, "user_show_with_message.golden.eml", buf.Bytes())
}
```

- [ ] **Step 3: Run, expect golden-not-found**

Run: `go test ./internal/email/... -run TestNewUserShowRendererGoldenWithMessage -count=1`
Expected: FAIL with `read golden testdata/user_show_with_message.golden.eml: ...`.

- [ ] **Step 4: Generate the golden**

Run: `go test ./internal/email/... -run TestNewUserShowRendererGoldenWithMessage -update-golden -count=1`
Expected: PASS, file `internal/email/testdata/user_show_with_message.golden.eml` created.

- [ ] **Step 5: Inspect, then re-run without `-update-golden`**

Open `internal/email/testdata/user_show_with_message.golden.eml`. Verify by eye:
- HTML body has a `<tr>` containing `Message` immediately after the header `<tr>` and before the stats `<tr>`.
- The two paragraphs are wrapped in `<p style="margin:0 0 10px;">`.
- The URL `https://example.com/runbook` is wrapped in `<a href="https://example.com/runbook"...>` with the trailing period **outside** the anchor.
- The plain-text body starts with the message followed by a blank line and `---`.

Then run: `go test ./internal/email/... -run TestNewUserShowRendererGoldenWithMessage -count=1`
Expected: PASS.

- [ ] **Step 6: Run all email tests**

Run: `go test ./internal/email/... -count=1`
Expected: every test PASSes.

- [ ] **Step 7: Commit**

```bash
git add internal/email/user_show_test.go internal/email/testdata/user_show_with_message.golden.eml
git commit -m "test(email): added golden for user show with message"
```

---

## Task 8: Extend `emailFlagValues` with `Message` + `MessageFile`

**Files:**
- Modify: `cmd/email.go:18-43`

- [ ] **Step 1: Extend the struct and reader**

In `cmd/email.go`, replace the `emailFlagValues` struct and `readEmailFlags` function with:

```go
// emailFlagValues holds the literal flag inputs from cobra; empty string means
// the flag was not set. Send is true iff --send-email was passed. Message is
// true iff --message was passed; MessageFile is the literal --message-file
// value (empty when not set).
type emailFlagValues struct {
	To          string
	From        string
	Subject     string
	HeaderBG    string
	LogoPath    string
	Send        bool
	Message     bool
	MessageFile string
}

// readEmailFlags pulls --email-to / --email-from / --email-subject /
// --email-header-bg / --email-logo / --send-email / --message / --message-file
// off a cobra command. Missing flags return zero values (no error).
func readEmailFlags(cmd *cobra.Command) emailFlagValues {
	to, _ := cmd.Flags().GetString("email-to")
	from, _ := cmd.Flags().GetString("email-from")
	subject, _ := cmd.Flags().GetString("email-subject")
	headerBG, _ := cmd.Flags().GetString("email-header-bg")
	logoPath, _ := cmd.Flags().GetString("email-logo")
	send, _ := cmd.Flags().GetBool("send-email")
	message, _ := cmd.Flags().GetBool("message")
	messageFile, _ := cmd.Flags().GetString("message-file")
	return emailFlagValues{
		To: to, From: from, Subject: subject,
		HeaderBG: headerBG, LogoPath: logoPath,
		Send: send, Message: message, MessageFile: messageFile,
	}
}
```

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: exits 0 (no callers rely on `emailFlagValues` field order).

- [ ] **Step 3: Run existing cmd tests**

Run: `go test ./cmd/... -count=1`
Expected: all existing tests PASS (no behaviour change; the new flags aren't read by cobra yet because nothing registers them).

- [ ] **Step 4: Commit**

```bash
git add cmd/email.go
git commit -m "feat(cmd): added Message and MessageFile to emailFlagValues"
```

---

## Task 9: Build `captureMessage` helper

**Files:**
- Create: `cmd/message.go`
- Create: `cmd/message_test.go`

- [ ] **Step 1: Write the failing tests**

Create `cmd/message_test.go`:

```go
package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMessageFlagsAcceptsNeither(t *testing.T) {
	if err := validateMessageFlags(emailFlagValues{}, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMessageFlagsAcceptsMessageWithEmailOutput(t *testing.T) {
	if err := validateMessageFlags(emailFlagValues{Message: true}, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateMessageFlagsRejectsBoth(t *testing.T) {
	err := validateMessageFlags(emailFlagValues{Message: true, MessageFile: "x"}, true)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestValidateMessageFlagsRejectsMessageWithoutEmailOutput(t *testing.T) {
	err := validateMessageFlags(emailFlagValues{Message: true}, false)
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}

func TestValidateMessageFlagsRejectsMessageFileWithoutEmailOutput(t *testing.T) {
	err := validateMessageFlags(emailFlagValues{MessageFile: "x"}, false)
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}

func TestCaptureMessageRejectsBothFlags(t *testing.T) {
	_, err := captureMessage(
		emailFlagValues{Message: true, MessageFile: "some.txt"},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestCaptureMessageRejectsWithoutEmailOutput(t *testing.T) {
	_, err := captureMessage(
		emailFlagValues{Message: true},
		false, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}

func TestCaptureMessageReturnsEmptyWhenNeitherFlagSet(t *testing.T) {
	got, err := captureMessage(
		emailFlagValues{},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty result, got %q", got)
	}
}

func TestCaptureMessageReadsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte("hi from file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hi from file" {
		t.Fatalf("got %q want %q", got, "hi from file")
	}
}

func TestCaptureMessageReadsFromStdinDash(t *testing.T) {
	got, err := captureMessage(
		emailFlagValues{MessageFile: "-"},
		true, "", "",
		strings.NewReader("piped note\n"), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "piped note" {
		t.Fatalf("got %q want %q", got, "piped note")
	}
}

func TestCaptureMessageFileDoesNotStripHashLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte("# this is a literal hash\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "# this is a literal hash\nbody"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCaptureMessageFileEmptyAborts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte("   \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "empty message") {
		t.Fatalf("expected empty-message error, got %v", err)
	}
}

func TestCaptureMessageFileUnreadable(t *testing.T) {
	_, err := captureMessage(
		emailFlagValues{MessageFile: "/no/such/path/jellyfish-test.txt"},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		func(string) error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "read --message-file") {
		t.Fatalf("expected file-read error, got %v", err)
	}
}

func TestCaptureMessageEditorStripsCommentLines(t *testing.T) {
	fake := func(path string) error {
		body := "# Jellyfish message for: subj\n# To: a@b\n# Lines starting with '#' will be ignored.\n#\n\nHi team\n\nSee you Friday.\n"
		return os.WriteFile(path, []byte(body), 0o600)
	}
	got, err := captureMessage(
		emailFlagValues{Message: true},
		true, "a@b", "subj",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Hi team\n\nSee you Friday."
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCaptureMessageEditorAbortsOnEmpty(t *testing.T) {
	fake := func(path string) error {
		body := "# all comments\n# nothing else\n"
		return os.WriteFile(path, []byte(body), 0o600)
	}
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err == nil || !strings.Contains(err.Error(), "empty message") {
		t.Fatalf("expected empty-message error, got %v", err)
	}
}

func TestCaptureMessageEditorFailurePropagates(t *testing.T) {
	fake := func(string) error { return errors.New("editor exited with status 1") }
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err == nil || !strings.Contains(err.Error(), "editor exited") {
		t.Fatalf("expected editor error, got %v", err)
	}
}

func TestCaptureMessageEditorTemplateContainsSubjectAndTo(t *testing.T) {
	var got string
	fake := func(path string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got = string(b)
		// Simulate the user adding a body and saving.
		return os.WriteFile(path, append(b, []byte("\nthe body\n")...), 0o600)
	}
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "alice@example.com", "Weekly brief",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "# Jellyfish message for: Weekly brief") {
		t.Errorf("template missing subject line; got:\n%s", got)
	}
	if !strings.Contains(got, "# To: alice@example.com") {
		t.Errorf("template missing recipient line; got:\n%s", got)
	}
	if !strings.Contains(got, "# Lines starting with '#' will be ignored.") {
		t.Errorf("template missing legend line; got:\n%s", got)
	}
}

func TestCaptureMessageEditorTemplateNoRecipient(t *testing.T) {
	var got string
	fake := func(path string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got = string(b)
		return os.WriteFile(path, append(b, []byte("\nbody\n")...), 0o600)
	}
	_, err := captureMessage(
		emailFlagValues{Message: true},
		true, "", "subj",
		strings.NewReader(""), &bytes.Buffer{},
		fake,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "# To: (none)") {
		t.Errorf("template missing '(none)' recipient placeholder; got:\n%s", got)
	}
}

func TestCaptureMessageSoftCapWarning(t *testing.T) {
	// 4001 chars of 'x'.
	long := strings.Repeat("x", 4001)
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	got, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &stderr,
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != long {
		t.Errorf("body should not be truncated; got %d chars want %d", len(got), len(long))
	}
	if !strings.Contains(stderr.String(), "warn:") || !strings.Contains(stderr.String(), "4001 chars") {
		t.Errorf("expected soft-cap warning on stderr; got %q", stderr.String())
	}
}

func TestCaptureMessageNoWarnAtCap(t *testing.T) {
	body := strings.Repeat("x", 4000)
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	_, err := captureMessage(
		emailFlagValues{MessageFile: path},
		true, "", "",
		strings.NewReader(""), &stderr,
		func(string) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("no warning expected at exactly 4000 chars; got %q", stderr.String())
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./cmd/... -run TestCaptureMessage -count=1`
Expected: compile error — `captureMessage` undefined.

- [ ] **Step 3: Implement `cmd/message.go`**

Create `cmd/message.go`:

```go
package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const messageSoftCap = 4000

// validateMessageFlags runs cheap flag-shape checks that do NOT touch the
// filesystem or launch an editor. Callers invoke this at the top of cobra
// RunE, ahead of any network or expensive setup, so bad flag combinations
// fail fast. The full capture (which DOES read files / open the editor)
// happens later via captureMessage.
func validateMessageFlags(flags emailFlagValues, hasEmailOutput bool) error {
	if !flags.Message && flags.MessageFile == "" {
		return nil
	}
	if flags.Message && flags.MessageFile != "" {
		return errors.New("--message and --message-file are mutually exclusive")
	}
	if !hasEmailOutput {
		return errors.New("--message requires email output (-o email or --send-email)")
	}
	return nil
}

// captureMessage resolves a --message / --message-file capture into a final
// plain-text body. Returns "" when neither flag is set. Returns an error for:
// both flags set; either flag set without email output; unreadable file;
// editor non-zero exit; empty resulting message. Emits a soft-cap warning to
// stderr when the result exceeds messageSoftCap. The flag-shape checks are
// duplicated from validateMessageFlags so this function is safe to call
// without an earlier validate step (idempotent).
func captureMessage(
	flags emailFlagValues,
	hasEmailOutput bool,
	recipient, subject string,
	stdin io.Reader,
	stderr io.Writer,
	runEditor func(path string) error,
) (string, error) {
	if err := validateMessageFlags(flags, hasEmailOutput); err != nil {
		return "", err
	}
	if !flags.Message && flags.MessageFile == "" {
		return "", nil
	}

	var (
		raw       string
		stripHash bool
	)
	switch {
	case flags.MessageFile != "":
		body, err := readMessageFile(flags.MessageFile, stdin)
		if err != nil {
			return "", fmt.Errorf("read --message-file %s: %w", flags.MessageFile, err)
		}
		raw = body
	default:
		body, err := captureMessageViaEditor(recipient, subject, runEditor)
		if err != nil {
			return "", err
		}
		raw = body
		stripHash = true
	}

	cleaned := strings.TrimSpace(maybeStripHashLines(raw, stripHash))
	if cleaned == "" {
		return "", errors.New("--message produced an empty message; aborting")
	}
	if len(cleaned) > messageSoftCap {
		_, _ = fmt.Fprintf(stderr, "warn: --message is %d chars; long messages may be clipped by mail clients\n", len(cleaned))
	}
	return cleaned, nil
}

func readMessageFile(path string, stdin io.Reader) (string, error) {
	if path == "-" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// #nosec G304 - path is a user-provided message file
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func captureMessageViaEditor(recipient, subject string, runEditor func(path string) error) (string, error) {
	if runEditor == nil {
		runEditor = runEditorTerminal
	}
	display := recipient
	if display == "" {
		display = "(none)"
	}
	templateBody := fmt.Sprintf(
		"# Jellyfish message for: %s\n# To: %s\n# Lines starting with '#' will be ignored.\n#\n\n",
		subject, display,
	)
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("create message scratch file: %w", err)
	}
	scratch := filepath.Join(os.TempDir(), "jellyfish-message-"+hex.EncodeToString(nonce[:])+".txt")
	if err := os.WriteFile(scratch, []byte(templateBody), 0o600); err != nil {
		return "", fmt.Errorf("create message scratch file: %w", err)
	}
	defer func() { _ = os.Remove(scratch) }()
	if err := runEditor(scratch); err != nil {
		return "", err
	}
	// #nosec G304 - scratch path is one we just wrote inside os.TempDir()
	b, err := os.ReadFile(scratch)
	if err != nil {
		return "", fmt.Errorf("read message scratch file: %w", err)
	}
	return string(b), nil
}

func maybeStripHashLines(s string, strip bool) string {
	if !strip {
		return s
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// runEditorTerminal is the production implementation of the editor launcher.
// Lookup order: $VISUAL > $EDITOR > vi. The chosen command is treated as a
// single token (no shell word-splitting). Returns an error if the editor
// exits non-zero or cannot be launched.
func runEditorTerminal(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	bin, err := exec.LookPath(editor)
	if err != nil {
		return fmt.Errorf("launch editor: %w", err)
	}
	c := exec.Command(bin, path)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("editor exited with status %d", exitErr.ExitCode())
		}
		return fmt.Errorf("launch editor: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run the message tests, expect pass**

Run: `go test ./cmd/... -run 'TestValidateMessageFlags|TestCaptureMessage' -v -count=1`
Expected: all sub-tests PASS (5 validate + 14 capture, all from Step 1).

- [ ] **Step 5: Run the full cmd test suite**

Run: `go test ./cmd/... -count=1`
Expected: every test PASSes (no existing behaviour changed).

- [ ] **Step 6: Commit**

```bash
git add cmd/message.go cmd/message_test.go
git commit -m "feat(cmd): added captureMessage helper for --message / --message-file"
```

---

## Task 10: Register flags on `user show` and pipe message into rendering + send

**Files:**
- Modify: `cmd/user.go:91-99` (flag registration)
- Modify: `cmd/user.go:62-89` (RunE — early validate)
- Modify: `cmd/user.go:154-183` (`renderUserBundle`)
- Modify: `cmd/user.go:185-224` (`runSendUserShow`)

- [ ] **Step 1: Register the flags**

In `cmd/user.go`, immediately after the `c.Flags().Bool("send-email", ...)` line in `newUserShowCmd`, add:

```go
	c.Flags().Bool("message", false, "Open $VISUAL/$EDITOR to compose a message rendered above the email body")
	c.Flags().String("message-file", "", "Read the email message body from a file (use - for stdin)")
```

The resulting final block:

```go
	c.Flags().Bool("send-email", false, "Send the rendered email via Gmail (requires `jellyfish configure email` to be run first)")
	c.Flags().Bool("message", false, "Open $VISUAL/$EDITOR to compose a message rendered above the email body")
	c.Flags().String("message-file", "", "Read the email message body from a file (use - for stdin)")
	return c
}
```

- [ ] **Step 2: Add early flag validation in the RunE**

In `cmd/user.go`, inside the `newUserShowCmd` RunE, insert a `validateMessageFlags` call immediately after `opts.EmailFlags = readEmailFlags(cmd)`. This must run **before** `buildClient` so a bad flag combo never triggers any network work.

Replace the RunE body so it reads (note the new lines after `opts.EmailFlags = readEmailFlags(cmd)`):

```go
		RunE: func(cmd *cobra.Command, args []string) error {
			outFmt, _ := cmd.Flags().GetString("output")
			opts.EmailFlags = readEmailFlags(cmd)
			hasEmailOutput := outFmt == "email" || opts.EmailFlags.Send
			if err := validateMessageFlags(opts.EmailFlags, hasEmailOutput); err != nil {
				return err
			}
			client, err := buildClient(cmd)
			if err != nil {
				return err
			}
			opts.Identifier = args[0]
			opts.Output = outFmt
			if cmd.Flags().Changed("output") {
				opts.ExplicitOutput = outFmt
			}
			opts.EmailNow = time.Now()
			if hasEmailOutput {
				prof, err := activeProfile(cmd)
				if err != nil {
					return err
				}
				opts.Profile = prof
			}
			if opts.KeychainGet == nil {
				opts.KeychainGet = keychain.GetGmailServiceAccount
			}
			if opts.NewSender == nil {
				opts.NewSender = gmail.NewSender
			}
			return runUserShow(cmd.Context(), client, cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
```

The change reuses `hasEmailOutput` so the existing `outFmt == "email" || opts.EmailFlags.Send` profile-load guard reads the same boolean.

- [ ] **Step 3: Pipe captured message into the email branch of `renderUserBundle`**

`runUserShow` is called from the RunE; `validateMessageFlags` has already run by this point so `captureMessage` will not fail on flag-shape errors here. Replace the body of `renderUserBundle`'s `case "email":` arm with:

```go
	case "email":
		now := opts.EmailNow
		if now.IsZero() {
			now = time.Now()
		}
		gitLookup := opts.gitEmail
		if gitLookup == nil {
			gitLookup = gitUserEmail
		}
		emailOpts, err := resolveEmailOptions(opts.EmailFlags, opts.Profile, gitLookup, now)
		if err != nil {
			return err
		}
		msg, err := captureMessage(opts.EmailFlags, true, emailOpts.To, emailOpts.Subject, os.Stdin, stderr, nil)
		if err != nil {
			return err
		}
		emailOpts.Message = msg
		return email.NewUserShowRendererWithStderr(emailOpts, stderr).Render(w, bundleToEmailInput(b))
```

Note the third arg to `captureMessage` is `true` because we are in `case "email":`, which by definition means email output is selected. The fifth arg is `os.Stdin`; this brings a new import:

Add `"os"` to the existing import block at the top of `cmd/user.go` (between `io` and `sort`):

```go
import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	...
)
```

- [ ] **Step 4: Pipe captured message into `runSendUserShow`**

In `runSendUserShow`, immediately after the existing `emailOpts.To = to` line, before the `var buf bytes.Buffer` line, add:

```go
	msg, err := captureMessage(opts.EmailFlags, true, emailOpts.To, emailOpts.Subject, os.Stdin, stderr, nil)
	if err != nil {
		return err
	}
	emailOpts.Message = msg
```

(`true` because `--send-email` is set; that's how this function is reached.)

- [ ] **Step 5: Verify the flags exist via a test**

Append to `cmd/user_test.go` (placing it next to the existing `if f := show.Flags().Lookup("email-header-bg")` assertion):

```go
	if f := show.Flags().Lookup("message"); f == nil {
		t.Fatal("--message flag is missing")
	}
	if f := show.Flags().Lookup("message-file"); f == nil {
		t.Fatal("--message-file flag is missing")
	}
```

Locate the existing test that does the `Lookup("email-header-bg")` check (around `cmd/user_test.go:274`) and add the two new assertions inside the same test function, immediately after the existing ones.

- [ ] **Step 6: Add a test that asserts non-email output rejects --message**

Append to `cmd/user_test.go`:

```go
func TestUserShowMessageRejectsNonEmailOutput(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"user", "show", "alice@example.com", "--message", "-o", "csv"})
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetOut(&bytes.Buffer{})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}
```

Add `"bytes"` and `"strings"` to the imports if not already present. The `newRootCmd` helper is already used by other tests in this file.

- [ ] **Step 7: Build, run cmd tests**

Run: `go build ./... && go test ./cmd/... -count=1`
Expected: all tests PASS.

- [ ] **Step 8: Smoke-test the binary by hand**

Run: `go build -o /tmp/jellyfish-msg . && /tmp/jellyfish-msg user show --help 2>&1 | grep -E 'message'`
Expected: two lines, one for `--message` and one for `--message-file`.

Run: `rm /tmp/jellyfish-msg`

- [ ] **Step 9: Commit**

```bash
git add cmd/user.go cmd/user_test.go
git commit -m "feat(user): wired --message and --message-file flags into user show"
```

---

## Task 11: Register flags on `vulns summary` and pipe message into rendering + send

**Files:**
- Modify: `cmd/vulns.go:224-230` (flag registration)
- Modify: `cmd/vulns.go:191-217` (RunE — early validate)
- Modify: `cmd/vulns.go:287-315` (`renderVulns`)
- Modify: `cmd/vulns.go:317-356` (`runSendVulnsSummary`)

- [ ] **Step 1: Register the flags**

In `cmd/vulns.go`, immediately after the `c.Flags().Bool("send-email", ...)` line in `newVulnsSummaryCmd`, add:

```go
	c.Flags().Bool("message", false, "Open $VISUAL/$EDITOR to compose a message rendered above the email body")
	c.Flags().String("message-file", "", "Read the email message body from a file (use - for stdin)")
```

- [ ] **Step 2: Add `os` to the import block**

The existing imports do not include `os`. Add it between `io` and `sort` in the import block at the top of `cmd/vulns.go`.

- [ ] **Step 3: Add early flag validation in the RunE**

In `cmd/vulns.go`, inside the `newVulnsSummaryCmd` RunE, insert a `validateMessageFlags` call immediately after `opts.EmailFlags = readEmailFlags(cmd)` and before `buildClient`. Use a `hasEmailOutput` local that the profile-load guard then reuses:

```go
		RunE: func(cmd *cobra.Command, _ []string) error {
			outFmt, _ := cmd.Flags().GetString("output")
			opts.Output = outFmt
			opts.EmailFlags = readEmailFlags(cmd)
			hasEmailOutput := outFmt == "email" || opts.EmailFlags.Send
			if err := validateMessageFlags(opts.EmailFlags, hasEmailOutput); err != nil {
				return err
			}
			if cmd.Flags().Changed("output") {
				opts.ExplicitOutput = outFmt
			}
			opts.EmailNow = time.Now()
			if hasEmailOutput {
				prof, err := activeProfile(cmd)
				if err != nil {
					return err
				}
				opts.Profile = prof
			}
			if opts.KeychainGet == nil {
				opts.KeychainGet = keychain.GetGmailServiceAccount
			}
			if opts.NewSender == nil {
				opts.NewSender = gmail.NewSender
			}
			client, err := buildClient(cmd)
			if err != nil {
				return err
			}
			return runVulnsSummary(cmd.Context(), client, cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
```

- [ ] **Step 4: Pipe captured message into the email branch of `renderVulns`**

`runVulnsSummary` is called from the RunE; `validateMessageFlags` has already run by this point so `captureMessage` will not fail on flag-shape errors here. In `renderVulns`, replace the `case "email":` arm so it reads:

```go
	case "email":
		now := opts.EmailNow
		if now.IsZero() {
			now = time.Now()
		}
		gitLookup := opts.gitEmail
		if gitLookup == nil {
			gitLookup = gitUserEmail
		}
		emailOpts, err := resolveEmailOptions(opts.EmailFlags, opts.Profile, gitLookup, now)
		if err != nil {
			return err
		}
		msg, err := captureMessage(opts.EmailFlags, true, emailOpts.To, emailOpts.Subject, os.Stdin, stderr, nil)
		if err != nil {
			return err
		}
		emailOpts.Message = msg
		return email.NewVulnSummaryRendererWithStderr(emailOpts, stderr).Render(w, vs)
```

- [ ] **Step 5: Pipe captured message into `runSendVulnsSummary`**

In `runSendVulnsSummary`, immediately after the existing `emailOpts.To = to` line, before the `var buf bytes.Buffer` line, add:

```go
	msg, err := captureMessage(opts.EmailFlags, true, emailOpts.To, emailOpts.Subject, os.Stdin, stderr, nil)
	if err != nil {
		return err
	}
	emailOpts.Message = msg
```

- [ ] **Step 6: Add the flag-existence assertions in vulns_test**

Locate the existing test in `cmd/vulns_test.go` that asserts `--email-header-bg` exists (search for `Lookup("email-header-bg")`). If none exists, append a small test:

```go
func TestVulnsSummaryHasMessageFlags(t *testing.T) {
	root := newRootCmd()
	var summary *cobra.Command
	for _, top := range root.Commands() {
		if top.Name() == "vulns" {
			for _, sub := range top.Commands() {
				if sub.Name() == "summary" {
					summary = sub
				}
			}
		}
	}
	if summary == nil {
		t.Fatal("vulns summary command not found")
	}
	if f := summary.Flags().Lookup("message"); f == nil {
		t.Fatal("--message flag is missing")
	}
	if f := summary.Flags().Lookup("message-file"); f == nil {
		t.Fatal("--message-file flag is missing")
	}
}
```

If the file already has a similar `Lookup` test for vulns summary, add the two assertions inside that test instead. (Inspect with: `grep -n "Lookup(\"email-header-bg\")" cmd/vulns_test.go`.)

The `newRootCmd` and `cobra.Command` references match the patterns already in use in `cmd/*_test.go`. Add the `github.com/spf13/cobra` import to `cmd/vulns_test.go` if it isn't already imported.

- [ ] **Step 7: Add a test that asserts non-email output rejects --message**

Append to `cmd/vulns_test.go`:

```go
func TestVulnsSummaryMessageRejectsNonEmailOutput(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"vulns", "summary", "--message", "-o", "csv"})
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetOut(&bytes.Buffer{})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires email output") {
		t.Fatalf("expected output-mode error, got %v", err)
	}
}
```

Add `"bytes"` and `"strings"` imports if not already present.

- [ ] **Step 8: Build, run cmd tests**

Run: `go build ./... && go test ./cmd/... -count=1`
Expected: all tests PASS.

- [ ] **Step 9: Smoke-test the binary**

Run: `go build -o /tmp/jellyfish-msg . && /tmp/jellyfish-msg vulns summary --help 2>&1 | grep -E 'message'`
Expected: two lines, one for `--message` and one for `--message-file`.

Run: `rm /tmp/jellyfish-msg`

- [ ] **Step 10: Commit**

```bash
git add cmd/vulns.go cmd/vulns_test.go
git commit -m "feat(vulns): wired --message and --message-file flags into vulns summary"
```

---

## Task 12: Integration test - flag plumbing end-to-end on user show

**Files:**
- Modify: `cmd/user_test.go`

- [ ] **Step 1: Add a test that asserts a `--message-file` value reaches the rendered email body**

`cmd/user_test.go` already has tests that exercise `runUserShow`. Locate the helper / pattern used by the existing email-output tests (search for `Output: "email"` or `runUserShow.*email` to find them). Append a test in the same style:

```go
func TestUserShowEmailOutputIncludesMessageFromFile(t *testing.T) {
	dir := t.TempDir()
	msgPath := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(msgPath, []byte("plumbing check\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &fakeIruClient{ /* reuse whatever fake the existing email test uses */ }
	var stdout, stderr bytes.Buffer
	opts := userShowOpts{
		Identifier: "alice@example.com",
		Output:     "email",
		EmailFlags: emailFlagValues{
			From:        "alice@example.com",
			MessageFile: msgPath,
		},
		EmailNow: time.Date(2026, 5, 16, 10, 42, 0, 0, time.UTC),
		Profile:  config.Profile{Subdomain: "acme", Email: config.EmailConfig{From: "alice@example.com"}},
	}
	if err := runUserShow(context.Background(), client, &stdout, &stderr, opts); err != nil {
		t.Fatalf("runUserShow: %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("plumbing check")) {
		t.Fatalf("rendered email does not contain message body; got:\n%s", stdout.String())
	}
}
```

**Important:** the fake client setup, the imports (`os`, `path/filepath`, `bytes`, `context`, `time`, `config`), and the exact fake-client name need to match patterns already in `cmd/user_test.go`. Before writing the test, run:

```
grep -n "runUserShow.*\".*email" cmd/user_test.go
```

to find the existing email-output test and use its fake-client + opts construction as the template. Copy that test, change `Output:` to keep `"email"`, add `MessageFile: msgPath`, and adjust the assertion.

- [ ] **Step 2: Run the new test, expect pass**

Run: `go test ./cmd/... -run TestUserShowEmailOutputIncludesMessageFromFile -v -count=1`
Expected: PASS.

- [ ] **Step 3: Run all cmd tests**

Run: `go test ./cmd/... -count=1`
Expected: every test PASSes.

- [ ] **Step 4: Commit**

```bash
git add cmd/user_test.go
git commit -m "test(user): asserted --message-file body lands in rendered email"
```

---

## Task 13: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Extend the flags table**

In `README.md`, find the email-flags table (search for `--email-header-bg`). Add two new rows at the bottom:

```markdown
| `--message`          | -                        | unset (no message section) |
| `--message-file`     | -                        | unset (no message section) |
```

- [ ] **Step 2: Add a "Message section" subsection**

In `README.md`, immediately after the existing `### Email output` subsection (and before `#### Sending via Gmail`), insert:

````markdown
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
````

- [ ] **Step 3: Verify the README still renders sensibly**

Run: `cat README.md | head -260 | tail -60`
Expected: human-readable, table renders cleanly, the new subsection appears between the existing "Email output" content and "Sending via Gmail".

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): documented --message and --message-file flags"
```

---

## Task 14: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `go test ./... -count=1`
Expected: every package PASSes.

- [ ] **Step 2: Lint**

Run: `make lint`
Expected: exits 0.

- [ ] **Step 3: Build the binary**

Run: `go build -o /tmp/jellyfish-final .`
Expected: exits 0.

- [ ] **Step 4: End-to-end smoke (no actual send)**

Render an .eml with a message from a file to stdout and grep for the message:

```bash
TMP=$(mktemp -t jellyfish-msg.XXXXXX)
echo "smoke check body" > "$TMP"
/tmp/jellyfish-final vulns summary -o email --message-file "$TMP" 2>/dev/null | grep -c "smoke check body"
rm "$TMP" /tmp/jellyfish-final
```

Expected: stdout `2` (or more) — the body appears in the text part and the HTML part. If 0 or 1, something is wrong.

Note: this requires a configured profile that can list vulnerabilities. If you don't have one, swap the command for a render-only path or skip Step 4 and rely on the golden tests.

- [ ] **Step 5: All checks passing — done**

The feature is complete. The two flags are wired on both commands, message capture runs before any expensive work, the renderer produces both HTML and plain-text bodies with the message, and existing goldens are byte-identical for no-message rendering.
