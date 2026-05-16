# Email `List-Id` and `X-Jellyfish-*` Headers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one `List-Id` header plus three `X-Jellyfish-*` headers (`Report`, `Tenant`, `Version`) to every Jellyfish-sent email so operators can filter and label them in Gmail and audit them in any client.

**Architecture:** Four new optional fields plumbed through one struct (`email.Options`), one helper (`messageHeaders`), one assembly function (`assembleMessage`), and one per-command write site (each cobra subcommand assigns its own `Report` value). No new packages. Existing `domainFromAddress` helper reused for the List-Id domain fallback.

**Tech Stack:** Go 1.21+, existing `internal/email` / `internal/config` / `internal/version` packages, Cobra.

---

## File map

| Path | Action | Responsibility |
|---|---|---|
| `internal/config/config.go` | modify | add `EmailConfig.ListIDDomain` field |
| `internal/email/email.go` | modify | add `Options.Report/Version/ListIDDomain`; extend `messageHeaders`; write new headers in `assembleMessage` |
| `internal/email/email_test.go` | modify | new tests for List-Id and X-Jellyfish-* writing + skip-empty behaviour |
| `internal/email/user_show.go` | modify | pass new `Options` fields into `messageHeaders` |
| `internal/email/vulns_summary.go` | modify | pass new `Options` fields into `messageHeaders` |
| `internal/email/testdata/*.golden.eml` | regenerate | six goldens gain `List-Id` and `X-Jellyfish-Tenant` lines |
| `cmd/email.go` | modify | `resolveEmailOptions` populates `Options.Version` + `Options.ListIDDomain` |
| `cmd/users.go` | modify | set `Report = "users-send"` |
| `cmd/user.go` | modify | set `Report = "user-show"` (both `renderUserBundle` email branch and `runSendUserShow`) |
| `cmd/vulns.go` | modify | set `Report = "vulns-summary"` (both `renderVulnsSummary` email branch and `runSendVulnsSummary`) |
| `cmd/users_test.go` | modify | new test asserting `X-Jellyfish-Report: users-send` on the bulk happy path |
| `cmd/user_test.go` | modify | new test asserting `X-Jellyfish-Report: user-show` on `user show --send-email` |
| `cmd/send_email_test.go` | modify | new test asserting `X-Jellyfish-Report: vulns-summary` on `vulns summary --send-email` |
| `README.md` | modify | new docs for `email.list_id_domain` config key + Gmail filter recipe |

---

## Task 1: Add `EmailConfig.ListIDDomain` to the config struct

**Files:**
- Modify: `internal/config/config.go` (around `type EmailConfig struct`)

- [ ] **Step 1: Baseline tests pass**

Run: `make test`
Expected: all green.

- [ ] **Step 2: Add the new field**

In `internal/config/config.go`, locate `type EmailConfig struct` (line 16 area). Append after the existing fields, in keeping with the same yaml-tag pattern:

```go
type EmailConfig struct {
	// ... existing fields stay unchanged ...
	GmailConfigured  bool   `yaml:"gmail_configured,omitempty"`
	ListIDDomain     string `yaml:"list_id_domain,omitempty"`
}
```

(Keep the existing fields verbatim; only `ListIDDomain` is new.)

- [ ] **Step 3: Run tests**

Run: `make test`
Expected: all green (no test mentions ListIDDomain yet; the field just compiles).

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): added email.list_id_domain config key"
```

---

## Task 2: Add `Report`, `Version`, `ListIDDomain` to `email.Options`

**Files:**
- Modify: `internal/email/email.go` (the `type Options struct` block, around lines 25-46)

- [ ] **Step 1: Add the three fields**

In `internal/email/email.go`, after the existing `Message string` field and before the `BoundaryOverride` test-injection block, add:

```go
	Message string // optional plain-text message; empty disables the message section

	// Filterable headers; all optional. Empty string means "skip the header".
	Report       string // command identity: "vulns-summary" | "user-show" | "users-send"
	Version      string // jellyfish build version (internal/version.Version)
	ListIDDomain string // explicit List-Id domain; empty falls back to domain of From
```

(Place the new block between the existing `Message` field and the existing `// Injected for tests` comment. Do not touch any other field.)

- [ ] **Step 2: Build to verify the struct compiles**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 3: Run tests**

Run: `make test`
Expected: all green (no caller sets the new fields yet, so behaviour is unchanged).

- [ ] **Step 4: Commit**

```bash
git add internal/email/email.go
git commit -m "feat(email): added Report Version ListIDDomain to Options"
```

---

## Task 3: Extend `messageHeaders` + write the new headers in `assembleMessage`

**Files:**
- Modify: `internal/email/email.go`
- Modify: `internal/email/email_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/email/email_test.go`:

```go
func TestAssembleMessageEmitsListIdFromDomain(t *testing.T) {
	hdr := messageHeaders{
		From:    "ops@example.com",
		To:      "alice@example.com",
		Subject: "s",
		Date:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
	}
	out, err := assembleMessage(hdr, "<p>x</p>", "x\n", "=_jf_X", "<i@b.c>", "", nil)
	if err != nil {
		t.Fatalf("assembleMessage: %v", err)
	}
	if !bytes.Contains(out, []byte("List-Id: <example.com>\r\n")) {
		t.Fatalf("expected List-Id derived from From domain; got:\n%s", out)
	}
}

func TestAssembleMessageHonoursExplicitListIDDomain(t *testing.T) {
	hdr := messageHeaders{
		From:         "ops@example.com",
		To:           "a@b.c",
		Subject:      "s",
		Date:         time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		ListIDDomain: "jellyfish.example.com",
	}
	out, err := assembleMessage(hdr, "<p>x</p>", "x\n", "=_jf_X", "<i@b.c>", "", nil)
	if err != nil {
		t.Fatalf("assembleMessage: %v", err)
	}
	if !bytes.Contains(out, []byte("List-Id: <jellyfish.example.com>\r\n")) {
		t.Fatalf("expected explicit List-Id; got:\n%s", out)
	}
	if bytes.Contains(out, []byte("List-Id: <example.com>\r\n")) {
		t.Fatalf("expected explicit List-Id to override From-derived; got:\n%s", out)
	}
}

func TestAssembleMessageEmitsAllXJellyfishHeaders(t *testing.T) {
	hdr := messageHeaders{
		From:    "ops@example.com",
		To:      "a@b.c",
		Subject: "s",
		Date:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Report:  "users-send",
		Tenant:  "acme",
		Version: "v1.2.3",
	}
	out, err := assembleMessage(hdr, "<p>x</p>", "x\n", "=_jf_X", "<i@b.c>", "", nil)
	if err != nil {
		t.Fatalf("assembleMessage: %v", err)
	}
	for _, want := range []string{
		"X-Jellyfish-Report: users-send\r\n",
		"X-Jellyfish-Tenant: acme\r\n",
		"X-Jellyfish-Version: v1.2.3\r\n",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("missing header %q in output:\n%s", want, out)
		}
	}
}

func TestAssembleMessageSkipsEmptyXHeaders(t *testing.T) {
	hdr := messageHeaders{
		From:    "ops@example.com",
		To:      "a@b.c",
		Subject: "s",
		Date:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		// Report, Tenant, Version all empty.
	}
	out, err := assembleMessage(hdr, "<p>x</p>", "x\n", "=_jf_X", "<i@b.c>", "", nil)
	if err != nil {
		t.Fatalf("assembleMessage: %v", err)
	}
	for _, unwanted := range []string{
		"X-Jellyfish-Report:",
		"X-Jellyfish-Tenant:",
		"X-Jellyfish-Version:",
	} {
		if bytes.Contains(out, []byte(unwanted)) {
			t.Errorf("did not expect header line containing %q; got:\n%s", unwanted, out)
		}
	}
}

func TestAssembleMessageSkipsListIDWhenNoFromDomain(t *testing.T) {
	hdr := messageHeaders{
		From:    "no-at-sign",
		To:      "a@b.c",
		Subject: "s",
		Date:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
	}
	out, err := assembleMessage(hdr, "<p>x</p>", "x\n", "=_jf_X", "<i@b.c>", "", nil)
	if err != nil {
		t.Fatalf("assembleMessage: %v", err)
	}
	if bytes.Contains(out, []byte("List-Id:")) {
		t.Fatalf("expected no List-Id when From has no @ and no explicit ListIDDomain; got:\n%s", out)
	}
}
```

- [ ] **Step 2: Run tests, watch them fail**

Run: `go test ./internal/email -run TestAssembleMessage -v`
Expected: FAIL with `unknown field Report in struct literal` (or similar) for the new fields, plus body mismatches for the List-Id assertions.

- [ ] **Step 3: Extend `messageHeaders`**

In `internal/email/email.go`, replace the `messageHeaders` struct (around line 81) with:

```go
// messageHeaders is the minimum set of headers assembleMessage writes.
type messageHeaders struct {
	From         string
	To           string
	Subject      string
	Date         time.Time
	Report       string // X-Jellyfish-Report; empty → skip
	Tenant       string // X-Jellyfish-Tenant; empty → skip
	Version      string // X-Jellyfish-Version; empty → skip
	ListIDDomain string // List-Id domain; empty → domainFromAddress(From); still empty → skip
}
```

- [ ] **Step 4: Add the header writes in `assembleMessage`**

In `internal/email/email.go`, locate the existing `writeHeader("MIME-Version", "1.0")` call (line 121). Immediately after that line (and before the `if logo == nil { writeHeader("Content-Type", ...) }` block), add:

```go
	writeHeader("MIME-Version", "1.0")
	listDomain := h.ListIDDomain
	if listDomain == "" {
		if d := domainFromAddress(h.From); d != "" && d != "localhost" {
			listDomain = d
		}
	}
	if listDomain != "" {
		writeHeader("List-Id", "<"+listDomain+">")
	}
	if h.Report != "" {
		writeHeader("X-Jellyfish-Report", h.Report)
	}
	if h.Tenant != "" {
		writeHeader("X-Jellyfish-Tenant", h.Tenant)
	}
	if h.Version != "" {
		writeHeader("X-Jellyfish-Version", h.Version)
	}
```

Notes on the implementation:
- `domainFromAddress` returns `"localhost"` when `From` lacks `@`. The skip-when-no-from-domain test relies on us treating `"localhost"` as "no real domain available" so we omit `List-Id` (rather than emit a bogus `List-Id: <localhost>`).
- The four new headers are written in stable order: `List-Id`, then `Report`, `Tenant`, `Version`. The order is part of the contract the goldens lock in.

- [ ] **Step 5: Run the new tests**

Run: `go test ./internal/email -run TestAssembleMessage -v`
Expected: PASS for all five new test functions. The existing `TestAssembleMessageHeadersAndStructure` should also still pass — it does not set the new fields, so the new headers are skipped.

- [ ] **Step 6: Run full test suite (golden tests will now FAIL)**

Run: `make test`
Expected: tests in `internal/email/` that compare against goldens (`TestNewVulnSummaryRendererGolden`, `TestNewVulnSummaryRendererGoldenEmpty`, `TestNewUserShowRendererGolden`, etc.) will FAIL — the renderers don't yet pass new fields, but the assembled output already includes `List-Id: <example.com>` (derived from the `alice@example.com` in pinned opts), which is not in the current goldens.

Wait — this only happens if the renderers DO pass `Tenant` to messageHeaders, which they will once Task 4 lands. Right now `vulns_summary.go:256` and `user_show.go:256` only pass `From / To / Subject / Date`. So Tenant doesn't reach the writer yet — but the From-derived List-Id WILL be emitted (since List-Id derives from `h.From`, which is always passed). So the goldens will fail on the new `List-Id: <example.com>` line.

This is expected. Tasks 4 and 5 finish the wiring and regenerate the goldens. Continue.

- [ ] **Step 7: Commit**

```bash
git add internal/email/email.go internal/email/email_test.go
git commit -m "feat(email): added List-Id and X-Jellyfish-* header writes"
```

---

## Task 4: Wire renderers to pass new `Options` fields into `messageHeaders`

**Files:**
- Modify: `internal/email/user_show.go` (around line 256, the `assembleMessage(messageHeaders{...}, ...)` call)
- Modify: `internal/email/vulns_summary.go` (around line 256, same call shape)

- [ ] **Step 1: Update `user_show.go`**

Replace the `messageHeaders{...}` literal in `internal/email/user_show.go` (currently four fields) with the six-field form:

```go
	bytesOut, err := assembleMessage(messageHeaders{
		From:         r.opts.From,
		To:           r.opts.To,
		Subject:      subject,
		Date:         r.opts.GeneratedAt,
		Report:       r.opts.Report,
		Tenant:       r.opts.Tenant,
		Version:      r.opts.Version,
		ListIDDomain: r.opts.ListIDDomain,
	}, htmlBody, textBody, boundary, messageID, outerBoundary, logo)
```

- [ ] **Step 2: Update `vulns_summary.go` identically**

Same change at the equivalent `assembleMessage` call in `internal/email/vulns_summary.go`.

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 4: Run the email package tests**

Run: `go test ./internal/email -v`
Expected: the five `TestAssembleMessage*` tests pass. The golden tests still FAIL because the goldens haven't been regenerated. Continue to Task 5.

- [ ] **Step 5: Commit**

```bash
git add internal/email/user_show.go internal/email/vulns_summary.go
git commit -m "feat(email): plumbed new header fields through renderers"
```

---

## Task 5: Regenerate goldens and verify only header lines changed

**Files:**
- Regenerate: `internal/email/testdata/user_show.golden.eml`
- Regenerate: `internal/email/testdata/user_show_no_detections.golden.eml`
- Regenerate: `internal/email/testdata/user_show_with_message.golden.eml`
- Regenerate: `internal/email/testdata/vulns_summary.golden.eml`
- Regenerate: `internal/email/testdata/vulns_summary_empty.golden.eml`
- Regenerate: `internal/email/testdata/vulns_summary_with_message.golden.eml`

- [ ] **Step 1: Confirm the goldens currently fail**

Run: `go test ./internal/email -run Golden -v`
Expected: FAIL with golden mismatches (multiple files).

- [ ] **Step 2: Regenerate via the existing `-update-golden` flag**

Run: `go test ./internal/email -run Golden -update-golden`
Expected: PASS. The flag is defined at `internal/email/vulns_summary_test.go:168` and applies to all golden tests via the shared `goldenAssert` helper.

- [ ] **Step 3: Verify the diff is ONLY new header lines**

Run: `git diff internal/email/testdata/ | head -80`
Expected: every changed line is one of:
- `+List-Id: <example.com>\r\n` (derived from pinned `From: alice@example.com`)
- `+X-Jellyfish-Tenant: example\r\n` (from pinned `Tenant: "example"`)

The pinned opts do NOT set Report/Version/ListIDDomain, so `X-Jellyfish-Report`, `X-Jellyfish-Version`, and explicit `List-Id` overrides will NOT appear in goldens. If you see any other diff (changed body, changed boundary, changed Date), STOP and investigate before committing.

- [ ] **Step 4: Run all email tests**

Run: `go test ./internal/email -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/email/testdata/
git commit -m "test(email): regenerated goldens with List-Id and Tenant headers"
```

---

## Task 6: `resolveEmailOptions` populates `Version` and `ListIDDomain`

**Files:**
- Modify: `cmd/email.go` (`resolveEmailOptions` function, around lines 63-102)

- [ ] **Step 1: Add the two assignments**

In `cmd/email.go`, locate `resolveEmailOptions`. After the existing line `opts.LogoPath = firstNonEmpty(flags.LogoPath, prof.Email.LogoPath)` (around line 78) and before the `opts.From = ...` block, add:

```go
	opts.LogoPath = firstNonEmpty(flags.LogoPath, prof.Email.LogoPath)
	opts.Version = version.Version
	opts.ListIDDomain = prof.Email.ListIDDomain

	opts.From = firstNonEmpty(flags.From, prof.Email.From)
```

Add the import for the version package at the top of `cmd/email.go` (alongside the existing imports):

```go
	"github.com/bawdo/jellyfish/internal/version"
```

(Check the existing imports first: if `version` is already imported, no change needed.)

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 3: Run tests**

Run: `make test`
Expected: all PASS. The `version.Version` value in tests is `"dev"` (the package default; see `internal/version/version.go`), so every test that goes through `resolveEmailOptions` now produces an email with `X-Jellyfish-Version: dev` — but no existing test asserts on its absence, so they still pass.

- [ ] **Step 4: Commit**

```bash
git add cmd/email.go
git commit -m "feat(cmd): populated email Version and ListIDDomain options"
```

---

## Task 7: Set `Report` per command + per-command tests

**Files:**
- Modify: `cmd/users.go` (in `runUsersSendEmail`, after the `baseEmailOpts, err := resolveEmailOptions(...)` call)
- Modify: `cmd/user.go` (in `runSendUserShow` AND in `renderUserBundle` email branch)
- Modify: `cmd/vulns.go` (in `runSendVulnsSummary` AND in `renderVulnsSummary` email branch)
- Modify: `cmd/users_test.go`
- Modify: `cmd/user_test.go`
- Modify: `cmd/send_email_test.go`

- [ ] **Step 1: Set `Report = "users-send"` in `cmd/users.go`**

In `cmd/users.go`, locate the line `baseEmailOpts, err := resolveEmailOptions(opts.EmailFlags, profForOpts, gitLookup, now)`. Immediately after the error-return block for that call, set the Report:

```go
	baseEmailOpts, err := resolveEmailOptions(opts.EmailFlags, profForOpts, gitLookup, now)
	if err != nil {
		return err
	}
	baseEmailOpts.Report = "users-send"
```

- [ ] **Step 2: Set `Report = "user-show"` in `cmd/user.go`**

In `cmd/user.go`, there are two places that build `emailOpts` from `resolveEmailOptions`:

1. `renderUserBundle` (the `case "email":` branch). After the existing `emailOpts, err := resolveEmailOptions(...)` block:

```go
		emailOpts, err := resolveEmailOptions(opts.EmailFlags, opts.Profile, gitLookup, now)
		if err != nil {
			return err
		}
		emailOpts.Report = "user-show"
```

2. `runSendUserShow`. Same two-line addition immediately after the existing `emailOpts, err := resolveEmailOptions(...)` block:

```go
	emailOpts, err := resolveEmailOptions(opts.EmailFlags, opts.Profile, gitLookup, now)
	if err != nil {
		return err
	}
	emailOpts.Report = "user-show"
```

- [ ] **Step 3: Set `Report = "vulns-summary"` in `cmd/vulns.go`**

In `cmd/vulns.go`, do the same in the two `resolveEmailOptions` call sites. Locate them with:

```bash
grep -n "resolveEmailOptions" cmd/vulns.go
```

After each call's error-return block, append:

```go
	emailOpts.Report = "vulns-summary"
```

(If the local variable is named differently — e.g., `eo` — match the local name.)

- [ ] **Step 4: Write the bulk-command Report test**

Append to `cmd/users_test.go`:

```go
func TestRunUsersSendEmailSetsReportHeader(t *testing.T) {
	client := &fakeClient{
		users:      []iru.User{{ID: "u-1", Email: "alice@example.com"}},
		devices:    []iru.Device{{DeviceID: "d-1", DeviceName: "MBP"}},
		detections: []iru.Detection{{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5}},
	}
	sender := &fakeGmailSender{returnID: "msg-1"}
	var stderr bytes.Buffer
	opts := newOpts(t, sender)
	opts.Emails = "alice@example.com"
	if err := runUsersSendEmail(context.Background(), client, &stderr, opts); err != nil {
		t.Fatalf("run: %v\nstderr=%s", err, stderr.String())
	}
	if sender.sent == nil {
		t.Fatal("sender was not called")
	}
	if !bytes.Contains(sender.sent, []byte("X-Jellyfish-Report: users-send\r\n")) {
		t.Fatalf("expected X-Jellyfish-Report: users-send; got:\n%s", sender.sent)
	}
}
```

- [ ] **Step 5: Write the user-show Report test**

Append to `cmd/user_test.go`:

```go
func TestUserShowSendEmailSetsReportHeader(t *testing.T) {
	client := &fakeClient{
		users:   []iru.User{{ID: "u-1", Name: "Alice", Email: "alice@example.com"}},
		devices: []iru.Device{{DeviceID: "d-1", DeviceName: "MBP", SerialNumber: "SN1"}},
		detections: []iru.Detection{
			{DeviceID: "d-1", CVEID: "CVE-A", Severity: "Critical", CVSSScore: 9.5, Name: "x", Version: "1.0"},
		},
	}
	sender := &fakeGmailSender{returnID: "msg-xyz"}
	opts := userShowOpts{
		Identifier:  "u-1",
		NoCache:     true,
		EmailFlags:  emailFlagValues{Send: true, From: "ops@example.com"},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		Profile:     config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		KeychainGet: func() ([]byte, error) { return []byte(`{"type":"service_account"}`), nil },
		NewSender:   func(_ context.Context, _ []byte, _ string) (gmail.Sender, error) { return sender, nil },
	}
	if err := runUserShow(context.Background(), client, &bytes.Buffer{}, &bytes.Buffer{}, opts); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !bytes.Contains(sender.sent, []byte("X-Jellyfish-Report: user-show\r\n")) {
		t.Fatalf("expected X-Jellyfish-Report: user-show; got:\n%s", sender.sent)
	}
}
```

- [ ] **Step 6: Write the vulns-summary Report test**

Append to `cmd/send_email_test.go` (this is where the vulns-summary send tests already live):

```go
func TestRunSendVulnsSummarySetsReportHeader(t *testing.T) {
	sender := &fakeGmailSender{}
	opts := vulnsSummaryOpts{
		Profile: config.Profile{
			Subdomain: "acme",
			Email: config.EmailConfig{
				From:            "alice@example.com",
				DefaultTo:       "ops@example.com",
				GmailConfigured: true,
			},
		},
		EmailFlags:  emailFlagValues{Send: true},
		EmailNow:    time.Date(2026, 5, 16, 0, 0, 0, 0, time.UTC),
		KeychainGet: stubKeychain(`{}`),
		NewSender:   newFakeSenderFactory(sender),
		gitEmail:    func() (string, error) { return "git@example.com", nil },
	}
	var stderr bytes.Buffer
	if err := runSendVulnsSummary(context.Background(), &stderr, opts, nil); err != nil {
		t.Fatalf("runSendVulnsSummary: %v", err)
	}
	if !bytes.Contains(sender.sent, []byte("X-Jellyfish-Report: vulns-summary\r\n")) {
		t.Fatalf("expected X-Jellyfish-Report: vulns-summary; got:\n%s", sender.sent)
	}
}
```

- [ ] **Step 7: Run all the new tests**

Run: `go test ./cmd -run "TestRunUsersSendEmailSetsReportHeader|TestUserShowSendEmailSetsReportHeader|TestRunSendVulnsSummarySetsReportHeader" -v`
Expected: PASS for all three.

- [ ] **Step 8: Run full test suite**

Run: `make test`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add cmd/users.go cmd/user.go cmd/vulns.go cmd/users_test.go cmd/user_test.go cmd/send_email_test.go
git commit -m "feat(cmd): set X-Jellyfish-Report per source command"
```

---

## Task 8: README docs

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document `email.list_id_domain` under "Configure email"**

In `README.md`, locate the section that begins `### Configure email defaults` (the section that lists `from / default_to / Gmail JSON / header_bg / logo`). Append a new paragraph after the existing prose for that section:

```markdown
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

`jellyfish configure email` does not prompt for this value — edit
`~/.config/jellyfish/config.yml` directly.
```

- [ ] **Step 2: Add a "Filtering in Gmail" subsection under "Email output"**

In `README.md`, locate the existing `### Email output` heading. After the existing prose in that section (after the `#### Sending via Gmail (--send-email)` block but before `### Exit codes`), add:

```markdown
#### Filtering Jellyfish mail in Gmail

Every Jellyfish-sent message carries a `List-Id` header derived from your
`email.from` domain (or from `email.list_id_domain`; see above). Gmail's
filter UI has a first-class `list:` operator for this — create a filter
with `Has the words: list:example.com` (substitute your own
domain) and label every Jellyfish mail in one rule.

Per-command discrimination lives in the `X-Jellyfish-Report` header
(values: `vulns-summary`, `user-show`, `users-send`). Gmail's filter UI
does not expose arbitrary header search, but you can view the value in
"Show original" or in any mail client that surfaces raw headers (sieve,
mutt, server-side rules). Two more headers are set for audit:
`X-Jellyfish-Tenant` (your Iru tenant subdomain) and `X-Jellyfish-Version`
(the jellyfish build that sent the message).
```

- [ ] **Step 3: Verify the file builds (README doesn't affect Go tests, but sanity)**

Run: `make test`
Expected: all PASS.

- [ ] **Step 4: Spot-check the new content**

Run: `grep -n "list_id_domain\|Filtering Jellyfish" README.md`
Expected: two matches for `list_id_domain` (one in prose, one in YAML), one match for `Filtering Jellyfish`.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs(readme): documented List-Id and X-Jellyfish filtering"
```

---

## Final verification

- [ ] **Run the full test suite**

Run: `make test && make lint`
Expected: `make test` green. `make lint` will show the 7 pre-existing warnings already on `master`; no NEW ones.

- [ ] **Smoke-test the header output**

Run: `go run . user show keith@example.com -o email | head -25`

Expected (the email block at the top should now include four new lines among the standard headers):

```
From: ...
To: ...
Subject: ...
Date: ...
Message-ID: ...
MIME-Version: 1.0
List-Id: <example.com>
X-Jellyfish-Report: user-show
X-Jellyfish-Tenant: <subdomain>
X-Jellyfish-Version: dev
Content-Type: ...
```

(`dev` is the version baked in when running via `go run`. A `make install`d binary will show the actual git-describe version.)

- [ ] **Confirm the bulk command also carries the headers**

Run: `go run . users send-email --emails k@example.com --dry-run --yes --email-from keith@example.com 2>&1 | grep -E "would-send|summary"`

This doesn't directly emit the headers (dry-run skips the send), but it verifies the bulk command still works end-to-end with the new wiring in place.
