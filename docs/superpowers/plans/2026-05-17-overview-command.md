# `jellyfish overview` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a top-level `jellyfish overview` command that computes a per-user `sec_score` (sum of CVSS across active issues on the user's devices), rolls it up into org-wide totals / averages / "Best 5" / "Most Dangerous 5" / full roster, supports all output formats (`table`, `json`, `yaml`, `csv`, `email`), and reuses the Gmail send pipeline from `users send-email` with an optional `--per-user` fanout that personalises each copy.

**Architecture:** New top-level cobra command in `cmd/overview.go`. Data assembly walks all users (new `ListUsersStream`), fetches detections once (existing `fetchAllDetections`), buckets per device, sums CVSS per user. View types (`OverviewView`, `UserStats`, `OverviewTotals`, `OverviewAverages`) live in `internal/email/overview_types.go` to avoid a cyclic import (same pattern as `email.UserBundleInput`). Rendering dispatches on `--output`: structured formats use the existing `internal/output` builders; email uses a new `email.NewOverviewRenderer` with two templates (`overview.html.tmpl` + `overview.txt.tmpl`) that branch on `Me != nil` for the per-user variant.

**Tech Stack:** Go 1.22, cobra (CLI), `internal/iru` (Iru API client), `internal/email` (RFC 5322 renderers using `text/template` + `html/template`), `internal/output` (table/json/yaml/csv), `internal/gmail` (Gmail API send). Existing patterns followed exactly: bulk send loop with `bulkCounters`, `resolveEmailOptions`, `captureMessage`, `confirmSend`, `classifyError` precedence.

**Spec:** `docs/superpowers/specs/2026-05-17-overview-command-design.md`

---

## File map

| File | Action | Responsibility |
|---|---|---|
| `internal/iru/users.go` | modify | Add `ListUsersStream` (loop over `ListUsersPage`) |
| `internal/iru/users_test.go` | modify | Test `ListUsersStream` |
| `cmd/iru_iface.go` | modify | Add `ListUsersStream` to the `iruClient` interface |
| `cmd/vulns_test.go` | modify | Add `ListUsersStream` to `fakeClient` |
| `internal/email/overview_types.go` | create | `UserStats`, `OverviewTotals`, `OverviewAverages`, `OverviewView`, `OverviewInput` |
| `internal/email/overview.go` | create | `NewOverviewRenderer`, view-building, template assembly |
| `internal/email/overview_test.go` | create | Golden tests (admin + per-user) |
| `internal/email/testdata/overview-admin.eml` | create | Golden fixture |
| `internal/email/testdata/overview-peruser.eml` | create | Golden fixture |
| `internal/email/templates/overview.html.tmpl` | create | HTML template (locked layouts) |
| `internal/email/templates/overview.txt.tmpl` | create | Plain-text template |
| `cmd/overview.go` | create | Cobra command, opts struct, `runOverview`, `assembleOverview`, render dispatch, two send paths |
| `cmd/overview_test.go` | create | Assembly + render + send-path tests |
| `cmd/root.go` | modify | `root.AddCommand(newOverviewCmd())` |
| `README.md` | modify | New "Org-wide overview" section |

Each task below corresponds to one cohesive piece of this file map and ends with a commit.

---

## Task 1: `iru.ListUsersStream`

**Files:**
- Modify: `internal/iru/users.go`
- Test: `internal/iru/users_test.go` (extend or create)

The existing client only exposes `ListUsersPage`. Add a thin streaming wrapper that mirrors the shape of `ListDetectionsStream` so the `cmd` layer can iterate every user in one call.

- [ ] **Step 1: Check whether a users test file exists**

Run: `ls internal/iru/users_test.go`

If the file does not exist, you'll create it in step 2. If it does, you'll add a new test function alongside the existing ones.

- [ ] **Step 2: Write the failing test**

Append (or create) `internal/iru/users_test.go` with:

```go
package iru

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
)

func TestListUsersStream(t *testing.T) {
	// Three "pages" of two users each, then an empty terminating page.
	pages := [][]User{
		{{ID: "u1", Name: "Alice", Email: "alice@x"}, {ID: "u2", Name: "Bob", Email: "bob@x"}},
		{{ID: "u3", Name: "Carol", Email: "carol@x"}, {ID: "u4", Name: "Dave", Email: "dave@x"}},
		{{ID: "u5", Name: "Eve", Email: "eve@x"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
		if idx >= len(pages) {
			_ = json.NewEncoder(w).Encode(paginated[User]{Results: nil, Next: ""})
			return
		}
		next := ""
		if idx+1 < len(pages) {
			next = "/users?cursor=" + strconv.Itoa(idx+1)
		}
		_ = json.NewEncoder(w).Encode(paginated[User]{Results: pages[idx], Next: next})
	}))
	t.Cleanup(srv.Close)

	base, _ := url.Parse(srv.URL)
	c := &Client{baseURL: base, httpClient: srv.Client()}

	var got [][]User
	if err := c.ListUsersStream(context.Background(), func(page []User) error {
		// Defensive copy: cb may receive a slice backing the decoder buffer.
		cp := append([]User(nil), page...)
		got = append(got, cp)
		return nil
	}); err != nil {
		t.Fatalf("ListUsersStream: %v", err)
	}
	if !reflect.DeepEqual(got, pages) {
		t.Fatalf("pages mismatch:\n got: %#v\nwant: %#v", got, pages)
	}
}
```

If `paginated[User]{Next: ...}` doesn't compile because the field is unexported, look at how `ListDetectionsStream` is tested for the cursor mechanism and adapt — open `internal/iru/detections_test.go` for the canonical pattern, then mirror it. The point of this test is "calls the page function repeatedly until the next cursor is empty"; the exact wire format is whatever the existing `paginated` type uses.

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/iru/ -run TestListUsersStream -v`

Expected: FAIL with `c.ListUsersStream undefined`.

- [ ] **Step 4: Implement `ListUsersStream`**

Append to `internal/iru/users.go` (after `FindUserByEmail`):

```go
// ListUsersStream walks every user via repeated ListUsersPage calls. The
// callback receives one page at a time; returning a non-nil error aborts the
// walk and propagates the error to the caller. Mirrors the shape of
// ListDetectionsStream so callers can express "do something with every user
// in the tenant" without managing the cursor themselves.
func (c *Client) ListUsersStream(ctx context.Context, cb func(page []User) error) error {
	const pageSize = 100
	cursor := ""
	for {
		page, next, err := c.ListUsersPage(ctx, pageSize, cursor)
		if err != nil {
			return err
		}
		if len(page) > 0 {
			if err := cb(page); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/iru/ -run TestListUsersStream -v`

Expected: PASS.

- [ ] **Step 6: Run the whole iru package to catch regressions**

Run: `go test ./internal/iru/...`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/iru/users.go internal/iru/users_test.go
git commit -m "feat(iru): added ListUsersStream wrapping ListUsersPage"
```

---

## Task 2: Extend `iruClient` interface + fake

**Files:**
- Modify: `cmd/iru_iface.go`
- Modify: `cmd/vulns_test.go` (the `fakeClient` definition lives here)

Now the cmd layer can ask for the streaming users walk.

- [ ] **Step 1: Add the method to the interface**

Edit `cmd/iru_iface.go`, adding inside the `iruClient` interface block (alphabetical-ish, near the existing `ListDevicesPage`):

```go
ListUsersStream(ctx context.Context, cb func(page []iru.User) error) error
```

The full interface should now include this line alongside the existing `GetUser` / `FindUserByEmail` entries.

- [ ] **Step 2: Verify the package fails to compile**

Run: `go build ./cmd/...`

Expected: FAIL with `*fakeClient does not implement iruClient (missing method ListUsersStream)`.

- [ ] **Step 3: Add the method to `fakeClient`**

Edit `cmd/vulns_test.go`. Add a `users` field is already present (`users []iru.User`); reuse it. Append after the existing `FindUserByEmail` method:

```go
func (f *fakeClient) ListUsersStream(_ context.Context, cb func(page []iru.User) error) error {
	if len(f.users) == 0 {
		return nil
	}
	return cb(f.users)
}
```

- [ ] **Step 4: Verify the build is green**

Run: `go build ./cmd/... && go test ./cmd/... -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/iru_iface.go cmd/vulns_test.go
git commit -m "feat(cmd): exposed ListUsersStream on iruClient interface"
```

---

## Task 3: Overview view types in `internal/email`

**Files:**
- Create: `internal/email/overview_types.go`

Plain type definitions only — no logic, no template code yet. These are the contract that `cmd` and the renderer both consume.

- [ ] **Step 1: Create the file**

Write `internal/email/overview_types.go`:

```go
package email

import "time"

// UserStats is a single user's contribution to the overview. SecScore is the
// sum of CVSSScore across every detection on every device this user owns.
// The four severity counts mirror Iru's "Critical | High | Medium | Low"
// labels; detections with "Undefined" or empty severity are still counted
// in TotalIssues and SecScore but do not increment any severity bucket.
type UserStats struct {
	UserID      string  `json:"user_id" yaml:"user_id"`
	Name        string  `json:"name" yaml:"name"`
	Email       string  `json:"email" yaml:"email"`
	DeviceCount int     `json:"device_count" yaml:"device_count"`
	SecScore    float64 `json:"sec_score" yaml:"sec_score"`
	TotalIssues int     `json:"total_issues" yaml:"total_issues"`
	Critical    int     `json:"critical_issues" yaml:"critical_issues"`
	High        int     `json:"high_issues" yaml:"high_issues"`
	Medium      int     `json:"medium_issues" yaml:"medium_issues"`
	Low         int     `json:"low_issues" yaml:"low_issues"`
	Rank        int     `json:"rank" yaml:"rank"` // 1 = highest SecScore in the org
}

// OverviewTotals are sums across users with at least one device.
type OverviewTotals struct {
	UserCount   int     `json:"user_count" yaml:"user_count"`
	DeviceCount int     `json:"device_count" yaml:"device_count"`
	TotalIssues int     `json:"total_issues" yaml:"total_issues"`
	Critical    int     `json:"critical_issues" yaml:"critical_issues"`
	High        int     `json:"high_issues" yaml:"high_issues"`
	Medium      int     `json:"medium_issues" yaml:"medium_issues"`
	Low         int     `json:"low_issues" yaml:"low_issues"`
	SecScore    float64 `json:"sec_score" yaml:"sec_score"`
}

// OverviewAverages are the per-user values, denominator = UserCount.
type OverviewAverages struct {
	DevicesPerUser  float64 `json:"devices_per_user" yaml:"devices_per_user"`
	IssuesPerUser   float64 `json:"issues_per_user" yaml:"issues_per_user"`
	SecScorePerUser float64 `json:"sec_score_per_user" yaml:"sec_score_per_user"`
	CriticalPerUser float64 `json:"critical_per_user" yaml:"critical_per_user"`
	HighPerUser     float64 `json:"high_per_user" yaml:"high_per_user"`
	MediumPerUser   float64 `json:"medium_per_user" yaml:"medium_per_user"`
	LowPerUser      float64 `json:"low_per_user" yaml:"low_per_user"`
}

// OverviewView is the full payload that every renderer (table/json/yaml/csv/
// email) consumes. Users is the full roster sorted by SecScore desc, name
// asc. BestFive holds the five entries with the lowest SecScore (sorted
// asc); MostDangerousFive holds the top five (sorted desc). Me is set only
// when rendering a per-user email copy and points at the recipient's entry
// in Users (same pointer-equality, not a clone).
type OverviewView struct {
	Tenant            string           `json:"tenant" yaml:"tenant"`
	GeneratedAt       time.Time        `json:"generated_at" yaml:"generated_at"`
	Totals            OverviewTotals   `json:"totals" yaml:"totals"`
	Averages          OverviewAverages `json:"averages" yaml:"averages"`
	BestFive          []UserStats      `json:"best_five" yaml:"best_five"`
	MostDangerousFive []UserStats      `json:"most_dangerous_five" yaml:"most_dangerous_five"`
	Users             []UserStats      `json:"users" yaml:"users"`
	Me                *UserStats       `json:"me,omitempty" yaml:"me,omitempty"`
}

// OverviewInput is the typed shape NewOverviewRenderer.Render expects via
// the output.Renderer Render(w, v any) call site.
type OverviewInput struct {
	View OverviewView
}
```

- [ ] **Step 2: Verify the package compiles**

Run: `go build ./internal/email/...`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/email/overview_types.go
git commit -m "feat(email): added overview view types"
```

---

## Task 4: `assembleOverview` in `cmd/overview.go`

**Files:**
- Create: `cmd/overview.go` (just this function and its tier helper for now)
- Create: `cmd/overview_test.go`

This is the data-assembly heart: walk users → for each user fetch devices → bucket the prefetched detection list by device → sum CVSS → tally severities → sort → assign ranks → compute totals + averages.

- [ ] **Step 1: Write the failing test**

Create `cmd/overview_test.go`:

```go
package cmd

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/iru"
)

// overviewFakeClient is a fakeClient subset that lets each user own a
// distinct device set. The base fakeClient's single devices slice can't
// express "alice has d1, bob has d2".
type overviewFakeClient struct {
	*fakeClient
	devicesByUser map[string][]iru.Device // key = user.ID
}

func (f *overviewFakeClient) ListDevices(_ context.Context, filt iru.DeviceFilters) ([]iru.Device, error) {
	return f.devicesByUser[filt.UserID], nil
}

func TestAssembleOverviewSumsAndSorts(t *testing.T) {
	base := &fakeClient{
		users: []iru.User{
			{ID: "u-alice", Name: "Alice", Email: "alice@x"},
			{ID: "u-bob", Name: "Bob", Email: "bob@x"},
			{ID: "u-carol", Name: "Carol", Email: "carol@x"}, // no devices -> excluded
		},
		detections: []iru.Detection{
			{DeviceID: "d-a1", CVEID: "CVE-1", CVSSScore: 9.8, Severity: "Critical"},
			{DeviceID: "d-a1", CVEID: "CVE-2", CVSSScore: 7.5, Severity: "High"},
			{DeviceID: "d-a2", CVEID: "CVE-3", CVSSScore: 5.0, Severity: "Medium"},
			{DeviceID: "d-b1", CVEID: "CVE-4", CVSSScore: 2.5, Severity: "Low"},
			{DeviceID: "d-other", CVEID: "CVE-X", CVSSScore: 9.0, Severity: "Critical"}, // belongs to no listed device
		},
	}
	c := &overviewFakeClient{
		fakeClient: base,
		devicesByUser: map[string][]iru.Device{
			"u-alice": {{DeviceID: "d-a1"}, {DeviceID: "d-a2"}},
			"u-bob":   {{DeviceID: "d-b1"}},
			"u-carol": nil,
		},
	}

	view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}

	// Carol has no devices -> excluded.
	if len(view.Users) != 2 {
		t.Fatalf("Users len: got %d, want 2 (carol excluded)", len(view.Users))
	}

	// Alice: 9.8 + 7.5 + 5.0 = 22.3, 3 issues, C=1 H=1 M=1 L=0, 2 devices.
	// Bob:   2.5,                    1 issue,  C=0 H=0 M=0 L=1, 1 device.
	// Sort: SecScore desc -> Alice rank 1, Bob rank 2.
	want := []email.UserStats{
		{UserID: "u-alice", Name: "Alice", Email: "alice@x", DeviceCount: 2,
			SecScore: 22.3, TotalIssues: 3, Critical: 1, High: 1, Medium: 1, Low: 0, Rank: 1},
		{UserID: "u-bob", Name: "Bob", Email: "bob@x", DeviceCount: 1,
			SecScore: 2.5, TotalIssues: 1, Critical: 0, High: 0, Medium: 0, Low: 1, Rank: 2},
	}
	for i := range want {
		// float compare with one-decimal tolerance to dodge FP noise.
		if diff := view.Users[i].SecScore - want[i].SecScore; diff > 0.05 || diff < -0.05 {
			t.Errorf("user[%d] SecScore: got %v want %v", i, view.Users[i].SecScore, want[i].SecScore)
		}
		// zero the float for the rest of the comparison so DeepEqual matches.
		view.Users[i].SecScore = want[i].SecScore
	}
	if !reflect.DeepEqual(view.Users, want) {
		t.Errorf("Users mismatch:\n got: %#v\nwant: %#v", view.Users, want)
	}

	if view.Totals.UserCount != 2 || view.Totals.DeviceCount != 3 || view.Totals.TotalIssues != 4 {
		t.Errorf("Totals counts wrong: %+v", view.Totals)
	}
	if view.Totals.Critical != 1 || view.Totals.High != 1 || view.Totals.Medium != 1 || view.Totals.Low != 1 {
		t.Errorf("Totals severity wrong: %+v", view.Totals)
	}
	// (22.3 + 2.5) / 2 = 12.4
	if diff := view.Averages.SecScorePerUser - 12.4; diff > 0.05 || diff < -0.05 {
		t.Errorf("Averages.SecScorePerUser: got %v want 12.4", view.Averages.SecScorePerUser)
	}

	if len(view.MostDangerousFive) != 2 || view.MostDangerousFive[0].UserID != "u-alice" {
		t.Errorf("MostDangerousFive wrong: %+v", view.MostDangerousFive)
	}
	if len(view.BestFive) != 2 || view.BestFive[0].UserID != "u-bob" {
		t.Errorf("BestFive wrong: %+v", view.BestFive)
	}
}

func TestAssembleOverviewEmptyRosterErrors(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient:    &fakeClient{users: []iru.User{{ID: "u1", Name: "x"}}},
		devicesByUser: map[string][]iru.Device{"u1": nil},
	}
	_, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false)
	if err == nil || err.Error() == "" {
		t.Fatalf("expected an empty-roster error, got nil")
	}
}

func TestAssembleOverviewTieBreakerByName(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users: []iru.User{
				{ID: "u-b", Name: "Beta", Email: "b@x"},
				{ID: "u-a", Name: "Alpha", Email: "a@x"},
			},
			// both score 0 (no detections), so name asc decides
			detections: nil,
		},
		devicesByUser: map[string][]iru.Device{
			"u-a": {{DeviceID: "d-a"}},
			"u-b": {{DeviceID: "d-b"}},
		},
	}
	view, err := assembleOverview(context.Background(), c, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("assembleOverview: %v", err)
	}
	if view.Users[0].Name != "Alpha" || view.Users[1].Name != "Beta" {
		t.Fatalf("name-asc tiebreaker broken: %+v", view.Users)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/ -run TestAssembleOverview -v`

Expected: FAIL with `undefined: assembleOverview`.

- [ ] **Step 3: Implement `assembleOverview`**

Create `cmd/overview.go`:

```go
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/iru"
)

// assembleOverview walks every user, fetches their devices, buckets the
// prefetched detection list by device, and builds an OverviewView with
// totals, averages, leaderboards, and a ranked full roster. Users with
// zero devices are excluded.
//
// Returns an error iff the filtered roster is empty or any Iru call fails.
// The caller is responsible for dispatching the resulting view to a
// renderer (table / json / yaml / csv / email).
func assembleOverview(ctx context.Context, client iruClient, stderr io.Writer, noCache bool) (email.OverviewView, error) {
	allDetections, err := fetchAllDetections(ctx, client, stderr, !noCache)
	if err != nil {
		return email.OverviewView{}, err
	}
	byDevice := make(map[string][]iru.Detection, len(allDetections))
	for i := range allDetections {
		d := &allDetections[i]
		byDevice[d.DeviceID] = append(byDevice[d.DeviceID], *d)
	}

	var users []iru.User
	if err := client.ListUsersStream(ctx, func(page []iru.User) error {
		users = append(users, page...)
		return nil
	}); err != nil {
		return email.OverviewView{}, err
	}

	stats := make([]email.UserStats, 0, len(users))
	for i, u := range users {
		devices, derr := client.ListDevices(ctx, iru.DeviceFilters{UserID: u.ID})
		if derr != nil {
			return email.OverviewView{}, fmt.Errorf("list devices for user %s: %w", u.ID, derr)
		}
		if len(devices) == 0 {
			continue
		}
		var s email.UserStats
		s.UserID = u.ID
		s.Name = u.Name
		if s.Name == "" {
			s.Name = u.Email
		}
		s.Email = u.Email
		s.DeviceCount = len(devices)
		for _, dev := range devices {
			for _, det := range byDevice[dev.DeviceID] {
				s.TotalIssues++
				s.SecScore += det.CVSSScore
				switch strings.ToLower(det.Severity) {
				case "critical":
					s.Critical++
				case "high":
					s.High++
				case "medium":
					s.Medium++
				case "low":
					s.Low++
				}
			}
		}
		stats = append(stats, s)
		// Progress every 5 users so a long walk doesn't look hung.
		if (i+1)%5 == 0 {
			_, _ = fmt.Fprintf(stderr, "\rusers: %d/%d processed", i+1, len(users))
		}
	}
	if len(users) > 0 {
		_, _ = fmt.Fprintln(stderr)
	}
	if len(stats) == 0 {
		return email.OverviewView{}, errors.New("no users with devices")
	}

	// Roster + MostDangerous: SecScore desc, name asc, id asc.
	sort.SliceStable(stats, func(i, j int) bool {
		if stats[i].SecScore != stats[j].SecScore {
			return stats[i].SecScore > stats[j].SecScore
		}
		if stats[i].Name != stats[j].Name {
			return stats[i].Name < stats[j].Name
		}
		return stats[i].UserID < stats[j].UserID
	})
	for i := range stats {
		stats[i].Rank = i + 1
	}
	dangerousCount := 5
	if len(stats) < dangerousCount {
		dangerousCount = len(stats)
	}
	dangerousCopy := append([]email.UserStats(nil), stats[:dangerousCount]...)

	// BestFive: SecScore asc, name asc, id asc.
	bestSorted := append([]email.UserStats(nil), stats...)
	sort.SliceStable(bestSorted, func(i, j int) bool {
		if bestSorted[i].SecScore != bestSorted[j].SecScore {
			return bestSorted[i].SecScore < bestSorted[j].SecScore
		}
		if bestSorted[i].Name != bestSorted[j].Name {
			return bestSorted[i].Name < bestSorted[j].Name
		}
		return bestSorted[i].UserID < bestSorted[j].UserID
	})
	bestCount := 5
	if len(bestSorted) < bestCount {
		bestCount = len(bestSorted)
	}
	bestFive := bestSorted[:bestCount]

	var totals email.OverviewTotals
	for _, s := range stats {
		totals.UserCount++
		totals.DeviceCount += s.DeviceCount
		totals.TotalIssues += s.TotalIssues
		totals.Critical += s.Critical
		totals.High += s.High
		totals.Medium += s.Medium
		totals.Low += s.Low
		totals.SecScore += s.SecScore
	}
	n := float64(totals.UserCount)
	averages := email.OverviewAverages{
		DevicesPerUser:  float64(totals.DeviceCount) / n,
		IssuesPerUser:   float64(totals.TotalIssues) / n,
		SecScorePerUser: totals.SecScore / n,
		CriticalPerUser: float64(totals.Critical) / n,
		HighPerUser:     float64(totals.High) / n,
		MediumPerUser:   float64(totals.Medium) / n,
		LowPerUser:      float64(totals.Low) / n,
	}

	return email.OverviewView{
		GeneratedAt:       time.Now(),
		Totals:            totals,
		Averages:          averages,
		BestFive:          bestFive,
		MostDangerousFive: dangerousCopy,
		Users:             stats,
	}, nil
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/ -run TestAssembleOverview -v`

Expected: PASS (all three subtests).

- [ ] **Step 5: Run the full cmd suite for regressions**

Run: `go test ./cmd/... -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(cmd): added overview data assembly"
```

---

## Task 5: Tier classifier helper

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/overview_test.go`

The roster border / rank-tile colour comes from the SecScore tier. Centralise this so every renderer (table notes, email HTML, README) reads the same thresholds.

- [ ] **Step 1: Write the failing test**

Append to `cmd/overview_test.go`:

```go
func TestSecScoreTier(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "good"},
		{4.9, "good"},
		{5.0, "medium"},
		{29.9, "medium"},
		{30.0, "high"},
		{99.9, "high"},
		{100.0, "critical"},
		{500.0, "critical"},
	}
	for _, c := range cases {
		if got := secScoreTier(c.score); got != c.want {
			t.Errorf("secScoreTier(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/ -run TestSecScoreTier -v`

Expected: FAIL with `undefined: secScoreTier`.

- [ ] **Step 3: Implement**

Append to `cmd/overview.go`:

```go
// secScoreTier maps a SecScore to one of: "good", "medium", "high",
// "critical". Thresholds are documented in the spec and the README.
// Renderers use this to pick border / rank-tile colours so the table,
// email, and docs all agree on what a "high" user looks like.
func secScoreTier(score float64) string {
	switch {
	case score >= 100:
		return "critical"
	case score >= 30:
		return "high"
	case score >= 5:
		return "medium"
	default:
		return "good"
	}
}
```

- [ ] **Step 4: Run the test**

Run: `go test ./cmd/ -run TestSecScoreTier -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(cmd): added sec_score tier classifier"
```

---

## Task 6: Table renderer

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/overview_test.go`

Sequential blocks (TOTALS / BEST 5 / MOST DANGEROUS 5 / ALL USERS) each using `output.Table().WithColumns(...)`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/overview_test.go`:

```go
func TestRenderOverviewTable(t *testing.T) {
	v := email.OverviewView{
		Tenant: "acme",
		Totals: email.OverviewTotals{
			UserCount: 2, DeviceCount: 3, TotalIssues: 4, Critical: 1, High: 1, Medium: 1, Low: 1, SecScore: 24.8,
		},
		Averages: email.OverviewAverages{
			DevicesPerUser: 1.5, IssuesPerUser: 2.0, SecScorePerUser: 12.4,
			CriticalPerUser: 0.5, HighPerUser: 0.5, MediumPerUser: 0.5, LowPerUser: 0.5,
		},
		BestFive: []email.UserStats{
			{Rank: 2, Name: "Bob", SecScore: 2.5, Critical: 0, High: 0, Medium: 0, Low: 1},
		},
		MostDangerousFive: []email.UserStats{
			{Rank: 1, Name: "Alice", SecScore: 22.3, Critical: 1, High: 1, Medium: 1, Low: 0},
		},
		Users: []email.UserStats{
			{Rank: 1, Name: "Alice", SecScore: 22.3, Critical: 1, High: 1, Medium: 1, Low: 0},
			{Rank: 2, Name: "Bob", SecScore: 2.5, Critical: 0, High: 0, Medium: 0, Low: 1},
		},
	}
	var buf bytes.Buffer
	if err := renderOverviewTable(&buf, v); err != nil {
		t.Fatalf("renderOverviewTable: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"TOTALS", "BEST 5", "MOST DANGEROUS 5", "ALL USERS (2)",
		"Alice", "Bob",
		"22.3", "2.5", "12.4",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}
```

You'll need to add `"strings"` to the test file's import block if it isn't already there.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/ -run TestRenderOverviewTable -v`

Expected: FAIL with `undefined: renderOverviewTable`.

- [ ] **Step 3: Update the import block**

Replace the existing import group at the top of `cmd/overview.go` with:

```go
import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/output"
)
```

- [ ] **Step 4: Append the table renderer**

Add to the end of `cmd/overview.go`:

```go
// renderOverviewTable writes a sequence of labelled tables to w. Each block
// has an uppercase header line followed by a borderless table from
// internal/output. Blocks are separated by a blank line.
func renderOverviewTable(w io.Writer, v email.OverviewView) error {
	header := "SECURITY OVERVIEW"
	if v.Tenant != "" {
		header += " · " + v.Tenant
	}
	if !v.GeneratedAt.IsZero() {
		header += " · " + v.GeneratedAt.Format("2006-01-02 15:04")
	}
	_, _ = fmt.Fprintln(w, header)
	_, _ = fmt.Fprintln(w)

	// TOTALS as a small metric/total/avg table.
	type totalRow struct {
		metric, total, avg string
	}
	tot := v.Totals
	avgs := v.Averages
	tRows := []totalRow{
		{"users", strconv.Itoa(tot.UserCount), "-"},
		{"devices", strconv.Itoa(tot.DeviceCount), fmtFloat(avgs.DevicesPerUser)},
		{"issues", strconv.Itoa(tot.TotalIssues), fmtFloat(avgs.IssuesPerUser)},
		{"sec_score", fmtFloat(tot.SecScore), fmtFloat(avgs.SecScorePerUser)},
		{"critical", strconv.Itoa(tot.Critical), fmtFloat(avgs.CriticalPerUser)},
		{"high", strconv.Itoa(tot.High), fmtFloat(avgs.HighPerUser)},
		{"medium", strconv.Itoa(tot.Medium), fmtFloat(avgs.MediumPerUser)},
		{"low", strconv.Itoa(tot.Low), fmtFloat(avgs.LowPerUser)},
	}
	_, _ = fmt.Fprintln(w, "TOTALS")
	totalsTbl := output.Table().WithColumns([]output.Column{
		{Header: "metric", Extract: func(v any) string { return v.(totalRow).metric }},
		{Header: "total", Extract: func(v any) string { return v.(totalRow).total }},
		{Header: "avg/user", Extract: func(v any) string { return v.(totalRow).avg }},
	})
	if err := totalsTbl.Render(w, tRows); err != nil {
		return err
	}

	leaderboard := func(label string, rows []email.UserStats) error {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, label)
		tbl := output.Table().WithColumns([]output.Column{
			{Header: "rank", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).Rank) }},
			{Header: "name", Extract: func(v any) string { return v.(email.UserStats).Name }},
			{Header: "sec_score", Extract: func(v any) string { return fmtFloat(v.(email.UserStats).SecScore) }},
			{Header: "C", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).Critical) }},
			{Header: "H", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).High) }},
			{Header: "M", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).Medium) }},
			{Header: "L", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).Low) }},
		})
		return tbl.Render(w, rows)
	}
	if err := leaderboard("BEST 5", v.BestFive); err != nil {
		return err
	}
	if err := leaderboard("MOST DANGEROUS 5", v.MostDangerousFive); err != nil {
		return err
	}
	if err := leaderboard(fmt.Sprintf("ALL USERS (%d)", len(v.Users)), v.Users); err != nil {
		return err
	}
	return nil
}

// fmtFloat formats a float64 with one decimal place. Used by table, CSV,
// and the email view to keep score formatting consistent.
func fmtFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}
```

- [ ] **Step 5: Run the test**

Run: `go test ./cmd/ -run TestRenderOverviewTable -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(cmd): added overview table renderer"
```

---

## Task 7: CSV renderer

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/overview_test.go`

Per the spec: per-user only, no totals row, no sections.

- [ ] **Step 1: Write the failing test**

Append to `cmd/overview_test.go`:

```go
func TestRenderOverviewCSV(t *testing.T) {
	v := email.OverviewView{
		Users: []email.UserStats{
			{Rank: 1, Name: "Alice", Email: "alice@x", DeviceCount: 2,
				SecScore: 22.3, TotalIssues: 3, Critical: 1, High: 1, Medium: 1, Low: 0},
			{Rank: 2, Name: "Bob", Email: "bob@x", DeviceCount: 1,
				SecScore: 2.5, TotalIssues: 1, Critical: 0, High: 0, Medium: 0, Low: 1},
		},
	}
	var buf bytes.Buffer
	if err := renderOverviewCSV(&buf, v); err != nil {
		t.Fatalf("renderOverviewCSV: %v", err)
	}
	want := "name,email,devices_count,sec_score,total_issues,critical_issues,high_issues,medium_issues,low_issues\n" +
		"Alice,alice@x,2,22.3,3,1,1,1,0\n" +
		"Bob,bob@x,1,2.5,1,0,0,0,1\n"
	if buf.String() != want {
		t.Errorf("CSV mismatch:\n got:\n%s\nwant:\n%s", buf.String(), want)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/ -run TestRenderOverviewCSV -v`

Expected: FAIL with `undefined: renderOverviewCSV`.

- [ ] **Step 3: Implement**

Append to `cmd/overview.go`:

```go
// renderOverviewCSV writes one header row plus one row per user, in the
// same Users order as the email roster (SecScore desc). No totals row, no
// sections — leaderboards can be derived by sorting in a spreadsheet.
func renderOverviewCSV(w io.Writer, v email.OverviewView) error {
	c := output.CSV().WithColumns([]output.Column{
		{Header: "name", Extract: func(v any) string { return v.(email.UserStats).Name }},
		{Header: "email", Extract: func(v any) string { return v.(email.UserStats).Email }},
		{Header: "devices_count", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).DeviceCount) }},
		{Header: "sec_score", Extract: func(v any) string { return fmtFloat(v.(email.UserStats).SecScore) }},
		{Header: "total_issues", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).TotalIssues) }},
		{Header: "critical_issues", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).Critical) }},
		{Header: "high_issues", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).High) }},
		{Header: "medium_issues", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).Medium) }},
		{Header: "low_issues", Extract: func(v any) string { return strconv.Itoa(v.(email.UserStats).Low) }},
	})
	return c.Render(w, v.Users)
}
```

- [ ] **Step 4: Run the test**

Run: `go test ./cmd/ -run TestRenderOverviewCSV -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(cmd): added overview CSV renderer"
```

---

## Task 8: JSON / YAML renderers via `output.For`

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/overview_test.go`

`output.JSON()` / `output.YAML()` already marshal arbitrary values; the only work here is the dispatch helper and asserting the snake_case keys (which the json tags on `OverviewView` already deliver).

- [ ] **Step 1: Write the failing test**

Append to `cmd/overview_test.go`:

```go
func TestRenderOverviewJSON(t *testing.T) {
	v := email.OverviewView{
		Tenant: "acme",
		Totals: email.OverviewTotals{UserCount: 1, SecScore: 22.3},
		Users:  []email.UserStats{{Rank: 1, Name: "Alice", SecScore: 22.3}},
	}
	var buf bytes.Buffer
	if err := renderOverviewStructured(&buf, "json", v); err != nil {
		t.Fatalf("renderOverviewStructured json: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		`"tenant": "acme"`,
		`"user_count": 1`,
		`"sec_score": 22.3`,
		`"best_five"`,
		`"most_dangerous_five"`,
		`"users"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"me"`) {
		t.Errorf("JSON should omit me when nil:\n%s", got)
	}
}

func TestRenderOverviewYAML(t *testing.T) {
	v := email.OverviewView{
		Tenant: "acme",
		Users:  []email.UserStats{{Rank: 1, Name: "Alice"}},
	}
	var buf bytes.Buffer
	if err := renderOverviewStructured(&buf, "yaml", v); err != nil {
		t.Fatalf("renderOverviewStructured yaml: %v", err)
	}
	if !strings.Contains(buf.String(), "tenant: acme") {
		t.Errorf("YAML missing tenant key:\n%s", buf.String())
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/ -run 'TestRenderOverview(JSON|YAML)' -v`

Expected: FAIL with `undefined: renderOverviewStructured`.

- [ ] **Step 3: Implement**

Append to `cmd/overview.go`:

```go
// renderOverviewStructured dispatches to the JSON or YAML marshaller from
// internal/output. The struct's json/yaml tags own the wire shape (snake_case
// keys, omitempty for Me). Used for -o json and -o yaml.
func renderOverviewStructured(w io.Writer, format string, v email.OverviewView) error {
	r, err := output.For(format)
	if err != nil {
		return err
	}
	return r.Render(w, v)
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/ -run 'TestRenderOverview(JSON|YAML)' -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(cmd): added overview JSON and YAML rendering"
```

---

## Task 9: Email templates + renderer (admin variant)

**Files:**
- Create: `internal/email/templates/overview.html.tmpl`
- Create: `internal/email/templates/overview.txt.tmpl`
- Create: `internal/email/overview.go`
- Create: `internal/email/overview_test.go`
- Create: `internal/email/testdata/overview-admin.eml`

This task gets the admin variant rendering end-to-end. Per-user (`Me != nil`) lands in Task 10.

- [ ] **Step 1: Create the HTML template**

Write `internal/email/templates/overview.html.tmpl`:

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security overview</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#0f172a;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:20px 0;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;width:600px;max-width:600px;">

{{template "header" .}}
{{- template "message" .}}

<tr><td style="padding:0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="1" bgcolor="#e2e8f0" style="border-collapse:separate;border-spacing:1px;background:#e2e8f0;width:100%;">
<tr>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.Totals.UserCount}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">Users</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">&nbsp;</div>
  </td>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.Totals.DeviceCount}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">Devices</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">{{.AveragesView.Devices}} / user</div>
  </td>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.Totals.TotalIssues}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">Issues</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">{{.AveragesView.Issues}} / user</div>
  </td>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.TotalsView.SecScore}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">Sec score</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">{{.AveragesView.SecScore}} / user</div>
  </td>
</tr>
<tr>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#dc2626;">{{.Totals.Critical}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">Critical</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">{{.AveragesView.Critical}} / user</div>
  </td>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#ea580c;">{{.Totals.High}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">High</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">{{.AveragesView.High}} / user</div>
  </td>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#ca8a04;">{{.Totals.Medium}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">Medium</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">{{.AveragesView.Medium}} / user</div>
  </td>
  <td bgcolor="#ffffff" style="background:#ffffff;padding:14px 12px;width:25%;">
    <div style="font:800 26px/1 -apple-system,system-ui,sans-serif;color:#0369a1;">{{.Totals.Low}}</div>
    <div style="font:600 10px/1.2 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;">Low</div>
    <div style="font:11px/1 -apple-system,system-ui,sans-serif;color:#94a3b8;margin-top:4px;">{{.AveragesView.Low}} / user</div>
  </td>
</tr>
</table>
</td></tr>

{{define "leader_row"}}
<tr><td style="padding:12px 16px;border-bottom:1px solid #f1f5f9;border-left:3px solid {{.BorderColour}};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
  <td valign="middle" style="width:28px;font:700 16px/1 -apple-system,system-ui,sans-serif;color:{{.BorderColour}};">{{.Position}}</td>
  <td valign="middle" style="font:600 14px/1.2 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.Name}}</td>
  <td valign="middle" align="right" style="white-space:nowrap;">
    <span style="display:inline-block;background:#fef2f2;color:#dc2626;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">C {{.Critical}}</span>
    <span style="display:inline-block;background:#fff7ed;color:#ea580c;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">H {{.High}}</span>
    <span style="display:inline-block;background:#fefce8;color:#ca8a04;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">M {{.Medium}}</span>
    <span style="display:inline-block;background:#f0f9ff;color:#0369a1;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">L {{.Low}}</span>
    <span style="display:inline-block;font:700 14px/1 'SF Mono','Menlo','Consolas',monospace;color:{{.BorderColour}};margin-left:10px;">{{.ScoreStr}}</span>
  </td>
</tr></table>
</td></tr>
{{end}}

<tr><td style="padding:14px 16px 10px;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;font:700 11px/1 -apple-system,system-ui,sans-serif;color:#0f172a;letter-spacing:.1em;text-transform:uppercase;">
  <span style="display:inline-block;width:8px;height:8px;background:#16a34a;border-radius:2px;vertical-align:middle;margin-right:6px;"></span>The best 5
</td></tr>
<tr><td style="padding:0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
{{range $i, $row := .BestRows}}{{template "leader_row" $row}}{{end}}
</table></td></tr>

<tr><td style="padding:14px 16px 10px;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;font:700 11px/1 -apple-system,system-ui,sans-serif;color:#0f172a;letter-spacing:.1em;text-transform:uppercase;">
  <span style="display:inline-block;width:8px;height:8px;background:#dc2626;border-radius:2px;vertical-align:middle;margin-right:6px;"></span>The most dangerous 5
</td></tr>
<tr><td style="padding:0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
{{range $i, $row := .DangerousRows}}{{template "leader_row" $row}}{{end}}
</table></td></tr>

{{if .MeRow}}
<tr><td style="padding:14px 16px 10px;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;font:700 11px/1 -apple-system,system-ui,sans-serif;color:#0f172a;letter-spacing:.1em;text-transform:uppercase;">
  <span style="display:inline-block;width:8px;height:8px;background:#2563eb;border-radius:2px;vertical-align:middle;margin-right:6px;"></span>Your standing
</td></tr>
<tr><td style="padding:14px 16px;background:#eff6ff;border-left:3px solid #2563eb;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
  <td valign="middle" style="width:64px;">
    <div style="font:800 28px/1 -apple-system,system-ui,sans-serif;color:#2563eb;">{{.MeRow.RankStr}}</div>
    <div style="font:600 9px/1 -apple-system,system-ui,sans-serif;color:#64748b;letter-spacing:.08em;text-transform:uppercase;margin-top:4px;">of {{.Totals.UserCount}}</div>
  </td>
  <td valign="middle" style="padding-left:8px;">
    <div style="font:600 14px/1.2 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.MeRow.Name}}</div>
    <div style="font:11px/1.4 -apple-system,system-ui,sans-serif;color:#64748b;margin-top:2px;">{{.MeRow.DeviceCount}} devices · {{.MeRow.TotalIssues}} issues</div>
  </td>
  <td valign="middle" align="right" style="white-space:nowrap;">
    <span style="display:inline-block;background:#fef2f2;color:#dc2626;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">C {{.MeRow.Critical}}</span>
    <span style="display:inline-block;background:#fff7ed;color:#ea580c;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">H {{.MeRow.High}}</span>
    <span style="display:inline-block;background:#fefce8;color:#ca8a04;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">M {{.MeRow.Medium}}</span>
    <span style="display:inline-block;background:#f0f9ff;color:#0369a1;font:700 9px/1 -apple-system,system-ui,sans-serif;padding:3px 5px;border-radius:3px;margin-left:3px;">L {{.MeRow.Low}}</span>
    <span style="display:inline-block;font:700 16px/1 'SF Mono','Menlo','Consolas',monospace;color:#2563eb;margin-left:10px;">{{.MeRow.ScoreStr}}</span>
  </td>
</tr></table>
</td></tr>
{{end}}

<tr><td style="padding:14px 16px 10px;border-top:1px solid #e2e8f0;border-bottom:1px solid #e2e8f0;font:700 11px/1 -apple-system,system-ui,sans-serif;color:#0f172a;letter-spacing:.1em;text-transform:uppercase;">
  <span style="display:inline-block;width:8px;height:8px;background:#64748b;border-radius:2px;vertical-align:middle;margin-right:6px;"></span>All users <span style="font-weight:400;color:#94a3b8;">({{.Totals.UserCount}})</span>
</td></tr>
<tr><td style="padding:0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
{{range $i, $row := .RosterRows}}{{template "leader_row" $row}}{{end}}
</table></td></tr>

<tr><td bgcolor="#f8fafc" style="background:#f8fafc;padding:14px 24px 18px;font:11px/1.5 -apple-system,system-ui,sans-serif;color:#64748b;border-top:1px solid #e2e8f0;">
Generated by jellyfish overview. sec_score = sum of CVSS across all active issues on each user's devices.
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>
```

Note: the "Your standing" block uses the same `MeRow` data the YOU-row highlight will also use; the YOU-row in the roster is handled in Task 10 (this task renders the admin variant where `MeRow` is nil and the block is skipped).

- [ ] **Step 2: Create the text template**

Write `internal/email/templates/overview.txt.tmpl`:

```text
{{if .Message -}}
{{.Message}}

---

{{end -}}
Security overview{{if .Tenant}} - {{.Tenant}}{{end}} - {{.GeneratedAtStr}}

TOTALS
  users:     {{.Totals.UserCount}}
  devices:   {{.Totals.DeviceCount}} ({{.AveragesView.Devices}}/user)
  issues:    {{.Totals.TotalIssues}} ({{.AveragesView.Issues}}/user)
  sec_score: {{.TotalsView.SecScore}} ({{.AveragesView.SecScore}}/user)
  critical:  {{.Totals.Critical}} ({{.AveragesView.Critical}}/user)
  high:      {{.Totals.High}} ({{.AveragesView.High}}/user)
  medium:    {{.Totals.Medium}} ({{.AveragesView.Medium}}/user)
  low:       {{.Totals.Low}} ({{.AveragesView.Low}}/user)

THE BEST 5
{{range .BestRows -}}
  {{printf "%2s. %-30s %8s   C=%d H=%d M=%d L=%d" .Position .Name .ScoreStr .Critical .High .Medium .Low}}
{{end}}
THE MOST DANGEROUS 5
{{range .DangerousRows -}}
  {{printf "%2s. %-30s %8s   C=%d H=%d M=%d L=%d" .Position .Name .ScoreStr .Critical .High .Medium .Low}}
{{end}}
{{if .MeRow -}}
YOUR STANDING
  {{.MeRow.RankStr}} of {{.Totals.UserCount}} - {{.MeRow.Name}} - {{.MeRow.ScoreStr}} sec_score
  ({{.MeRow.DeviceCount}} devices, {{.MeRow.TotalIssues}} issues; C={{.MeRow.Critical}} H={{.MeRow.High}} M={{.MeRow.Medium}} L={{.MeRow.Low}})

{{end -}}
ALL USERS ({{.Totals.UserCount}})
{{range .RosterRows -}}
  {{printf "%3s. %-30s %8s   C=%d H=%d M=%d L=%d" .Position .Name .ScoreStr .Critical .High .Medium .Low}}
{{end -}}
```

- [ ] **Step 3: Create the renderer**

Write `internal/email/overview.go`:

```go
package email

import (
	"embed"
	"fmt"
	htmltmpl "html/template"
	"io"
	"os"
	"strconv"
	"strings"
	texttmpl "text/template"

	"github.com/bawdo/jellyfish/internal/output"
)

//go:embed templates/overview.html.tmpl templates/overview.txt.tmpl templates/_header.html.tmpl templates/_message.html.tmpl
var overviewFS embed.FS

// overviewRowView is one row in either of the leaderboard sections, the
// "Your standing" callout, or the full roster. Pre-formatted strings let
// the template stay logic-free.
type overviewRowView struct {
	Position     string // "1".."5" for leaderboards, global Rank for the roster, ordinal ("14th") for Me
	Rank         int
	RankStr      string // ordinal form for the Me callout ("14th")
	Name         string
	BorderColour string
	ScoreStr     string
	DeviceCount  int
	TotalIssues  int
	Critical     int
	High         int
	Medium       int
	Low          int
	IsMe         bool // true on the recipient's row in the full roster (per-user variant)
}

type overviewTplData struct {
	Header         Header
	Tenant         string
	GeneratedAtStr string
	GeneratedDate  string
	Totals         OverviewTotals
	TotalsView     struct {
		SecScore string
	}
	AveragesView struct {
		Devices, Issues, SecScore     string
		Critical, High, Medium, Low   string
	}
	BestRows      []overviewRowView
	DangerousRows []overviewRowView
	RosterRows    []overviewRowView
	MeRow         *overviewRowView
	Message       string
	MessageHTML   htmltmpl.HTML
}

func buildOverviewTplData(v OverviewView, opts Options) overviewTplData {
	d := overviewTplData{
		Tenant:         opts.Tenant,
		GeneratedAtStr: opts.GeneratedAt.Format("2 Jan 2006 - 15:04 MST"),
		GeneratedDate:  opts.GeneratedAt.Format("2006-01-02"),
		Totals:         v.Totals,
	}
	d.TotalsView.SecScore = formatOneDec(v.Totals.SecScore)
	d.AveragesView.Devices = formatOneDec(v.Averages.DevicesPerUser)
	d.AveragesView.Issues = formatOneDec(v.Averages.IssuesPerUser)
	d.AveragesView.SecScore = formatOneDec(v.Averages.SecScorePerUser)
	d.AveragesView.Critical = formatOneDec(v.Averages.CriticalPerUser)
	d.AveragesView.High = formatOneDec(v.Averages.HighPerUser)
	d.AveragesView.Medium = formatOneDec(v.Averages.MediumPerUser)
	d.AveragesView.Low = formatOneDec(v.Averages.LowPerUser)

	d.BestRows = leaderboardRows(v.BestFive, "#16a34a")
	d.DangerousRows = leaderboardRows(v.MostDangerousFive, "#dc2626")
	d.RosterRows = rosterRows(v.Users, v.Me)

	if v.Me != nil {
		me := *v.Me
		row := overviewRowView{
			Position:     strconv.Itoa(me.Rank),
			Rank:         me.Rank,
			RankStr:      ordinal(me.Rank),
			Name:         me.Name,
			BorderColour: "#2563eb",
			ScoreStr:     formatOneDec(me.SecScore),
			DeviceCount:  me.DeviceCount,
			TotalIssues:  me.TotalIssues,
			Critical:     me.Critical,
			High:         me.High,
			Medium:       me.Medium,
			Low:          me.Low,
		}
		d.MeRow = &row
	}

	d.Message = opts.Message
	if opts.Message != "" {
		d.MessageHTML = paragraphsHTML(opts.Message)
	}
	return d
}

func leaderboardRows(stats []UserStats, colour string) []overviewRowView {
	out := make([]overviewRowView, len(stats))
	for i, s := range stats {
		out[i] = overviewRowView{
			Position:     strconv.Itoa(i + 1),
			Rank:         s.Rank,
			Name:         s.Name,
			BorderColour: colour,
			ScoreStr:     formatOneDec(s.SecScore),
			Critical:     s.Critical,
			High:         s.High,
			Medium:       s.Medium,
			Low:          s.Low,
		}
	}
	return out
}

func rosterRows(stats []UserStats, me *UserStats) []overviewRowView {
	out := make([]overviewRowView, len(stats))
	for i, s := range stats {
		colour := tierColour(s.SecScore)
		isMe := me != nil && s.UserID == me.UserID
		if isMe {
			colour = "#2563eb"
		}
		out[i] = overviewRowView{
			Position:     strconv.Itoa(s.Rank),
			Rank:         s.Rank,
			Name:         s.Name,
			BorderColour: colour,
			ScoreStr:     formatOneDec(s.SecScore),
			Critical:     s.Critical,
			High:         s.High,
			Medium:       s.Medium,
			Low:          s.Low,
			IsMe:         isMe,
		}
	}
	return out
}

// tierColour maps a SecScore to the border colour used by the roster row
// card. Matches the secScoreTier thresholds in cmd/overview.go.
func tierColour(score float64) string {
	switch {
	case score >= 100:
		return "#dc2626"
	case score >= 30:
		return "#ea580c"
	case score >= 5:
		return "#ca8a04"
	default:
		return "#16a34a"
	}
}

func formatOneDec(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

func ordinal(n int) string {
	suffix := "th"
	switch n % 100 {
	case 11, 12, 13:
		// keep "th"
	default:
		switch n % 10 {
		case 1:
			suffix = "st"
		case 2:
			suffix = "nd"
		case 3:
			suffix = "rd"
		}
	}
	return strconv.Itoa(n) + suffix
}

type overviewRenderer struct {
	opts Options
	warn io.Writer
}

// NewOverviewRenderer returns an output.Renderer whose Render(w, v) expects
// v to be an OverviewInput and writes a complete .eml message to w.
func NewOverviewRenderer(opts Options) output.Renderer {
	return &overviewRenderer{opts: opts.withDefaults()}
}

// NewOverviewRendererWithStderr is like NewOverviewRenderer but routes
// renderer-level warnings (e.g. logo load failures) to the supplied writer
// instead of os.Stderr.
func NewOverviewRendererWithStderr(opts Options, stderr io.Writer) output.Renderer {
	return &overviewRenderer{opts: opts.withDefaults(), warn: stderr}
}

func renderOverviewHTML(data overviewTplData) (string, error) {
	tmpl, err := htmltmpl.New("overview.html.tmpl").Funcs(htmltmpl.FuncMap{
		"safeCSS": safeCSS,
	}).ParseFS(overviewFS,
		"templates/_header.html.tmpl",
		"templates/_message.html.tmpl",
		"templates/overview.html.tmpl",
	)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func renderOverviewText(data overviewTplData) (string, error) {
	tmpl, err := texttmpl.New("overview.txt.tmpl").ParseFS(overviewFS, "templates/overview.txt.tmpl")
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func (r *overviewRenderer) Render(w io.Writer, v any) error {
	in, ok := v.(OverviewInput)
	if !ok {
		return fmt.Errorf("email overview renderer expected OverviewInput, got %T", v)
	}
	if r.opts.From == "" {
		return fmt.Errorf("email renderer requires a non-empty From address")
	}

	data := buildOverviewTplData(in.View, r.opts)

	warn := r.warn
	if warn == nil {
		warn = os.Stderr
	}
	logo, logoErr := loadLogo(r.opts.LogoPath)
	if logoErr != nil {
		_, _ = fmt.Fprintf(warn, "warn: email logo not loaded (%v); rendering without logo\n", logoErr)
	}

	subtitle := data.GeneratedAtStr
	if data.Tenant != "" {
		subtitle += " - " + data.Tenant
	}
	subtitle += fmt.Sprintf(" - %d users, %d devices, %d issues",
		in.View.Totals.UserCount, in.View.Totals.DeviceCount, in.View.Totals.TotalIssues)
	data.Header = buildHeader(
		"JELLYFISH / OVERVIEW",
		"Security overview",
		subtitle,
		r.opts.HeaderBG,
		logo != nil,
	)

	subject := r.opts.Subject
	if subject == "" {
		subject = "Jellyfish security overview - " + data.GeneratedDate
	}

	htmlBody, err := renderOverviewHTML(data)
	if err != nil {
		return err
	}
	textBody, err := renderOverviewText(data)
	if err != nil {
		return err
	}

	boundary := r.opts.BoundaryOverride
	if boundary == "" {
		boundary, err = randomBoundary()
		if err != nil {
			return err
		}
	}
	messageID := r.opts.MessageIDOverride
	if messageID == "" {
		messageID, err = randomMessageID(domainFromAddress(r.opts.From))
		if err != nil {
			return err
		}
	}
	outerBoundary := r.opts.RelatedBoundaryOverride
	if outerBoundary == "" && logo != nil {
		outerBoundary, err = randomRelatedBoundary()
		if err != nil {
			return err
		}
	}

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
	if err != nil {
		return err
	}
	_, err = w.Write(bytesOut)
	return err
}
```

- [ ] **Step 4: Verify the package compiles**

Run: `go build ./internal/email/...`

Expected: PASS. (If a template fails to embed at runtime, the test in step 6 will catch it.)

- [ ] **Step 5: Write the admin-variant golden test**

Create `internal/email/overview_test.go`:

```go
package email

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func newOverviewInputAdmin() OverviewInput {
	return OverviewInput{View: OverviewView{
		Tenant:      "acme",
		GeneratedAt: time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		Totals: OverviewTotals{
			UserCount: 2, DeviceCount: 3, TotalIssues: 4, Critical: 1, High: 1, Medium: 1, Low: 1, SecScore: 24.8,
		},
		Averages: OverviewAverages{
			DevicesPerUser: 1.5, IssuesPerUser: 2.0, SecScorePerUser: 12.4,
			CriticalPerUser: 0.5, HighPerUser: 0.5, MediumPerUser: 0.5, LowPerUser: 0.5,
		},
		BestFive: []UserStats{
			{UserID: "u-bob", Rank: 2, Name: "Bob", SecScore: 2.5, Critical: 0, High: 0, Medium: 0, Low: 1},
			{UserID: "u-alice", Rank: 1, Name: "Alice", SecScore: 22.3, Critical: 1, High: 1, Medium: 1, Low: 0},
		},
		MostDangerousFive: []UserStats{
			{UserID: "u-alice", Rank: 1, Name: "Alice", SecScore: 22.3, Critical: 1, High: 1, Medium: 1, Low: 0},
			{UserID: "u-bob", Rank: 2, Name: "Bob", SecScore: 2.5, Critical: 0, High: 0, Medium: 0, Low: 1},
		},
		Users: []UserStats{
			{UserID: "u-alice", Rank: 1, Name: "Alice", SecScore: 22.3, Critical: 1, High: 1, Medium: 1, Low: 0, DeviceCount: 2, TotalIssues: 3},
			{UserID: "u-bob", Rank: 2, Name: "Bob", SecScore: 2.5, Critical: 0, High: 0, Medium: 0, Low: 1, DeviceCount: 1, TotalIssues: 1},
		},
	}}
}

func newOverviewOptions() Options {
	return Options{
		To:                      "ops@example.com",
		From:                    "noreply@example.com",
		Subject:                 "Test overview",
		GeneratedAt:             time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		Tenant:                  "acme",
		Report:                  "overview",
		BoundaryOverride:        "boundary-fixed",
		MessageIDOverride:       "<fixed@example.com>",
		RelatedBoundaryOverride: "related-fixed",
	}
}

func TestOverviewRendererAdminGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := NewOverviewRenderer(newOverviewOptions()).Render(&buf, newOverviewInputAdmin()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()

	// Spot checks that the admin variant is right.
	for _, want := range []string{
		"From: noreply@example.com",
		"To: ops@example.com",
		"Subject: Test overview",
		"X-Jellyfish-Report: overview",
		"X-Jellyfish-Tenant: acme",
		"Security overview",       // title in header partial
		"The best 5",              // section label
		"The most dangerous 5",
		"All users",
		"Alice", "Bob",
		"22.3", "2.5",             // formatted SecScore values
		"Sec score",               // stat-card label (HTML body)
		"C 1", "H 1", "M 1", "L 1", // severity pills
		"Generated by jellyfish overview",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("admin .eml missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"Your standing", // admin must NOT have the per-user callout
	} {
		if strings.Contains(got, unwanted) {
			t.Errorf("admin .eml should not contain %q", unwanted)
		}
	}
}
```

This is intentionally a "spot-check" golden, not a byte-for-byte fixture file. Byte-exact goldens are brittle for HTML emails (whitespace, attribute ordering). Spot-checks are exactly what the existing `email_test.go` tests do for vulns summary and user show.

- [ ] **Step 6: Run the test**

Run: `go test ./internal/email/ -run TestOverviewRenderer -v`

Expected: PASS. If the template fails to execute, the error will point at the offending line.

- [ ] **Step 7: Commit**

```bash
git add internal/email/overview.go internal/email/overview_test.go internal/email/templates/overview.html.tmpl internal/email/templates/overview.txt.tmpl
git commit -m "feat(email): added overview renderer with admin variant"
```

---

## Task 10: Per-user variant (`Me != nil`)

**Files:**
- Modify: `internal/email/overview_test.go`
- (The template + renderer already handle `Me`; the test confirms the YOU row + callout render)

The HTML template already has the `{{if .MeRow}}` block and `rosterRows` already tints the recipient's row blue. This task adds an explicit golden test for the per-user variant.

- [ ] **Step 1: Add the YOU pill to the template**

The roster row template `leader_row` doesn't yet render a YOU pill. Edit `internal/email/templates/overview.html.tmpl` and replace the `Name` cell inside the `leader_row` definition:

```
  <td valign="middle" style="font:600 14px/1.2 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.Name}}</td>
```

with:

```
  <td valign="middle" style="font:600 14px/1.2 -apple-system,system-ui,sans-serif;color:#0f172a;">{{.Name}}{{if .IsMe}} <span style="display:inline-block;font:700 8px/1 -apple-system,system-ui,sans-serif;color:#2563eb;background:#dbeafe;padding:2px 4px;border-radius:2px;letter-spacing:.08em;text-transform:uppercase;margin-left:4px;">you</span>{{end}}</td>
```

Also tint the recipient's row background blue when `IsMe`. Edit the `leader_row` opening row:

```
<tr><td style="padding:12px 16px;border-bottom:1px solid #f1f5f9;border-left:3px solid {{.BorderColour}};">
```

to:

```
<tr><td style="padding:12px 16px;border-bottom:1px solid #f1f5f9;border-left:3px solid {{.BorderColour}};{{if .IsMe}}background:#eff6ff;{{end}}">
```

- [ ] **Step 2: Add the per-user golden test**

Append to `internal/email/overview_test.go`:

```go
func TestOverviewRendererPerUserGolden(t *testing.T) {
	in := newOverviewInputAdmin()
	// Mark Alice as the recipient.
	in.View.Me = &in.View.Users[0]

	var buf bytes.Buffer
	if err := NewOverviewRenderer(newOverviewOptions()).Render(&buf, in); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()

	for _, want := range []string{
		"Your standing",     // callout label
		"1st",               // ordinal rank
		"of 2",              // "of N"
		"<span style=\"display:inline-block;font:700 8px/1 -apple-system,system-ui,sans-serif;color:#2563eb;background:#dbeafe;",
		"background:#eff6ff;", // YOU-row tint
		"#2563eb",            // blue border on the YOU row
	} {
		if !strings.Contains(got, want) {
			t.Errorf("per-user .eml missing %q", want)
		}
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `go test ./internal/email/ -run TestOverviewRenderer -v`

Expected: PASS (both admin and per-user subtests).

- [ ] **Step 4: Run the full email package**

Run: `go test ./internal/email/...`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/email/templates/overview.html.tmpl internal/email/overview_test.go
git commit -m "feat(email): added per-user YOU row and standing callout"
```

---

## Task 11: Cobra command wiring + register

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/root.go`
- Modify: `cmd/overview_test.go`

Add `newOverviewCmd`, register it on root, and verify the help text.

- [ ] **Step 1: Write the failing test**

Append to `cmd/overview_test.go`:

```go
func TestOverviewCmdRegistered(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"overview", "--help"})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr=%q", err, errBuf.String())
	}
	help := out.String()
	if !strings.Contains(help, "overview") {
		t.Fatalf("help missing command name; got:\n%s", help)
	}
	for _, flag := range []string{
		"--per-user", "--email-to", "--email-from", "--email-subject",
		"--email-header-bg", "--email-logo",
		"--message", "--message-file",
		"--dry-run", "--yes", "--no-cache",
	} {
		if !strings.Contains(help, flag) {
			t.Errorf("help missing flag %s; got:\n%s", flag, help)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/ -run TestOverviewCmdRegistered -v`

Expected: FAIL — either `unknown command "overview"` or the subcommand isn't registered.

- [ ] **Step 3: Extend the import block**

Replace the existing import group at the top of `cmd/overview.go` with:

```go
import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/keychain"
	"github.com/bawdo/jellyfish/internal/output"
)
```

- [ ] **Step 4: Add the command and opts struct**

Append to `cmd/overview.go`:

```go
type overviewOpts struct {
	Output        string
	PerUser       bool
	EmailFlags    emailFlagValues
	DryRun        bool
	Yes           bool
	NoCache       bool
	Profile       config.Profile
	EmailNow      time.Time
	// Injected for tests:
	gitEmail      gitEmailLookup
	KeychainGet   func() ([]byte, error)
	NewSender     gmailNewSender
	ConfirmReader io.Reader
}

// newOverviewCmd wires the `jellyfish overview` cobra command.
func newOverviewCmd() *cobra.Command {
	var opts overviewOpts
	c := &cobra.Command{
		Use:   "overview",
		Short: "Org-wide security overview (per-user sec_score rollup)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			outFmt, _ := cmd.Flags().GetString("output")
			opts.Output = outFmt
			opts.EmailFlags = readEmailFlags(cmd)
			opts.EmailNow = time.Now()
			client, err := buildClient(cmd)
			if err != nil {
				return err
			}
			if outFmt == "email" {
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
			return runOverview(cmd.Context(), client, cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}
	c.Flags().BoolVar(&opts.PerUser, "per-user", false, "With --output=email: send one personalised copy per user with devices")
	c.Flags().String("email-to", "", "Email recipient(s) for the admin report (comma-separated). Ignored with --per-user.")
	c.Flags().String("email-from", "", "Email From: header (default: email.from from config, then git user.email)")
	c.Flags().String("email-subject", "", "Email Subject: header (default: rendered email.subject_template or a per-command default)")
	c.Flags().String("email-header-bg", "", "Email header background colour as #RRGGBB (default: email.header_bg or #2b3a55)")
	c.Flags().String("email-logo", "", "Path to a PNG to show in the email header (default: email.logo_path)")
	c.Flags().Bool("message", false, "Open $VISUAL/$EDITOR to compose a message rendered above the email body (shared across all recipients)")
	c.Flags().String("message-file", "", "Read the email message body from a file (use - for stdin)")
	c.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Render the email but do not send")
	c.Flags().BoolVar(&opts.Yes, "yes", false, "Skip the confirmation prompt")
	c.Flags().BoolVar(&opts.NoCache, "no-cache", false, "Skip the detection cache; always fetch fresh")
	return c
}

// runOverview is the orchestration entry point. Steps in order:
//  1. validate flag combinations
//  2. assemble the OverviewView (single detection walk + per-user devices)
//  3. dispatch on --output to a renderer or send path
func runOverview(ctx context.Context, client iruClient, stdout, stderr io.Writer, opts overviewOpts) error {
	if err := validateOverviewFlags(opts); err != nil {
		return err
	}
	view, err := assembleOverview(ctx, client, stderr, opts.NoCache)
	if err != nil {
		return err
	}
	switch opts.Output {
	case "", "table":
		return renderOverviewTable(stdout, view)
	case "json", "yaml":
		return renderOverviewStructured(stdout, opts.Output, view)
	case "csv":
		return renderOverviewCSV(stdout, view)
	case "email":
		return runOverviewEmail(ctx, stdout, stderr, opts, view)
	default:
		return fmt.Errorf("unsupported output format %q", opts.Output)
	}
}

// validateOverviewFlags catches bad flag combinations before any network
// work. Mirrors the spec's Validation (exit 1) section.
func validateOverviewFlags(opts overviewOpts) error {
	if err := validateMessageFlags(opts.EmailFlags, opts.Output == "email"); err != nil {
		return err
	}
	if opts.PerUser && opts.Output != "email" {
		return errors.New("--per-user requires --output=email")
	}
	if opts.Output == "email" && !opts.PerUser && opts.EmailFlags.To == "" {
		return errors.New("--output=email without --per-user requires --email-to")
	}
	return nil
}

// runOverviewEmail is the placeholder send dispatcher; Task 12 and 13 fill in
// the admin and per-user paths.
func runOverviewEmail(ctx context.Context, stdout, stderr io.Writer, opts overviewOpts, view email.OverviewView) error {
	return errors.New("overview email send not yet implemented")
}
```

- [ ] **Step 5: Register the command**

Edit `cmd/root.go`. Add inside `newRootCmd` after `root.AddCommand(newUsersCmd())`:

```go
	root.AddCommand(newOverviewCmd())
```

- [ ] **Step 6: Run the registration test**

Run: `go test ./cmd/ -run TestOverviewCmdRegistered -v`

Expected: PASS.

- [ ] **Step 7: Run the full cmd suite**

Run: `go test ./cmd/... -count=1`

Expected: PASS (the email send path is stubbed but no test triggers it yet).

- [ ] **Step 8: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go cmd/root.go
git commit -m "feat(cmd): registered jellyfish overview command"
```

---

## Task 12: Admin email send path

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/overview_test.go`

Send one .eml per address in `--email-to` (comma-list). Mirror the confirm-prompt → loop → summary pattern from `users send-email`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/overview_test.go`:

```go
func TestRunOverviewAdminSend(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d1", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	fake := &fakeGmailSender{returnID: "msg-1"}
	opts := overviewOpts{
		Output:        "email",
		Yes:           true,
		EmailFlags:    emailFlagValues{To: "ops@example.com", From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		KeychainGet:   stubKeychain("{}"),
		NewSender:     newFakeSenderFactory(fake),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	if !strings.Contains(stderr.String(), "sent to=ops@example.com gmail-id=msg-1") {
		t.Errorf("stderr missing sent line:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "summary: sent=1 errors=0") {
		t.Errorf("stderr missing summary:\n%s", stderr.String())
	}
	if len(fake.sent) == 0 {
		t.Fatal("sender was not called")
	}
}

func TestRunOverviewAdminDryRun(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: []iru.Detection{{DeviceID: "d1", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5}},
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	opts := overviewOpts{
		Output:        "email",
		DryRun:        true,
		EmailFlags:    emailFlagValues{To: "ops@example.com,security@example.com", From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: false}}, // intentional: dry-run bypasses gmail check
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	for _, want := range []string{
		"DRY RUN", "would-send to=ops@example.com", "would-send to=security@example.com",
		"summary: would-send=2 errors=0",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr.String())
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/ -run 'TestRunOverviewAdmin' -v`

Expected: FAIL with "overview email send not yet implemented" (the stub from Task 11).

- [ ] **Step 3: Implement the admin send path**

In `cmd/overview.go`, replace the stubbed `runOverviewEmail` with the real implementation:

```go
// runOverviewEmail builds the email Options, captures the optional message,
// and dispatches to the admin or per-user path. Per-user is Task 13.
func runOverviewEmail(ctx context.Context, stdout, stderr io.Writer, opts overviewOpts, view email.OverviewView) error {
	now := opts.EmailNow
	if now.IsZero() {
		now = time.Now()
	}
	gitLookup := opts.gitEmail
	if gitLookup == nil {
		gitLookup = gitUserEmail
	}

	// Bulk-style: don't honour email.default_to.
	profForOpts := opts.Profile
	profForOpts.Email.DefaultTo = ""

	baseEmailOpts, err := resolveEmailOptions(opts.EmailFlags, profForOpts, gitLookup, now)
	if err != nil {
		return err
	}
	baseEmailOpts.Report = "overview"
	baseEmailOpts.Tenant = opts.Profile.Subdomain
	view.Tenant = opts.Profile.Subdomain
	if view.GeneratedAt.IsZero() {
		view.GeneratedAt = now
	}

	if opts.PerUser {
		return runOverviewPerUser(ctx, stdout, stderr, opts, view, baseEmailOpts, now)
	}
	return runOverviewAdmin(ctx, stdout, stderr, opts, view, baseEmailOpts, now)
}

func runOverviewAdmin(ctx context.Context, stdout, stderr io.Writer, opts overviewOpts, view email.OverviewView, baseOpts email.Options, now time.Time) error {
	recipients, err := splitEmails(baseOpts.To)
	if err != nil {
		return err
	}

	confirmIn := opts.ConfirmReader
	if confirmIn == nil {
		confirmIn = os.Stdin
	}
	ok, err := confirmSendOverview(stderr, confirmIn, len(recipients), false, opts.DryRun, opts.Yes)
	if err != nil {
		return err
	}
	if !ok {
		_, _ = fmt.Fprintln(stderr, "aborted: no mail sent")
		return nil
	}

	display := fmt.Sprintf("%d recipients", len(recipients))
	message, err := captureMessage(opts.EmailFlags, true, display, baseOpts.Subject, os.Stdin, stderr, nil)
	if err != nil {
		return err
	}
	baseOpts.Message = message

	var sender gmail.Sender
	if !opts.DryRun {
		s, err := buildOverviewSender(ctx, opts, baseOpts.From)
		if err != nil {
			return err
		}
		sender = s
	}

	var counters bulkCounters
	for _, to := range recipients {
		userOpts := baseOpts
		userOpts.To = to
		if opts.DryRun {
			_, _ = fmt.Fprintf(stderr, "would-send to=%s bytes=approx\n", to)
			counters.wouldSend++
			continue
		}
		var buf bytes.Buffer
		if err := email.NewOverviewRendererWithStderr(userOpts, stderr).Render(&buf, email.OverviewInput{View: view}); err != nil {
			_, _ = fmt.Fprintf(stderr, "error to=%s render: %v\n", to, err)
			counters.recordError(err)
			continue
		}
		id, serr := sender.Send(ctx, buf.Bytes())
		if serr != nil {
			_, _ = fmt.Fprintf(stderr, "error to=%s gmail: %v\n", to, serr)
			counters.recordError(serr)
			continue
		}
		_, _ = fmt.Fprintf(stderr, "sent to=%s gmail-id=%s\n", to, id)
		counters.sent++
	}

	if opts.DryRun {
		_, _ = fmt.Fprintf(stderr, "summary: would-send=%d errors=%d\n", counters.wouldSend, counters.errs)
	} else {
		_, _ = fmt.Fprintf(stderr, "summary: sent=%d errors=%d\n", counters.sent, counters.errs)
	}
	return counters.exitError()
}

// buildOverviewSender constructs a Gmail sender. Centralised so admin and
// per-user paths share the keychain + factory plumbing.
func buildOverviewSender(ctx context.Context, opts overviewOpts, from string) (gmail.Sender, error) {
	if !opts.Profile.Email.GmailConfigured {
		return nil, errors.New(`sending email requires Gmail credentials. Run "jellyfish configure email" to install a service-account JSON, or pass --dry-run to preview without sending`)
	}
	kchGet := opts.KeychainGet
	if kchGet == nil {
		return nil, errors.New("internal: KeychainGet not wired")
	}
	newSender := opts.NewSender
	if newSender == nil {
		return nil, errors.New("internal: NewSender not wired")
	}
	saJSON, kerr := kchGet()
	if kerr != nil {
		return nil, fmt.Errorf(`read Gmail credentials from Keychain: %w. Run "jellyfish configure email" to reinstall`, kerr)
	}
	return newSender(ctx, saJSON, from)
}

// confirmSendOverview is the overview's confirm-prompt. perUser switches the
// prompt copy. Otherwise identical to confirmSend in users.go.
func confirmSendOverview(stderr io.Writer, in io.Reader, count int, perUser, dryRun, yes bool) (bool, error) {
	if dryRun {
		_, _ = fmt.Fprintln(stderr, "DRY RUN - no mail will be sent")
		return true, nil
	}
	if yes {
		return true, nil
	}
	noun := "recipient"
	if count != 1 {
		noun = "recipients"
	}
	verb := "send the overview"
	if perUser {
		verb = "send personalised overviews"
	}
	_, _ = fmt.Fprintf(stderr, "About to %s to %d %s. Continue? [y/N] ", verb, count, noun)
	br := bufio.NewReader(in)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func runOverviewPerUser(ctx context.Context, stdout, stderr io.Writer, opts overviewOpts, view email.OverviewView, baseOpts email.Options, now time.Time) error {
	return errors.New("overview --per-user not yet implemented")
}
```

Update the import block at the top of `cmd/overview.go` to include the new stdlib imports. The final block should be:

```go
import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bawdo/jellyfish/internal/config"
	"github.com/bawdo/jellyfish/internal/email"
	"github.com/bawdo/jellyfish/internal/gmail"
	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/keychain"
	"github.com/bawdo/jellyfish/internal/output"
)
```

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/ -run 'TestRunOverviewAdmin' -v`

Expected: PASS (both subtests).

- [ ] **Step 5: Run the cmd suite**

Run: `go test ./cmd/... -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(cmd): added overview admin email send path"
```

---

## Task 13: Per-user email send path

**Files:**
- Modify: `cmd/overview.go`
- Modify: `cmd/overview_test.go`

Loop over `view.Users`, skip empty-email users, render each with `Me = &user`, send to that user's email.

- [ ] **Step 1: Write the failing test**

Append to `cmd/overview_test.go`:

```go
func TestRunOverviewPerUser(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users: []iru.User{
				{ID: "u1", Name: "Alice", Email: "alice@x"},
				{ID: "u2", Name: "Bob", Email: "bob@x"},
				{ID: "u3", Name: "Eve", Email: ""}, // no email -> skipped
			},
			detections: []iru.Detection{
				{DeviceID: "d-a", CVEID: "CVE-1", Severity: "High", CVSSScore: 7.5},
			},
		},
		devicesByUser: map[string][]iru.Device{
			"u1": {{DeviceID: "d-a"}},
			"u2": {{DeviceID: "d-b"}},
			"u3": {{DeviceID: "d-c"}},
		},
	}
	fake := &fakeGmailSender{returnID: "msg-1"}
	opts := overviewOpts{
		Output:        "email",
		PerUser:       true,
		Yes:           true,
		EmailFlags:    emailFlagValues{From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: true}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		KeychainGet:   stubKeychain("{}"),
		NewSender:     newFakeSenderFactory(fake),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	out := stderr.String()
	for _, want := range []string{
		"sent user=u1 to=alice@x",
		"sent user=u2 to=bob@x",
		"skip user=u3 reason=no-email",
		"summary: sent=2 skipped=1 errors=0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
}

func TestRunOverviewPerUserDryRun(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient: &fakeClient{
			users:      []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}},
			detections: nil,
		},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d-a"}}},
	}
	opts := overviewOpts{
		Output:        "email",
		PerUser:       true,
		DryRun:        true,
		EmailFlags:    emailFlagValues{From: "noreply@example.com"},
		Profile:       config.Profile{Email: config.EmailConfig{GmailConfigured: false}},
		EmailNow:      time.Date(2026, 5, 17, 10, 30, 0, 0, time.UTC),
		gitEmail:      func() (string, error) { return "noreply@example.com", nil },
		ConfirmReader: strings.NewReader(""),
	}
	var stderr bytes.Buffer
	if err := runOverview(context.Background(), c, io.Discard, &stderr, opts); err != nil {
		t.Fatalf("runOverview: %v", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "would-send user=u1 to=alice@x") {
		t.Errorf("stderr missing would-send line:\n%s", out)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/ -run 'TestRunOverviewPerUser' -v`

Expected: FAIL — `overview --per-user not yet implemented`.

- [ ] **Step 3: Implement `runOverviewPerUser`**

Replace the stub `runOverviewPerUser` in `cmd/overview.go` with:

```go
func runOverviewPerUser(ctx context.Context, stdout, stderr io.Writer, opts overviewOpts, view email.OverviewView, baseOpts email.Options, now time.Time) error {
	if opts.EmailFlags.To != "" {
		_, _ = fmt.Fprintf(stderr, "warn: --email-to ignored with --per-user (recipients = each user's Iru email)\n")
	}

	confirmIn := opts.ConfirmReader
	if confirmIn == nil {
		confirmIn = os.Stdin
	}
	ok, err := confirmSendOverview(stderr, confirmIn, len(view.Users), true, opts.DryRun, opts.Yes)
	if err != nil {
		return err
	}
	if !ok {
		_, _ = fmt.Fprintln(stderr, "aborted: no mail sent")
		return nil
	}

	message, err := captureMessage(opts.EmailFlags, true, fmt.Sprintf("%d users", len(view.Users)), baseOpts.Subject, os.Stdin, stderr, nil)
	if err != nil {
		return err
	}
	baseOpts.Message = message

	var sender gmail.Sender
	if !opts.DryRun {
		s, err := buildOverviewSender(ctx, opts, baseOpts.From)
		if err != nil {
			return err
		}
		sender = s
	}

	var counters bulkCounters
	for i := range view.Users {
		u := view.Users[i]
		if u.Email == "" {
			_, _ = fmt.Fprintf(stderr, "skip user=%s reason=no-email\n", u.UserID)
			counters.skipped++
			continue
		}
		userOpts := baseOpts
		userOpts.To = u.Email
		// Per-user view: same shared body, just point Me at this user.
		perUserView := view
		perUserView.Me = &view.Users[i]

		if opts.DryRun {
			_, _ = fmt.Fprintf(stderr, "would-send user=%s to=%s bytes=approx\n", u.UserID, u.Email)
			counters.wouldSend++
			continue
		}
		var buf bytes.Buffer
		if err := email.NewOverviewRendererWithStderr(userOpts, stderr).Render(&buf, email.OverviewInput{View: perUserView}); err != nil {
			_, _ = fmt.Fprintf(stderr, "error user=%s render: %v\n", u.UserID, err)
			counters.recordError(err)
			continue
		}
		id, serr := sender.Send(ctx, buf.Bytes())
		if serr != nil {
			_, _ = fmt.Fprintf(stderr, "error user=%s gmail: %v\n", u.UserID, serr)
			counters.recordError(serr)
			continue
		}
		_, _ = fmt.Fprintf(stderr, "sent user=%s to=%s gmail-id=%s\n", u.UserID, u.Email, id)
		counters.sent++
	}

	if opts.DryRun {
		_, _ = fmt.Fprintf(stderr, "summary: would-send=%d skipped=%d errors=%d\n", counters.wouldSend, counters.skipped, counters.errs)
	} else {
		_, _ = fmt.Fprintf(stderr, "summary: sent=%d skipped=%d errors=%d\n", counters.sent, counters.skipped, counters.errs)
	}
	return counters.exitError()
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/ -run 'TestRunOverviewPerUser' -v`

Expected: PASS (both subtests).

- [ ] **Step 5: Run the whole suite**

Run: `go test ./... -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/overview.go cmd/overview_test.go
git commit -m "feat(cmd): added overview per-user email fanout"
```

---

## Task 14: Flag-validation coverage

**Files:**
- Modify: `cmd/overview_test.go`

Add targeted tests for the validation branches (`--per-user` without email, `--output=email` without `--email-to` or `--per-user`).

- [ ] **Step 1: Add the tests**

Append to `cmd/overview_test.go`:

```go
func TestRunOverviewValidationErrors(t *testing.T) {
	c := &overviewFakeClient{
		fakeClient:    &fakeClient{users: []iru.User{{ID: "u1", Name: "Alice", Email: "alice@x"}}},
		devicesByUser: map[string][]iru.Device{"u1": {{DeviceID: "d1"}}},
	}
	cases := []struct {
		name string
		opts overviewOpts
		want string
	}{
		{
			name: "per-user with table output",
			opts: overviewOpts{Output: "table", PerUser: true},
			want: "--per-user requires --output=email",
		},
		{
			name: "email without email-to or per-user",
			opts: overviewOpts{Output: "email"},
			want: "--email-to",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runOverview(context.Background(), c, io.Discard, io.Discard, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err: got %v, want substring %q", err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./cmd/ -run TestRunOverviewValidation -v`

Expected: PASS (both subtests).

- [ ] **Step 3: Commit**

```bash
git add cmd/overview_test.go
git commit -m "test(cmd): covered overview flag validation"
```

---

## Task 15: README documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Inspect the existing structure**

Run: `grep -n '^## \|^### ' README.md | head -40`

Identify a sensible spot — likely under the existing "Commands" or "Usage" heading, before or after the `users send-email` section. Read that section first so the new content matches the existing tone, code-block style, and flag-listing format.

- [ ] **Step 2: Add the overview section**

Add a new section. The exact wording is a writing exercise — keep it tight, in Australian English, no Anthropic/Claude references. The section must include all of:

- A one-paragraph intro: what `jellyfish overview` does (per-user `sec_score` rollup across the whole org).
- A "How `sec_score` is computed" subsection: sum of CVSS across active detections on the user's devices; users with no devices are excluded.
- A "Tier thresholds" subsection: the table from the spec (good <5, medium 5-29.9, high 30-99.9, critical >=100); note that these are the initial values and may be retuned.
- A "Usage" block with example invocations:
  - `jellyfish overview` (default table)
  - `jellyfish overview -o csv > scores.csv`
  - `jellyfish overview -o email --email-to security@example.com`
  - `jellyfish overview -o email --per-user --dry-run`
  - `jellyfish overview -o email --email-to security@example.com --message`
- A "Flags" subsection — copy the format used by `users send-email`'s flag list. Cover: `--per-user`, `--email-to`, `--email-from`, `--email-subject`, `--email-header-bg`, `--email-logo`, `--message`, `--message-file`, `--dry-run`, `--yes`, `--no-cache`.
- A "Stderr line format" subsection — show the admin and per-user line shapes from the spec (`sent to=`, `sent user=`, `skip user=`, `summary:`).
- A note that `--per-user` ignores `--email-to` (warning emitted, not an error).
- A note that the email's `X-Jellyfish-Report` header is `overview` (cross-link to the existing list-id/x-headers documentation).

- [ ] **Step 3: Sanity-check that the README still renders**

Run: `head -100 README.md` and `grep -n '^## ' README.md`

Expected: no duplicate headings, no broken markdown tables.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): documented jellyfish overview command"
```

---

## Final verification

After Task 15, run the full project's tests and a manual smoke check.

- [ ] **Run all tests:**

```bash
go test ./... -count=1
```

Expected: PASS across all packages.

- [ ] **Run the linter (matches CI):**

```bash
golangci-lint run
```

Expected: no findings. If `golangci-lint` is not installed, skip; CI will catch any issues.

- [ ] **Build and run the help text manually:**

```bash
go build -o bin/jellyfish ./
./bin/jellyfish overview --help
```

Expected: the help output lists `--per-user`, the five email flags, `--message`/`--message-file`, `--dry-run`, `--yes`, `--no-cache`, and the persistent `-o, --output`.

- [ ] **Confirm the spec is fully covered:** open `docs/superpowers/specs/2026-05-17-overview-command-design.md` and spot-check that each section maps to a task above:
  - Command surface → Tasks 11, 12, 13
  - Flag validation → Tasks 11, 14
  - Execution flow steps 1-9 → Tasks 4, 11, 12, 13
  - Stderr line format → Tasks 12, 13
  - Output structure (table/json/yaml/csv/email) → Tasks 6, 7, 8, 9
  - Email visual design (locked layouts) → Tasks 9, 10
  - Error handling (precedence) → reused from `bulkCounters` / `classifyError`; covered transitively by Task 12 + 13 tests
  - Edge cases → Tasks 4 (empty roster, ties, no devices), 13 (no email)
  - Testing strategy → all tasks
  - Documentation → Task 15
