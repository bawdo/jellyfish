package cmd

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
	wroteProgress := false
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
			wroteProgress = true
		}
	}
	if wroteProgress {
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
	dangerousFive := append([]email.UserStats(nil), stats[:min(5, len(stats))]...)

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
	bestFive := append([]email.UserStats(nil), bestSorted[:min(5, len(bestSorted))]...)

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
		MostDangerousFive: dangerousFive,
		Users:             stats,
	}, nil
}

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
