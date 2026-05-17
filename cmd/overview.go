package cmd

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

// assembleOverview walks all detections (cached) and all devices (single
// paginated stream), derives the user roster from device.User (Iru embeds
// id/name/email/active/is_archived on each device record), buckets
// detections by device, sums CVSS per user, sorts by SecScore desc with
// deterministic tie-breakers, and produces an OverviewView with totals,
// averages, BestFive, MostDangerousFive, and the full roster.
//
// userFilter, when non-nil, restricts the roster to users whose email
// (lowercased) appears in the map. Filter entries that match no device
// owner are warned on stderr. Pass nil to include all users with devices.
//
// Returns an error if either Iru call fails or the (filtered) roster is
// empty.
func assembleOverview(ctx context.Context, client iruClient, stderr io.Writer, noCache bool, userFilter map[string]struct{}) (email.OverviewView, error) {
	allDetections, err := fetchAllDetections(ctx, client, stderr, !noCache)
	if err != nil {
		return email.OverviewView{}, err
	}
	byDevice := make(map[string][]iru.Detection, len(allDetections))
	for i := range allDetections {
		byDevice[allDetections[i].DeviceID] = append(byDevice[allDetections[i].DeviceID], allDetections[i])
	}

	devicesByUser := make(map[string][]iru.Device)
	usersByID := make(map[string]iru.User)
	pages := 0
	totalDevices := 0
	err = client.ListDevicesStream(ctx, iru.DeviceFilters{}, func(page []iru.Device) error {
		for _, d := range page {
			if d.User.ID == "" {
				continue // device with no owner — not part of any user's roster
			}
			devicesByUser[d.User.ID] = append(devicesByUser[d.User.ID], d)
			if _, seen := usersByID[d.User.ID]; !seen {
				usersByID[d.User.ID] = d.User
			}
		}
		pages++
		totalDevices += len(page)
		_, _ = fmt.Fprintf(stderr, "\rfetching devices: %d pages, %d records...", pages, totalDevices)
		return nil
	})
	if pages > 0 {
		_, _ = fmt.Fprintln(stderr)
	}
	if err != nil {
		return email.OverviewView{}, err
	}

	// Apply optional user-email filter (case-insensitive).
	if userFilter != nil {
		present := make(map[string]struct{}, len(usersByID))
		for _, u := range usersByID {
			if u.Email != "" {
				present[strings.ToLower(u.Email)] = struct{}{}
			}
		}
		for want := range userFilter {
			if _, ok := present[want]; !ok {
				_, _ = fmt.Fprintf(stderr, "warn: %s not in tenant devices\n", want)
			}
		}
		for id, u := range usersByID {
			if _, ok := userFilter[strings.ToLower(u.Email)]; !ok {
				delete(usersByID, id)
				delete(devicesByUser, id)
			}
		}
	}

	stats := make([]email.UserStats, 0, len(usersByID))
	for id, u := range usersByID {
		devices := devicesByUser[id]
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
	case score >= email.SecScoreCriticalAt:
		return "critical"
	case score >= email.SecScoreHighAt:
		return "high"
	case score >= email.SecScoreMediumAt:
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

type overviewOpts struct {
	Output         string
	PerUser        bool
	CSVPath        string
	Emails         string
	CSVEmailColumn string
	EmailFlags     emailFlagValues
	DryRun         bool
	Yes            bool
	NoCache        bool
	Profile        config.Profile
	EmailNow       time.Time
	// Injected for tests:
	gitEmail      gitEmailLookup
	KeychainGet   func() ([]byte, error)
	NewSender     gmailNewSender
	ConfirmReader io.Reader
	MessageReader io.Reader
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
	c.Flags().StringVar(&opts.CSVPath, "csv", "", "Path to a CSV file holding the user emails to include. Mutually exclusive with --emails. Default: all users with devices.")
	c.Flags().StringVar(&opts.Emails, "emails", "", "Comma-separated list of user emails to include. Mutually exclusive with --csv. Default: all users with devices.")
	c.Flags().StringVar(&opts.CSVEmailColumn, "csv-email-column", "", "CSV column name holding the email address (default: auto-detect email/user_email/e-mail)")
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
	filter, err := buildOverviewUserFilter(opts)
	if err != nil {
		return err
	}
	view, err := assembleOverview(ctx, client, stderr, opts.NoCache, filter)
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
		return runOverviewEmail(ctx, stderr, opts, view)
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
	if opts.CSVPath != "" && opts.Emails != "" {
		return errors.New("--csv and --emails are mutually exclusive")
	}
	return nil
}

// buildOverviewUserFilter parses --csv / --emails into a case-insensitive
// email set, or returns nil when neither flag is set (meaning "include all
// users with devices"). --csv-email-column is honoured for header overrides.
func buildOverviewUserFilter(opts overviewOpts) (map[string]struct{}, error) {
	if opts.CSVPath == "" && opts.Emails == "" {
		return nil, nil
	}
	emails, err := readEmailList(opts.CSVPath, opts.Emails, opts.CSVEmailColumn)
	if err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(emails))
	for _, e := range emails {
		out[strings.ToLower(e)] = struct{}{}
	}
	return out, nil
}

// runOverviewEmail builds the email Options, captures the optional message,
// and dispatches to the admin or per-user path. Per-user is Task 13.
func runOverviewEmail(ctx context.Context, stderr io.Writer, opts overviewOpts, view email.OverviewView) error {
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
		return runOverviewPerUser(ctx, stderr, opts, view, baseEmailOpts, now)
	}
	return runOverviewAdmin(ctx, stderr, opts, view, baseEmailOpts, now)
}

func runOverviewAdmin(ctx context.Context, stderr io.Writer, opts overviewOpts, view email.OverviewView, baseOpts email.Options, now time.Time) error {
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
	msgIn := opts.MessageReader
	if msgIn == nil {
		msgIn = os.Stdin
	}
	message, err := captureMessage(opts.EmailFlags, true, display, baseOpts.Subject, msgIn, stderr, nil)
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
		var buf bytes.Buffer
		if err := email.NewOverviewRendererWithStderr(userOpts, stderr).Render(&buf, email.OverviewInput{View: view}); err != nil {
			_, _ = fmt.Fprintf(stderr, "error to=%s render: %v\n", to, err)
			counters.recordError(err)
			continue
		}
		if opts.DryRun {
			_, _ = fmt.Fprintf(stderr, "would-send to=%s bytes=%d\n", to, buf.Len())
			counters.wouldSend++
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

func runOverviewPerUser(ctx context.Context, stderr io.Writer, opts overviewOpts, view email.OverviewView, baseOpts email.Options, now time.Time) error {
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

	msgIn := opts.MessageReader
	if msgIn == nil {
		msgIn = os.Stdin
	}
	message, err := captureMessage(opts.EmailFlags, true, fmt.Sprintf("%d users", len(view.Users)), baseOpts.Subject, msgIn, stderr, nil)
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

		var buf bytes.Buffer
		if err := email.NewOverviewRendererWithStderr(userOpts, stderr).Render(&buf, email.OverviewInput{View: perUserView}); err != nil {
			_, _ = fmt.Fprintf(stderr, "error user=%s render: %v\n", u.UserID, err)
			counters.recordError(err)
			continue
		}
		if opts.DryRun {
			_, _ = fmt.Fprintf(stderr, "would-send user=%s to=%s bytes=%d\n", u.UserID, u.Email, buf.Len())
			counters.wouldSend++
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
