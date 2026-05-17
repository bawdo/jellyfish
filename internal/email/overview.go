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
	Position       string // "1".."5" for leaderboards, global Rank for the roster, ordinal ("14th") for Me
	Rank           int
	RankStr        string // ordinal form for the Me callout ("14th")
	Name           string
	BorderColour   string
	ScoreStr       string
	DeviceCount    int // kept for internal use
	TotalIssues    int // kept for internal use
	Critical       int // kept for internal use
	High           int
	Medium         int
	Low            int
	DeviceCountStr string // human-readable form for templates
	TotalIssuesStr string
	CriticalStr    string
	HighStr        string
	MediumStr      string
	LowStr         string
	IsMe           bool // true on the recipient's row in the full roster (per-user variant)
}

type overviewTplData struct {
	Header         Header
	Tenant         string
	GeneratedAtStr string
	GeneratedDate  string
	Totals         OverviewTotals
	TotalsView     struct {
		UserCount   string
		DeviceCount string
		TotalIssues string
		SecScore    string
		Critical    string
		High        string
		Medium      string
		Low         string
	}
	AveragesView struct {
		Devices, Issues, SecScore   string
		Critical, High, Medium, Low string
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
	d.TotalsView.UserCount = formatInt(v.Totals.UserCount)
	d.TotalsView.DeviceCount = formatInt(v.Totals.DeviceCount)
	d.TotalsView.TotalIssues = formatInt(v.Totals.TotalIssues)
	d.TotalsView.SecScore = formatOneDec(v.Totals.SecScore)
	d.TotalsView.Critical = formatInt(v.Totals.Critical)
	d.TotalsView.High = formatInt(v.Totals.High)
	d.TotalsView.Medium = formatInt(v.Totals.Medium)
	d.TotalsView.Low = formatInt(v.Totals.Low)
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
			Position:       strconv.Itoa(me.Rank),
			Rank:           me.Rank,
			RankStr:        ordinal(me.Rank),
			Name:           me.Name,
			BorderColour:   "#2563eb",
			ScoreStr:       formatOneDec(me.SecScore),
			DeviceCount:    me.DeviceCount,
			TotalIssues:    me.TotalIssues,
			Critical:       me.Critical,
			High:           me.High,
			Medium:         me.Medium,
			Low:            me.Low,
			DeviceCountStr: formatInt(me.DeviceCount),
			TotalIssuesStr: formatInt(me.TotalIssues),
			CriticalStr:    formatInt(me.Critical),
			HighStr:        formatInt(me.High),
			MediumStr:      formatInt(me.Medium),
			LowStr:         formatInt(me.Low),
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
			CriticalStr:  formatInt(s.Critical),
			HighStr:      formatInt(s.High),
			MediumStr:    formatInt(s.Medium),
			LowStr:       formatInt(s.Low),
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
			Position:       strconv.Itoa(s.Rank),
			Rank:           s.Rank,
			Name:           s.Name,
			BorderColour:   colour,
			ScoreStr:       formatOneDec(s.SecScore),
			Critical:       s.Critical,
			High:           s.High,
			Medium:         s.Medium,
			Low:            s.Low,
			DeviceCount:    s.DeviceCount,
			TotalIssues:    s.TotalIssues,
			DeviceCountStr: formatInt(s.DeviceCount),
			TotalIssuesStr: formatInt(s.TotalIssues),
			CriticalStr:    formatInt(s.Critical),
			HighStr:        formatInt(s.High),
			MediumStr:      formatInt(s.Medium),
			LowStr:         formatInt(s.Low),
			IsMe:           isMe,
		}
	}
	return out
}

// tierColour maps a SecScore to the border colour used by the roster row
// card. Matches the secScoreTier thresholds in cmd/overview.go.
func tierColour(score float64) string {
	switch {
	case score >= SecScoreCriticalAt:
		return "#dc2626"
	case score >= SecScoreHighAt:
		return "#ea580c"
	case score >= SecScoreMediumAt:
		return "#ca8a04"
	default:
		return "#16a34a"
	}
}

// formatOneDec formats a float with one decimal place and comma-separated
// thousands in the integer part (e.g. 1234.27 -> "1,234.3"). Used by the
// email view for human-readable display. Other output formats (CSV / JSON /
// YAML / CLI table) bypass this and use raw values.
func formatOneDec(f float64) string {
	raw := strconv.FormatFloat(f, 'f', 1, 64) // e.g. "-1234.3" or "1234.3"
	dot := strings.IndexByte(raw, '.')
	if dot < 0 {
		return commaThousands(raw)
	}
	return commaThousands(raw[:dot]) + raw[dot:]
}

// formatInt formats an integer with comma-separated thousands
// (e.g. 18553 -> "18,553"). Used by the email view.
func formatInt(n int) string {
	return commaThousands(strconv.Itoa(n))
}

// commaThousands inserts commas every 3 digits from the right of the
// integer part of s. s may carry a leading '-' sign. s must not contain a
// decimal point or any other non-digit char beyond an optional leading
// minus — callers strip the fractional part before calling.
func commaThousands(s string) string {
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign = "-"
		s = s[1:]
	}
	if len(s) <= 3 {
		return sign + s
	}
	var b strings.Builder
	head := len(s) % 3
	if head > 0 {
		b.WriteString(s[:head])
	}
	for i := head; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return sign + b.String()
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
		return fmt.Errorf("%w: email overview renderer expected OverviewInput, got %T", ErrRender, v)
	}
	if r.opts.From == "" {
		return fmt.Errorf("%w: email renderer requires a non-empty From address", ErrRender)
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
		return fmt.Errorf("%w: %v", ErrRender, err)
	}
	textBody, err := renderOverviewText(data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRender, err)
	}

	boundary := r.opts.BoundaryOverride
	if boundary == "" {
		boundary, err = randomBoundary()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRender, err)
		}
	}
	messageID := r.opts.MessageIDOverride
	if messageID == "" {
		messageID, err = randomMessageID(domainFromAddress(r.opts.From))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRender, err)
		}
	}
	outerBoundary := r.opts.RelatedBoundaryOverride
	if outerBoundary == "" && logo != nil {
		outerBoundary, err = randomRelatedBoundary()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRender, err)
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
		return fmt.Errorf("%w: %v", ErrRender, err)
	}
	if _, err = w.Write(bytesOut); err != nil {
		return fmt.Errorf("%w: %v", ErrRender, err)
	}
	return nil
}
