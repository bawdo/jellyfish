package email

import (
	"embed"
	"fmt"
	htmltmpl "html/template"
	"io"
	"sort"
	"strings"
	texttmpl "text/template"

	"github.com/bawdo/jellyfish/internal/iru"
	"github.com/bawdo/jellyfish/internal/output"
)

// UserBundleInput is the typed shape that NewUserShowRenderer expects. The
// cmd-layer UserBundle struct mirrors this; cmd translates before calling.
// Keeping a package-local type avoids a circular import.
type UserBundleInput struct {
	User    iru.User
	Devices []UserBundleDevice
}

type UserBundleDevice struct {
	Device     iru.Device
	Detections []iru.Detection
}

//go:embed templates/user_show.txt.tmpl templates/user_show.html.tmpl templates/_header.html.tmpl templates/_message.html.tmpl
var userShowFS embed.FS

type userShowView struct {
	Header         Header
	User           iru.User
	Tenant         string
	GeneratedAtStr string
	GeneratedDate  string
	TotalCVEs      int
	severityCounts
	DeviceCount int
	Devices     []userShowDeviceView
	Message     string
	MessageHTML htmltmpl.HTML
}

type userShowDeviceView struct {
	Device iru.Device
	Rows   []userShowRow
}

type userShowRow struct {
	CVEID         string
	Severity      string
	SeverityClass string
	CVSSStr       string
	Package       string
	NVDLink       string
	MITRELink     string
}

func buildUserShowView(b UserBundleInput, opts Options) userShowView {
	view := userShowView{
		User:           b.User,
		Tenant:         opts.Tenant,
		GeneratedAtStr: opts.GeneratedAt.Format("2 Jan 2006 - 15:04 MST"),
		GeneratedDate:  opts.GeneratedAt.Format("2006-01-02"),
		DeviceCount:    len(b.Devices),
		Devices:        make([]userShowDeviceView, len(b.Devices)),
	}
	for i, dev := range b.Devices {
		dets := append([]iru.Detection(nil), dev.Detections...)
		sort.SliceStable(dets, func(i, j int) bool {
			ri, rj := iru.SeverityRank(dets[i].Severity), iru.SeverityRank(dets[j].Severity)
			if ri != rj {
				return ri < rj
			}
			return dets[i].CVSSScore > dets[j].CVSSScore
		})
		rows := make([]userShowRow, 0, len(dets))
		for _, det := range dets {
			view.tally(det.Severity)
			view.TotalCVEs++
			pkg := det.Name
			if det.Version != "" {
				pkg = det.Name + "@" + det.Version
			}
			rows = append(rows, userShowRow{
				CVEID:         det.CVEID,
				Severity:      det.Severity,
				SeverityClass: severityClass(det.Severity),
				CVSSStr:       fmt.Sprintf("%.1f", det.CVSSScore),
				Package:       pkg,
				NVDLink:       buildCVELink(opts.CVELinkPrimary, det.CVEID),
				MITRELink:     buildCVELink(opts.CVELinkSecondary, det.CVEID),
			})
		}
		view.Devices[i] = userShowDeviceView{Device: dev.Device, Rows: rows}
	}
	view.Message = opts.Message
	if opts.Message != "" {
		view.MessageHTML = paragraphsHTML(opts.Message)
	}
	return view
}

func renderUserShowText(v userShowView) (string, error) {
	tmpl, err := texttmpl.New("user_show.txt.tmpl").Funcs(texttmpl.FuncMap{
		"cond": func(b bool, t, f string) string {
			if b {
				return t
			}
			return f
		},
	}).ParseFS(userShowFS, "templates/user_show.txt.tmpl")
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func renderUserShowHTML(v userShowView) (string, error) {
	tmpl, err := htmltmpl.New("user_show.html.tmpl").Funcs(htmltmpl.FuncMap{
		"sevRowBG":  sevRowBG,
		"sevPillBG": sevPillBG,
		"sevPillFG": sevPillFG,
		"safeCSS":   safeCSS,
	}).ParseFS(userShowFS,
		"templates/_header.html.tmpl",
		"templates/_message.html.tmpl",
		"templates/user_show.html.tmpl",
	)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

type userShowRenderer struct {
	opts Options
	warn io.Writer
}

// NewUserShowRenderer returns an output.Renderer whose Render(w, v) expects
// v to be a UserBundleInput and writes a complete .eml message to w.
func NewUserShowRenderer(opts Options) output.Renderer {
	return &userShowRenderer{opts: opts.withDefaults()}
}

// NewUserShowRendererWithStderr is like NewUserShowRenderer but routes
// renderer-level warnings (e.g. logo load failures) to the supplied writer
// instead of os.Stderr.
func NewUserShowRendererWithStderr(opts Options, stderr io.Writer) output.Renderer {
	return &userShowRenderer{opts: opts.withDefaults(), warn: stderr}
}

func (r *userShowRenderer) Render(w io.Writer, v any) error {
	bundle, ok := v.(UserBundleInput)
	if !ok {
		return fmt.Errorf("%w: email user show renderer expected UserBundleInput, got %T", ErrRender, v)
	}
	if err := validateCVELinks(r.opts); err != nil {
		return err
	}
	if r.opts.From == "" {
		return fmt.Errorf("%w: email renderer requires a non-empty From address", ErrRender)
	}

	view := buildUserShowView(bundle, r.opts)
	logo := resolveLogo(r.opts.LogoPath, r.warn)

	subtitle := r.opts.GeneratedAt.Format("2 Jan 2006 - 15:04 MST")
	if bundle.User.Email != "" {
		subtitle = bundle.User.Email + " - " + subtitle
	}
	if view.Tenant != "" {
		subtitle += " - " + view.Tenant
	}
	subtitle += fmt.Sprintf(" - %d CVEs across %d device(s)", view.TotalCVEs, view.DeviceCount)
	view.Header = buildHeader("JELLYFISH / USER",
		"Vulnerability exposure - "+bundle.User.Name,
		subtitle, r.opts.HeaderBG, logo != nil,
	)

	subject := r.opts.Subject
	if subject == "" {
		who := bundle.User.Name
		if who == "" {
			who = bundle.User.Email
		}
		subject = "Vulnerability exposure - " + who + " - " + view.GeneratedDate
	}

	htmlBody, err := renderUserShowHTML(view)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRender, err)
	}
	textBody, err := renderUserShowText(view)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRender, err)
	}

	return finishEmail(w, r.opts, subject, htmlBody, textBody, logo)
}
