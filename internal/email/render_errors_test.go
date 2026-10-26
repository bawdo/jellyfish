package email

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/bawdo/jellyfish/internal/output"
)

// failingWriter rejects every write, standing in for a closed pipe or a
// full disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// renderCase is one renderer with options and an input it accepts.
type renderCase struct {
	name  string
	opts  func() Options
	build func(Options) output.Renderer
	input any
}

func allRenderers() []renderCase {
	return []renderCase{
		{"vulns summary", newPinnedOpts, NewVulnSummaryRenderer, sampleVulns()},
		{"user show", newPinnedUserShowOpts, NewUserShowRenderer, sampleUserBundle()},
		{"overview", newOverviewOptions, NewOverviewRenderer, newOverviewInputAdmin()},
	}
}

// renderErrCase is one way to make a render fail. A nil w renders into a
// buffer that must stay empty.
type renderErrCase struct {
	name    string
	mutate  func(*Options)
	input   any
	w       io.Writer
	wantMsg string
}

// Every renderer failure is wrapped as ErrRender, which classifyError maps
// to exit code 1, and nothing is written for a rejected render.
func TestRenderersWrapFailuresAsErrRender(t *testing.T) {
	for _, rc := range allRenderers() {
		t.Run(rc.name, func(t *testing.T) {
			cases := []renderErrCase{
				{"wrong input type", nil, 42, nil, "got int"},
				{"empty From", func(o *Options) { o.From = "" }, rc.input, nil, "non-empty From"},
				{"write failure", nil, rc.input, failingWriter{}, "disk full"},
			}
			if rc.name != "overview" {
				// The overview carries no CVE links, so only the CVE
				// renderers validate the templates.
				cases = append(cases,
					renderErrCase{"primary link without token", func(o *Options) { o.CVELinkPrimary = "https://no-token.example/" }, rc.input, nil, "primary CVE link"},
					renderErrCase{"secondary link without token", func(o *Options) { o.CVELinkSecondary = "https://no-token.example/" }, rc.input, nil, "secondary CVE link"},
				)
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					opts := rc.opts()
					if tc.mutate != nil {
						tc.mutate(&opts)
					}
					var buf bytes.Buffer
					w := tc.w
					if w == nil {
						w = &buf
					}
					err := rc.build(opts).Render(w, tc.input)
					if !errors.Is(err, ErrRender) {
						t.Fatalf("expected ErrRender, got %v", err)
					}
					if !strings.Contains(err.Error(), tc.wantMsg) {
						t.Errorf("error %q does not mention %q", err.Error(), tc.wantMsg)
					}
					if buf.Len() != 0 {
						t.Errorf("rejected render wrote %d bytes", buf.Len())
					}
				})
			}
		})
	}
}

var (
	innerBoundaryRe = regexp.MustCompile(`multipart/alternative; boundary="(=_jf_[0-9a-f]{16})"`)
	outerBoundaryRe = regexp.MustCompile(`multipart/related; type="multipart/alternative"; boundary="(=_jfr_[0-9a-f]{16})"`)
	messageIDRe     = regexp.MustCompile(`(?m)^Message-ID: <\d+\.[0-9a-f]{6}@example\.com>\r$`)
)

// Without the test overrides each render picks fresh random boundaries and a
// Message-ID on the From domain, so two sends never share them.
func TestRenderersGenerateBoundariesAndMessageID(t *testing.T) {
	for _, rc := range allRenderers() {
		t.Run(rc.name, func(t *testing.T) {
			render := func() string {
				opts := rc.opts()
				opts.BoundaryOverride = ""
				opts.MessageIDOverride = ""
				opts.RelatedBoundaryOverride = ""
				opts.LogoPath = "testdata/logo_small.png"
				var buf bytes.Buffer
				if err := rc.build(opts).Render(&buf, rc.input); err != nil {
					t.Fatalf("Render: %v", err)
				}
				return buf.String()
			}
			a, b := render(), render()
			for _, msg := range []string{a, b} {
				if !innerBoundaryRe.MatchString(msg) {
					t.Fatalf("no generated multipart/alternative boundary in:\n%.600s", msg)
				}
				if !outerBoundaryRe.MatchString(msg) {
					t.Fatalf("no generated multipart/related boundary in:\n%.600s", msg)
				}
				if !messageIDRe.MatchString(msg) {
					t.Fatalf("no generated Message-ID on the From domain in:\n%.600s", msg)
				}
			}
			if innerBoundaryRe.FindStringSubmatch(a)[1] == innerBoundaryRe.FindStringSubmatch(b)[1] {
				t.Error("two renders shared a multipart/alternative boundary")
			}
			if outerBoundaryRe.FindStringSubmatch(a)[1] == outerBoundaryRe.FindStringSubmatch(b)[1] {
				t.Error("two renders shared a multipart/related boundary")
			}
		})
	}
}
