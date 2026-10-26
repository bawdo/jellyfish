package email

import (
	"errors"
	"strings"
	"testing"
)

func TestSeverityClassAndPalette(t *testing.T) {
	cases := []struct {
		sev, class, rowBG string
	}{
		{"Critical", "crit", "#dc2626"},
		{"HIGH", "high", "#ea580c"},
		{"medium", "med", "#ca8a04"},
		{"Low", "low", sevPaletteNeutral.rowBG},
		{"", "und", sevPaletteNeutral.rowBG},
		{"Informational", "und", sevPaletteNeutral.rowBG},
	}
	for _, c := range cases {
		class := severityClass(c.sev)
		if class != c.class {
			t.Errorf("severityClass(%q) = %q, want %q", c.sev, class, c.class)
		}
		if got := sevRowBG(class); got != c.rowBG {
			t.Errorf("sevRowBG(%q) = %q, want %q", class, got, c.rowBG)
		}
	}
	// Classes without their own palette share the neutral pill colours.
	for _, class := range []string{"low", "und", "bogus"} {
		if sevPillBG(class) != sevPaletteNeutral.pillBG || sevPillFG(class) != sevPaletteNeutral.pillFG {
			t.Errorf("%q: expected the neutral pill palette", class)
		}
	}
}

func TestSeverityCountsIgnoresUnknown(t *testing.T) {
	var c severityCounts
	for _, s := range []string{"Critical", "high", "High", "Medium", "low", "", "Unknown"} {
		c.tally(s)
	}
	if c != (severityCounts{CriticalCount: 1, HighCount: 2, MediumCount: 1, LowCount: 1}) {
		t.Fatalf("got %+v", c)
	}
}

// Header colours that fail validation fall back to dark text instead of
// erroring mid-render.
func TestComputeHeaderStyleFallsBackOnBadColour(t *testing.T) {
	for _, bg := range []string{"", "red", "#12345", "#GGGGGG"} {
		if _, _, _, err := hexToRGB(bg); err == nil {
			t.Errorf("hexToRGB(%q): expected an error", bg)
		}
		got := computeHeaderStyle(bg)
		if got.TextFG != "#0f172a" || got.BadgeFG != "#0f172a" || got.BadgeBG != "rgba(15,23,42,0.10)" {
			t.Errorf("computeHeaderStyle(%q) = %+v, want the dark-text palette", bg, got)
		}
	}
}

func TestTierColour(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{SecScoreCriticalAt, "#dc2626"},
		{SecScoreCriticalAt - 0.1, "#ea580c"},
		{SecScoreHighAt, "#ea580c"},
		{SecScoreHighAt - 0.1, "#ca8a04"},
		{SecScoreMediumAt, "#ca8a04"},
		{SecScoreMediumAt - 0.1, "#16a34a"},
		{0, "#16a34a"},
	}
	for _, c := range cases {
		if got := tierColour(c.score); got != c.want {
			t.Errorf("tierColour(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestOrdinal(t *testing.T) {
	cases := map[int]string{
		1: "1st", 2: "2nd", 3: "3rd", 4: "4th",
		11: "11th", 12: "12th", 13: "13th",
		21: "21st", 22: "22nd", 23: "23rd",
		101: "101st", 111: "111th", 112: "112th", 113: "113th",
	}
	for n, want := range cases {
		if got := ordinal(n); got != want {
			t.Errorf("ordinal(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestLinkifyHTMLEmptyInput(t *testing.T) {
	if got := linkifyHTML(""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// Blank lines before the first paragraph produce no empty <p>.
func TestParagraphsHTMLSkipsLeadingBlankLines(t *testing.T) {
	got := string(paragraphsHTML("\n\nhello"))
	if n := strings.Count(got, "<p"); n != 1 {
		t.Fatalf("expected one paragraph, got %d in %q", n, got)
	}
	if !strings.Contains(got, ">hello</p>") {
		t.Errorf("paragraph text missing: %q", got)
	}
}

// errReader fails every read.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadLogoBytesWrapsReadError(t *testing.T) {
	readErr := errors.New("io failure")
	data, err := readLogoBytes(errReader{readErr}, "logo.png")
	if !errors.Is(err, readErr) {
		t.Fatalf("expected the read error in the chain, got %v", err)
	}
	if !strings.Contains(err.Error(), "read logo.png") {
		t.Errorf("error %q does not name the file", err.Error())
	}
	if data != nil {
		t.Errorf("expected no data, got %d bytes", len(data))
	}
}
