package output

import (
	"bytes"
	"encoding/csv"
	"strconv"
	"strings"
	"testing"
)

func TestCSVRendererSliceWithColumns(t *testing.T) {
	rows := []tableItem{
		{Name: "rover", Age: 4},
		{Name: "spot", Age: 7},
	}

	r := CSV().WithColumns([]Column{
		{Header: "name", Extract: func(v any) string { return v.(tableItem).Name }},
		{Header: "age", Extract: func(v any) string { return strconv.Itoa(v.(tableItem).Age) }},
	})

	buf := &bytes.Buffer{}
	if err := r.Render(buf, rows); err != nil {
		t.Fatal(err)
	}

	want := "name,age\nrover,4\nspot,7\n"
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
}

func TestCSVRendererEscapesCommas(t *testing.T) {
	r := CSV().WithColumns([]Column{
		{Header: "v", Extract: func(v any) string { return v.(string) }},
	})
	buf := &bytes.Buffer{}
	if err := r.Render(buf, []string{"a,b"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"a,b"`) {
		t.Fatalf("expected quoting, got %q", buf.String())
	}
}

func TestCSVRendererNeutralisesFormulaInjection(t *testing.T) {
	r := CSV().WithColumns([]Column{
		{Header: "v", Extract: func(v any) string { return v.(string) }},
	})
	cases := []struct {
		name, in, want string
	}{
		{"equals", "=1+1", "'=1+1"},
		{"plus", "+1+1", "'+1+1"},
		{"minus", "-2+3", "'-2+3"},
		{"at", "@SUM(A1:A9)", "'@SUM(A1:A9)"},
		{"tab", "\t=HYPERLINK(1)", "'\t=HYPERLINK(1)"},
		// CR is stripped as a terminal control first, which leaves "=" leading.
		{"carriage return", "\r=HYPERLINK(1)", "'=HYPERLINK(1)"},
		{"safe plain", "MacBook Pro", "MacBook Pro"},
		{"safe interior dash", "lib-ssl", "lib-ssl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			if err := r.Render(buf, []string{c.in}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			// Re-parse the output the way a spreadsheet would, then assert
			// the cell can no longer begin with a formula trigger.
			recs, err := csv.NewReader(buf).ReadAll()
			if err != nil {
				t.Fatalf("re-parse CSV: %v", err)
			}
			if len(recs) != 2 {
				t.Fatalf("expected header + 1 data row, got %d records", len(recs))
			}
			if got := recs[1][0]; got != c.want {
				t.Errorf("cell: got %q want %q", got, c.want)
			}
		})
	}
}

// CSV is often printed straight to a terminal, so cells carrying endpoint
// chosen text (device names, paths) must not carry escape sequences. Tab and
// newline are kept: encoding/csv quotes them and they are legitimate data.
func TestCSVRendererStripsTerminalControls(t *testing.T) {
	r := CSV().WithColumns([]Column{
		{Header: "v", Extract: func(v any) string { return v.(string) }},
	})
	cases := []struct {
		name, in, want string
	}{
		{"osc title", "Mac\x1b]0;pwned\x07Book", "Mac]0;pwnedBook"},
		{"csi clear", "a\x1b[2Jb", "a[2Jb"},
		{"c1 csi", "a\u009b31mb", "a31mb"},
		{"del", "a\x7fb", "ab"},
		{"carriage return", "a\rb", "ab"},
		{"invalid utf8 c1 byte", "a\x9bb", "a\uFFFDb"},
		{"tab kept", "a\tb", "a\tb"},
		{"newline kept", "line one\nline two", "line one\nline two"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			if err := r.Render(buf, []string{c.in}); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if strings.ContainsAny(buf.String(), "\x1b\x07\x7f\u009b") {
				t.Fatalf("control left in output: %q", buf.String())
			}
			recs, err := csv.NewReader(buf).ReadAll()
			if err != nil {
				t.Fatalf("re-parse CSV: %v", err)
			}
			if got := recs[1][0]; got != c.want {
				t.Errorf("cell: got %q want %q", got, c.want)
			}
		})
	}
}
