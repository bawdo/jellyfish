package output

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

type tableItem struct {
	Name string
	Age  int
}

func intStr(i int) string { return strconv.Itoa(i) }

func TestTableRendererSliceWithColumns(t *testing.T) {
	rows := []tableItem{
		{Name: "rover", Age: 4},
		{Name: "spot", Age: 7},
	}

	r := Table().WithColumns([]Column{
		{Header: "NAME", Extract: func(v any) string { return v.(tableItem).Name }},
		{Header: "AGE", Extract: func(v any) string { return intStr(v.(tableItem).Age) }},
	})

	buf := &bytes.Buffer{}
	if err := r.Render(buf, rows); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"NAME", "AGE", "rover", "spot", "4", "7"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestTableRendererSingleStruct(t *testing.T) {
	r := Table().WithColumns([]Column{
		{Header: "NAME", Extract: func(v any) string { return v.(tableItem).Name }},
		{Header: "AGE", Extract: func(v any) string { return intStr(v.(tableItem).Age) }},
	})

	buf := &bytes.Buffer{}
	if err := r.Render(buf, tableItem{Name: "rover", Age: 4}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "rover") {
		t.Fatalf("expected name in output, got: %s", buf.String())
	}
}

// Cell values can carry API data chosen by end users (device names, for
// example). Control characters must not reach the admin's terminal, or an
// OSC/CSI sequence could retitle the window, clear the screen and so on.
func TestTableRendererStripsControlCharacters(t *testing.T) {
	names := []string{
		"evil\x1b]0;pwned\x07mac", // OSC set-title, BEL terminated
		"wipe\x1b[2Jmac",          // CSI clear screen
		"c1\u009b31mmac",          // 8-bit CSI (C1)
		"del\x7fnul\x00tab\tnl\nmac",
	}
	rows := make([]tableItem, len(names))
	for i, n := range names {
		rows[i] = tableItem{Name: n}
	}

	r := Table().WithColumns([]Column{
		{Header: "NAME", Extract: func(v any) string { return v.(tableItem).Name }},
	})

	buf := &bytes.Buffer{}
	if err := r.Render(buf, rows); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, b := range out {
		if (b < 0x20 && b != '\n') || b == 0x7f || (b >= 0x80 && b <= 0x9f) {
			t.Fatalf("control character %U leaked into table output:\n%q", b, out)
		}
	}
	for _, want := range []string{"evil]0;pwnedmac", "wipe[2Jmac", "c131mmac", "delnultabnlmac"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%q", want, out)
		}
	}
}

func TestSanitiseTerminalLeavesPrintableTextAlone(t *testing.T) {
	for _, s := range []string{"", "MacBook Pro", "Keith’s Mac – 2024", "日本語"} {
		if got := SanitiseTerminal(s); got != s {
			t.Fatalf("SanitiseTerminal(%q) = %q, want unchanged", s, got)
		}
	}
}
