package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestColumnRenderersRequireColumns(t *testing.T) {
	for name, render := range map[string]func() error{
		"csv":   func() error { return CSV().Render(&bytes.Buffer{}, []tableItem{{Name: "x"}}) },
		"table": func() error { return Table().Render(&bytes.Buffer{}, []tableItem{{Name: "x"}}) },
	} {
		err := render()
		if err == nil || !strings.Contains(err.Error(), "requires WithColumns") {
			t.Errorf("%s: expected a WithColumns error, got %v", name, err)
		}
	}
}

// csvWriteFailure is larger than the csv package's internal buffer, so a
// record this long forces a write to the underlying writer mid-record.
var csvWriteFailure = strings.Repeat("x", 8192)

// A failing destination (closed pipe, full disk) must surface as an error
// from Render, whether it fails on the header, on a row, or at the final
// flush, and a failed row must stop the walk.
func TestCSVRendererPropagatesWriteErrors(t *testing.T) {
	cases := []struct {
		name     string
		header   string
		rows     any
		wantRows int // Extract calls expected before Render gives up
	}{
		{"header", csvWriteFailure, []string{"a", "b"}, 0},
		{"first row of a slice", "v", []string{csvWriteFailure, "b"}, 1},
		{"single value", "v", csvWriteFailure, 1},
		{"final flush", "v", []string{"a", "b"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extracts := 0
			r := CSV().WithColumns([]Column{
				{Header: tc.header, Extract: func(v any) string { extracts++; return v.(string) }},
			})
			err := r.Render(failWriter{}, tc.rows)
			if err == nil || !strings.Contains(err.Error(), "boom") {
				t.Fatalf("expected the writer's error, got %v", err)
			}
			if extracts != tc.wantRows {
				t.Fatalf("Extract called %d times, want %d", extracts, tc.wantRows)
			}
		})
	}
}

// eachRow stops at the first emit error and returns it unchanged.
func TestEachRowStopsAtFirstEmitError(t *testing.T) {
	stop := errors.New("stop")
	cols := []Column{{Header: "v", Extract: func(v any) string { return v.(string) }}}
	var seen []string
	err := eachRow(cols, []string{"a", "b", "c"}, func(cells []string) error {
		seen = append(seen, cells[0])
		if cells[0] == "b" {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("expected stop, got %v", err)
	}
	if strings.Join(seen, ",") != "a,b" {
		t.Fatalf("emitted %v, want [a b]", seen)
	}
}
