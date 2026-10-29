package output

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/jedib0t/go-pretty/v6/table"
)

// Column declares one column in a table render. Extract is called per row.
type Column struct {
	Header  string
	Extract func(v any) string
}

type tableRenderer struct {
	columns []Column
}

// Table returns a renderer that needs WithColumns called before Render.
func Table() *tableRenderer { return &tableRenderer{} }

// WithColumns returns a renderer configured for the given columns.
func (r *tableRenderer) WithColumns(cols []Column) *tableRenderer {
	r.columns = cols
	return r
}

// Render writes v as a table. v must be a struct or a slice of structs.
func (r *tableRenderer) Render(w io.Writer, v any) error {
	if len(r.columns) == 0 {
		return errors.New("table renderer requires WithColumns before Render")
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)

	header := make(table.Row, len(r.columns))
	for i, c := range r.columns {
		header[i] = c.Header
	}
	t.AppendHeader(header)

	err := eachRow(r.columns, v, func(cells []string) error {
		row := make(table.Row, len(cells))
		for i, c := range cells {
			row[i] = SanitiseTerminal(c)
		}
		t.AppendRow(row)
		return nil
	})
	if err != nil {
		return err
	}

	t.Render()
	return nil
}

// SanitiseTerminal neutralises terminal escape injection in single-line text
// such as a table cell: cells carry API data that end users choose (device
// names, for example), and an embedded ESC/CSI/OSC sequence would otherwise
// be interpreted by the admin's terminal. Every C0 control (including tab and
// newline, which also break the table layout), DEL and every C1 control is
// removed outright rather than replaced, so the remaining text stays
// readable. The table renderer uses this. The data formats are handled
// separately: CSV strips the same controls but keeps tab and newline, JSON
// escapes DEL and C1 losslessly, and YAML escapes every control itself.
func SanitiseTerminal(s string) string {
	return stripControls(s, isTerminalControl)
}

// SanitiseTerminalText is SanitiseTerminal for multi-line text, such as an
// error message bound for stderr: newline is kept so the message keeps its
// line breaks, and every other C0 control (including carriage return, which
// could overwrite what was already printed), DEL and C1 control is removed.
func SanitiseTerminalText(s string) string {
	return stripControls(s, func(r rune) bool {
		return r != '\n' && isTerminalControl(r)
	})
}

// stripControls removes every rune drop reports true for. Invalid UTF-8 is
// replaced with U+FFFD first: a lone byte such as 0x9b decodes as RuneError
// rather than as the C1 control it is to an 8-bit terminal (CSI), so it
// would otherwise slip past both the fast path and drop.
func stripControls(s string, drop func(rune) bool) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	if !strings.ContainsFunc(s, drop) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if drop(r) {
			return -1
		}
		return r
	}, s)
}

// isTerminalControl reports whether r is a C0 control, DEL or a C1 control.
func isTerminalControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// eachRow calls emit once per row of v, with each row's cells as a []string.
// v must be a struct or a slice/array of structs. The first emit error stops
// iteration and is returned.
func eachRow(cols []Column, v any, emit func(cells []string) error) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		for i := 0; i < rv.Len(); i++ {
			if err := emitCells(cols, rv.Index(i).Interface(), emit); err != nil {
				return err
			}
		}
		return nil
	}
	return emitCells(cols, v, emit)
}

func emitCells(cols []Column, v any, emit func(cells []string) error) error {
	cells := make([]string, len(cols))
	for i, c := range cols {
		cells[i] = c.Extract(v)
	}
	return emit(cells)
}
