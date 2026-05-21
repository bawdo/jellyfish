package output

import (
	"errors"
	"io"
	"reflect"

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
			row[i] = c
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
