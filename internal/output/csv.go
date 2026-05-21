package output

import (
	"encoding/csv"
	"errors"
	"io"
)

type csvRenderer struct {
	columns []Column
}

func CSV() *csvRenderer { return &csvRenderer{} }

func (r *csvRenderer) WithColumns(cols []Column) *csvRenderer {
	r.columns = cols
	return r
}

func (r *csvRenderer) Render(w io.Writer, v any) error {
	if len(r.columns) == 0 {
		return errors.New("csv renderer requires WithColumns before Render")
	}

	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := make([]string, len(r.columns))
	for i, c := range r.columns {
		header[i] = c.Header
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	if err := eachRow(r.columns, v, cw.Write); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}
