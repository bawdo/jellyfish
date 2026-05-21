package output

import (
	"encoding/csv"
	"errors"
	"io"
	"strings"
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

	if err := eachRow(r.columns, v, func(cells []string) error {
		for i := range cells {
			cells[i] = sanitiseCell(cells[i])
		}
		return cw.Write(cells)
	}); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// formulaTriggers are the leading characters a spreadsheet (Excel, Numbers,
// LibreOffice) treats as the start of a formula. Tab and CR are included
// because Excel strips them and re-evaluates the following character.
const formulaTriggers = "=+-@\t\r"

// sanitiseCell neutralises spreadsheet formula injection ("CSV injection"):
// a cell whose first character could start a formula is prefixed with a
// single quote so the spreadsheet renders it as literal text. encoding/csv
// quotes fields containing delimiters but does not stop formula evaluation -
// only changing the leading character does.
func sanitiseCell(s string) string {
	if s != "" && strings.ContainsRune(formulaTriggers, rune(s[0])) {
		return "'" + s
	}
	return s
}
