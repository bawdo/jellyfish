package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

type jsonRenderer struct{}

func JSON() Renderer { return jsonRenderer{} }

func (jsonRenderer) Render(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(escapeDELAndC1(buf.Bytes()))
	return err
}

// isDELOrC1 reports whether r is DEL or a C1 control.
func isDELOrC1(r rune) bool {
	return r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// escapeDELAndC1 rewrites DEL and C1 controls in encoded JSON as \uXXXX
// escapes. encoding/json escapes C0 controls but writes these raw, and a
// terminal can act on them (U+009B is CSI). They can only occur inside JSON
// strings, so the escaped output decodes to exactly the same value.
func escapeDELAndC1(b []byte) []byte {
	if !bytes.ContainsFunc(b, isDELOrC1) {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if isDELOrC1(r) {
			out = fmt.Appendf(out, `\u%04x`, r)
		} else {
			out = append(out, b[:size]...)
		}
		b = b[size:]
	}
	return out
}
