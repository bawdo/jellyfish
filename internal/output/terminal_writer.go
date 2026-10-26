package output

import (
	"bytes"
	"io"
)

// terminalWriter sanitises everything written through it with
// SanitiseTerminalText, so text bound for the admin's terminal (stderr
// status lines carrying user records, upstream error text and the like)
// cannot smuggle in ESC/CSI/OSC sequences.
type terminalWriter struct {
	w io.Writer
}

// NewTerminalWriter returns a writer that strips terminal controls from
// every Write before passing it to w. Newline is kept, as is a carriage
// return that opens a Write: that is the "\rfetching ...: N pages" progress
// idiom, where the format string (never the data) supplies the leading \r.
// A \r anywhere else is removed, so data cannot overwrite earlier output.
//
// Each Write is sanitised on its own, so callers must write whole strings
// (fmt.Fprint* always does); a multi-byte rune split across two Writes would
// be replaced with U+FFFD.
func NewTerminalWriter(w io.Writer) io.Writer {
	return &terminalWriter{w: w}
}

func (t *terminalWriter) Write(p []byte) (int, error) {
	prefix := ""
	body := p
	if len(body) > 0 && body[0] == '\r' {
		prefix = "\r"
		body = bytes.TrimLeft(body, "\r")
	}
	if _, err := io.WriteString(t.w, prefix+SanitiseTerminalText(string(body))); err != nil {
		return 0, err
	}
	return len(p), nil
}
