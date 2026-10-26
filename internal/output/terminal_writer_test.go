package output

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestTerminalWriterStripsControlsKeepsNewline(t *testing.T) {
	var buf bytes.Buffer
	w := NewTerminalWriter(&buf)
	in := "error input=a\x1b]0;pwned\x07@x.com lookup: bad\r\x9b31m\tthing\n"
	n, err := fmt.Fprint(w, in)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(in) {
		t.Fatalf("n = %d, want %d (the caller's length, not the sanitised length)", n, len(in))
	}
	if got, want := buf.String(), "error input=a]0;pwned@x.com lookup: bad�31mthing\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTerminalWriterKeepsLeadingCarriageReturn(t *testing.T) {
	var buf bytes.Buffer
	w := NewTerminalWriter(&buf)
	_, _ = fmt.Fprintf(w, "\rfetching %s: %d pages...", "detections", 3)
	_, _ = fmt.Fprintf(w, "\rfetching %s: %d pages...", "detec\rtions\x1b[2K", 4)
	want := "\rfetching detections: 3 pages...\rfetching detections[2K: 4 pages..."
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTerminalWriterLeavesPlainTextAlone(t *testing.T) {
	var buf bytes.Buffer
	w := NewTerminalWriter(&buf)
	in := "sent input=keith@example.com to=keith@example.com gmail-id=abc\nKeith’s Mac – 日本語\n"
	_, _ = fmt.Fprint(w, in)
	if got := buf.String(); got != in {
		t.Fatalf("got %q, want unchanged %q", got, in)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestTerminalWriterPropagatesError(t *testing.T) {
	if _, err := NewTerminalWriter(failWriter{}).Write([]byte("x")); err == nil {
		t.Fatal("want error from underlying writer")
	}
}
