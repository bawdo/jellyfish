package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONRendererSimpleStruct(t *testing.T) {
	r := JSON()
	buf := &bytes.Buffer{}
	type item struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	if err := r.Render(buf, item{Name: "rover", Age: 4}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"name": "rover"`) {
		t.Fatalf("bad JSON output: %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected trailing newline, got %q", out)
	}
}

// encoding/json escapes C0 controls but writes DEL and C1 controls raw. They
// must be escaped too, without changing what the JSON decodes to.
func TestJSONRendererEscapesDELAndC1(t *testing.T) {
	type item struct {
		Name string `json:"name"`
	}
	in := item{Name: "a\x1b[2Jb\u009b31m\x7fc\u0080\u009fé"}
	buf := &bytes.Buffer{}
	if err := JSON().Render(buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, r := range out {
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) || (r < 0x20 && r != '\n') {
			t.Fatalf("raw control %U in output %q", r, out)
		}
	}
	if !strings.Contains(out, `\u009b`) || !strings.Contains(out, `\u007f`) {
		t.Fatalf("expected \\u009b and \\u007f escapes, got %q", out)
	}
	var back item
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output no longer decodes: %v", err)
	}
	if back != in {
		t.Fatalf("round trip: got %q want %q", back.Name, in.Name)
	}
}
