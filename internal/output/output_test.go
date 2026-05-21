package output

import "testing"

func TestForReturnsWholeValueRenderers(t *testing.T) {
	for _, format := range []string{"json", "yaml"} {
		r, err := For(format)
		if err != nil {
			t.Fatalf("For(%q): unexpected error %v", format, err)
		}
		if r == nil {
			t.Fatalf("For(%q): nil renderer", format)
		}
	}
}

func TestForRejectsColumnAndUnknownFormats(t *testing.T) {
	// table and csv are column-based and cannot be built by For; everything
	// unrecognised is also an error.
	for _, format := range []string{"table", "csv", "", "bogus"} {
		r, err := For(format)
		if err == nil {
			t.Fatalf("For(%q): expected an error, got renderer %v", format, r)
		}
	}
}
