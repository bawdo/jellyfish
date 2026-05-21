package output

import (
	"fmt"
	"io"
)

// Renderer writes a value v to w in a specific format.
type Renderer interface {
	Render(w io.Writer, v any) error
}

// For returns the whole-value renderer for format. Only json and yaml are
// handled here; table and csv are column-based and must be built by the caller
// with Table()/CSV().WithColumns(...).
func For(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSON(), nil
	case "yaml":
		return YAML(), nil
	default:
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
}
