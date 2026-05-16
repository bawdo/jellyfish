package email

import (
	"html/template"
	"strings"
	"testing"
)

func TestLinkifyHTMLEscapesPlainText(t *testing.T) {
	got := linkifyHTML(`a <b> & "c"`)
	want := template.HTML(`a &lt;b&gt; &amp; &#34;c&#34;`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLWrapsSimpleURL(t *testing.T) {
	got := linkifyHTML(`see https://example.com here`)
	want := template.HTML(`see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a> here`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLExcludesTrailingPunctuation(t *testing.T) {
	got := linkifyHTML(`see https://example.com.`)
	want := template.HTML(`see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a>.`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLExcludesTrailingClosingParen(t *testing.T) {
	got := linkifyHTML(`(see https://example.com)`)
	want := template.HTML(`(see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a>)`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLHandlesMultipleURLs(t *testing.T) {
	got := linkifyHTML(`a https://x.test b https://y.test c`)
	want := template.HTML(`a <a href="https://x.test" style="color:#0f172a;text-decoration:underline;">https://x.test</a> b <a href="https://y.test" style="color:#0f172a;text-decoration:underline;">https://y.test</a> c`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLHandlesHTTPScheme(t *testing.T) {
	got := linkifyHTML(`http://example.com`)
	want := template.HTML(`<a href="http://example.com" style="color:#0f172a;text-decoration:underline;">http://example.com</a>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinkifyHTMLNoURL(t *testing.T) {
	got := linkifyHTML(`just plain text`)
	want := template.HTML(`just plain text`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLSingleParagraph(t *testing.T) {
	got := paragraphsHTML(`hi team`)
	want := template.HTML(`<p style="margin:0 0 10px;">hi team</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLMultipleParagraphs(t *testing.T) {
	got := paragraphsHTML("para one\n\npara two")
	want := template.HTML(`<p style="margin:0 0 10px;">para one</p><p style="margin:0 0 10px;">para two</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLLineBreakInsideParagraph(t *testing.T) {
	got := paragraphsHTML("line one\nline two")
	want := template.HTML(`<p style="margin:0 0 10px;">line one<br>line two</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLLinkifiesPerParagraph(t *testing.T) {
	got := paragraphsHTML("see https://example.com\n\nbye")
	want := template.HTML(`<p style="margin:0 0 10px;">see <a href="https://example.com" style="color:#0f172a;text-decoration:underline;">https://example.com</a></p><p style="margin:0 0 10px;">bye</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLEmptyInput(t *testing.T) {
	got := paragraphsHTML(``)
	if got != template.HTML(``) {
		t.Fatalf("got %q want empty", got)
	}
}

func TestParagraphsHTMLCollapsesMultipleBlankLines(t *testing.T) {
	got := paragraphsHTML("a\n\n\n\nb")
	want := template.HTML(`<p style="margin:0 0 10px;">a</p><p style="margin:0 0 10px;">b</p>`)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParagraphsHTMLNULInURLDoesNotBreakAnchor(t *testing.T) {
	// A NUL inside a URL must not be wrapped into the href — paragraphsHTML
	// uses NUL as a line-break placeholder, so any NUL in a URL match would
	// otherwise be rewritten to <br> inside the href attribute.
	got := paragraphsHTML("see https://x.test/a\x00b end")
	wantPrefix := `<p style="margin:0 0 10px;">see <a href="https://x.test/a"`
	if !strings.HasPrefix(string(got), wantPrefix) {
		t.Fatalf("URL should stop at NUL; got:\n%s", got)
	}
	if strings.Contains(string(got), `<br>end" `) || strings.Contains(string(got), `<br>end" style=`) {
		t.Fatalf("NUL inside URL match leaked into href attribute; got:\n%s", got)
	}
}
