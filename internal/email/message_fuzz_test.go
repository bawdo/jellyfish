package email

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

// anchorRe matches exactly the anchor linkifyHTML writes, capturing the href
// and the link text.
var anchorRe = regexp.MustCompile(`<a href="([^"<>]*)" style="color:#0f172a;text-decoration:underline;">([^"<>]*)</a>`)

// FuzzLinkifyHTML checks that linkifyHTML, whose output is trusted as
// template.HTML, can't be talked into emitting markup of the input's
// choosing. The only raw tags in the output are its own anchors, each with an
// http(s) href equal to its text, and once those are unwrapped and the
// entities decoded the input comes back exactly.
func FuzzLinkifyHTML(f *testing.F) {
	for _, s := range []string{
		"",
		"plain message, no links",
		"see https://x.test.",
		"(docs at https://x.test/a?b=1&c=2), then http://y.test;",
		`<script>alert(1)</script> https://x.test/"><img src=x onerror=alert(1)>`,
		"https://x.test/'onmouseover='alert(1)",
		"javascript:alert(1) https://ok.test",
		"https://\x00x.test",
		"https://x.test/é\xff",
		"&amp; &lt;b&gt; https://x.test/?a=&lt;",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, plain string) {
		out := string(linkifyHTML(plain))
		for _, m := range anchorRe.FindAllStringSubmatch(out, -1) {
			href, text := m[1], m[2]
			if href != text {
				t.Fatalf("linkifyHTML(%q): href %q differs from text %q", plain, href, text)
			}
			if u := html.UnescapeString(href); !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				t.Fatalf("linkifyHTML(%q): href %q is not http(s)", plain, href)
			}
		}
		unwrapped := anchorRe.ReplaceAllString(out, "$2")
		if strings.ContainsAny(unwrapped, `<>"'`) {
			t.Fatalf("linkifyHTML(%q) = %q: raw markup outside the anchors", plain, out)
		}
		if got := html.UnescapeString(unwrapped); got != plain {
			t.Fatalf("linkifyHTML(%q) = %q: text decodes to %q", plain, out, got)
		}
	})
}
