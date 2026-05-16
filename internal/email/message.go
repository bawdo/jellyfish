package email

import (
	"html"
	"html/template"
	"regexp"
	"strings"
)

// urlPattern matches http:// or https:// followed by anything that is not
// whitespace or HTML-significant. Trailing punctuation is trimmed after the
// match (see linkifyHTML).
var urlPattern = regexp.MustCompile(`https?://[^\x00\s<>"']+`)

// linkifyHTML returns plain escaped for HTML, with http(s):// URLs wrapped in
// <a> anchors. Trailing . , ; : ) characters at the end of a URL match are
// excluded from the anchor so "see https://x.test." renders the period
// outside the link.
func linkifyHTML(plain string) template.HTML {
	if plain == "" {
		return ""
	}
	var sb strings.Builder
	idx := 0
	for _, loc := range urlPattern.FindAllStringIndex(plain, -1) {
		start, end := loc[0], loc[1]
		// Peel trailing punctuation back out of the URL.
		for end > start && strings.ContainsRune(".,;:)", rune(plain[end-1])) {
			end--
		}
		sb.WriteString(html.EscapeString(plain[idx:start]))
		raw := plain[start:end]
		escapedURL := html.EscapeString(raw)
		sb.WriteString(`<a href="`)
		sb.WriteString(escapedURL)
		sb.WriteString(`" style="color:#0f172a;text-decoration:underline;">`)
		sb.WriteString(escapedURL)
		sb.WriteString(`</a>`)
		idx = end
	}
	sb.WriteString(html.EscapeString(plain[idx:]))
	// #nosec G203 - body is html.EscapeString-escaped above; only the literal <a>...</a> wrappers and the inline style are raw
	return template.HTML(sb.String())
}

// blankLineRun splits a string on runs of one or more blank lines (lines
// containing only whitespace).
var blankLineRun = regexp.MustCompile(`(?:\r?\n[ \t]*){2,}`)

// paragraphsHTML wraps each paragraph (separated by blank-line runs) in a
// styled <p>, calls linkifyHTML on the paragraph body, and replaces single
// newlines inside a paragraph with <br>. Empty input returns empty.
func paragraphsHTML(plain string) template.HTML {
	if plain == "" {
		return ""
	}
	paragraphs := blankLineRun.Split(plain, -1)
	var sb strings.Builder
	for _, p := range paragraphs {
		p = strings.TrimRight(p, "\r\n")
		if p == "" {
			continue
		}
		lines := strings.Split(p, "\n")
		for i, line := range lines {
			lines[i] = strings.TrimRight(line, "\r")
		}
		body := strings.Join(lines, "\x00") // placeholder we can swap to <br> after escaping
		linked := string(linkifyHTML(body))
		linked = strings.ReplaceAll(linked, "\x00", "<br>")
		sb.WriteString(`<p style="margin:0 0 10px;">`)
		sb.WriteString(linked)
		sb.WriteString(`</p>`)
	}
	// #nosec G203 - body is built from linkifyHTML output (already escaped) and literal <p>/<br> tags
	return template.HTML(sb.String())
}
