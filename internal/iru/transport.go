package iru

import (
	"net/http"
	"net/url"
	"strings"
)

// authTransport adds Authorization: Bearer <token> to requests bound for the
// API origin (scheme and host from baseURL) only. Requests anywhere else,
// such as a followed redirect to another host or a same-host downgrade from
// https to http, go out without the token. It does not log the token.
type authTransport struct {
	token  string
	scheme string // API scheme from baseURL; compared case-insensitively
	host   string // API host from baseURL; compared case-insensitively
	base   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !sameOrigin(req.URL, t.scheme, t.host) {
		return t.base.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

// sameOrigin reports whether u has the API scheme and host. An empty API
// scheme or host (unparseable baseURL) never matches, so the token is
// withheld. Matching the base scheme rather than demanding https keeps
// plain http test servers working while still refusing a downgrade.
func sameOrigin(u *url.URL, apiScheme, apiHost string) bool {
	return apiScheme != "" && strings.EqualFold(u.Scheme, apiScheme) && sameHost(u.Host, apiHost)
}

// sameHost reports whether host matches the API host. An empty API host
// (unparseable baseURL) never matches, so the token is withheld.
func sameHost(host, apiHost string) bool {
	return apiHost != "" && strings.EqualFold(host, apiHost)
}
