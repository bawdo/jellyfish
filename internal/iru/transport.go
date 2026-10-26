package iru

import (
	"net/http"
	"strings"
)

// authTransport adds Authorization: Bearer <token> to requests bound for the
// API host only. Requests to any other host (e.g. a followed redirect) go out
// without the token. It does not log the token.
type authTransport struct {
	token string
	host  string // API host from baseURL; compared case-insensitively
	base  http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !sameHost(req.URL.Host, t.host) {
		return t.base.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r)
}

// sameHost reports whether host matches the API host. An empty API host
// (unparseable baseURL) never matches, so the token is withheld.
func sameHost(host, apiHost string) bool {
	return apiHost != "" && strings.EqualFold(host, apiHost)
}
