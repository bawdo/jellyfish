package iru

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// recordingTransport is an in-memory RoundTripper. It records the path and
// Authorization header of every request it sees and answers via respond.
type recordingTransport struct {
	seen    []seenRequest
	respond func(r *http.Request) *http.Response
}

type seenRequest struct {
	host, path, auth string
}

func (f *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.seen = append(f.seen, seenRequest{
		host: r.URL.Host,
		path: r.URL.Path,
		auth: r.Header.Get("Authorization"),
	})
	return f.respond(r), nil
}

func fakeResponse(r *http.Request, status int, location string) *http.Response {
	h := http.Header{}
	if location != "" {
		h.Set("Location", location)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(`{}`)),
		Request:    r,
	}
}

const (
	testAPIHost = "acme.api.kandji.io"
	testBaseURL = "https://" + testAPIHost + "/api/v1"
	testToken   = "SECRET-TOKEN"
)

// redirectToEvil sends every API-host request to a foreign host.
func redirectToEvil(r *http.Request) *http.Response {
	if r.URL.Host == testAPIHost {
		return fakeResponse(r, http.StatusFound, "https://evil.example/steal")
	}
	return fakeResponse(r, http.StatusOK, "")
}

func TestAuthHeaderSentToAPIHost(t *testing.T) {
	fake := &recordingTransport{respond: func(r *http.Request) *http.Response {
		return fakeResponse(r, http.StatusOK, "")
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(fake))

	if err := c.do(context.Background(), http.MethodGet, "/devices", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if len(fake.seen) != 1 || fake.seen[0].auth != "Bearer "+testToken {
		t.Fatalf("requests = %+v, want one carrying the bearer token", fake.seen)
	}
}

func TestCrossHostRedirectIsRefused(t *testing.T) {
	fake := &recordingTransport{respond: redirectToEvil}
	c := NewClient(testBaseURL, testToken, withBaseTransport(fake))

	err := c.do(context.Background(), http.MethodGet, "/users", nil, nil)
	if err == nil {
		t.Fatal("expected an error refusing the cross-host redirect, got nil")
	}
	for _, s := range fake.seen {
		if s.host != testAPIHost {
			t.Fatalf("redirect was followed to %s (Authorization %q)", s.host, s.auth)
		}
	}
}

func TestAuthTransportSkipsForeignHost(t *testing.T) {
	// Defence in depth: even if a caller-supplied CheckRedirect follows a
	// cross-host redirect, the token must not go with it.
	fake := &recordingTransport{respond: redirectToEvil}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	c := NewClient(testBaseURL, testToken, WithHTTPClient(hc), withBaseTransport(fake))

	if err := c.do(context.Background(), http.MethodGet, "/users", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if len(fake.seen) != 2 || fake.seen[1].host != "evil.example" {
		t.Fatalf("requests = %+v, want the caller's CheckRedirect to follow to evil.example", fake.seen)
	}
	if got := fake.seen[1].auth; got != "" {
		t.Fatalf("evil.example received Authorization %q, want none", got)
	}
}

func TestSameHostRedirectKeepsToken(t *testing.T) {
	fake := &recordingTransport{respond: func(r *http.Request) *http.Response {
		if r.URL.Path == "/api/v1/devices" {
			// Upper-case host: host matching must be case-insensitive.
			return fakeResponse(r, http.StatusFound, "https://ACME.api.kandji.io/api/v1/devices/")
		}
		return fakeResponse(r, http.StatusOK, "")
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(fake))

	if err := c.do(context.Background(), http.MethodGet, "/devices", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if len(fake.seen) != 2 {
		t.Fatalf("requests = %+v, want the original and one redirect", fake.seen)
	}
	for i, s := range fake.seen {
		if s.auth != "Bearer "+testToken {
			t.Fatalf("request %d (%s%s) Authorization = %q, want bearer token", i, s.host, s.path, s.auth)
		}
	}
}
