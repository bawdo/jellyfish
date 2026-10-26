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
	scheme, host, path, auth string
}

func (f *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.seen = append(f.seen, seenRequest{
		scheme: r.URL.Scheme,
		host:   r.URL.Host,
		path:   r.URL.Path,
		auth:   r.Header.Get("Authorization"),
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

// downgradeToHTTP sends every https request to the same host over plain http.
func downgradeToHTTP(r *http.Request) *http.Response {
	if r.URL.Scheme == "https" {
		return fakeResponse(r, http.StatusFound, "http://"+testAPIHost+"/api/v1/devices")
	}
	return fakeResponse(r, http.StatusOK, "")
}

func TestSchemeDowngradeRedirectIsRefused(t *testing.T) {
	fake := &recordingTransport{respond: downgradeToHTTP}
	c := NewClient(testBaseURL, testToken, withBaseTransport(fake))

	err := c.do(context.Background(), http.MethodGet, "/devices", nil, nil)
	if err == nil {
		t.Fatal("expected an error refusing the https to http redirect, got nil")
	}
	for _, s := range fake.seen {
		if s.scheme != "https" {
			t.Fatalf("redirect was followed to %s://%s (Authorization %q)", s.scheme, s.host, s.auth)
		}
	}
}

func TestAuthTransportSkipsSchemeDowngrade(t *testing.T) {
	// Defence in depth: even if a caller-supplied CheckRedirect follows a
	// same-host https to http redirect, the token must not go in plaintext.
	fake := &recordingTransport{respond: downgradeToHTTP}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	c := NewClient(testBaseURL, testToken, WithHTTPClient(hc), withBaseTransport(fake))

	if err := c.do(context.Background(), http.MethodGet, "/devices", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if len(fake.seen) != 2 || fake.seen[1].scheme != "http" {
		t.Fatalf("requests = %+v, want the caller's CheckRedirect to follow to http", fake.seen)
	}
	if got := fake.seen[0].auth; got != "Bearer "+testToken {
		t.Fatalf("https request Authorization = %q, want bearer token", got)
	}
	if got := fake.seen[1].auth; got != "" {
		t.Fatalf("plain http request received Authorization %q, want none", got)
	}
}

func TestAuthTransportSchemeMatchIsCaseInsensitive(t *testing.T) {
	var got string
	at := &authTransport{
		token:  testToken,
		scheme: "https",
		host:   testAPIHost,
		base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			got = r.Header.Get("Authorization")
			return fakeResponse(r, http.StatusOK, ""), nil
		}),
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+testAPIHost+"/api/v1/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.Scheme = "HTTPS"
	if _, err := at.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer "+testToken {
		t.Fatalf("Authorization = %q, want bearer token for upper-case scheme", got)
	}
}

// A same-origin redirect loop is still cut off at Go's usual cap of ten
// requests, with the token sent only to the API host.
func TestSameHostRedirectLoopIsCapped(t *testing.T) {
	fake := &recordingTransport{respond: func(r *http.Request) *http.Response {
		return fakeResponse(r, http.StatusFound, testBaseURL+"/devices")
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(fake))

	err := c.do(context.Background(), http.MethodGet, "/devices", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("expected the redirect cap error, got %v", err)
	}
	if len(fake.seen) != 10 {
		t.Fatalf("requests = %d, want 10", len(fake.seen))
	}
	for i, s := range fake.seen {
		if s.host != testAPIHost || s.auth != "Bearer "+testToken {
			t.Fatalf("request %d went to %s with Authorization %q", i, s.host, s.auth)
		}
	}
}
