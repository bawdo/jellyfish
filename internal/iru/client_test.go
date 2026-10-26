package iru

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientSetsAuthAndUserAgent(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn-abc", WithUserAgent("jellyfish/test"))
	if err := c.do(context.Background(), http.MethodGet, "/ping", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}

	if got == nil {
		t.Fatal("no request captured")
	}
	if h := got.Header.Get("Authorization"); h != "Bearer tkn-abc" {
		t.Fatalf("auth header %q", h)
	}
	if h := got.Header.Get("User-Agent"); !strings.HasPrefix(h, "jellyfish/") {
		t.Fatalf("user-agent header %q", h)
	}
}

func TestWithTimeoutSurvivesWithHTTPClient(t *testing.T) {
	const want = 7 * time.Second

	// WithTimeout before WithHTTPClient - the fragile ordering.
	c1 := NewClient("http://iru.test/api/v1", "tkn",
		WithTimeout(want),
		WithHTTPClient(&http.Client{}),
	)
	if c1.httpClient.Timeout != want {
		t.Errorf("WithTimeout then WithHTTPClient: timeout = %v, want %v", c1.httpClient.Timeout, want)
	}

	// WithHTTPClient before WithTimeout - the order that already worked.
	c2 := NewClient("http://iru.test/api/v1", "tkn",
		WithHTTPClient(&http.Client{}),
		WithTimeout(want),
	)
	if c2.httpClient.Timeout != want {
		t.Errorf("WithHTTPClient then WithTimeout: timeout = %v, want %v", c2.httpClient.Timeout, want)
	}
}

func TestWithHTTPClientKeepsAuthTransport(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	// A caller-supplied client with no Transport must still authenticate.
	c := NewClient(srv.URL, "tkn-xyz", WithHTTPClient(&http.Client{}))
	if err := c.do(context.Background(), http.MethodGet, "/ping", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if got == nil {
		t.Fatal("no request captured")
	}
	if h := got.Header.Get("Authorization"); h != "Bearer tkn-xyz" {
		t.Fatalf("auth header %q", h)
	}
}

func TestClientHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn", WithTimeout(50*time.Millisecond))
	err := c.do(context.Background(), http.MethodGet, "/slow", nil, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// bodyTransport answers every request in memory with a 200 and a fixed body.
type bodyTransport struct{ body string }

func (b bodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(b.body)),
		Request:    r,
	}, nil
}

func TestDecodeErrorTruncatesLargeBody(t *testing.T) {
	// Not valid JSON, and far longer than the excerpt bound.
	body := "{" + strings.Repeat("x", 10000)
	c := NewClient(testBaseURL, testToken, withBaseTransport(bodyTransport{body: body}))
	var out map[string]any
	err := c.do(context.Background(), http.MethodGet, "/users", nil, &out)
	if err == nil {
		t.Fatal("expected decode error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "decode response:") {
		t.Errorf("missing decode prefix: %q", msg)
	}
	if !strings.Contains(msg, "...(10001 bytes total)") {
		t.Errorf("missing truncation marker: %q", msg)
	}
	// The excerpt is "{" plus 511 x's: never 512 x's in a row.
	if strings.Contains(msg, strings.Repeat("x", maxRawExcerpt)) {
		t.Errorf("excerpt longer than %d bytes", maxRawExcerpt)
	}
	if !strings.Contains(msg, strings.Repeat("x", maxRawExcerpt-1)) {
		t.Errorf("excerpt shorter than expected")
	}
	if len(msg) > 2*maxRawExcerpt {
		t.Errorf("error message is %d bytes, want it bounded", len(msg))
	}
}

func TestDecodeErrorKeepsSmallBodyWhole(t *testing.T) {
	c := NewClient(testBaseURL, testToken, withBaseTransport(bodyTransport{body: "not json"}))
	var out map[string]any
	err := c.do(context.Background(), http.MethodGet, "/users", nil, &out)
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), `raw="not json")`) {
		t.Errorf("small body should be quoted whole: %q", err.Error())
	}
	if strings.Contains(err.Error(), "bytes total") {
		t.Errorf("small body should not carry a truncation marker: %q", err.Error())
	}
}

func TestRawExcerptBoundary(t *testing.T) {
	exact := strings.Repeat("a", maxRawExcerpt)
	if got := rawExcerpt([]byte(exact)); got != exact {
		t.Errorf("body of exactly %d bytes was altered", maxRawExcerpt)
	}
	over := exact + "b"
	want := exact + "...(513 bytes total)"
	if got := rawExcerpt([]byte(over)); got != want {
		t.Errorf("rawExcerpt(%d bytes) = %q, want %q", len(over), got, want)
	}
}

func TestNewClientDoesNotMutateCallerHTTPClient(t *testing.T) {
	hc := &http.Client{}
	c := NewClient(testBaseURL, testToken, WithHTTPClient(hc), WithTimeout(7*time.Second))

	if hc.Transport != nil {
		t.Errorf("caller's Transport was set to %T, want nil", hc.Transport)
	}
	if hc.CheckRedirect != nil {
		t.Error("caller's CheckRedirect was set, want nil")
	}
	if hc.Timeout != 0 {
		t.Errorf("caller's Timeout = %v, want 0", hc.Timeout)
	}
	if c.httpClient == hc {
		t.Fatal("Client shares the caller's *http.Client, want a copy")
	}
	// The copy still gets the auth and retry stack and the timeout.
	if _, ok := c.httpClient.Transport.(*authTransport); !ok {
		t.Errorf("copy Transport = %T, want *authTransport", c.httpClient.Transport)
	}
	if c.httpClient.CheckRedirect == nil {
		t.Error("copy has no CheckRedirect, want the redirect guard")
	}
	if c.httpClient.Timeout != 7*time.Second {
		t.Errorf("copy Timeout = %v, want 7s", c.httpClient.Timeout)
	}
}

func TestNewClientKeepsCallerTransportAndCheckRedirect(t *testing.T) {
	rt := bodyTransport{body: "{}"}
	called := false
	cr := func(*http.Request, []*http.Request) error { called = true; return nil }
	hc := &http.Client{Transport: rt, CheckRedirect: cr}
	c := NewClient(testBaseURL, testToken, WithHTTPClient(hc))

	if _, ok := c.httpClient.Transport.(bodyTransport); !ok {
		t.Errorf("Transport = %T, want the caller's bodyTransport", c.httpClient.Transport)
	}
	_ = c.httpClient.CheckRedirect(nil, nil)
	if !called {
		t.Error("caller's CheckRedirect was replaced")
	}
}
