package iru

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryWait(t *testing.T) {
	const backoff = 200 * time.Millisecond
	cases := []struct {
		name       string
		retryAfter string
		want       time.Duration
		wantOK     bool
	}{
		{"absent uses backoff", "", backoff, true},
		{"zero is honoured", "0", 0, true},
		{"small seconds honoured", "5", 5 * time.Second, true},
		{"at cap honoured", "10", maxRetryAfter, true},
		{"just above cap gives up", "11", 0, false},
		{"old 30s cap gives up", "30", 0, false},
		{"far above cap gives up", "3600", 0, false},
		{"huge value gives up", "999999999999", 0, false},
		{"negative falls back to backoff", "-5", backoff, true},
		{"http-date unsupported falls back to backoff", "Wed, 21 Oct 2015 07:28:00 GMT", backoff, true},
		{"garbage falls back to backoff", "soon", backoff, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := retryWait(tc.retryAfter, backoff)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("retryWait(%q) = (%v, %v), want (%v, %v)", tc.retryAfter, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestMaxRetryAfterBelowDefaultTimeout(t *testing.T) {
	// A cap equal to the client timeout can never be honoured in full.
	c := NewClient(testBaseURL, testToken)
	if maxRetryAfter >= c.httpClient.Timeout {
		t.Fatalf("maxRetryAfter %v must be below the default client timeout %v", maxRetryAfter, c.httpClient.Timeout)
	}
}

func TestWaitFitsDeadline(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		deadline    time.Time
		hasDeadline bool
		wait        time.Duration
		want        bool
	}{
		{"no deadline always fits", time.Time{}, false, time.Hour, true},
		{"leaves more than the margin fits", now.Add(2 * time.Second), true, 500 * time.Millisecond, true},
		{"leaves exactly the margin fits", now.Add(2 * time.Second), true, 2*time.Second - retryMargin, true},
		{"leaves just under the margin does not fit", now.Add(2 * time.Second), true, 2*time.Second - retryMargin + time.Nanosecond, false},
		{"ends before deadline but inside the margin does not fit", now.Add(time.Second), true, 500 * time.Millisecond, false},
		{"ends exactly at deadline does not fit", now.Add(time.Second), true, time.Second, false},
		{"ends after deadline does not fit", now.Add(200 * time.Millisecond), true, 5 * time.Second, false},
		{"deadline already passed does not fit", now.Add(-time.Second), true, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := waitFitsDeadline(tc.deadline, tc.hasDeadline, now, tc.wait); got != tc.want {
				t.Fatalf("waitFitsDeadline = %v, want %v", got, tc.want)
			}
		})
	}
}

// rateLimited returns a fake base transport that always answers 429 with the
// given Retry-After and a recognisable body, counting the calls it sees.
func rateLimited(calls *atomic.Int32, retryAfter string) http.RoundTripper {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		h := http.Header{}
		h.Set("Retry-After", retryAfter)
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader(`{"detail":"slow down"}`)),
			Request:    r,
		}, nil
	})
}

// roundTripWithin runs rt.RoundTrip(req) and fails the test if it takes
// longer than limit, so a regression shows up as a failure, not a hang.
func roundTripWithin(t *testing.T, rt http.RoundTripper, req *http.Request, limit time.Duration) (*http.Response, error) {
	t.Helper()
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := rt.RoundTrip(req)
		done <- result{resp, err}
	}()
	select {
	case r := <-done:
		return r.resp, r.err
	case <-time.After(limit):
		t.Fatalf("RoundTrip did not return within %v", limit)
		return nil, nil
	}
}

func assertRateLimitedResponse(t *testing.T, resp *http.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected the 429 response, got error %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %+v", resp)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"detail":"slow down"}` {
		t.Fatalf("expected upstream body preserved, got %q", body)
	}
}

func TestRetryTransportReturns429WhenWaitWouldPassDeadline(t *testing.T) {
	// The server asks for 5s (inside the cap) but the ctx only allows 200ms.
	// Waiting would only end in a ctx error, so the 429 itself comes back.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var calls atomic.Int32
	rt := &retryTransport{base: rateLimited(&calls, "5")}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := roundTripWithin(t, rt, req, 2*time.Second)
	assertRateLimitedResponse(t, resp, err)
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
	// Well under the 5s Retry-After, with room for a slow -race run.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected an immediate return, took %v", elapsed)
	}
}

func TestRetryTransportReturns429WhenWaitLeavesNoRoomForRetry(t *testing.T) {
	// The 2s wait ends before the 2.5s deadline, but with less than
	// retryMargin to spare, so the retry would likely time out. The 429
	// comes back straight away instead.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second+500*time.Millisecond)
	defer cancel()

	var calls atomic.Int32
	rt := &retryTransport{base: rateLimited(&calls, "2")}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	resp, err := roundTripWithin(t, rt, req, 4*time.Second)
	assertRateLimitedResponse(t, resp, err)
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected an immediate return, not the 2s wait, took %v", elapsed)
	}
}

// endlessBody is an unbounded response body that counts the bytes read from
// it and records whether it was closed.
type endlessBody struct {
	read   atomic.Int64
	closed atomic.Bool
}

func (b *endlessBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read.Add(int64(len(p)))
	return len(p), nil
}

func (b *endlessBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestRetryTransportBoundsErrorBody(t *testing.T) {
	// A 429 with an endless body must not be buffered in full. Retry-After
	// above the cap returns the response after the first attempt.
	body := &endlessBody{}
	rt := &retryTransport{base: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		h := http.Header{}
		h.Set("Retry-After", "3600")
		return &http.Response{StatusCode: http.StatusTooManyRequests, Header: h, Body: body, Request: r}, nil
	})}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := roundTripWithin(t, rt, req, 2*time.Second)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := body.read.Load(); got > maxErrorBody {
		t.Fatalf("read %d bytes of the upstream body, want at most %d", got, maxErrorBody)
	}
	if !body.closed.Load() {
		t.Fatal("upstream body was not closed")
	}
	buf, _ := io.ReadAll(resp.Body)
	if len(buf) != maxErrorBody {
		t.Fatalf("buffered body = %d bytes, want %d", len(buf), maxErrorBody)
	}
}

func TestRetryTransportReturns429WhenRetryAfterExceedsCap(t *testing.T) {
	// No deadline at all: a Retry-After above the cap must not be waited out.
	var calls atomic.Int32
	rt := &retryTransport{base: rateLimited(&calls, "3600")}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := roundTripWithin(t, rt, req, 2*time.Second)
	assertRateLimitedResponse(t, resp, err)
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
}

func TestClientTimeoutSurfacesRateLimit(t *testing.T) {
	// End to end: http.Client.Timeout puts a deadline on the request ctx. A
	// Retry-After that would outlast it must surface as ErrRateLimited, not
	// as a deadline error.
	var calls atomic.Int32
	c := NewClient(testBaseURL, testToken,
		WithTimeout(200*time.Millisecond),
		withBaseTransport(rateLimited(&calls, "5")))

	done := make(chan error, 1)
	go func() { done <- c.do(context.Background(), http.MethodGet, "/devices", nil, nil) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("expected ErrRateLimited, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("do did not return within 2s")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
}

func TestRetriesOn429ThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	if err := c.do(context.Background(), http.MethodGet, "/x", nil, nil); err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestRetryPreservesErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"detail":"slow down"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %v", err)
	}
	if apiErr.Message != "slow down" {
		t.Fatalf("expected upstream message to survive retries, got %q", apiErr.Message)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRetryHonoursContextCancellationOnTransportError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls atomic.Int32
	rt := &retryTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("dial tcp: connection refused")
	})}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled when ctx is cancelled mid-retry, got %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected to stop after 1 attempt once ctx is cancelled, got %d", got)
	}
}

func TestRetriesGiveUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil {
		t.Fatal("expected failure after exhausting retries")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}
