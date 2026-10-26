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
	}{
		{"absent uses backoff", "", backoff},
		{"zero is honoured", "0", 0},
		{"small seconds honoured", "5", 5 * time.Second},
		{"at cap honoured", "30", maxRetryAfter},
		{"above cap is clamped", "3600", maxRetryAfter},
		{"huge value is clamped", "999999999999", maxRetryAfter},
		{"negative falls back to backoff", "-5", backoff},
		{"http-date unsupported falls back to backoff", "Wed, 21 Oct 2015 07:28:00 GMT", backoff},
		{"garbage falls back to backoff", "soon", backoff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryWait(tc.retryAfter, backoff); got != tc.want {
				t.Fatalf("retryWait(%q) = %v, want %v", tc.retryAfter, got, tc.want)
			}
		})
	}
}

func TestRetryTransportWaitsOnLargeRetryAfterUntilCtxDone(t *testing.T) {
	// Wiring check without real sleeps: the server asks for an hour and the
	// context allows 50ms. The transport must be waiting (not retrying
	// immediately) and must return on the ctx deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var calls atomic.Int32
	rt := &retryTransport{base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		h := http.Header{}
		h.Set("Retry-After", "3600")
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.RoundTrip(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 attempt before ctx deadline, got %d", got)
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
