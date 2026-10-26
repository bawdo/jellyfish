package iru

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusNotFound, ErrNotFound},
		{http.StatusTooManyRequests, ErrRateLimited},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(`{"detail":"nope"}`))
		}))
		client := NewClient(srv.URL, "tkn")
		err := client.do(context.Background(), http.MethodGet, "/x", nil, nil)
		srv.Close()
		if !errors.Is(err, c.want) {
			t.Fatalf("status %d: expected %v, got %v", c.status, c.want, err)
		}
	}
}

func TestAPIErrorCarriesStatusAndMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"bad subdomain"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %v", err)
	}
	if apiErr.Status != 400 {
		t.Fatalf("status: %d", apiErr.Status)
	}
	if apiErr.Message == "" {
		t.Fatalf("expected non-empty message")
	}
}

func TestDecodeAPIErrorBoundsBody(t *testing.T) {
	// An endless error body must be cut off at maxErrorBody, not read to
	// exhaustion.
	body := &endlessBody{}
	err := decodeAPIError(&http.Response{StatusCode: http.StatusBadGateway, Body: body})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadGateway {
		t.Fatalf("expected *APIError with status 502, got %v", err)
	}
	if got := body.read.Load(); got > maxErrorBody {
		t.Fatalf("read %d bytes of the body, want at most %d", got, maxErrorBody)
	}
}

func TestAPIErrorString(t *testing.T) {
	cases := []struct {
		err  *APIError
		want string
	}{
		{&APIError{Status: 500}, "iru: api error: status 500"},
		{&APIError{Status: 400, Message: "bad subdomain"}, "iru: api error: status 400: bad subdomain"},
	}
	for _, c := range cases {
		if got := c.err.Error(); got != c.want {
			t.Errorf("Error() = %q, want %q", got, c.want)
		}
	}
}

// Statuses without a sentinel must not match any of them, so they fall to
// the generic exit codes rather than auth or not-found.
func TestAPIErrorIsOnlyMatchesItsOwnSentinel(t *testing.T) {
	sentinels := []error{ErrUnauthorized, ErrForbidden, ErrNotFound, ErrRateLimited}
	for _, status := range []int{400, 409, 500, 502} {
		err := error(&APIError{Status: status})
		for _, s := range sentinels {
			if errors.Is(err, s) {
				t.Errorf("status %d matched %v", status, s)
			}
		}
	}
	if errors.Is(&APIError{Status: http.StatusNotFound}, ErrForbidden) {
		t.Error("404 must not match ErrForbidden")
	}
}

func TestDecodeAPIErrorMessage(t *testing.T) {
	cases := []struct {
		name, body, wantMsg, wantCode string
	}{
		{"detail and code", `{"detail":"nope","code":"E1"}`, "nope", "E1"},
		{"short plain text kept", "gateway exploded", "gateway exploded", ""},
		{"json without detail kept whole", `{"errors":["x"]}`, `{"errors":["x"]}`, ""},
		{"long plain text dropped", strings.Repeat("x", 512), "", ""},
		{"empty body", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := decodeAPIError(&http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader(c.body)),
			})
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected *APIError, got %v", err)
			}
			if apiErr.Status != http.StatusBadGateway || apiErr.Message != c.wantMsg || apiErr.Code != c.wantCode {
				t.Fatalf("got %+v, want message %q code %q", apiErr, c.wantMsg, c.wantCode)
			}
		})
	}
}
