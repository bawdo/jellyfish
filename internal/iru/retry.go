package iru

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maxAttempts = 3

// maxRetryAfter caps how long a server-supplied Retry-After can stall a
// request, so a hostile or misconfigured hop can't hang the CLI.
const maxRetryAfter = 30 * time.Second

// retryWait returns how long to wait before the next attempt. A Retry-After
// value in whole seconds is honoured, clamped to maxRetryAfter. Anything else
// (absent, negative, HTTP-date form, garbage) falls back to backoff.
func retryWait(retryAfter string, backoff time.Duration) time.Duration {
	if retryAfter == "" {
		return backoff
	}
	secs, err := strconv.ParseInt(retryAfter, 10, 64)
	if err != nil || secs < 0 {
		return backoff
	}
	// Compare in seconds before converting so huge values can't overflow
	// time.Duration.
	if secs >= int64(maxRetryAfter/time.Second) {
		return maxRetryAfter
	}
	return time.Duration(secs) * time.Second
}

// retryTransport retries idempotent requests on 429 and 5xx with backoff.
type retryTransport struct {
	base http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return t.base.RoundTrip(req)
	}

	ctx := req.Context()
	var lastResp *http.Response
	var lastErr error
	backoff := 200 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := t.base.RoundTrip(req.Clone(ctx))
		if err == nil && !shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		wait := backoff
		if err != nil {
			lastErr = err
		} else {
			// Buffer the body before closing so a later decodeAPIError on the
			// returned lastResp still sees the upstream error text. Reading to
			// EOF then closing also lets the transport reuse the connection.
			buf, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(buf))
			lastResp = resp
			wait = retryWait(resp.Header.Get("Retry-After"), backoff)
		}

		if attempt == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		backoff *= 2
	}

	if lastResp != nil {
		return lastResp, nil
	}
	return nil, lastErr
}

func shouldRetry(status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && status <= 599
}
