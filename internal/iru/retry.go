package iru

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maxAttempts = 3

// maxRetryAfter is the longest server-supplied Retry-After the transport will
// wait out. It sits well below the default 30s http.Client.Timeout so a
// honoured wait still leaves room for the retry itself. A longer request is
// not waited on at all: the 429/5xx goes straight back to the caller, which
// maps it to a clear rate-limit or upstream error instead of a timeout.
const maxRetryAfter = 10 * time.Second

// retryWait returns how long to wait before the next attempt, and false when
// the server asked for longer than maxRetryAfter (the caller should stop
// retrying and return the response it has). A Retry-After value in whole
// seconds is honoured. Anything else (absent, negative, HTTP-date form,
// garbage) falls back to backoff.
func retryWait(retryAfter string, backoff time.Duration) (time.Duration, bool) {
	if retryAfter == "" {
		return backoff, true
	}
	secs, err := strconv.ParseInt(retryAfter, 10, 64)
	if err != nil || secs < 0 {
		return backoff, true
	}
	// Compare in seconds before converting so huge values can't overflow
	// time.Duration.
	if secs > int64(maxRetryAfter/time.Second) {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

// waitFitsDeadline reports whether a wait starting at now ends before the
// deadline. Without a deadline any wait fits. A wait that ends at or after
// the deadline would only produce a context error, so it does not fit.
func waitFitsDeadline(deadline time.Time, hasDeadline bool, now time.Time, wait time.Duration) bool {
	if !hasDeadline {
		return true
	}
	return now.Add(wait).Before(deadline)
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
			var ok bool
			if wait, ok = retryWait(resp.Header.Get("Retry-After"), backoff); !ok {
				// The server wants longer than we are prepared to wait.
				return lastResp, nil
			}
		}

		if attempt == maxAttempts {
			break
		}
		// http.Client.Timeout surfaces here as a ctx deadline. If the wait
		// would outlast it, give the caller the response we have now rather
		// than a context error later.
		if dl, ok := ctx.Deadline(); !waitFitsDeadline(dl, ok, time.Now(), wait) {
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
