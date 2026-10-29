package iru

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FuzzNextCursor covers both shapes Iru returns in `next`. A cursor wrapped
// in a /users style URL must come back out exactly, a value with no colon
// (so no scheme) is a raw /detections cursor and must come back unchanged,
// and an arbitrary value is only ever rewritten when it parsed as an
// absolute URL.
func FuzzNextCursor(f *testing.F) {
	for _, s := range []string{
		"",
		"cD0yMDI0LTAxLTAxKzAwJTNBMDAlM0EwMA==",
		"https://acme.api.kandji.io/api/v1/users?cursor=cD0x&limit=300",
		"https://acme.api.kandji.io/api/v1/users?limit=300",
		"http://[::1",
		"a b&c=d;e",
		"%zz",
		"javascript:alert(1)",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := (paginated[int]{}).nextCursor(); got != "" {
			t.Fatalf("nil next: got %q, want empty", got)
		}

		users := "https://acme.api.kandji.io/api/v1/users?cursor=" + url.QueryEscape(s) + "&limit=300"
		if got := (paginated[int]{Next: &users}).nextCursor(); got != s {
			t.Fatalf("users-shape next %q: got cursor %q, want %q", users, got, s)
		}

		got := (paginated[int]{Next: &s}).nextCursor()
		if !strings.Contains(s, ":") && got != s {
			t.Fatalf("raw cursor %q: got %q, want it unchanged", s, got)
		}
		if got != s {
			if u, err := url.Parse(s); err != nil || u.Scheme == "" {
				t.Fatalf("next %q rewritten to %q but is not an absolute URL", s, got)
			}
		}
	})
}

// FuzzDecodeAPIError feeds arbitrary statuses and error bodies through
// decodeAPIError. The status must survive, errors.Is must map exactly the
// documented statuses onto their sentinels (classifyError's exit codes rest
// on that), and Message must be either the JSON detail or, for a short body
// with none, the body itself.
func FuzzDecodeAPIError(f *testing.F) {
	for _, c := range []struct {
		status int
		body   string
	}{
		{400, `{"detail":"bad request","code":"invalid"}`},
		{401, `{"detail":"Invalid token."}`},
		{403, `{"errors":["nope"]}`},
		{404, ``},
		{429, `rate limited`},
		{500, `<html>oops</html>`},
		{502, `{"detail":""}`},
		{418, `null`},
		{400, `{"detail":5}`},
	} {
		f.Add(c.status, []byte(c.body))
	}
	sentinels := map[int]error{
		http.StatusUnauthorized:    ErrUnauthorized,
		http.StatusForbidden:       ErrForbidden,
		http.StatusNotFound:        ErrNotFound,
		http.StatusTooManyRequests: ErrRateLimited,
	}
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		resp := &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body))}
		err := decodeAPIError(resp)
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("decodeAPIError returned %T, want *APIError", err)
		}
		if apiErr.Status != status {
			t.Fatalf("Status = %d, want %d", apiErr.Status, status)
		}
		for code, sentinel := range sentinels {
			if got := errors.Is(err, sentinel); got != (status == code) {
				t.Fatalf("status %d: errors.Is(%v) = %v", status, sentinel, got)
			}
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
			t.Fatalf("Error() = %q does not name status %d", err.Error(), status)
		}

		read := body
		if len(read) > maxErrorBody {
			read = read[:maxErrorBody]
		}
		var payload struct {
			Detail string `json:"detail"`
			Code   string `json:"code"`
		}
		decoded := json.Unmarshal(read, &payload) == nil
		switch {
		case apiErr.Message == "":
			if decoded && payload.Detail != "" {
				t.Fatalf("detail %q dropped", payload.Detail)
			}
		case decoded && apiErr.Message == payload.Detail:
		case apiErr.Message == string(read) && len(read) < 512:
		default:
			t.Fatalf("Message %q is neither the detail nor a short raw body", apiErr.Message)
		}
	})
}

// FuzzRetryWait checks the Retry-After handling, a server-controlled header.
// Whatever the header says, the wait is either the caller's backoff or a
// whole number of seconds no longer than maxRetryAfter, and the transport is
// only told to give up when the header is a whole number above that cap.
func FuzzRetryWait(f *testing.F) {
	const backoff = int64(200 * time.Millisecond)
	for _, s := range []string{
		"", "0", "1", "10", "11", "120", "-1", "+5", " 5", "5s", "1.5",
		"Wed, 21 Oct 2015 07:28:00 GMT", "99999999999999999999", "9223372036854775807",
	} {
		f.Add(s, backoff)
	}
	f.Fuzz(func(t *testing.T, retryAfter string, backoffNs int64) {
		if backoffNs < 0 {
			return
		}
		backoff := time.Duration(backoffNs)
		wait, ok := retryWait(retryAfter, backoff)
		secs, parseErr := strconv.ParseInt(retryAfter, 10, 64)
		if !ok {
			if parseErr != nil || secs <= int64(maxRetryAfter/time.Second) || wait != 0 {
				t.Fatalf("retryWait(%q) gave up (wait %v) on a value within the cap", retryAfter, wait)
			}
			return
		}
		if wait == backoff {
			return
		}
		if parseErr != nil || secs < 0 || wait != time.Duration(secs)*time.Second || wait > maxRetryAfter {
			t.Fatalf("retryWait(%q, %v) = %v: neither backoff nor an honoured Retry-After",
				retryAfter, backoff, wait)
		}
	})
}

// FuzzDeviceUnmarshal decodes arbitrary device JSON through the custom
// UnmarshalJSON that tolerates Iru's polymorphic `user` field. A record that
// decodes must survive a marshal and decode round trip unchanged, and a
// device whose user is "" or null must always decode with a zero User.
func FuzzDeviceUnmarshal(f *testing.F) {
	for _, s := range []string{
		`{"device_id":"d-1","device_name":"Mac","user":{"id":"u-1","email":"a@x","name":"Alice","active":true}}`,
		`{"device_id":"d-2","device_name":"iPhone","user":""}`,
		`{"device_id":"d-3","user":null}`,
		`{"device_id":"d-4"}`,
		`{"device_id":"d-5","user":"  "}`,
		`{"device_id":"d-6","user":42}`,
		`{"device_id":"d-7","tags":["a","b"],"user":{"integration":{"id":1,"name":"Entra ID"}}}`,
		`{"device_id":"d-8","USER":{"id":"u-8"}}`,
		`[]`,
		`null`,
	} {
		f.Add([]byte(s), "d-1")
	}
	f.Fuzz(func(t *testing.T, data []byte, id string) {
		var d Device
		if err := json.Unmarshal(data, &d); err == nil {
			again, err := json.Marshal(d)
			if err != nil {
				t.Fatalf("marshal decoded device: %v", err)
			}
			var d2 Device
			if err := json.Unmarshal(again, &d2); err != nil {
				t.Fatalf("decode re-marshalled device %s: %v", again, err)
			}
			if !reflect.DeepEqual(d, d2) {
				t.Fatalf("round trip changed device:\n first %+v\nsecond %+v", d, d2)
			}
		}

		// Marshalling replaces invalid UTF-8, so compare against the id as
		// it decodes rather than as it was fuzzed.
		quoted, err := json.Marshal(id)
		if err != nil {
			t.Fatalf("marshal id: %v", err)
		}
		var wantID string
		if err := json.Unmarshal(quoted, &wantID); err != nil {
			t.Fatalf("decode id %s: %v", quoted, err)
		}
		for _, user := range []string{`""`, `null`, ` "" `} {
			raw := []byte(`{"device_id":` + string(quoted) + `,"user":` + user + `}`)
			var dev Device
			if err := json.Unmarshal(raw, &dev); err != nil {
				t.Fatalf("decode %s: %v", raw, err)
			}
			if dev.DeviceID != wantID || !reflect.DeepEqual(dev.User, User{}) {
				t.Fatalf("decode %s: got id %q user %+v", raw, dev.DeviceID, dev.User)
			}
		}
	})
}
