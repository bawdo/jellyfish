package iru

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ownerTransport answers every request in memory with body and records the
// requests it saw, so a test can assert that nothing was sent at all.
type ownerTransport struct {
	reqs []*http.Request
	body func(r *http.Request) string
}

func (b *ownerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b.reqs = append(b.reqs, r)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(b.body(r))),
		Request:    r,
	}, nil
}

func TestGetUserRejectsUnsafeIDWithoutRequest(t *testing.T) {
	for _, id := range []string{"", "   ", ".", "..", " .. "} {
		bt := &ownerTransport{body: func(*http.Request) string { return `{"id":"u-1"}` }}
		c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
		if _, err := c.GetUser(context.Background(), id); err == nil {
			t.Errorf("GetUser(%q): expected an error, got nil", id)
		}
		if len(bt.reqs) != 0 {
			t.Errorf("GetUser(%q): sent %d request(s), want none", id, len(bt.reqs))
		}
	}
}

// Requesting /users/ hits the list endpoint, whose paginated body decodes
// into a zero User. A record with no id must never pass as a user.
func TestGetUserRejectsRecordWithoutID(t *testing.T) {
	bt := &ownerTransport{body: func(*http.Request) string {
		return `{"next": null, "previous": null, "results": [{"id": "u-1"}]}`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
	if _, err := c.GetUser(context.Background(), "u-1"); err == nil {
		t.Fatal("expected an error for a record with no id, got nil")
	}
}

// Iru's serial_number filter is a contains match, so a partial serial can
// return other devices first. Only an exact serial may be returned.
func TestGetDeviceBySerialRequiresExactMatch(t *testing.T) {
	bt := &ownerTransport{body: func(r *http.Request) string {
		if r.URL.Query().Get("offset") != "0" {
			return `[]`
		}
		return `[{"device_id":"d-long","serial_number":"XC02ABC1"},{"device_id":"d-exact","serial_number":"c02abc"}]`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
	d, err := c.GetDeviceBySerial(context.Background(), "C02ABC")
	if err != nil {
		t.Fatal(err)
	}
	if d.DeviceID != "d-exact" {
		t.Fatalf("got %+v, want d-exact", d)
	}
}

func TestGetDeviceBySerialPartialOnlyIsNotFound(t *testing.T) {
	bt := &ownerTransport{body: func(*http.Request) string {
		return `[{"device_id":"d-long","serial_number":"XC02ABC1"}]`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
	_, err := c.GetDeviceBySerial(context.Background(), "C02ABC")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetDeviceBySerialAmbiguous(t *testing.T) {
	bt := &ownerTransport{body: func(*http.Request) string {
		return `[{"device_id":"d-1","serial_number":"SN9"},{"device_id":"d-2","serial_number":"SN9"}]`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
	_, err := c.GetDeviceBySerial(context.Background(), "SN9")
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
}

func TestGetDeviceBySerialRejectsEmptyWithoutRequest(t *testing.T) {
	for _, s := range []string{"", "  "} {
		bt := &ownerTransport{body: func(*http.Request) string { return `[]` }}
		c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
		if _, err := c.GetDeviceBySerial(context.Background(), s); err == nil {
			t.Errorf("GetDeviceBySerial(%q): expected an error, got nil", s)
		}
		if len(bt.reqs) != 0 {
			t.Errorf("GetDeviceBySerial(%q): sent %d request(s), want none", s, len(bt.reqs))
		}
	}
}

// If the server's email filter is looser than exact, other users' records
// must not be returned as matches.
func TestFindUsersByEmailKeepsOnlyExactMatches(t *testing.T) {
	bt := &ownerTransport{body: func(*http.Request) string {
		return `{"next": null, "previous": null, "results": [
			{"id": "u-other", "email": "jimbob@x.com"},
			{"id": "u-bob", "email": "Bob@X.com"}]}`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
	users, err := c.FindUsersByEmail(context.Background(), "bob@x.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].ID != "u-bob" {
		t.Fatalf("got %+v, want only u-bob", users)
	}
}

func TestFindUsersByEmailNoExactMatchIsNotFound(t *testing.T) {
	bt := &ownerTransport{body: func(*http.Request) string {
		return `{"next": null, "previous": null, "results": [{"id": "u-other", "email": "jimbob@x.com"}]}`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(bt))
	_, err := c.FindUsersByEmail(context.Background(), "bob@x.com")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
