package iru

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// statusTransport answers every request in memory with a fixed status and a
// {"detail":...} body, counting the requests it sees.
type statusTransport struct {
	status int
	calls  int
}

func (s *statusTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls++
	return &http.Response{
		StatusCode: s.status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(`{"detail":"no access"}`)),
		Request:    r,
	}, nil
}

// Every resource method must hand the API error back unchanged so that
// classifyError in cmd can map it to an exit code, and must not return a
// partial result alongside it.
func TestResourceMethodsPropagateAPIErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		call func(c *Client) (any, error)
	}{
		{"ListDevicesPage", func(c *Client) (any, error) {
			return c.ListDevicesPage(ctx, DeviceFilters{}, 10, 0)
		}},
		{"ListDevices", func(c *Client) (any, error) {
			return c.ListDevices(ctx, DeviceFilters{})
		}},
		{"GetDeviceBySerial", func(c *Client) (any, error) {
			return c.GetDeviceBySerial(ctx, "C02XYZ")
		}},
		{"GetUser", func(c *Client) (any, error) {
			return c.GetUser(ctx, "u-1")
		}},
		{"ListUsersPage", func(c *Client) (any, error) {
			users, next, err := c.ListUsersPage(ctx, 10, "")
			if next != "" {
				return next, err
			}
			return users, err
		}},
		{"FindUsersByEmail", func(c *Client) (any, error) {
			return c.FindUsersByEmail(ctx, "a@example.com")
		}},
		{"ListDetectionsPage", func(c *Client) (any, error) {
			dets, next, err := c.ListDetectionsPage(ctx, DetectionFilters{}, 10, "")
			if next != "" {
				return next, err
			}
			return dets, err
		}},
		{"ListDetections", func(c *Client) (any, error) {
			return c.ListDetections(ctx, DetectionFilters{})
		}},
		{"ListVulnerabilitiesPage", func(c *Client) (any, error) {
			vulns, total, err := c.ListVulnerabilitiesPage(ctx, VulnerabilityFilters{}, 1, 10)
			if total != 0 {
				return total, err
			}
			return vulns, err
		}},
		{"ListVulnerabilities", func(c *Client) (any, error) {
			return c.ListVulnerabilities(ctx, VulnerabilityFilters{})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &statusTransport{status: http.StatusForbidden}
			c := NewClient(testBaseURL, testToken, withBaseTransport(rt))
			got, err := tc.call(c)
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("expected ErrForbidden, got %v", err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Message != "no access" {
				t.Fatalf("expected *APIError carrying the detail, got %#v", err)
			}
			if !isEmpty(got) {
				t.Fatalf("expected no result alongside the error, got %#v", got)
			}
			// 403 is not retryable: exactly one request, and the walkers
			// stop at the first failed page.
			if rt.calls != 1 {
				t.Fatalf("expected 1 request, got %d", rt.calls)
			}
		})
	}
}

// isEmpty reports whether v is the zero value of its type or an empty
// slice, i.e. carries no result.
func isEmpty(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice {
		return rv.Len() == 0
	}
	return rv.IsZero()
}
