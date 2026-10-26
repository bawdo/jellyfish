package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/bawdo/jellyfish/internal/iru"
)

// timeoutErr is a net.Error that reports a timeout, as http.Client.Timeout's
// internal error does.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "Client.Timeout exceeded while awaiting headers" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyErrorNetworkFailures(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
	dns := &net.DNSError{Err: "no such host", Name: "acme.api.kandji.io", IsNotFound: true}
	get := func(err error) error {
		return &url.Error{Op: "Get", URL: "https://acme.api.kandji.io/api/v1/users", Err: err}
	}

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"connection refused", get(refused), 4},
		{"connection refused wrapped", fmt.Errorf("list users: %w", get(refused)), 4},
		{"dns failure", get(&net.OpError{Op: "dial", Net: "tcp", Err: dns}), 4},
		{"bare dns error", get(dns), 4},
		{"connection reset", get(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), 4},
		{"client timeout", get(timeoutErr{}), 4},
		{"context deadline", get(context.DeadlineExceeded), 4},
		{"server hung up", get(io.EOF), 4},
		{"truncated response", get(io.ErrUnexpectedEOF), 4},

		{"redirect to foreign host refused", get(errors.New(`iru: refusing redirect to foreign host "evil.example"`)), 1},
		{"redirect scheme downgrade refused", get(errors.New(`iru: refusing redirect to scheme "http", want "https"`)), 1},
		{"user interrupt", get(context.Canceled), 1},
		{"user interrupt during dial", get(&net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}), 1},
		{"malformed url", &url.Error{Op: "parse", URL: "https://bad host", Err: errors.New("invalid character \" \" in host name")}, 1},
		{"unsupported scheme", get(errors.New(`unsupported protocol scheme "ftp"`)), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyError(tc.err); got != tc.want {
				t.Fatalf("classifyError(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// The tests below drive the real iru client so the classification is checked
// against the errors net/http actually returns, not only hand-built ones.

func TestClassifyErrorRealConnectionRefusedIsExit4(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL + "/api/v1"
	srv.Close() // nothing listens on the port any more

	c := iru.NewClient(base, "tok")
	_, err := c.GetUser(context.Background(), "u-1")
	if err == nil {
		t.Fatal("want an error from a closed server")
	}
	if got := classifyError(err); got != 4 {
		t.Fatalf("classifyError(%v) = %d, want 4", err, got)
	}
}

func TestClassifyErrorRealClientTimeoutIsExit4(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := iru.NewClient(srv.URL+"/api/v1", "tok", iru.WithTimeout(50*time.Millisecond))
	_, err := c.GetUser(context.Background(), "u-1")
	if err == nil {
		t.Fatal("want a timeout error")
	}
	if got := classifyError(err); got != 4 {
		t.Fatalf("classifyError(%v) = %d, want 4", err, got)
	}
}

func TestClassifyErrorRealRedirectRefusalIsExit1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example/steal", http.StatusFound)
	}))
	defer srv.Close()

	c := iru.NewClient(srv.URL+"/api/v1", "tok")
	_, err := c.GetUser(context.Background(), "u-1")
	if err == nil {
		t.Fatal("want the redirect to be refused")
	}
	if got := classifyError(err); got != 1 {
		t.Fatalf("classifyError(%v) = %d, want 1", err, got)
	}
}

func TestClassifyErrorRealCancelIsExit1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	c := iru.NewClient(srv.URL+"/api/v1", "tok")
	_, err := c.GetUser(ctx, "u-1")
	if err == nil {
		t.Fatal("want a cancellation error")
	}
	if got := classifyError(err); got != 1 {
		t.Fatalf("classifyError(%v) = %d, want 1", err, got)
	}
}
