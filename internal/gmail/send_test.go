package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

func TestNewSenderRejectsMissingClientEmail(t *testing.T) {
	j := []byte(`{
		"type": "service_account",
		"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC=\n-----END PRIVATE KEY-----\n",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`)
	s, err := NewSender(context.Background(), j, "alice@example.com")
	if err == nil || !strings.Contains(err.Error(), "client_email") {
		t.Fatalf("expected a client_email error, got %v", err)
	}
	if s != nil {
		t.Fatal("expected no Sender alongside the error")
	}
}

// fakeGmail stands in for the Gmail API. It records the request and answers
// with status and body; it never talks to Google.
type fakeGmail struct {
	status int
	body   string
	calls  atomic.Int32

	method, path string
	raw          string
}

func (f *fakeGmail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	f.method, f.path = r.Method, r.URL.Path
	var msg struct {
		Raw string `json:"raw"`
	}
	_ = json.NewDecoder(r.Body).Decode(&msg)
	f.raw = msg.Raw
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_, _ = w.Write([]byte(f.body))
}

// newTestSender points an apiSender at srv with no credentials.
func newTestSender(t *testing.T, srv *httptest.Server) Sender {
	t.Helper()
	svc, err := gmailapi.NewService(context.Background(),
		option.WithEndpoint(srv.URL+"/"),
		option.WithHTTPClient(srv.Client()),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return &apiSender{svc: svc}
}

func TestSendPostsRawMessageAsMe(t *testing.T) {
	fake := &fakeGmail{status: http.StatusOK, body: `{"id":"msg-123"}`}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	// Bytes that would produce '+', '/' and '=' in standard base64.
	rfc822 := []byte("Subject: hi\r\n\r\n\xfb\xff\xfe?>")
	id, err := newTestSender(t, srv).Send(context.Background(), rfc822)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if id != "msg-123" {
		t.Errorf("id = %q, want msg-123", id)
	}
	if fake.method != http.MethodPost || !strings.HasSuffix(fake.path, "/users/me/messages/send") {
		t.Errorf("request = %s %s, want POST .../users/me/messages/send", fake.method, fake.path)
	}
	if strings.ContainsAny(fake.raw, "+/=") {
		t.Errorf("raw is not unpadded base64url: %q", fake.raw)
	}
	dec, err := base64.RawURLEncoding.DecodeString(fake.raw)
	if err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if string(dec) != string(rfc822) {
		t.Errorf("raw decodes to %q, want %q", dec, rfc822)
	}
}

// API failures come back mapped onto the package sentinels, so cmd can turn
// them into exit codes; statuses without a sentinel still return an error.
func TestSendClassifiesAPIErrors(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusInternalServerError, ErrUpstream},
		{http.StatusBadRequest, nil},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			fake := &fakeGmail{status: tc.status, body: `{"error":{"code":` +
				strconv.Itoa(tc.status) + `,"message":"denied"}}`}
			srv := httptest.NewServer(fake)
			t.Cleanup(srv.Close)

			id, err := newTestSender(t, srv).Send(context.Background(), []byte("Subject: x\r\n\r\nbody"))
			if err == nil {
				t.Fatal("expected an error")
			}
			if id != "" {
				t.Errorf("id = %q, want empty on failure", id)
			}
			var ge *googleapi.Error
			if !errors.As(err, &ge) || ge.Code != tc.status {
				t.Fatalf("expected *googleapi.Error with code %d in chain, got %v", tc.status, err)
			}
			for _, s := range []error{ErrUnauthorized, ErrForbidden, ErrRateLimited, ErrUpstream} {
				if got, want := errors.Is(err, s), s == tc.want; got != want {
					t.Errorf("errors.Is(err, %v) = %v, want %v", s, got, want)
				}
			}
		})
	}
}
