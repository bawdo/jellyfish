package gmail

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// tokenEndpoint answers Google's OAuth token endpoint in memory with a fixed
// status and body, so a test can drive the real JWT token fetch without a
// network or a listening port.
type tokenEndpoint struct {
	status int
	body   string
}

func (e *tokenEndpoint) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: e.status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(e.body)),
		Request:    r,
	}, nil
}

// serviceAccountWithFreshKey builds service-account JSON around an RSA key
// generated for this test run, so the JWT really is signed before the token
// request goes out.
func serviceAccountWithFreshKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"private_key_id": "k1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "tester@test.iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.example.test/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A refused token request (DWD not granted, key revoked, unknown subject)
// never reaches Gmail, so it carries no googleapi.Error. It must still map
// onto a sentinel so the exit code says auth, not user error or upstream.
func TestSendClassifiesTokenEndpointErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"invalid grant", http.StatusBadRequest, ErrUnauthorized},
		{"unauthorized client", http.StatusUnauthorized, ErrUnauthorized},
		{"forbidden", http.StatusForbidden, ErrUnauthorized},
		{"rate limited", http.StatusTooManyRequests, ErrRateLimited},
		{"server error", http.StatusServiceUnavailable, ErrUpstream},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := &tokenEndpoint{status: tc.status, body: `{"error":"invalid_grant","error_description":"Not a valid email."}`}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: ep})

			s, err := NewSender(ctx, serviceAccountWithFreshKey(t), "alice@example.com")
			if err != nil {
				t.Fatalf("NewSender: %v", err)
			}
			_, err = s.Send(ctx, []byte("Subject: x\r\n\r\nbody"))
			if err == nil {
				t.Fatal("expected an error")
			}
			var re *oauth2.RetrieveError
			if !errors.As(err, &re) {
				t.Fatalf("expected *oauth2.RetrieveError in chain, got %v", err)
			}
			for _, s := range []error{ErrUnauthorized, ErrForbidden, ErrRateLimited, ErrUpstream} {
				if got, want := errors.Is(err, s), s == tc.want; got != want {
					t.Errorf("errors.Is(err, %v) = %v, want %v (err: %v)", s, got, want, err)
				}
			}
		})
	}
}

func TestClassifyAPIErrorRetrieveErrorWithoutResponse(t *testing.T) {
	err := classifyAPIError(&oauth2.RetrieveError{ErrorCode: "invalid_grant"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}
