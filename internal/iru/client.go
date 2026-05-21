package iru

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client talks to the Iru/Kandji API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// Option configures a Client at construction time. Options record intent into
// a clientConfig; NewClient reconciles them once after all are applied, so
// option ordering never changes the result.
type Option func(*clientConfig)

// clientConfig collects option intent before NewClient builds the Client.
type clientConfig struct {
	httpClient *http.Client
	userAgent  string
	timeout    *time.Duration
}

// WithHTTPClient supplies a custom *http.Client. NewClient attaches the auth
// transport when the supplied client has none, and still applies WithTimeout
// (if also given) regardless of the order the two options are passed in.
func WithHTTPClient(h *http.Client) Option {
	return func(cfg *clientConfig) { cfg.httpClient = h }
}

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(cfg *clientConfig) { cfg.userAgent = ua }
}

// WithTimeout sets the http.Client timeout. It is honoured whether passed
// before or after WithHTTPClient.
func WithTimeout(d time.Duration) Option {
	return func(cfg *clientConfig) { cfg.timeout = &d }
}

// NewClient constructs a Client. baseURL must end with /api/v1 (no trailing slash).
func NewClient(baseURL, token string, opts ...Option) *Client {
	cfg := clientConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	// Preserve the auth transport when callers swap in their own http.Client.
	if httpClient.Transport == nil {
		httpClient.Transport = &authTransport{
			token: token,
			base:  &retryTransport{base: http.DefaultTransport},
		}
	}
	if cfg.timeout != nil {
		httpClient.Timeout = *cfg.timeout
	}

	userAgent := "jellyfish/dev"
	if cfg.userAgent != "" {
		userAgent = cfg.userAgent
	}

	return &Client{
		baseURL:    baseURL,
		userAgent:  userAgent,
		httpClient: httpClient,
	}
}

// do builds and sends a request. If out is non-nil and the response status is 2xx,
// the body is JSON-decoded into out.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, out any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var body io.Reader
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	data, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("read response body: %w", readErr)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w (raw=%q)", err, string(data))
	}
	return nil
}
