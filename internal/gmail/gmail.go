package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gmailapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// Error sentinels for cmd.classifyError integration.
var (
	ErrUnauthorized = errors.New("gmail: unauthorized")
	ErrForbidden    = errors.New("gmail: forbidden")
	ErrRateLimited  = errors.New("gmail: rate limited")
	ErrUpstream     = errors.New("gmail: upstream")
)

// Sender sends a pre-built RFC 5322 message via Gmail API users.messages.send,
// using the service account in saJSON to impersonate subjectUser via DWD.
type Sender interface {
	Send(ctx context.Context, rfc822 []byte) (messageID string, err error)
}

type apiSender struct {
	svc *gmailapi.Service
}

// NewSender returns a Sender. saJSON is the raw service-account JSON read from
// Keychain. subjectUser is the Workspace user to impersonate (the "From"
// address). The OAuth scope is hard-coded to gmail.send.
func NewSender(ctx context.Context, saJSON []byte, subjectUser string) (Sender, error) {
	if subjectUser == "" {
		return nil, errors.New("gmail: subjectUser must not be empty")
	}
	cfg, err := google.JWTConfigFromJSON(saJSON, gmailapi.GmailSendScope)
	if err != nil {
		return nil, fmt.Errorf("gmail: parse service-account JSON: %w", err)
	}
	if cfg.Email == "" {
		return nil, errors.New("gmail: service-account JSON has no client_email")
	}
	cfg.Subject = subjectUser
	svc, err := gmailapi.NewService(ctx, option.WithTokenSource(cfg.TokenSource(ctx)))
	if err != nil {
		return nil, fmt.Errorf("gmail: build service: %w", err)
	}
	return &apiSender{svc: svc}, nil
}

func (s *apiSender) Send(ctx context.Context, rfc822 []byte) (string, error) {
	raw := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(rfc822)
	msg := &gmailapi.Message{Raw: raw}
	sent, err := s.svc.Users.Messages.Send("me", msg).Context(ctx).Do()
	if err != nil {
		return "", classifyAPIError(err)
	}
	return sent.Id, nil
}

// ValidateServiceAccountJSON checks structure-level invariants on a candidate
// service-account JSON blob: parseable JSON, type=="service_account",
// non-empty client_email. Used at configure time so bad input is rejected
// before it hits Keychain.
func ValidateServiceAccountJSON(b []byte) error {
	var probe struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	if probe.Type != "service_account" {
		return fmt.Errorf(`type is %q, want "service_account"`, probe.Type)
	}
	if probe.ClientEmail == "" {
		return errors.New("missing client_email field")
	}
	return nil
}

// classifyAPIError wraps a Gmail API error with one of the package sentinels
// based on the HTTP status code. A refused OAuth token request never reaches
// Gmail, so it is classified from the token endpoint's status instead. Other
// errors pass through unchanged.
func classifyAPIError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return classifyTokenError(err, re)
	}
	var ge *googleapi.Error
	if !errors.As(err, &ge) {
		return err
	}
	switch {
	case ge.Code == 401:
		return fmt.Errorf("%w: %w", ErrUnauthorized, ge)
	case ge.Code == 403:
		return fmt.Errorf("%w: %w", ErrForbidden, ge)
	case ge.Code == 429:
		return fmt.Errorf("%w: %w", ErrRateLimited, ge)
	case ge.Code >= 500:
		return fmt.Errorf("%w: %w", ErrUpstream, ge)
	default:
		return err
	}
}

// classifyTokenError maps a failed token request. Google answers a bad grant
// (delegation not granted, key revoked, unknown subject) with a 4xx, so any
// refusal other than a rate limit or server error is an auth failure.
func classifyTokenError(err error, re *oauth2.RetrieveError) error {
	status := 0
	if re.Response != nil {
		status = re.Response.StatusCode
	}
	switch {
	case status == 429:
		return fmt.Errorf("%w: %w", ErrRateLimited, err)
	case status >= 500:
		return fmt.Errorf("%w: %w", ErrUpstream, err)
	default:
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
}
