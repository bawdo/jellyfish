package iru

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// GetUser fetches a single user by ID.
func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	var u User
	if err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(id), nil, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// ListUsersPage fetches one page of users. cursor is the opaque value taken
// from the previous page's next URL; pass "" for the first page. The returned
// nextCursor is "" when there are no more pages.
func (c *Client) ListUsersPage(ctx context.Context, limit int, cursor string) ([]User, string, error) {
	return c.listUsersPage(ctx, limit, cursor, nil)
}

// listUsersPage fetches one page of /users. extra holds additional query
// parameters (e.g. an email filter) and may be nil; limit and cursor are set
// on top of it.
func (c *Client) listUsersPage(ctx context.Context, limit int, cursor string, extra url.Values) ([]User, string, error) {
	q := url.Values{}
	for k, vs := range extra {
		q[k] = append([]string(nil), vs...)
	}
	q.Set("limit", strconv.Itoa(limit))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	var p paginated[User]
	if err := c.do(ctx, http.MethodGet, "/users", q, &p); err != nil {
		return nil, "", err
	}
	return p.Results, p.nextCursor(), nil
}

// FindUsersByEmail returns every user with the given email address. Iru's
// `?email=` filter is an exact server-side match but the same address can
// legitimately belong to more than one user record (e.g. when a single human
// is represented by multiple Iru accounts). The walk is paginated via
// WalkCursor so all matches are returned. Returns ErrNotFound when no
// records match.
func (c *Client) FindUsersByEmail(ctx context.Context, email string) ([]User, error) {
	var out []User
	filter := url.Values{"email": {email}}
	err := WalkCursor[User](ctx, DefaultLimit,
		func(ctx context.Context, limit int, cursor string) ([]User, string, error) {
			return c.listUsersPage(ctx, limit, cursor, filter)
		},
		func(page []User) error {
			out = append(out, page...)
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// ListUsersStream walks every user via repeated ListUsersPage calls. The
// callback receives one page at a time; returning a non-nil error aborts the
// walk and propagates the error to the caller.
func (c *Client) ListUsersStream(ctx context.Context, cb func(page []User) error) error {
	return WalkCursor[User](ctx, DefaultLimit,
		func(ctx context.Context, limit int, cursor string) ([]User, string, error) {
			return c.ListUsersPage(ctx, limit, cursor)
		},
		cb,
	)
}
