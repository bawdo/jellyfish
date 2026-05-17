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
	q := url.Values{}
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

// FindUserByEmail returns the user with the given email address. The filter
// is server-side via Iru's `?email=` query param, which returns at most one
// exact match. Returns ErrNotFound if no user matches.
func (c *Client) FindUserByEmail(ctx context.Context, email string) (User, error) {
	q := url.Values{}
	q.Set("email", email)
	q.Set("limit", "1")
	var p paginated[User]
	if err := c.do(ctx, http.MethodGet, "/users", q, &p); err != nil {
		return User{}, err
	}
	if len(p.Results) == 0 {
		return User{}, ErrNotFound
	}
	return p.Results[0], nil
}

// ListUsersStream walks every user via repeated ListUsersPage calls. The
// callback receives one page at a time; returning a non-nil error aborts the
// walk and propagates the error to the caller. Mirrors the shape of
// ListDetectionsStream so callers can express "do something with every user
// in the tenant" without managing the cursor themselves.
func (c *Client) ListUsersStream(ctx context.Context, cb func(page []User) error) error {
	const pageSize = 100
	cursor := ""
	for {
		page, next, err := c.ListUsersPage(ctx, pageSize, cursor)
		if err != nil {
			return err
		}
		if len(page) > 0 {
			if err := cb(page); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		cursor = next
	}
}
