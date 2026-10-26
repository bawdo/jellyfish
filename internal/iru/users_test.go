package iru

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestGetUserByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/users/u-1") {
			t.Errorf("path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"u-1","name":"Keith","email":"k@x"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	u, err := c.GetUser(context.Background(), "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "u-1" || u.Email != "k@x" {
		t.Fatalf("got %+v", u)
	}
}

func TestFindUsersByEmailUsesServerFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"next": null, "previous": null, "results": [{"id": "u-match", "email": "Keith@example.com"}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	users, err := c.FindUsersByEmail(context.Background(), "keith@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].ID != "u-match" {
		t.Fatalf("got %+v", users)
	}
	if !strings.Contains(gotQuery, "email=keith%40example.com") {
		t.Fatalf("expected email filter in query, got %q", gotQuery)
	}
	if strings.Contains(gotQuery, "limit=1") {
		t.Fatalf("expected no limit=1 in query (helper should walk all matches), got %q", gotQuery)
	}
}

func TestFindUsersByEmailNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"next": null, "previous": null, "results": []}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	_, err := c.FindUsersByEmail(context.Background(), "nobody@x")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFindUsersByEmailReturnsAllMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"next": null, "previous": null, "results": [
			{"id": "u-1", "name": "Keith A", "email": "keith@example.com"},
			{"id": "u-2", "name": "Keith B", "email": "keith@example.com"}
		]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	users, err := c.FindUsersByEmail(context.Background(), "keith@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d: %+v", len(users), users)
	}
	if users[0].ID != "u-1" || users[1].ID != "u-2" {
		t.Fatalf("expected [u-1, u-2] in order, got %+v", users)
	}
}

func TestFindUsersByEmailWalksPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		switch cursor {
		case "":
			_, _ = w.Write([]byte(`{"next": "https://example.iru?cursor=page2", "previous": null, "results": [{"id": "u-1", "email": "k@x"}]}`))
		case "page2":
			_, _ = w.Write([]byte(`{"next": null, "previous": null, "results": [{"id": "u-2", "email": "k@x"}]}`))
		default:
			t.Errorf("unexpected cursor: %q", cursor)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	users, err := c.FindUsersByEmail(context.Background(), "k@x")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].ID != "u-1" || users[1].ID != "u-2" {
		t.Fatalf("got %+v", users)
	}
}

func TestListUsersStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		switch cursor {
		case "":
			// First page: 2 users, next cursor points to page2.
			_, _ = w.Write([]byte(`{"next":"https://example.iru?cursor=page2","previous":null,"results":[{"id":"u-1","name":"Alice","email":"alice@x"},{"id":"u-2","name":"Bob","email":"bob@x"}]}`))
		case "page2":
			// Second page: 2 users, next cursor points to page3.
			_, _ = w.Write([]byte(`{"next":"https://example.iru?cursor=page3","previous":null,"results":[{"id":"u-3","name":"Charlie","email":"charlie@x"},{"id":"u-4","name":"David","email":"david@x"}]}`))
		case "page3":
			// Third page: 1 user, no next (signals end).
			_, _ = w.Write([]byte(`{"next":null,"previous":null,"results":[{"id":"u-5","name":"Eve","email":"eve@x"}]}`))
		default:
			t.Errorf("unexpected cursor: %q", cursor)
		}
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	var pages [][]User
	err := c.ListUsersStream(context.Background(), func(page []User) error {
		pages = append(pages, page)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 3 {
		t.Fatalf("expected 3 pages, got %d", len(pages))
	}
	if len(pages[0]) != 2 || pages[0][0].ID != "u-1" {
		t.Fatalf("first page expected 2 users starting with u-1, got %+v", pages[0])
	}
	if len(pages[1]) != 2 || pages[1][0].ID != "u-3" {
		t.Fatalf("second page expected 2 users starting with u-3, got %+v", pages[1])
	}
	if len(pages[2]) != 1 || pages[2][0].ID != "u-5" {
		t.Fatalf("third page expected 1 user (u-5), got %+v", pages[2])
	}
}

// queryTransport records each request's query string and answers in memory
// via respond, keyed on the request's cursor param.
type queryTransport struct {
	queries []url.Values
	respond func(cursor string) string
}

func (q *queryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	q.queries = append(q.queries, r.URL.Query())
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(q.respond(r.URL.Query().Get("cursor")))),
		Request:    r,
	}, nil
}

func TestListUsersPageQueryInMemory(t *testing.T) {
	qt := &queryTransport{respond: func(string) string {
		return `{"next": "https://` + testAPIHost + `/api/v1/users?cursor=c2", "previous": null, "results": [{"id": "u-1"}]}`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(qt))
	users, next, err := c.ListUsersPage(context.Background(), 25, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].ID != "u-1" || next != "c2" {
		t.Fatalf("got users=%+v next=%q", users, next)
	}
	if len(qt.queries) != 1 {
		t.Fatalf("requests: got %d want 1", len(qt.queries))
	}
	q := qt.queries[0]
	if q.Get("limit") != "25" || q.Get("cursor") != "c1" {
		t.Errorf("query %v", q)
	}
	if q.Has("email") {
		t.Errorf("ListUsersPage must not send an email filter: %v", q)
	}

	// No cursor on the first page.
	if _, _, err := c.ListUsersPage(context.Background(), 10, ""); err != nil {
		t.Fatal(err)
	}
	if q := qt.queries[1]; q.Has("cursor") || q.Get("limit") != "10" {
		t.Errorf("first page query %v", q)
	}
}

func TestFindUsersByEmailQueryInMemory(t *testing.T) {
	qt := &queryTransport{respond: func(cursor string) string {
		if cursor == "" {
			return `{"next": "https://` + testAPIHost + `/api/v1/users?cursor=p2", "previous": null, "results": [{"id": "u-1"}]}`
		}
		return `{"next": null, "previous": null, "results": [{"id": "u-2"}]}`
	}}
	c := NewClient(testBaseURL, testToken, withBaseTransport(qt))
	users, err := c.FindUsersByEmail(context.Background(), "k@x")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].ID != "u-1" || users[1].ID != "u-2" {
		t.Fatalf("got %+v", users)
	}
	if len(qt.queries) != 2 {
		t.Fatalf("requests: got %d want 2", len(qt.queries))
	}
	for i, q := range qt.queries {
		if got := q["email"]; len(got) != 1 || got[0] != "k@x" {
			t.Errorf("request %d: email %v, want exactly [k@x]", i, got)
		}
		if q.Get("limit") != strconv.Itoa(DefaultLimit) {
			t.Errorf("request %d: limit %q", i, q.Get("limit"))
		}
	}
	if qt.queries[0].Has("cursor") || qt.queries[1].Get("cursor") != "p2" {
		t.Errorf("cursors: %v / %v", qt.queries[0], qt.queries[1])
	}
}
