package iru

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestFindUserByEmailUsesServerFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"next": null, "previous": null, "results": [{"id": "u-match", "email": "Keith@example.com"}]}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	u, err := c.FindUserByEmail(context.Background(), "keith@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "u-match" {
		t.Fatalf("got %+v", u)
	}
	if !strings.Contains(gotQuery, "email=keith%40example.com") {
		t.Fatalf("expected email filter in query, got %q", gotQuery)
	}
}

func TestFindUserByEmailNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"next": null, "previous": null, "results": []}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, "tkn")
	_, err := c.FindUserByEmail(context.Background(), "nobody@x")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
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
