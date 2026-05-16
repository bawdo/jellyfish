package cmd

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestUsersSendEmailRegistered(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"users", "send-email", "--help"})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr=%q", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "send-email") {
		t.Fatalf("help output missing command name; got %q", out.String())
	}
	for _, flag := range []string{"--csv", "--emails", "--csv-email-column", "--email-to", "--message", "--message-file", "--dry-run", "--yes", "--no-cache"} {
		if !strings.Contains(out.String(), flag) {
			t.Errorf("help output missing flag %s; got:\n%s", flag, out.String())
		}
	}
}

func TestSplitEmails(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr string
	}{
		{name: "single", in: "a@x.com", want: []string{"a@x.com"}},
		{name: "trimmed whitespace", in: "  a@x.com , b@x.com  ", want: []string{"a@x.com", "b@x.com"}},
		{name: "case-insensitive dedupe preserves first", in: "A@x.com,a@x.com,B@x.com", want: []string{"A@x.com", "B@x.com"}},
		{name: "empty entries skipped", in: "a@x.com,,b@x.com", want: []string{"a@x.com", "b@x.com"}},
		{name: "invalid no at-sign", in: "a@x.com,not-an-email", wantErr: "not-an-email"},
		{name: "empty input", in: "", wantErr: "no email addresses"},
		{name: "only whitespace", in: " , , ", wantErr: "no email addresses"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitEmails(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}
