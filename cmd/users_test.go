package cmd

import (
	"bytes"
	"os"
	"path/filepath"
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

func writeCSV(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestReadCSVRecipientsAutoDetect(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"email column", "email,name\na@x.com,Alice\nb@x.com,Bob\n", []string{"a@x.com", "b@x.com"}},
		{"user_email column", "name,user_email\nAlice,a@x.com\n", []string{"a@x.com"}},
		{"e-mail column", "e-mail,dept\na@x.com,eng\n", []string{"a@x.com"}},
		{"mixed case header", "Name,EMAIL\nAlice,a@x.com\n", []string{"a@x.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeCSV(t, "in.csv", tc.body)
			got, err := readCSVRecipients(p, "")
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestReadCSVRecipientsColumnOverride(t *testing.T) {
	body := "name,primary_contact,backup\nAlice,a@x.com,b@x.com\n"
	p := writeCSV(t, "in.csv", body)
	got, err := readCSVRecipients(p, "primary_contact")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"a@x.com"}) {
		t.Errorf("got %#v", got)
	}
}

func TestReadCSVRecipientsDedupePreservingOrder(t *testing.T) {
	body := "email\nA@x.com\na@x.com\nB@x.com\n"
	p := writeCSV(t, "in.csv", body)
	got, err := readCSVRecipients(p, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"A@x.com", "B@x.com"}) {
		t.Errorf("got %#v", got)
	}
}

func TestReadCSVRecipientsStripsBOMAndCRLF(t *testing.T) {
	body := "\xef\xbb\xbfemail\r\na@x.com\r\nb@x.com\r\n"
	p := writeCSV(t, "in.csv", body)
	got, err := readCSVRecipients(p, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"a@x.com", "b@x.com"}) {
		t.Errorf("got %#v", got)
	}
}

func TestReadCSVRecipientsErrors(t *testing.T) {
	cases := []struct {
		name, body, column, wantErr string
	}{
		{"missing file", "", "", "open"},
		{"no header at all", "", "", "empty"},
		{"no email column auto", "id,name\n1,Alice\n", "", "no email column"},
		{"override column missing", "name,phone\nAlice,555\n", "primary_contact", "primary_contact"},
		{"empty after header", "email\n", "", "no recipients"},
		{"row with non-email cell", "email\nnot-an-email\n", "", "not a valid email"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			switch tc.name {
			case "missing file":
				path = filepath.Join(t.TempDir(), "does-not-exist.csv")
			case "no header at all":
				path = writeCSV(t, "empty.csv", "")
			default:
				path = writeCSV(t, "in.csv", tc.body)
			}
			_, err := readCSVRecipients(path, tc.column)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err: got %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
