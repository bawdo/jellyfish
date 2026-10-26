//go:build darwin

package keychain

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	kc "github.com/keybase/go-keychain"
)

// Real-Keychain tests are gated. CI macOS runners can opt in.
//
// They run against the developer's own login keychain, so skipIfNoKeychain
// also routes every call through guardedStore, which refuses the accounts
// jellyfish really uses. A test that reaches for one fails before anything
// is read, overwritten or deleted.
func skipIfNoKeychain(t *testing.T) {
	t.Helper()
	if os.Getenv("JELLYFISH_KEYCHAIN_TESTS") != "1" {
		t.Skip("set JELLYFISH_KEYCHAIN_TESTS=1 to run macOS Keychain integration tests")
	}
	prev := store
	store = guardedStore{fail: t.Errorf, next: securityStore{}}
	t.Cleanup(func() { store = prev })
}

// productionAccounts are the real jellyfish credentials: the Iru API token
// and the Gmail service-account JSON.
var productionAccounts = map[string]bool{"default": true, productionGmailAccount: true}

// guardedStore passes calls to next unless the account is a production one,
// in which case it reports through fail and returns an error instead.
type guardedStore struct {
	fail func(format string, args ...any)
	next itemStore
}

func (g guardedStore) check(op, account string) error {
	if productionAccounts[account] {
		g.fail("real-Keychain test tried to %s production account %q", op, account)
		return fmt.Errorf("refused to %s production account %q", op, account)
	}
	return nil
}

func (g guardedStore) query(account string) ([]kc.QueryResult, error) {
	if err := g.check("query", account); err != nil {
		return nil, err
	}
	return g.next.query(account)
}

func (g guardedStore) add(account string, data []byte) error {
	if err := g.check("add", account); err != nil {
		return err
	}
	return g.next.add(account, data)
}

func (g guardedStore) remove(account string) error {
	if err := g.check("remove", account); err != nil {
		return err
	}
	return g.next.remove(account)
}

// useThrowawayGmailAccount points the Gmail helpers at a unique test account
// for the rest of the test.
func useThrowawayGmailAccount(t *testing.T) {
	t.Helper()
	prev := accountGmailServiceAccount
	accountGmailServiceAccount = "jellyfish-test-gmail-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { accountGmailServiceAccount = prev })
}

func TestRoundTrip(t *testing.T) {
	skipIfNoKeychain(t)
	account := "jellyfish-test-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _ = Delete(account) })

	if err := Set(account, "secret-1"); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := Get(account)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "secret-1" {
		t.Fatalf("got %q want %q", got, "secret-1")
	}

	if err := Set(account, "secret-2"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got2, err := Get(account)
	if err != nil {
		t.Fatalf("get after replace: %v", err)
	}
	if got2 != "secret-2" {
		t.Fatalf("got %q want %q", got2, "secret-2")
	}
}

func TestGetMissing(t *testing.T) {
	skipIfNoKeychain(t)
	_, err := Get("definitely-not-set-" + time.Now().Format("150405.000000"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGmailServiceAccountRoundTrip(t *testing.T) {
	skipIfNoKeychain(t)
	useThrowawayGmailAccount(t)
	t.Cleanup(func() { _ = DeleteGmailServiceAccount() })

	want := []byte(`{"type":"service_account","client_email":"x@y.iam.gserviceaccount.com"}`)
	if err := SetGmailServiceAccount(want); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := GetGmailServiceAccount()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("round-trip mismatch:\n got: %s\nwant: %s", got, want)
	}

	if err := DeleteGmailServiceAccount(); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := GetGmailServiceAccount(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}
