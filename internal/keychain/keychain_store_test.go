//go:build darwin

package keychain

import (
	"errors"
	"fmt"
	"testing"

	kc "github.com/keybase/go-keychain"
)

// fakeStore is an in-memory itemStore. The *Err fields, when set, are
// returned instead of touching items; calls records every operation in order.
type fakeStore struct {
	items     map[string][]byte
	queryErr  error
	addErrs   []error // consumed one per add call; nil entries fall through
	removeErr error
	calls     []string
}

func (f *fakeStore) query(account string) ([]kc.QueryResult, error) {
	f.calls = append(f.calls, "query "+account)
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	data, ok := f.items[account]
	if !ok {
		return nil, nil
	}
	return []kc.QueryResult{{Service: Service, Account: account, Data: data}}, nil
}

func (f *fakeStore) add(account string, data []byte) error {
	f.calls = append(f.calls, "add "+account)
	if len(f.addErrs) > 0 {
		err := f.addErrs[0]
		f.addErrs = f.addErrs[1:]
		if err != nil {
			return err
		}
	}
	if _, ok := f.items[account]; ok {
		return kc.ErrorDuplicateItem
	}
	f.items[account] = data
	return nil
}

func (f *fakeStore) remove(account string) error {
	f.calls = append(f.calls, "remove "+account)
	if f.removeErr != nil {
		return f.removeErr
	}
	if _, ok := f.items[account]; !ok {
		return kc.ErrorItemNotFound
	}
	delete(f.items, account)
	return nil
}

func useFakeStore(t *testing.T, items map[string][]byte) *fakeStore {
	t.Helper()
	if items == nil {
		items = map[string][]byte{}
	}
	f := &fakeStore{items: items}
	prev := store
	store = f
	t.Cleanup(func() { store = prev })
	return f
}

func assertCalls(t *testing.T, f *fakeStore, want ...string) {
	t.Helper()
	if len(f.calls) != len(want) {
		t.Fatalf("calls: got %q want %q", f.calls, want)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("calls: got %q want %q", f.calls, want)
		}
	}
}

var errBoom = errors.New("boom")

func TestGetReturnsStoredData(t *testing.T) {
	f := useFakeStore(t, map[string][]byte{"default": []byte("tok")})
	got, err := Get("default")
	if err != nil || got != "tok" {
		t.Fatalf("got %q, %v; want tok", got, err)
	}
	assertCalls(t, f, "query default")
}

func TestGetAbsentIsErrNotFound(t *testing.T) {
	useFakeStore(t, nil)
	if _, err := Get("default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestGetPassesQueryErrorThrough(t *testing.T) {
	f := useFakeStore(t, map[string][]byte{"default": []byte("tok")})
	f.queryErr = errBoom
	got, err := Get("default")
	if !errors.Is(err, errBoom) || got != "" {
		t.Fatalf("got %q, %v; want empty and errBoom", got, err)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("a Keychain failure must not read as not found")
	}
}

func TestSetAddsNewItem(t *testing.T) {
	f := useFakeStore(t, nil)
	if err := Set("default", "tok"); err != nil {
		t.Fatal(err)
	}
	if string(f.items["default"]) != "tok" {
		t.Errorf("stored %q", f.items["default"])
	}
	assertCalls(t, f, "add default")
}

func TestSetReplacesDuplicate(t *testing.T) {
	f := useFakeStore(t, map[string][]byte{"default": []byte("old")})
	if err := Set("default", "new"); err != nil {
		t.Fatal(err)
	}
	if string(f.items["default"]) != "new" {
		t.Errorf("stored %q, want new", f.items["default"])
	}
	assertCalls(t, f, "add default", "remove default", "add default")
}

func TestSetReturnsRemoveFailureWithoutReAdding(t *testing.T) {
	f := useFakeStore(t, map[string][]byte{"default": []byte("old")})
	f.removeErr = errBoom
	if err := Set("default", "new"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
	if string(f.items["default"]) != "old" {
		t.Errorf("existing item changed to %q", f.items["default"])
	}
	assertCalls(t, f, "add default", "remove default")
}

func TestSetReturnsSecondAddFailure(t *testing.T) {
	f := useFakeStore(t, map[string][]byte{"default": []byte("old")})
	f.addErrs = []error{nil, errBoom}
	if err := Set("default", "new"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
	assertCalls(t, f, "add default", "remove default", "add default")
}

func TestSetReturnsOtherAddErrorWithoutRemoving(t *testing.T) {
	f := useFakeStore(t, map[string][]byte{"default": []byte("old")})
	f.addErrs = []error{errBoom}
	if err := Set("default", "new"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
	assertCalls(t, f, "add default")
}

func TestDelete(t *testing.T) {
	cases := []struct {
		name      string
		items     map[string][]byte
		removeErr error
		wantErr   error
	}{
		{name: "present", items: map[string][]byte{"default": []byte("tok")}},
		{name: "absent is not an error"},
		{name: "other failure passes through", removeErr: errBoom, wantErr: errBoom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := useFakeStore(t, tc.items)
			f.removeErr = tc.removeErr
			err := Delete("default")
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil {
				if _, ok := f.items["default"]; ok {
					t.Error("item still present")
				}
			}
		})
	}
}

// The Gmail helpers store under their own account, never the Iru token's.
func TestGmailServiceAccountUsesItsOwnAccount(t *testing.T) {
	f := useFakeStore(t, map[string][]byte{"default": []byte("iru-token")})
	blob := []byte(`{"type":"service_account"}`)
	if err := SetGmailServiceAccount(blob); err != nil {
		t.Fatal(err)
	}
	got, err := GetGmailServiceAccount()
	if err != nil || string(got) != string(blob) {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := DeleteGmailServiceAccount(); err != nil {
		t.Fatal(err)
	}
	if _, err := GetGmailServiceAccount(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
	if string(f.items["default"]) != "iru-token" {
		t.Error("the Iru token was disturbed")
	}
	assertCalls(t, f,
		"add gmail_default", "query gmail_default", "remove gmail_default", "query gmail_default")
}

func TestGetGmailServiceAccountPassesErrorThrough(t *testing.T) {
	f := useFakeStore(t, nil)
	f.queryErr = errBoom
	got, err := GetGmailServiceAccount()
	if !errors.Is(err, errBoom) || got != nil {
		t.Fatalf("got %q, %v; want nil and errBoom", got, err)
	}
}

// The guard used by the real-Keychain tests refuses production accounts
// without passing the call on. Checked against a fake so it runs ungated.
func TestGuardedStoreRefusesProductionAccounts(t *testing.T) {
	for _, account := range []string{"default", "iru:acme-us", productionGmailAccount} {
		t.Run(account, func(t *testing.T) {
			inner := &fakeStore{items: map[string][]byte{account: []byte("real")}}
			var reports []string
			g := guardedStore{next: inner, fail: func(format string, args ...any) {
				reports = append(reports, fmt.Sprintf(format, args...))
			}}
			if _, err := g.query(account); err == nil {
				t.Error("query was allowed")
			}
			if err := g.add(account, []byte("x")); err == nil {
				t.Error("add was allowed")
			}
			if err := g.remove(account); err == nil {
				t.Error("remove was allowed")
			}
			if len(inner.calls) != 0 {
				t.Errorf("calls reached the store: %q", inner.calls)
			}
			if string(inner.items[account]) != "real" {
				t.Error("production item changed")
			}
			if len(reports) != 3 {
				t.Errorf("want one failure report per refused call, got %q", reports)
			}
		})
	}
}

func TestGuardedStorePassesTestAccountsThrough(t *testing.T) {
	inner := &fakeStore{items: map[string][]byte{}}
	g := guardedStore{fail: t.Errorf, next: inner}
	if err := g.add("jellyfish-test-x", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.query("jellyfish-test-x"); err != nil {
		t.Fatal(err)
	}
	if err := g.remove("jellyfish-test-x"); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, inner, "add jellyfish-test-x", "query jellyfish-test-x", "remove jellyfish-test-x")
}
