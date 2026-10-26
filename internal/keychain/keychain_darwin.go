//go:build darwin

package keychain

import (
	"errors"

	kc "github.com/keybase/go-keychain"
)

// itemStore is the account-level surface of the Security framework that
// Get, Set and Delete build on. The decisions (replace on duplicate, absent
// means ErrNotFound or success) live in those functions so they can be
// tested against a fake; securityStore is kept as a thin translation onto
// go-keychain and is exercised by the gated real-Keychain tests.
type itemStore interface {
	query(account string) ([]kc.QueryResult, error)
	add(account string, data []byte) error
	remove(account string) error
}

var store itemStore = securityStore{}

// Get returns the stored token for account, or ErrNotFound.
func Get(account string) (string, error) {
	results, err := store.query(account)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", ErrNotFound
	}
	return string(results[0].Data), nil
}

// Set writes (or replaces) the token for account.
func Set(account, token string) error {
	err := store.add(account, []byte(token))
	if errors.Is(err, kc.ErrorDuplicateItem) {
		// Replace the existing item.
		if delErr := store.remove(account); delErr != nil {
			return delErr
		}
		return store.add(account, []byte(token))
	}
	return err
}

// Delete removes the token for account. Returns nil if it did not exist.
func Delete(account string) error {
	err := store.remove(account)
	if errors.Is(err, kc.ErrorItemNotFound) {
		return nil
	}
	return err
}

// securityStore talks to the macOS Keychain through go-keychain. Every item
// is a generic password under Service.
type securityStore struct{}

func genericPassword(account string) kc.Item {
	item := kc.NewItem()
	item.SetSecClass(kc.SecClassGenericPassword)
	item.SetService(Service)
	item.SetAccount(account)
	return item
}

func (securityStore) query(account string) ([]kc.QueryResult, error) {
	q := genericPassword(account)
	q.SetMatchLimit(kc.MatchLimitOne)
	q.SetReturnData(true)
	return kc.QueryItem(q)
}

func (securityStore) add(account string, data []byte) error {
	item := genericPassword(account)
	item.SetData(data)
	item.SetSynchronizable(kc.SynchronizableNo)
	item.SetAccessible(kc.AccessibleWhenUnlocked)
	return kc.AddItem(item)
}

func (securityStore) remove(account string) error {
	return kc.DeleteItem(genericPassword(account))
}
