package keychain

// productionGmailAccount is the Keychain account name under the existing
// jellyfish service that stores the Gmail service-account JSON.
const productionGmailAccount = "gmail_default"

// accountGmailServiceAccount is the account the Gmail helpers use. It is a
// var only so the gated real-Keychain tests can point it at a throwaway
// account and never touch a configured credential.
var accountGmailServiceAccount = productionGmailAccount

// SetGmailServiceAccount writes (or replaces) the service-account JSON blob.
func SetGmailServiceAccount(jsonBytes []byte) error {
	return Set(accountGmailServiceAccount, string(jsonBytes))
}

// GetGmailServiceAccount returns the stored service-account JSON, or
// ErrNotFound if `jellyfish configure email` was never run.
func GetGmailServiceAccount() ([]byte, error) {
	s, err := Get(accountGmailServiceAccount)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// DeleteGmailServiceAccount removes the stored credential. Nil if absent.
func DeleteGmailServiceAccount() error {
	return Delete(accountGmailServiceAccount)
}
