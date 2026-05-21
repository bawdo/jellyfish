package keychain

import "errors"

// Service is the macOS Keychain service identifier used by jellyfish.
const Service = "jellyfish.secrets"

// ErrNotFound is the sentinel returned when no item exists for the given
// account. Callers compare against it with errors.Is.
var ErrNotFound = errors.New("keychain item not found")
