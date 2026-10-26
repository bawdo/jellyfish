// Package atomicfile replaces files whole, with a mode that is enforced
// rather than only applied on creation.
package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFile writes data to path with mode perm, replacing any existing file.
//
// Unlike os.WriteFile, perm holds whether or not path already exists: the data
// goes to a temp file in the same directory, which is chmodded to perm,
// synced, and renamed over path. Readers see the old file or the new one,
// never a partial write. If path is a symlink the write lands on its target,
// so the link itself survives. The parent directory must already exist.
func WriteFile(path string, data []byte, perm fs.FileMode) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp already uses 0600, but perm is explicit so callers can rely
	// on it whatever the umask or a future change to CreateTemp.
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	ok = true
	return nil
}
