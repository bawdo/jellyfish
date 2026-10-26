package email

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"path/filepath"
)

// logoPart is the inline image attachment included in the multipart/related
// envelope when a logo is configured.
type logoPart struct {
	Bytes []byte
	Name  string
	CID   string
}

// MaxLogoBytes caps the on-disk PNG size accepted by loadLogo. 512 KiB is
// generous for a header logo and well under any mail-client size limit.
const MaxLogoBytes = 512 * 1024

// MaxLogoDimension caps a logo's width and height in pixels. The header
// renders the logo at a few dozen pixels tall, so nothing larger is ever
// needed, and checking the PNG header against this bound before a full
// decode stops a small, highly compressed file from forcing a huge pixel
// buffer allocation (a decompression bomb).
const MaxLogoDimension = 2048

// loadLogo reads path, validates it as a regular-file PNG no larger than
// MaxLogoBytes on disk and MaxLogoDimension pixels on either side, and
// returns a *logoPart. An empty path returns (nil, nil): callers treat that
// as "no logo configured", not an error.
func loadLogo(path string) (*logoPart, error) {
	if path == "" {
		return nil, nil
	}
	// #nosec G304 - path is the operator's own config or flag input
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	// A FIFO or device reports size 0 and can be read without end (or block
	// forever on open), so only regular files get past this point.
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("logo %s is not a regular file", path)
	}
	if info.Size() > MaxLogoBytes {
		return nil, fmt.Errorf("logo %s is %d bytes (max %d)", path, info.Size(), MaxLogoBytes)
	}
	// #nosec G304 - see above
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	// The Stat size is only advisory (the file can grow after the check),
	// so the read itself is bounded too.
	data, err := readLogoBytes(f, path)
	if err != nil {
		return nil, err
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode PNG %s: %w", path, err)
	}
	if cfg.Width > MaxLogoDimension || cfg.Height > MaxLogoDimension {
		return nil, fmt.Errorf("logo %s is %dx%d pixels (max %dx%d)",
			path, cfg.Width, cfg.Height, MaxLogoDimension, MaxLogoDimension)
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("decode PNG %s: %w", path, err)
	}
	return &logoPart{
		Bytes: data,
		Name:  filepath.Base(path),
		CID:   "jf-logo",
	}, nil
}

// readLogoBytes reads at most MaxLogoBytes from r, failing if there is more.
// path is used only in error messages.
func readLogoBytes(r io.Reader, path string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxLogoBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > MaxLogoBytes {
		return nil, fmt.Errorf("logo %s is over %d bytes (max %d)", path, MaxLogoBytes, MaxLogoBytes)
	}
	return data, nil
}

// ValidateLogoFile checks that path points at a readable PNG within
// MaxLogoBytes and MaxLogoDimension. Returns the byte length on success.
func ValidateLogoFile(path string) (int64, error) {
	if path == "" {
		// loadLogo treats "" as "no logo"; here an explicit path is required.
		return 0, errors.New("logo path is empty")
	}
	part, err := loadLogo(path)
	if err != nil {
		return 0, err
	}
	return int64(len(part.Bytes)), nil
}
