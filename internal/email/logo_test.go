package email

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadLogoSuccess(t *testing.T) {
	p, err := loadLogo("testdata/logo_small.png")
	if err != nil {
		t.Fatalf("loadLogo: %v", err)
	}
	if p == nil {
		t.Fatal("loadLogo: nil part")
	}
	if p.CID != "jf-logo" {
		t.Errorf("CID: got %q want jf-logo", p.CID)
	}
	if p.Name != "logo_small.png" {
		t.Errorf("Name: got %q want logo_small.png", p.Name)
	}
	want, err := os.ReadFile("testdata/logo_small.png")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(p.Bytes, want) {
		t.Errorf("Bytes: got %d bytes, want %d bytes (content mismatch)", len(p.Bytes), len(want))
	}
}

func TestLoadLogoMissing(t *testing.T) {
	_, err := loadLogo(filepath.Join(t.TempDir(), "nope.png"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadLogoNotPNG(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not_png.png")
	if err := os.WriteFile(path, []byte("this is not a png"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := loadLogo(path)
	if err == nil {
		t.Fatal("expected error for non-PNG bytes")
	}
}

func TestLoadLogoTooBig(t *testing.T) {
	_, err := loadLogo("testdata/logo_too_big.png")
	if err == nil {
		t.Fatal("expected error for oversize PNG")
	}
}

func TestLoadLogoEmptyPathReturnsNilNil(t *testing.T) {
	p, err := loadLogo("")
	if err != nil {
		t.Fatalf("loadLogo(\"\"): unexpected error %v", err)
	}
	if p != nil {
		t.Fatalf("loadLogo(\"\"): expected nil, got %+v", p)
	}
}

func TestReadLogoFileSuccess(t *testing.T) {
	want, err := os.Stat("testdata/logo_small.png")
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	data, err := ReadLogoFile("testdata/logo_small.png")
	if err != nil {
		t.Fatalf("ReadLogoFile: %v", err)
	}
	if int64(len(data)) != want.Size() {
		t.Errorf("size: got %d want %d", len(data), want.Size())
	}
}

func TestReadLogoFileErrors(t *testing.T) {
	dir := t.TempDir()
	notPNG := filepath.Join(dir, "not_png.png")
	if err := os.WriteFile(notPNG, []byte("this is not a png"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	missing := filepath.Join(dir, "nope.png")
	cases := []struct {
		name, path, prefix string
	}{
		{"missing", missing, "stat " + missing + ": "},
		{"too big", "testdata/logo_too_big.png", "logo testdata/logo_too_big.png is "},
		{"not png", notPNG, "decode PNG " + notPNG + ": "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ReadLogoFile(tc.path)
			if err == nil {
				t.Fatal("expected error")
			}
			if data != nil {
				t.Errorf("bytes on error: got %d, want nil", len(data))
			}
			if !strings.HasPrefix(err.Error(), tc.prefix) {
				t.Errorf("error %q, want prefix %q", err.Error(), tc.prefix)
			}
		})
	}
}

func TestReadLogoFileEmptyPath(t *testing.T) {
	data, err := ReadLogoFile("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if data != nil {
		t.Errorf("bytes on error: got %d, want nil", len(data))
	}
	if got, want := err.Error(), "logo path is empty"; got != want {
		t.Errorf("error %q, want %q", got, want)
	}
}

func TestLoadLogoRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := loadLogo(dir)
	if err == nil {
		t.Fatal("expected error for a directory")
	}
	if want := "logo " + dir + " is not a regular file"; err.Error() != want {
		t.Errorf("error %q, want %q", err.Error(), want)
	}
}

func TestLoadLogoRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logo.png")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	// A FIFO with no writer would block a naive read forever, so run the
	// call with a deadline: a hang here is the bug this test guards against.
	done := make(chan error, 1)
	go func() {
		_, err := loadLogo(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for a FIFO")
		}
		if want := "logo " + path + " is not a regular file"; err.Error() != want {
			t.Errorf("error %q, want %q", err.Error(), want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loadLogo blocked reading a FIFO")
	}
}

// pngWithDimensions encodes a 1x1 PNG and rewrites its IHDR width and height
// (recomputing the chunk CRC), giving a tiny file whose header claims w x h.
// png.DecodeConfig reads only the IHDR, so this is enough to exercise the
// dimension check without allocating a large image.
func pngWithDimensions(t *testing.T, w, h uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatalf("encode: %v", err)
	}
	data := buf.Bytes()
	// 8-byte signature, then IHDR: length(4) type(4) data(13) crc(4).
	if string(data[12:16]) != "IHDR" {
		t.Fatalf("unexpected PNG layout: %q", data[12:16])
	}
	binary.BigEndian.PutUint32(data[16:20], w)
	binary.BigEndian.PutUint32(data[20:24], h)
	binary.BigEndian.PutUint32(data[29:33], crc32.ChecksumIEEE(data[12:29]))
	return data
}

func TestLoadLogoRejectsOversizedDimensions(t *testing.T) {
	cases := []struct {
		name string
		w, h uint32
	}{
		{"wide", MaxLogoDimension + 1, 1},
		{"tall", 1, MaxLogoDimension + 1},
		{"bomb", 100000, 100000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "big.png")
			if err := os.WriteFile(path, pngWithDimensions(t, tc.w, tc.h), 0o600); err != nil {
				t.Fatalf("setup: %v", err)
			}
			_, err := loadLogo(path)
			if err == nil {
				t.Fatal("expected error for oversized dimensions")
			}
			want := fmt.Sprintf("logo %s is %dx%d pixels (max %dx%d)", path, tc.w, tc.h, MaxLogoDimension, MaxLogoDimension)
			if err.Error() != want {
				t.Errorf("error %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestReadLogoBytesIsBounded(t *testing.T) {
	// Stands in for a file that grew after the Stat size check: the read
	// itself must stop at MaxLogoBytes+1 rather than trusting Stat.
	over := io.LimitReader(zeroReader{}, MaxLogoBytes*4)
	_, err := readLogoBytes(over, "grown.png")
	if err == nil {
		t.Fatal("expected error for a read over MaxLogoBytes")
	}
	if want := fmt.Sprintf("logo grown.png is over %d bytes (max %d)", MaxLogoBytes, MaxLogoBytes); err.Error() != want {
		t.Errorf("error %q, want %q", err.Error(), want)
	}

	data, err := readLogoBytes(io.LimitReader(zeroReader{}, MaxLogoBytes), "exact.png")
	if err != nil {
		t.Fatalf("exactly MaxLogoBytes should be accepted: %v", err)
	}
	if len(data) != MaxLogoBytes {
		t.Errorf("len: got %d want %d", len(data), MaxLogoBytes)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestLoadLogoAcceptsMaxDimensionHeader(t *testing.T) {
	// The header check must not reject an image exactly at the bound. The
	// patched IDAT no longer matches, so full decode fails afterwards: that
	// is fine, it proves the dimension gate let it through to decode.
	path := filepath.Join(t.TempDir(), "edge.png")
	if err := os.WriteFile(path, pngWithDimensions(t, MaxLogoDimension, MaxLogoDimension), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := loadLogo(path)
	if err == nil || !strings.HasPrefix(err.Error(), "decode PNG "+path+": ") {
		t.Fatalf("error %v, want a decode PNG error (dimension gate passed)", err)
	}
}
