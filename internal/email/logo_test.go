package email

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestValidateLogoFileSuccess(t *testing.T) {
	want, err := os.Stat("testdata/logo_small.png")
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	n, err := ValidateLogoFile("testdata/logo_small.png")
	if err != nil {
		t.Fatalf("ValidateLogoFile: %v", err)
	}
	if n != want.Size() {
		t.Errorf("size: got %d want %d", n, want.Size())
	}
}

func TestValidateLogoFileErrors(t *testing.T) {
	dir := t.TempDir()
	notPNG := filepath.Join(dir, "not_png.png")
	if err := os.WriteFile(notPNG, []byte("this is not a png"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	missing := filepath.Join(dir, "nope.png")
	cases := []struct {
		name, path, prefix string
	}{
		{"empty", "", "stat : "},
		{"missing", missing, "stat " + missing + ": "},
		{"too big", "testdata/logo_too_big.png", "logo testdata/logo_too_big.png is "},
		{"not png", notPNG, "decode PNG " + notPNG + ": "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := ValidateLogoFile(tc.path)
			if err == nil {
				t.Fatal("expected error")
			}
			if n != 0 {
				t.Errorf("size on error: got %d want 0", n)
			}
			if !strings.HasPrefix(err.Error(), tc.prefix) {
				t.Errorf("error %q, want prefix %q", err.Error(), tc.prefix)
			}
		})
	}
}
