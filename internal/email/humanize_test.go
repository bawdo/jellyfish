package email

import "testing"

func TestFormatInt(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{9, "9"},
		{999, "999"},
		{1000, "1,000"},
		{1234, "1,234"},
		{12345, "12,345"},
		{123456, "123,456"},
		{1234567, "1,234,567"},
		{18553, "18,553"},
		{-1234, "-1,234"},
	}
	for _, c := range cases {
		if got := formatInt(c.in); got != c.want {
			t.Errorf("formatInt(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatOneDec(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0.0, "0.0"},
		{0.5, "0.5"},
		{1.0, "1.0"},
		{22.3, "22.3"},
		{999.95, "1,000.0"}, // strconv.FormatFloat rounds 999.95 up on this platform
		{1000.0, "1,000.0"},
		{1234.27, "1,234.3"},
		{8914.32, "8,914.3"},
		{12345.5, "12,345.5"},
		{18553.0, "18,553.0"},
		{-1234.5, "-1,234.5"},
	}
	for _, c := range cases {
		if got := formatOneDec(c.in); got != c.want {
			t.Errorf("formatOneDec(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
