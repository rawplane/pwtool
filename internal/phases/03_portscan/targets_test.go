package portscan

import "testing"

func TestExtractHost(t *testing.T) {
	line := `{"input":"example.com","url":"https://example.com/path","host":"1.2.3.4","cdn":false}`
	got := extractHost(line)
	if got != "example.com" {
		t.Errorf("extractHost = %q, want example.com", got)
	}
}

func TestExtractHostCDN(t *testing.T) {
	line := `{"url":"https://cdn.example.com","cdn":true}`
	got := extractHost(line)
	if got != "cdn.example.com" {
		t.Errorf("extractHost = %q, want cdn.example.com", got)
	}
}

func TestStripScheme(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080/x", "example.com:8080"},
		{"example.com", "example.com"},
	}
	for _, c := range cases {
		if got := stripScheme(c.in); got != c.want {
			t.Errorf("stripScheme(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
