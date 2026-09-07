package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateExcludeSubRegex(t *testing.T) {
	c := &Config{Domain: "ex.com", Threads: 10, Timeout: 10, NucleiSeverity: "low",
		ExcludeSubs: []string{"^(dev|test)\\.", "[invalid("}}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for invalid exclude-sub regex, got nil")
	}
}

func TestValidateBurpProxy(t *testing.T) {
	c := &Config{Domain: "ex.com", Threads: 10, Timeout: 10, NucleiSeverity: "low",
		BurpPassive: true, BurpProxy: "bad-host;rm -rf /:8080"}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for malicious proxy host, got nil")
	}
	c.BurpProxy = "127.0.0.1:8080"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid burp proxy rejected: %v", err)
	}
}

func TestApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()
	if c.Threads != DefaultThreads {
		t.Errorf("Threads default = %d, want %d", c.Threads, DefaultThreads)
	}
	if c.Timeout != DefaultTimeout {
		t.Errorf("Timeout default = %d, want %d", c.Timeout, DefaultTimeout)
	}
	if c.NucleiSeverity != DefaultNucleiSeverity {
		t.Errorf("NucleiSeverity default = %q, want %q", c.NucleiSeverity, DefaultNucleiSeverity)
	}
	if c.BurpProxy != "127.0.0.1:8080" {
		t.Errorf("BurpProxy default = %q, want 127.0.0.1:8080", c.BurpProxy)
	}
}

func TestLoadYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `# metsuke config
threads: 100
timeout: 30
nuclei_severity: high,critical
webhook_url: https://hooks.example.com/test
session_headers:
  - "Cookie: session=abc"
  - "X-Custom: value"
exclude_subs:
  - "^dev\\."
  - "^test\\."
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := &Config{}
	if err := LoadYAMLFile(c, path); err != nil {
		t.Fatalf("LoadYAMLFile: %v", err)
	}
	if c.Threads != 100 {
		t.Errorf("Threads = %d, want 100", c.Threads)
	}
	if c.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", c.Timeout)
	}
	if c.NucleiSeverity != "high,critical" {
		t.Errorf("NucleiSeverity = %q, want high,critical", c.NucleiSeverity)
	}
	if len(c.SessionHeaders) != 2 {
		t.Errorf("len(SessionHeaders) = %d, want 2", len(c.SessionHeaders))
	}
	if len(c.ExcludeSubs) != 2 {
		t.Errorf("len(ExcludeSubs) = %d, want 2", len(c.ExcludeSubs))
	}
}

func TestLoadYAMLFileMissing(t *testing.T) {
	c := &Config{}
	if err := LoadYAMLFile(c, "/nonexistent/path/config.yaml"); err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port string
		ok   bool
	}{
		{"127.0.0.1:8080", "127.0.0.1", "8080", true},
		{"localhost:80", "localhost", "80", true},
		{"noport", "", "", false},
		{"trail:", "", "", false},
	}
	for _, c := range cases {
		h, p, ok := splitHostPort(c.in)
		if h != c.host || p != c.port || ok != c.ok {
			t.Errorf("splitHostPort(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, h, p, ok, c.host, c.port, c.ok)
		}
	}
}

func TestIsNumeric(t *testing.T) {
	if !isNumeric("8080") {
		t.Error("isNumeric(8080) = false, want true")
	}
	if isNumeric("80a") {
		t.Error("isNumeric(80a) = true, want false")
	}
	if isNumeric("") {
		t.Error("isNumeric() = true, want false")
	}
}
