package config

import (
	"testing"
)

func TestValidateValidDomain(t *testing.T) {
	c := &Config{Domain: "Example.COM", Threads: 50, Timeout: 10, NucleiSeverity: "low,medium,high,critical"}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c.Domain != "example.com" {
		t.Errorf("domain not lowercased: %q", c.Domain)
	}
}

func TestValidateMissingDomain(t *testing.T) {
	c := &Config{Threads: 50, Timeout: 10, NucleiSeverity: "low"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing domain, got nil")
	}
}

func TestValidateBadDomain(t *testing.T) {
	cases := []string{
		"not a domain",
		"localhost",
		"-bad.example.com",
		"example..com",
	}
	for _, d := range cases {
		c := &Config{Domain: d, Threads: 50, Timeout: 10, NucleiSeverity: "low"}
		c.ApplyDefaults()
		if err := c.Validate(); err == nil {
			t.Errorf("expected error for bad domain %q, got nil", d)
		}
	}
}

func TestValidateThreadsRange(t *testing.T) {
	for _, n := range []int{0, -1, 501, 1000} {
		c := &Config{Domain: "ex.com", Threads: n, Timeout: 10, NucleiSeverity: "low"}
		if err := c.Validate(); err == nil {
			t.Errorf("expected error for threads=%d, got nil", n)
		}
	}
}

func TestValidateTimeoutRange(t *testing.T) {
	for _, n := range []int{0, 2, 301, 500} {
		c := &Config{Domain: "ex.com", Threads: 10, Timeout: n, NucleiSeverity: "low"}
		if err := c.Validate(); err == nil {
			t.Errorf("expected error for timeout=%d, got nil", n)
		}
	}
}

func TestValidateNucleiSeverity(t *testing.T) {
	c := &Config{Domain: "ex.com", Threads: 10, Timeout: 10, NucleiSeverity: "bogus"}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for bogus severity, got nil")
	}
	c.NucleiSeverity = "low,medium,high,critical,info,unknown"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid severity list rejected: %v", err)
	}
}
