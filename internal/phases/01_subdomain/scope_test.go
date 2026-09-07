package subdomain

import "testing"

func TestInScope(t *testing.T) {
	domain := "example.com"
	cases := []struct {
		host string
		want bool
	}{
		// In scope
		{"example.com", true},
		{"www.example.com", true},
		{"a.b.example.com", true},
		{"EXAMPLE.COM", true},  // case-insensitive
		{"WWW.Example.Com", true},

		// Out of scope — the v3 substring bug would pass these
		{"evil.example.com.attacker.io", false},
		{"notexample.com", false},
		{"example.com.evil", false},
		{"example.com.attacker.io", false},
		{"xexample.com", false},
		{"", false},
		{"example", false},
	}
	for _, c := range cases {
		got := InScope(c.host, domain)
		if got != c.want {
			t.Errorf("InScope(%q, %q) = %v, want %v", c.host, domain, got, c.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"*.example.com", "example.com"},
		{"WWW.example.com.", "www.example.com"},
		{"  foo.example.com  ", "foo.example.com"},
		{"bar.example.com\n", "bar.example.com"},
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeHost(c.in)
		if got != c.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExcluded(t *testing.T) {
	patterns := []string{"^dev\\.", "^test\\."}
	if !excluded("dev.example.com", patterns) {
		t.Error("dev.example.com should be excluded")
	}
	if excluded("www.example.com", patterns) {
		t.Error("www.example.com should not be excluded")
	}
	// Invalid regex should not cause a panic, just skip.
	if excluded("anything", []string{"[invalid("}) {
		t.Error("invalid regex should not match anything")
	}
}
