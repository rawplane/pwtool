package urldiscovery

import (
	"strings"
	"testing"
)

func TestTemplateSegment(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// UUID → :uuid
		{"550e8400-e29b-41d4-a716-446655440000", ":uuid"},
		// hex >=24 → :rid
		{"507f1f77bcf86cd799439011", ":rid"}, // 24 hex
		// alnum mixed >=14 → :rid
		{"abcDEF1234567890", ":rid"}, // 16 chars, letters+digits
		// numeric → :id
		{"12345", ":id"},
		// non-matching → unchanged
		{"users", "users"},
		{"api", "api"},
		{"", ""},
		// short alnum mixed → unchanged
		{"abc123", "abc123"}, // <14
	}
	for _, c := range cases {
		got := templateSegment(c.in)
		if got != c.want {
			t.Errorf("templateSegment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSignature(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "uuid in path",
			url:  "https://example.com/users/550e8400-e29b-41d4-a716-446655440000/profile",
			want: "https://example.com/users/:uuid/profile",
		},
		{
			name: "numeric id",
			url:  "https://example.com/posts/12345",
			want: "https://example.com/posts/:id",
		},
		{
			name: "params sorted",
			url:  "https://example.com/search?q=test&page=2",
			want: "https://example.com/search&page&q",
		},
		{
			name: "params dedup same sig",
			url:  "https://example.com/search?page=2&q=test",
			want: "https://example.com/search&page&q",
		},
		{
			name: "no query",
			url:  "https://example.com/about",
			want: "https://example.com/about",
		},
		{
			name: "hex resource id",
			url:  "https://example.com/v1/507f1f77bcf86cd799439011",
			want: "https://example.com/v1/:rid",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := signature(c.url)
			if got != c.want {
				t.Errorf("signature(%q) = %q, want %q", c.url, got, c.want)
			}
		})
	}
}

func TestSignatureDedupDifferentOrderSameResult(t *testing.T) {
	// Two URLs with same path + same params in different order must have
	// the same signature.
	sig1 := signature("https://x.com/p?a=1&b=2&c=3")
	sig2 := signature("https://x.com/p?c=3&a=1&b=2")
	if sig1 != sig2 {
		t.Errorf("signatures differ:\n  %q\n  %q", sig1, sig2)
	}
}

func TestNormalizeAndDedupe(t *testing.T) {
	input := strings.Join([]string{
		"https://example.com/users/12345",
		"https://example.com/users/67890", // same sig as above → deduped
		"https://example.com/users/12345", // exact duplicate
		"https://example.com/about",
		"https://example.com/search?q=a&page=2",
		"https://example.com/search?page=2&q=b", // same sig as above
		"",
	}, "\n")
	var out strings.Builder
	if err := NormalizeAndDedupe(strings.NewReader(input), &out); err != nil {
		t.Fatalf("NormalizeAndDedupe: %v", err)
	}
	got := out.String()
	// Should contain exactly 3 unique lines.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 unique URLs, got %d:\n%s", len(lines), got)
	}
	// Should preserve ORIGINAL URLs, not templated.
	if !strings.Contains(got, "https://example.com/users/12345") {
		t.Error("output should preserve the original URL, not the templated one")
	}
	if strings.Contains(got, ":id") {
		t.Error("output must NOT contain templated placeholders")
	}
}
