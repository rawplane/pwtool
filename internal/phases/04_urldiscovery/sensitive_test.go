package urldiscovery

import "testing"

func TestMatchSensitivePositive(t *testing.T) {
	cases := []string{
		"https://example.com/.env",
		"https://example.com/.env?foo=1",
		"https://example.com/.git",
		"https://example.com/.git/config",
		"https://example.com/admin",
		"https://example.com/admin/login",
		"https://example.com/config",
		"https://example.com/auth/oauth",
		"https://example.com/oauth/token",
		"https://example.com/api/v1/users",
		"https://example.com/graphql",
		"https://example.com/swagger",
		"https://example.com/openapi.json",
		"https://example.com/login",
		"https://example.com/session",
		"https://example.com/jwt",
		"https://example.com/.yml",
		"https://example.com/config.yaml",
		"https://example.com/internal/debug",
		"https://example.com/firebase/config",
		"https://example.com/aws/credentials",
		"https://example.com/token",
		"https://example.com/refresh-token",
		"https://example.com/webhooks/callback",
		"https://example.com/management",
		"https://example.com/credentials",
		"https://example.com/authentication",
		"https://example.com/sso/login",
	}
	for _, url := range cases {
		if !MatchSensitiveEndpoint(url) {
			t.Errorf("expected match for %q", url)
		}
	}
}

func TestMatchSensitiveNegative(t *testing.T) {
	cases := []string{
		"https://example.com/",
		"https://example.com/blog/post-1",
		"https://example.com/images/logo.png",
		"https://example.com/static/app.js",
		"https://example.com/about",
		"https://example.com/contact",
		"https://example.com/products",
		"https://example.com/health",
	}
	for _, url := range cases {
		if MatchSensitiveEndpoint(url) {
			t.Errorf("expected NO match for %q", url)
		}
	}
}

func TestFindSensitiveURLs(t *testing.T) {
	lines := []string{
		"https://example.com/admin",
		"https://example.com/blog",
		"https://example.com/admin", // duplicate
		"https://example.com/.env",
		"https://example.com/static/style.css",
	}
	got := FindSensitiveURLs(lines)
	if len(got) != 2 {
		t.Errorf("expected 2 sensitive URLs, got %d: %v", len(got), got)
	}
}
