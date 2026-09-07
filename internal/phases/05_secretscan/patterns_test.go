package secretscan

import "testing"

func TestFindSecretsPositive(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"AWS AKIA", "const key = 'AKIAIOSFODNN7EXAMPLE';"},
		{"AWS ASIA", "token = 'ASIAIOSFODNN7EXAMPLE'"},
		{"Google API", `var key = "AIzaSyDQ8G_35charkey_-abcdefghijklmnopqrstuvwxyz"`},
		{"GitHub PAT", "export GH_TOKEN='ghp_abcdefghijklmnopqrstuvwxyz0123456789AB'"},
		{"Slack webhook", "url='https://hooks.slack.com/services/T12345678/ABCDE/xyz123'"},
		{"PEM private key", "-----BEGIN RSA PRIVATE KEY-----"},
		{"JWT", "jwt = 'eyJhbGciOiJIUzI1NiIsInR5c.eyJzdWIiOiIxMjM0NTY3.ABCdef123_-extra10'"},
		{"Stripe live key", "sk_live_1234567890abcdefghijkl"},
		{"Telegram bot token", "bot_token='1234567890:AAH1234567890_-abcdefghijklmnopqrstuvwxyz'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FindSecrets(c.content)
			if len(got) == 0 {
				t.Errorf("expected at least one secret match for %q, got none", c.name)
			}
		})
	}
}

func TestFindSecretsNegative(t *testing.T) {
	cases := []string{
		"console.log('hello world');",
		"const x = 12345;",
		"function foo() { return 'bar'; }",
		"// just a comment",
		"var apiKey = 'short';",
	}
	for _, c := range cases {
		got := FindSecrets(c)
		if len(got) != 0 {
			t.Errorf("expected no secrets in %q, got %v", c, got)
		}
	}
}

func TestFindSecretsDedup(t *testing.T) {
	content := "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE again"
	got := FindSecrets(content)
	if len(got) != 1 {
		t.Errorf("expected 1 unique match (deduped), got %d: %v", len(got), got)
	}
}

func TestFindSecretsMultiple(t *testing.T) {
	content := "AKIAIOSFODNN7EXAMPLE ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
	got := FindSecrets(content)
	if len(got) != 2 {
		t.Errorf("expected 2 matches, got %d: %v", len(got), got)
	}
}
