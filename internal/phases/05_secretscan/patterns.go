// Package secretscan implements Phase 5: JS hardcoded-secret detection.
package secretscan

import "regexp"

// SecretPatterns is a byte-for-byte port of the bash version's
// METSUKE_SECRET_PATTERNS. It matches common credential patterns found in
// JS files: AWS keys, Google API keys, GitHub tokens, Slack webhooks,
// Telegram bot tokens, PEM private key headers, JWTs, Stripe live keys,
// and Slack webhook URLs.
//
// This regex is production-validated — do NOT alter it without an explicit
// request. Any change must be accompanied by unit tests covering both
// positive and negative cases.
const SecretPatterns = `(AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[0-9A-Za-z-]{10,}|[0-9]{8,10}:AA[A-Za-z0-9_-]{33}|-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}|sk_live_[0-9a-zA-Z]{20,}|hooks\.slack\.com/services/T[A-Za-z0-9_/]{8,}`

// secretRE is the compiled form of the patterns above.
var secretRE = regexp.MustCompile(SecretPatterns)

// FindSecrets returns all unique matches of the secret patterns in content.
// Mirrors `grep -aoE "$METSUKE_SECRET_PATTERNS" | sort -u`.
func FindSecrets(content string) []string {
	matches := secretRE.FindAllString(content, -1)
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
