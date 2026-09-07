// Package subdomain implements Phase 1: subdomain enumeration.
package subdomain

import (
	"regexp"
	"strings"
)

// InScope returns true if host is an anchored match for domain: host equals
// domain OR host ends with "."+domain. Case-insensitive.
//
// This replaces the v3 bash substring bug (grep -F ".$DOMAIN") which let
// hosts like evil.example.net.attacker.io pass the filter.
func InScope(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return false
	}
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// ScopeRegex returns the compiled anchored scope regex (^|\.)domain$.
// This is used for bulk grep-style filtering that mirrors the bash version.
func ScopeRegex(domain string) *regexp.Regexp {
	escaped := strings.ToLower(domain)
	// No need to escape dots for our custom usage; we use HasSuffix in
	// InScope, but expose a regex for compatibility/tests.
	pattern := `(?:^|\.)` + regexp.QuoteMeta(escaped) + `$`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}

// normalizeHost lowercases a host, strips leading "*." and trailing ".",
// and removes all internal whitespace — mirroring the bash version's
// sed 's/^\*\.//; s/[[:space:]]//g; s/\.$//'
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimSuffix(h, ".")
	// Remove any embedded whitespace.
	var b strings.Builder
	for _, r := range h {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
